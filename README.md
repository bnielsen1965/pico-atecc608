# pico-atecc608

A Raspberry Pi Pico C module for interfacing with the **Microchip ATECC608**
crypto co-processor over I2C. It is designed to be **embedded in other Pico
projects** as a reusable sub-module, so a project does not have to
re-implement the ATECC wake handshake, I2C protocol, CRC, or any of the
command plumbing. It builds on Microchip's **cryptoauthlib v3.8.0**, adding
an RP2350 I2C HAL and a curated, stable `atecc608_*` API.

> **Scope.** This repository is the *driver/module*, not an application.
> Applications (password stores, FIDO2 authenticators, secure firmware
> updates, …) build on the module's primitives. The
> [Application scenarios](#application-scenarios--provisioning-guidance)
> section documents the agreed chip configuration that those applications
> share. `PLAN.md` holds the development plan and decisions; `RESUME.md` is
> the continuity snapshot.

---

## Status

- **Done:** module skeleton + build wiring; RP2350 I2C HAL; curated
  `atecc608_*` core API (hardware-validated, read-only); config-zone builder
  + guarded provisioning API + host unit tests against a mock chip (`ctest`
  green).
- **In progress:** provisioning the connected chip with the agreed
  development configuration (below) — pending explicit write approval. The
  chip is currently **unprovisioned**.
- **Next:** crypto pass-through (KDF / sign / verify wrappers), a
  config-read-back console demo, full on-hardware validation + bring-up
  checklist.

---

## Application scenarios — provisioning guidance

The chip is configured **once**: slot types and per-slot access rules live in
the config zone, and locking that zone makes them permanent. The
configuration must therefore serve *every* application the chip will host.
The agreed design principle:

> **Lock the layout, keep the contents open.**
> The config zone is locked during provisioning — slot types, access rules,
> counters, and I/O protection become permanent. Key *material* stays
> replaceable under the frozen rules: slots allow key generation and content
> writes without an auth key, so each application can provision its own keys
> while developing. When an application's keys go to production, that slot is
> **individually locked** — which freezes the *contents* but not *use* (a
> locked slot can still sign, verify, or serve as a KDF source).

The ATECC608 does no bulk encryption (no AES-GCM/CTR). The division of labor
in every scenario is: **chip = key vault + signer/verifier** (ECC P-256,
KDF, monotonic counters); **Pico = bulk crypto** (the RP2350 has hardware
AES and SHA-256).

### Agreed slot configuration (16 slots)

| Slot | Type | Serves |
|---|---|---|
| 0 | EC P-256 public | firmware validation key (primary) |
| 1 | EC P-256 private | device identity key |
| 2 | EC P-256 public | device identity public key |
| 3–6 | EC P-256 private ×4 | FIDO2 / passkey credentials |
| 7 | non-ECC secret (unreadable) | password-store master (KDF source) |
| 8–10 | non-ECC secret (unreadable) ×3 | spare compartments (future apps) |
| 11 | EC P-256 public | second firmware key (dual-signer / rotation) |
| 12 | EC P-256 private | spare (ECDH with host, 2nd identity) |
| 13 | EC P-256 public | pair of 12 |
| 14 | non-ECC secret (unreadable) | I/O protection key |
| 15 | data (no key) | spare |

Counters (21-bit, monotonic, config-zone fields): **Counter 0** = FIDO2
signature count (the CTAP global counter); **Counter 1** = firmware
anti-rollback (minimum accepted image version).

**I/O protection is enabled from the start**: sensitive command outputs
(KDF, ECDH) are AES-encrypted on the bus using the key stored in slot 14
(the Pico holds a copy). Slot 14 is an unreadable secret slot (`is_secret`)
— the key cannot be read back in clear, matching the pattern of the
cryptoauthlib reference config, which keeps its I/O key in a secret
non-ECC slot. The slot-7 master and the private keys in 3–6/12 never
appear in clear on the I2C bus.

### Scenario 1 — PIN-gated password store

- **Master:** a high-entropy secret generated on-chip into slot 7 at
  provisioning. The slot is `is_secret` — it cannot be read at all, not even
  an encrypted read. It never leaves the chip.
- **Vault:** an AES-256-GCM blob on Pico flash. The 16-byte per-vault salt is
  drawn from the chip's RNG at vault creation and stored in the vault header
  on flash (a salt is not secret).
- **Unlock:** the Pico issues a KDF (PRF mode) — source = slot 7, input =
  salt ‖ PIN — and the chip returns the derived 32-byte key (encrypted in
  transit by I/O protection). The Pico uses it for AES-256-GCM. Wrong PIN →
  wrong derived key → GCM auth tag fails.
- **PIN policy:** 8–16 hex digits (32–64 bits of entropy).
- **Per-entry keys:** the same master with a per-entry salt in the KDF input
  gives each entry its own key. Because different (PIN, salt) pairs derive
  different keys, one master can serve unlimited stores; slots 8–10 remain
  for apps that want a fully separate master.
- **Brute-force lockout:** enforced Pico-side (fail count + lock flag in
  NVS; e.g. 5 failures → locked until a deliberate reset). The chip has no
  native lockout, and a 32–64-bit PIN already makes online guessing
  infeasible — the lockout is defense in depth.

### Scenario 2 — FIDO2 / passkey (CTAP2)

- **Credentials:** each credential is an EC P-256 private key in slots 3–6,
  generated on-chip (GenKey); the private key never leaves the chip, and the
  public key is derived from the slot for registration. **4 slots = 4
  discoverable credentials total**, across all sites.
- **Resident (discoverable) keys:** the private key is always on the chip in
  either mode; "resident" means the *metadata* (credential ID, user handle,
  RP ID hash, slot index) is stored in a small DB in Pico flash, letting the
  authenticator enumerate its credentials. A Pico reflash loses the DB, not
  the keys — slots can be re-bound or regenerated.
- **Assertion:** the Pico computes SHA-256(authData ‖ clientDataHash) in
  hardware; the chip signs the digest.
- **Counter:** Counter 0 is read before and incremented after each assertion.
  It is monotonic and cannot be reset by reflashing the Pico — a reset is a
  clone signal to relying parties.

### Scenario 3 — Secure firmware updates

- **Validation:** the firmware signing key's public key lives in slot 0; the
  private signing key lives only on the build machine. Bootloader flow:
  SHA-256 the candidate image (hardware) → chip `Verify` against slot 0 →
  check image version > Counter 1 → swap → increment Counter 1 to the new
  version.
- **Anti-rollback:** Counter 1 is chip-side because the threat (malicious or
  rolled-back firmware, flash reflash) can also write Pico flash — a
  flash-resident version counter would be reset by the very attack it
  defends against.
- Slot 11 holds a second public key for dual signers or key rotation.
- Note: this is **bootloader-level** validation. The RP2350's ROM-level
  hardware secure boot accepts keys in flash only, so the chip's role stays
  at the first-stage-bootloader level.

### Scenario 4 — Device identity / attestation

Slots 1/2 form the identity pair (generated on-chip at provisioning). A host
keeps the public key (or a certificate); the chip signs challenges for
device enrollment, pairing, or attestation.

### Spare capacity (future apps)

- **Slots 8–10 — spare compartments.** Each future app can claim one:
  generate its secret on-chip (GenKey), use it as a KDF source or other
  non-ECC key, and individually lock the slot when it goes to production.
  Unclaimed slots stay empty and available indefinitely — the config lock
  does not prevent later GenKey; only an individual slot lock freezes
  contents.
- **Slots 12/13** — a spare EC pair (ECDH secure channel to a host PC, a
  second identity, …). **Slot 15** — general-purpose data.

### Locking discipline (provisioning order)

Every step is read-back verified; locks come last and are irreversible:

1. **Write the config zone** per the agreed layout — reversible while the
   zone is unlocked.
2. **Provision contents:** GenKey the identity/FIDO2/spare keys and the
   slot-7 secret, write the firmware public key(s) and the I/O protection
   key — all reversible while the slots are unlocked.
3. **Verify:** config read-back, public-key reads, sign/verify round-trip,
   KDF round-trip, counter reads.
4. **Lock the config zone** — *irreversible*; the layout is permanent.
5. **Per app, at production time:** individually lock its slot(s) —
   *irreversible*.

The provisioning API (`atecc608_prov`) enforces this: write → read-back →
byte-compare, locks gated behind read-back plus a typed-confirmation hook,
and idempotent re-runs while the relevant zone is unlocked.

---

## What the module provides

- **Core API** (`include/atecc608/atecc608.h`): `atecc608_init` (I2C
  instance, pins, baud), `probe`, `info` (part/revision), `serial` (factory
  serial), `is_locked` (config/data zone), `random`, `read_config_zone`,
  `read_slot`, `read_pubkey`, `write_config_zone`, `write_slot`, plus
  `atecc608_last_error()` / `atecc608_status_str()` — every call's failure
  is available as a curated status.
- **Config-zone builder** (`atecc608_config.h`): a field-level intent struct
  → 128-byte config array, a parser, CRC-16, and a writable-region diff —
  consumers express intent, never raw bytes.
- **Guarded provisioning** (`atecc608_prov.h`): idempotent
  `provision_config` (read-back verified, preserves the chip's I2C address
  byte), `lock_config_zone`, `lock_data_zone`, `lock_data_slot`, `genkey`,
  `counter_read` / `counter_increment` — every irreversible step is
  confirm-hook gated.
- **Crypto pass-through** (KDF / sign / verify / `read_pubkey` wrappers):
  next phase, added as consumers need them.

---

## Hardware

- **Chip:** ATECC608 family (the target part is an **ATECC608C**). In
  cryptoauthlib there is no separate `ATECC608C` identifier — the A/B/C parts
  all map to device type 3, so use `ATECC608`.
- **Interface:** standard I2C, up to 1 MHz. This project wakes at **100 kHz**
  and runs normal traffic at **400 kHz**.
- **Address:** 7-bit `0x60` (ADR pin → GND) or `0x61` (ADR pin → VDD). The
  driver auto-detects.
- **Pull-ups:** the ATECC I2C lines need pull-ups to 3V3 (4.7 kΩ typical);
  the firmware enables the on-chip pull-ups as a fallback.
- **Wake:** after power-up the chip sleeps until woken. It takes ~1.5 ms
  (tWHI) for the wake to be ready and up to ~400 µs to initialize; if left
  idle ~1.3 s it auto-sleeps again (the driver re-wakes as needed).

### Sample wiring (the console app)

| Pico 2 (RP2350) | ATECC608 |
|---|---|
| GP20 (I2C0 SDA) | SDA (pull-up to 3V3) |
| GP21 (I2C0 SCL) | SCL (pull-up to 3V3) |
| 3V3 | VCC |
| GND | GND |
| GP0 / GP1 (UART0) | USB-serial console (optional) |
| USB | flashing + CDC console |

Pins are `#define`s in `app/main.c` — a consuming project supplies its own.

---

## Requirements

- Raspberry Pi Pico 2 (RP2350). *(RP2040 support is not currently planned;
  the HAL could add it later.)*
- [pico-sdk](https://github.com/raspberrypi/pico-sdk)
- ATECC608 on the I2C bus
- Microchip cryptoauthlib v3.8.0 — **fetched at build time** by CMake from
  `github.com/microchiptech/cryptoauthlib`; **no cryptoauthlib source is
  stored in this repo** (see Licensing).

---

## Building

The first `cmake` configure **fetches cryptoauthlib v3.8.0 from GitHub**
(network needed once; it is cached under `build/` afterward and is never
stored in this repo). For an air-gapped build, point CMake at a local clone
instead: `-DCRYPTOAUTHLIB_SOURCE_DIR=/path/to/cryptoauthlib`.

```sh
# Pico 2, Cortex-M33 cores (default). Needs PICO_SDK_PATH to point at pico-sdk.
mkdir -p build && cd build
cmake .. -DPICO_SDK_PATH="$HOME/Projects/pico-sdk"
make -j

# Flash over USB: drag build/app/pico-atecc608.uf2 to the RPI-RP2 drive,
# or use the `bootrom` console command to re-enter BOOTSEL.
```

The build produces the demo image in `build/app/` (`pico-atecc608.uf2` /
`.bin` / `.elf` / `.map`) and two static libraries in `build/`:
**`libatecc608.a`** (the module) and **`libcryptoauth_core.a`** (the fetched
cryptoauthlib core, compiled for the Pico target).

Console is on both USB CDC serial and UART0 (GP0/GP1).

### Console commands

| Command | Action |
|---|---|
| `help` | list commands |
| `bootrom` | reset into BOOTSEL (USB bootloader) |
| `probe` | wake handshake at 0x60/0x61 to locate the chip |
| `diag` | I2C bus levels + raw wake-handshake bytes |
| `random` | 32 random bytes from the chip |
| `info` | part id + silicon revision |
| `serial` | factory serial number |
| `lock` | lock status (config zone / data zone) |

---

## Host unit tests

`tests/` is a standalone host CMake project: the same cryptoauthlib v3.8.0,
the module's config/provisioning sources, and a **mock chip HAL** that
emulates the ATECC608 wire protocol and factory state. No hardware needed.

```sh
cmake -S tests -B tests/build -DCRYPTOAUTHLIB_SOURCE_DIR=/path/to/cryptoauthlib
cmake --build tests/build -j
ctest --test-dir tests/build --output-on-failure
```

- `test_config` — builder byte-exactness against a golden vector, parse
  round-trip, counter-encoding vectors, CRC equivalence with the library.
- `test_prov` — provisioning/lock/genkey/counter flows against the mock,
  including the confirm and state guards.

---

## Repository layout

```
app/                  demo/diagnostic console app (pico-command-line)
include/atecc608/     public headers: atecc608.h (core API),
                      atecc608_config.h (config builder),
                      atecc608_prov.h (guarded provisioning),
                      atecc608_types.h (shared types/status)
src/                  module sources: atecc608.c (core API), hal_rp2350.c/.h
                      (RP2350 I2C HAL), atecc608_config.c, atecc608_prov.c,
                      atecc608_status.c, atecc608_int.h
tests/                host unit tests (standalone CMake, mock chip HAL)
pico-command-line/    submodule — minimal console/CLI framework
CMakeLists.txt        module + demo build; fetches cryptoauthlib at build time
PLAN.md               development plan, decisions, discovery notes, open items
RESUME.md             continuity snapshot (exact state + next steps)
ATECC608C-...-DS40002513.pdf   ATECC608C *summary* data sheet
```

---

## Reference / source of truth

The protocol and command semantics are taken from **Microchip cryptoauthlib
v3.8.0** (canonical: `github.com/microchiptech/cryptoauthlib`, tag `v3.8.0`; a
local clone at `../cryptoauthlib` is a development reference only), which is
the authority for this project:

- **`cryptoauthlib-manual.pdf`** (747 pages, in the cryptoauthlib repo) — full
  public reference: config-zone field-definition tables, command reference,
  and the complete `atcab_*` API.
- **`lib/calib/calib_device.h`** — the ATECC608 **config-zone byte layout**
  and all bit-field definitions (SlotConfig, KeyConfig, ChipOptions,
  ChipMode, counters, …).
- The full **ATECC608C datasheet is under NDA**; only the summary sheet
  (DS40002513, in the repo) is public. cryptoauthlib + its manual cover the
  configuration and command details the module needs.

---

## Licensing

This module depends on **Microchip cryptoauthlib**, under Microchip's
**source-available license** — *not* a standard permissive/MIT license.

- cryptoauthlib is **fetched at build time** by CMake
  (`FetchContent`) from `github.com/microchiptech/cryptoauthlib`, pinned to
  `v3.8.0`. **No cryptoauthlib source is stored in this repository**, so this
  repo does not redistribute it — the Microchip project carries its own
  `license.txt`.
- The license permits use "**exclusively with Microchip products**" —
  consistent with an ATECC608 driver, but the fetched cryptoauthlib / our HAL
  can't be repurposed for a non-Microchip part under those terms.

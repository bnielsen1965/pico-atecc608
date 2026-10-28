# Examples — proof of concept

This repo contains **two projects**:

1. **The module** (the product): `include/atecc608/` + `src/` + `tests/` —
   the RP2350/Pico library that applications use to talk to the ATECC608.
2. **The examples** (this folder): proof-of-concept code — the chip
   provisioning flow and demonstration applications (password store,
   FIDO2, …). They live here, are built by this repo, and are **not part
   of the library's API surface**.

## The per-example contract

Each example is a **discrete application** (one example directory per app,
not one app with several modes). Every example's startup is two-part:

1. **Check:** is the chip on the bus already provisioned (config zone
   locked / expected layout)?
2. **If yes** — run the application. **If no** — provision it first with
   the console (`prov` command set — the proven sequence, in the exact
   order, is in [`docs/BRINGUP.md`](../docs/BRINGUP.md)), then run the
   application.

The console is the provisioner; the examples never provision a chip
themselves. `common/dev_config.h` is the single shared config intent so
the console and the byte-plan tool always encode the same image.

## What's here

- **`console/`** — the provisioner + diagnostic console over the serial
  port (pico-command-line, a submodule in this folder): probe/diagnostic
  smoke commands, the `prov` provisioning command set, the config
  read-back (`config`), and the on-hardware `selftest` validation suite.
  Pico-side state lives in littlefs (pico-littlefs, a submodule in this
  folder): `/io_key.bin` (the I/O key copy). The `bootrom` command
  re-enters BOOTSEL for reflashing.
- **`vault/`** — PIN-gated password-store demo (the "Scenario 1" console
  app): the chip is the KDF master (slot 7), the Pico does AES-256-GCM
  (pure C, NIST-vector-verified) over flat littlefs entries
  `/v_<name>`. See the "Vault example" section below.
- **`tools/dump_devconfig.c`** — host tool that encodes the agreed dev
  config and prints the exact 128-byte config-zone image + summary CRC
  from the module's real builder (the byte plan).
- **`common/dev_config.h`** — the agreed development config as a build
  intent, shared by the console (`prov status/config/lock`) and the
  byte-plan tool so both always encode the same image.

## Console example

Console output is on **both** USB CDC serial (no extra wiring) and UART0
(GPIO 0 TX / GPIO 1 RX, for a USB-serial adapter).

> **Bringing up a fresh chip?** [`docs/BRINGUP.md`](../docs/BRINGUP.md)
> is the reusable bring-up checklist: wiring, first-boot expectations on
> a factory-fresh chip, the proven provisioning sequence in the exact
> order (with the order constraints), per-chip golden recording, and the
> known failure modes.

### Commands

Diagnostics (read-only):

| Command | What it does |
|---|---|
| `help` | list commands |
| `bootrom` | reboot into BOOTSEL mode |
| `probe` | wake handshake at 0x60/0x61 to locate the chip |
| `diag` | I2C bus levels + raw wake-handshake bytes |
| `random` | 32 random bytes from the chip |
| `info` | part id + silicon revision |
| `serial` | factory serial number |
| `lock` | lock status (config zone / data zone) |
| `config` | decoded config-zone read-back (field by field + summary CRC) |
| `selftest [generic]` | read-only on-hardware validation suite (chip identity, config vs intent, key presence, KDF round-trip, I/O key, counters); `generic` runs the invariants only, without per-chip golden values |

Provisioning (every step is idempotent and safe to re-run while the
relevant zone/slot is unlocked; the irreversible locks gate on a typed
confirm, and everything goes through the module's confirm-callback API —
see [`docs/BRINGUP.md`](../docs/BRINGUP.md) for the proven order):

| Command | Does | Reversible? |
|---|---|---|
| `prov status` | chip state + factory-zone dump + diff vs planned image + `/io_key.bin` persistence | read-only |
| `prov config` | build intent → write config zone (I2C address byte + Lock-managed SlotLocked bytes preserved) → read-back verify | yes, while the config zone is unlocked |
| `prov lock` | re-verify zone vs intent → typed confirm → Lock the config zone with its summary CRC | **no** |
| `prov iokey` | Pico TRNG → Write slot 14 (chip ACK — a secret slot has no read-back) → print 64 hex chars → save `/io_key.bin` | yes, while the data zone is unlocked (re-run re-keys) |
| `prov genkey <slot>` | fresh EC P-256 key pair in slot 1/3/4/5/6/12 (data zone must be unlocked) | yes, while the slot is unlocked |
| `prov pubkey <slot>` | public key of the slot's private key | read-only (works locked) |
| `prov lockdata [CONFIRM]` | Lock the data zone | **no** |
| `prov iokeytest` | verify slot 14's I/O key via an I/O-protected KDF round-trip, using the key saved in `/io_key.bin` | read-only |
| `prov kdf <slot>` | 32-B KDF PRF from the slot (I/O-protected; run twice — expect identical output) | read-only |
| `prov lockslot <slot> [CONFIRM]` | Lock one data slot (e.g. slot 14, the final I/O-key hardening step) | **no** |
| `prov randtest` | chip RNG ×2, print — the `0xFFFF0000` factory pattern while unlocked | read-only |
| `prov iokeyshow` | DEV-ONLY: print the I/O key saved in `/io_key.bin` (compare against the out-of-band copy; never ship) | read-only |

The typed confirm is the command line itself: the command handlers run on
core1 while the console's stdin loop runs on core0, so an interactive
prompt inside a command would have its keystrokes split between the two
cores. `prov lock` / `prov lockdata` / `prov lockslot <slot>` verify and
abort without the confirm; with `CONFIRM` on the line they carry it.

## Vault example

A demo of "Scenario 1 — PIN-gated password store" below (not a full
password manager): `example/vault/` builds
`build/example/vault/pico-atecc608-vault.uf2`.

**Division of labour:** the chip is the *key master*, not a bulk cipher —
each unlock derives a 32-byte AES-256 key with `atecc608_kdf_prf` (PRF
mode, source = slot 7, fixed zero TempKey nonce, message = the entry's
16-B salt ‖ PIN; with `kdf_prot=1` the derived key arrives I/O-encrypted
on the bus and the module decrypts it in transit, so it never appears in
clear). The Pico is the *bulk cipher* — AES-256-GCM in pure C
(`vault_gcm.c`, forward-only AES + GCM, host-verified against NIST GCM
vectors; this pico-sdk fork has no hardware_crypto module, and the
ATECC608 performs no AES at all).

**Storage:** one fixed 96-byte littlefs file per entry, `/v_<name>`,
**flat at the volume root** (pico-littlefs has no mkdir; `list` filters
the `v_` prefix next to `/io_key.bin`). Layout: magic `'VAU1'` +
salt[16] + GCM nonce[12] (chip RNG at `add` time, not secret) + pt_len
+ ct[40] + tag[16] + CRC-32 (standard reflected, over the preceding
bytes). The entry *name* is bound as GCM AAD, so ciphertexts cannot be
swapped between entries or renamed. A wrong PIN derives a wrong key →
GCM tag failure; "wrong PIN" and "corrupt entry" are deliberately not
distinguished (a CRC pre-check reports storage corruption as such).
`add` replaces an existing entry with a fresh salt/nonce.

**Startup contract (same as the console):** the chip must already be
provisioned — config and data zones LOCKED (the KDF target=output gate)
and `/io_key.bin` present (written by the console's `prov iokey`). The
app prints what is missing and where to get it; it never provisions.
`/io_key.bin` and the entries survive console ↔ vault reflashes
(littlefs volume @ 0x80000; a uf2 reflash touches only the app region).

**Commands:**

| Command | What it does |
|---|---|
| `help` | list commands |
| `probe` | chip presence check (wake handshake) |
| `bootrom` | reboot into BOOTSEL mode |
| `list` | list stored entries |
| `add <name> <pin> <password>` | derive the key, GCM-encrypt, store (replaces an existing entry, fresh salt/nonce) |
| `get <name> <pin>` | derive the key, GCM-decrypt + print the password |
| `dump <name>` | show the raw stored 96-B entry as text (no PIN — a littlefs read; non-printable bytes as `?`): proves the password is not in flash in the clear, since any plaintext leak would stand out as readable text |
| `rm <name>` | delete the entry |

Limits: name 1..16 chars from `[A-Za-z0-9._-]`; PIN 1..24 chars;
password 1..40 chars (no spaces — the command line is one buffer).

**Brute-force resistance (for apps you build on this pattern):** the demo
deliberately implements no lockout — a wrong PIN fails the GCM tag check
and nothing is counted (the chip's KDF cannot tell a wrong PIN from a
right one, and no chip counter is touched). If you build a similar app,
consider adding a Pico-side failure counter + lock flag in littlefs — e.g.
5 failures → locked until a deliberate reset (see [Scenario 1](#scenario-1--pin-gated-password-store)).
The chip's two monotonic counters are the wrong tool for that: they only
ever increment (anti-rollback / CTAP semantics) and cannot be reset.

**Demo caveats (bench use only):**
- The console echoes what you type — the PIN and password are visible on
  the serial console, and `get` prints the password. That is the point
  of the demo.
- The bench chip's slot 7 holds all-zero factory content (the data zone
  is locked, so it is never re-keyed). The demo works with it as-is; a
  real deployment provisions a random master into slot 7 during
  bring-up, before the data-zone lock.

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
(the Pico holds a copy in littlefs). Slot 14 is an unreadable secret slot
(`is_secret`) and **lockable**: development leaves it unlocked (a lost copy
is recoverable by re-keying); production slot-locks it as the final
hardening step after the recorded copy is verified (closes the
bus-attacker re-key hole). This matches the pattern of the cryptoauthlib
reference config, which keeps its I/O key in a secret non-ECC slot. The
slot-7 master and the private keys in 3–6/12 never appear in clear on the
I2C bus.

### Scenario 1 — PIN-gated password store

- **Master:** a high-entropy secret generated on-chip into slot 7 at
  provisioning. The slot is `is_secret` — it cannot be read at all, not even
  an encrypted read. It never leaves the chip.
- **Vault:** an AES-256-GCM blob on Pico flash (littlefs). The 16-byte
  per-vault salt is drawn from the chip's RNG at vault creation and stored
  in the vault header on flash (a salt is not secret).
- **Unlock:** the Pico issues a KDF (PRF mode) — source = slot 7, input =
  salt ‖ PIN — and the chip returns the derived 32-byte key (encrypted on
  the bus via I/O protection); the Pico decrypts the vault header with
  AES-256-GCM. A wrong PIN yields a
  wrong derived key → GCM auth tag fails.
- **Brute-force lockout:** enforced Pico-side (fail count + lock flag in
  the littlefs store; e.g. 5 failures → locked until a deliberate reset).
  The chip has no native lockout, and a 32–64-bit PIN already makes online
  guessing infeasible — the lockout is defense in depth.

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

The bench-proven console command sequence in the exact order (with the
order constraints — GenKey needs the data zone UNLOCKED, the KDF needs it
LOCKED, slot 14 locked last) is [`docs/BRINGUP.md`](../docs/BRINGUP.md)
§4.

## Building

The examples build with the top-level build (see the top-level README):
`cmake .. && make` in `build/` produces
`build/example/console/pico-atecc608.uf2` (the console) and
`build/example/vault/pico-atecc608-vault.uf2` (the vault demo). To build
only the library: `-DATECC608_BUILD_EXAMPLES=OFF`.

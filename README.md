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

## Application scenarios

This repo contains two projects: the **module** (the product: the
RP2350/ATECC608 library in `include/`, `src/`, `tests/`) and the
**examples** (proof of concept: the chip provisioning flow and
demonstration applications, in `example/`).

The application scenarios (PIN-gated password store, FIDO2/passkey,
secure firmware updates, device identity), the agreed 16-slot
configuration, and the provisioning/locking discipline are documented
in [`example/README.md`](example/README.md).

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
  byte and the Lock-managed SlotLocked bytes), `lock_config_zone`,
  `lock_data_zone`, `lock_data_slot`, `genkey`, `counter_read` /
  `counter_increment` — every irreversible step is confirm-hook gated.
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

### Sample wiring (the console example)

| Pico 2 (RP2350) | ATECC608 |
|---|---|
| GP20 (I2C0 SDA) | SDA (pull-up to 3V3) |
| GP21 (I2C0 SCL) | SCL (pull-up to 3V3) |
| 3V3 | VCC |
| GND | GND |
| GP0 / GP1 (UART0) | USB-serial console (optional) |
| USB | flashing + CDC console |

Pins are `#define`s in `example/console/main.c` — a consuming project
supplies its own.

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

Clone with submodules (the examples use `example/pico-command-line` and
`example/pico-littlefs`; the latter nests LittleFS inside it):

```sh
git clone --recursive <this repo>
# or, if already cloned: git submodule update --init --recursive
```

The first `cmake` configure **fetches cryptoauthlib v3.8.0 from GitHub**
(network needed once; it is cached under `build/` afterward and is never
stored in this repo). For an air-gapped build, point CMake at a local clone
instead: `-DCRYPTOAUTHLIB_SOURCE_DIR=/path/to/cryptoauthlib`.

```sh
# Pico 2, Cortex-M33 cores (default). Needs PICO_SDK_PATH to point at pico-sdk.
mkdir -p build && cd build
cmake .. -DPICO_SDK_PATH="$HOME/Projects/pico-sdk"
make -j

# Flash over USB: drag build/example/console/pico-atecc608.uf2 to the
# RP2350 drive, or use the `bootrom` console command to re-enter BOOTSEL.
```

The build produces the console example image in
`build/example/console/` (`pico-atecc608.uf2` / `.bin` / `.elf` / `.map`)
and two static libraries in `build/`: **`libatecc608.a`** (the module) and
**`libcryptoauth_core.a`** (the fetched cryptoauthlib core, compiled for
the Pico target).

The examples build by default; to build only the library use
`-DATECC608_BUILD_EXAMPLES=OFF`. Example console commands (probe/diag
smoke tests plus the Phase 4B `prov` provisioning set) are documented in
[`example/README.md`](example/README.md).

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
example/              proof-of-concept examples (NOT part of the library):
                      console/ (bench console: probe/diag + prov commands),
                      tools/ (dump_devconfig host tool), common/ (shared
                      provision-on-first-boot base), submodules
                      pico-command-line/ (console/CLI framework) and
                      pico-littlefs/ (Pico-side persistence) — examples
                      only; see example/README.md
include/atecc608/     public headers: atecc608.h (core API),
                      atecc608_config.h (config builder),
                      atecc608_prov.h (guarded provisioning),
                      atecc608_types.h (shared types/status)
src/                  module sources: atecc608.c (core API), hal_rp2350.c/.h
                      (RP2350 I2C HAL), atecc608_config.c, atecc608_prov.c,
                      atecc608_status.c, atecc608_int.h
tests/                host unit tests (standalone CMake, mock chip HAL)
CMakeLists.txt        module build (+ examples by default,
                      ATECC608_BUILD_EXAMPLES=OFF to skip); fetches
                      cryptoauthlib at build time
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

# pico-atecc608

A Raspberry Pi Pico C module for interfacing with the **Microchip ATECC608**
crypto co-processor over I2C. It is designed to be **embedded in other Pico
projects** as a reusable sub-module, so a project does not have to
re-implement the ATECC wake handshake, I2C protocol, CRC, or any of the
command plumbing. It builds on Microchip's **cryptoauthlib v3.8.0**, adding
an RP2350 I2C HAL and a curated, stable `atecc608_*` API.

> **Scope.** This repository is the *driver/module*, not an application.
> Applications (password stores, FIDO2 authenticators, …) build on the
> module's primitives; this repo's worked examples are the console
> (provisioner + diagnostics), the password store, and the FIDO2 key.
> The application scenarios and the agreed chip configuration they share
> are documented in
> [`example/README.md`](example/README.md#application-scenarios--provisioning-guidance).

> **NOTE:** Before utilizing this module you should review the Microchip licensing terms 
> to ensure your project aligns with those terms. This module relies on the Microchip 
> cryptoauthlib library but does not redistribute the library, if you include this 
> module in your project the crtypoauthlib library will be downloaded to your project 
> at build time. This module was developed without access to the full datasheet 
> specifications which require signing an NDA. No NDA was signed so no datasheet 
> access was granted.
---

## Application scenarios

This repo contains two projects: the **module** (the product: the
RP2350/ATECC608 library in `include/`, `src/`, `tests/`) and the
**examples** (proof of concept: the chip provisioning flow and
demonstration applications, in `example/`).

The example applications (PIN-gated password store, FIDO2/passkey), the
agreed 16-slot chip configuration — which also reserves capacity for
secure firmware updates and device identity — and the
provisioning/locking discipline are documented in
[`example/README.md`](example/README.md).

---

## What the module provides

- **Core API** (`include/atecc608/atecc608.h`): `atecc608_init` (I2C
  instance, pins, baud) / `atecc608_deinit`, `probe`, `info` (part/revision),
  `serial` (factory serial), `is_locked` (config/data zone), `random`,
  `read_config_zone`, `read_slot`, `read_pubkey`, `write_config_zone`,
  `write_slot`, plus `atecc608_last_error()` / `atecc608_status_str()` —
  every call's failure is available as a curated status.
- **Config-zone builder** (`atecc608_config.h`): a field-level intent struct
  → 128-byte config array, a parser, CRC-16, and a writable-region diff —
  consumers express intent, never raw bytes.
- **Guarded provisioning** (`atecc608_prov.h`): idempotent
  `provision_config` (read-back verified, preserves the chip's I2C address
  byte and the Lock-managed SlotLocked bytes), `lock_config_zone`,
  `lock_data_zone`, `lock_data_slot`, `genkey`, `get_pubkey`,
  `write_iokey` (the I/O-protection key to slot 14), `counter_read` /
  `counter_increment` — every irreversible step is confirm-hook gated.
- **KDF wrapper** (`atecc608_crypto.h`): `atecc608_kdf_prf` — on-chip KDF
  (PRF mode) with enforced I/O protection: with `kdf_prot=1` the 32-byte
  derived key arrives AES-encrypted on the bus (slot-14 key) and the module
  decrypts it in transit, so it never appears in clear on the wire.
  Sign/verify wrappers will be added as consumers need them.

---

## Using the module in your own project

The supported way to use the module is as a **git submodule** wired in with
CMake `add_subdirectory()`. The module is a small, self-contained CMake
static library: the public headers in `include/atecc608/`, the
implementation in `src/`, and a build-time fetch of Microchip cryptoauthlib.
When embedded it **pulls in nothing else**: no examples, and none of this
repo's submodules (`lib/tinyusb`, `example/pico-command-line`,
`example/pico-littlefs` are example-only, and a plain
`git submodule update --init` in your project does not initialize nested
submodules — that needs `--recursive`).

**1. Add the submodule**

```sh
git submodule add https://github.com/<owner>/pico-atecc608.git libs/pico-atecc608
git submodule update --init libs/pico-atecc608
```

**2. Wire it up.** Your project must already do the normal pico-sdk setup —
`project()` + `pico_sdk_init()` with your own `PICO_BOARD` / `PICO_PLATFORM`
/ `PICO_SDK_PATH` — *before* adding the module. The module builds for
**your** board and platform:

```cmake
add_subdirectory(libs/pico-atecc608)

target_link_libraries(your_app PRIVATE atecc608::atecc608)
```

- **Examples are OFF by default when embedded** — your build gets only the
  `atecc608::atecc608` target. To also build this repo's example apps, pass
  `-DATECC608_BUILD_EXAMPLES=ON` and run
  `git submodule update --init --recursive` inside `libs/pico-atecc608`.
- **Air-gapped build:** pass
  `-DCRYPTOAUTHLIB_SOURCE_DIR=/path/to/cryptoauthlib` (cryptoauthlib is
  fetched at build time and never stored in this repo).

**3. Use the API**

```c
#include "atecc608/atecc608.h"

atecc608_cfg_t cfg = {
    .i2c     = i2c0,
    .sda_pin = 20,
    .scl_pin = 21,
    .addr    = ATECC608_ADDR_ADR_LOW,   // 0x60 (ADR to GND)
    .baud    = ATECC608_FAST_BAUD_HZ,   // 400 kHz
};

if (atecc608_init(&cfg) != ATECC608_OK) {
    // atecc608_last_error() carries the raw ATCA_STATUS
}

atecc608_info_t info;
atecc608_info(&info);      // info.part == 0x60, info.revision
uint8_t rnd[16];
atecc608_random(rnd, 16);  // 16 bytes of chip TRNG
```

Every `atecc608_*` call returns an `atecc608_status_t`; on failure,
`atecc608_last_error()` returns the underlying cryptoauthlib
`ATCA_STATUS` and `atecc608_status_str()` gives short text. The full API
— lifecycle, diagnostics, zone/slot access, the config builder, guarded
provisioning, and the KDF wrapper — is documented in the headers under
`include/atecc608/`.

**Alternative: copy the files.** If you'd rather not nest CMake projects,
copy the module into yours instead:

| From this repo | Into your project |
|---|---|
| `include/atecc608/` (the 5 public headers) | `include/atecc608/` |
| `src/` (`atecc608.c`, `atecc608_config.c`, `atecc608_crypto.c`, `atecc608_prov.c`, `atecc608_status.c`, `hal_rp2350.c`/`.h`, `atecc608_int.h`) | `src/` (or a subfolder) |
| the `cryptoauthlib` fetch + `cryptoauth_core` + `atecc608` targets from the top-level `CMakeLists.txt` | your `CMakeLists.txt` |

The CMake to copy is the two top-level sections marked
`# cryptoauthlib — fetched at build time` and
`# module library`; together they produce the
`atecc608::atecc608` target. They assume your project already calls
`pico_sdk_init()` and sets `CMAKE_C_STANDARD 11` (both are pico-sdk
conventions). Air-gapped: pass
`-DCRYPTOAUTHLIB_SOURCE_DIR=/path/to/cryptoauthlib`.

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

- Raspberry Pi Pico 2 (RP2350)
- [pico-sdk](https://github.com/raspberrypi/pico-sdk)
- ATECC608 on the I2C bus
- Microchip cryptoauthlib v3.8.0 — **fetched at build time** by CMake from
  `github.com/microchiptech/cryptoauthlib`; **no cryptoauthlib source is
  stored in this repo** (see Licensing).

---

## Building

Clone. The submodules are **examples-only** (`example/pico-command-line`,
`example/pico-littlefs` — the latter nests LittleFS inside it — and
`lib/tinyusb`); a library-only build needs none of them:

```sh
git clone --recursive <this repo>
# or, if already cloned: git submodule update --init --recursive
# library only: skip the submodules and pass -DATECC608_BUILD_EXAMPLES=OFF
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

# Flash over USB: drag build/example/console/pico-atecc608.uf2 (the
# console), build/example/vault/pico-atecc608-vault.uf2 (the vault
# demo) or build/example/fido2/pico-atecc608-fido2.uf2 (the FIDO2
# key) to the RP2350 drive, or use the `bootrom` command to
# re-enter BOOTSEL.
```

The build produces the example images — `build/example/console/`
(`pico-atecc608.uf2`, the console), `build/example/vault/`
(`pico-atecc608-vault.uf2`, the password-store demo) and
`build/example/fido2/` (`pico-atecc608-fido2.uf2`, the FIDO2/passkey
authenticator), each with `.bin` / `.elf` / `.map` — and two static
libraries in `build/`:
**`libatecc608.a`** (the module) and **`libcryptoauth_core.a`** (the
fetched cryptoauthlib core, compiled for the Pico target).

The examples build by default in standalone builds of this repo; to build
only the library use `-DATECC608_BUILD_EXAMPLES=OFF` (this is also the
default when the repo is embedded via `add_subdirectory()` — see
[Using the module in your own project](#using-the-module-in-your-own-project)).
The examples (diagnostic smoke tests, the `prov` provisioning set, the
vault password-store demo, and the FIDO2 key) are documented in
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
- `test_crypto` — the KDF wrapper's plumbing (nonce loading, parameter
  encoding, response parsing) and the enforced I/O-protection decrypt path,
  against the mock's deterministic PRF.
- `test_vault_gcm` — the vault example's pure-C AES-256-GCM (the exact
  device code) against OpenSSL-verified NIST GCM vectors.
- `test_sha256` — the FIDO2 example's pure-C SHA-256 (the exact device
  code) against NIST vectors.
- `test_cred` — the FIDO2 credential store: record (de)serialization,
  CRC, alloc/find/insert/erase over the 4-slot array.
- `test_cbor` — the FIDO2 example's minimal CTAP2 CBOR codec: RFC 8949
  known-answer vectors, the CTAP2 canonical-form strictness (non-
  canonical widths rejected), definite-length-only, and the
  nesting-depth safety rail.
- `test_ctaphid` — the CTAPHID transport state machine: packet
  framing/sequencing, channel allocation, INIT/PING/WINK, keep-alive
  throttling, and the deferred user-presence transaction lifecycle
  (cancel, timeout, eviction).
- `test_ctap` — the CTAP2 command dispatch: GET_INFO / MakeCredential /
  GetAssertion / GET_NEXT_ASSERTION / RESET byte-pinned against a
  deterministic key-backend fake (the full CTAP2 error table, the
  error-ordering rules, store-full and backend-failure paths, and a
  structurally-truncated-CBOR sweep at every cut point).

---

## Repository layout

```
example/              proof-of-concept examples (NOT part of the library):
                      console/ (provisioning + diagnostic console),
                      vault/ (PIN-gated password-store demo),
                      fido2/ (CTAP2/FIDO2 passkey authenticator, USB HID),
                      tools/ (dump_devconfig host tool), common/ (shared
                      dev config), submodules pico-command-line/ (console
                      CLI framework) and pico-littlefs/ (Pico-side
                      persistence) — examples only; see example/README.md
include/atecc608/     public headers: atecc608.h (core API),
                      atecc608_config.h (config builder),
                      atecc608_crypto.h (KDF wrapper),
                      atecc608_prov.h (guarded provisioning),
                      atecc608_types.h (shared types/status)
src/                  module sources: atecc608.c (core API), hal_rp2350.c/.h
                      (RP2350 I2C HAL), atecc608_config.c,
                      atecc608_crypto.c, atecc608_prov.c,
                      atecc608_status.c, atecc608_int.h
tests/                host unit tests (standalone CMake, mock chip HAL)
CMakeLists.txt        module build; standalone builds also build the
                      examples (embedded add_subdirectory() is library-only
                      by default; ATECC608_BUILD_EXAMPLES toggles); fetches
                      cryptoauthlib at build time
```

---

## Reference / source of truth

The protocol and command semantics are taken from **Microchip cryptoauthlib
v3.8.0** (`github.com/microchiptech/cryptoauthlib`, tag `v3.8.0`), which is
the authority for this project:

- **`cryptoauthlib-manual.pdf`** (747 pages, in the cryptoauthlib repo) — full
  public reference: config-zone field-definition tables, command reference,
  and the complete `atcab_*` API.
- **`lib/calib/calib_device.h`** — the ATECC608 **config-zone byte layout**
  and all bit-field definitions (SlotConfig, KeyConfig, ChipOptions,
  ChipMode, counters, …).
- The full **ATECC608C datasheet is under NDA**. A public *summary* sheet
  (DS40002513) is available from Microchip, as is the full datasheet with an
  NDA — neither is vendored in this repo (buyers of the part receive the
  documentation from Microchip). cryptoauthlib + its manual cover the
  configuration and command details the module needs.

---

## Licensing

This repository's code — the `atecc608_*` module, the RP2350 I2C HAL, the
examples, and the tests — is licensed under the **MIT License** (see
[`LICENSE`](LICENSE)).

It depends on **Microchip cryptoauthlib**, under Microchip's
**source-available license** — *not* a standard permissive/MIT license.

- cryptoauthlib is **fetched at build time** by CMake
  (`FetchContent`) from `github.com/microchiptech/cryptoauthlib`, pinned to
  `v3.8.0`. **No cryptoauthlib source is stored in this repository**, so this
  repo does not redistribute it — the Microchip project carries its own
  `license.txt`.
- The license permits use "**exclusively with Microchip products**" —
  consistent with an ATECC608 driver, but the fetched cryptoauthlib / our HAL
  can't be repurposed for a non-Microchip part under those terms.

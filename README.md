# pico-atecc608

A Raspberry Pi Pico C module for interfacing with the **Microchip ATECC608**
crypto co-processor over I2C. It is designed to be **embedded in other Pico
projects** as a reusable sub-module, so a project does not have to re-implement
the ATECC wake handshake, I2C protocol, CRC, or any of the command plumbing.

> **Scope.** This repository is the *driver/module*, not an application. The
> earlier "dual-vault password store" idea is a **potential consumer** of this
> module, not part of it. The module exposes the primitives (probing, key
> provisioning, counters, crypto pass-through); applications build on top of
> them. See `PLAN.md` for direction and open questions.

---

## What it does

**Implemented today** — a self-contained, dependency-free I2C driver and a
console smoke-test app:

- I2C **wake handshake** (general-call pulse → 4-byte `04 11 33 43` wake
  packet), with address auto-detect at `0x60` / `0x61`.
- Command transport with the ATECC I/O tokens, 16-bit CRC, polling, and
  sleep **re-wake** + guarded **bus recovery** for a stuck SDA line.
- `RANDOM`, `INFO` (silicon revision), and `READ` (config block 0 → factory
  serial number).

**Build / module (Phase 1 — done)** — the repo is now a CMake **module**: it
builds `libatecc608.a` and, at configure time, fetches and compiles
**cryptoauthlib v3.8.0** (`libcryptoauth_core.a`) for the Pico target — the
source is downloaded into the build dir and never stored in this repo. The thin
RP2350 I2C HAL that connects the driver to cryptoauthlib is next (Phase 2).

**Planned** (see `PLAN.md`) — build on Microchip's **cryptoauthlib v3.8.0**
through a thin RP2350 I2C HAL, and expose a stable, curated `atecc608_*` API:
init/probe/diagnostics, config-zone read/verify/write/lock, key provisioning,
monotonic counters, and crypto pass-through (KDF, sign, verify, key
generation). Provisioning is a guarded **library API** (the module ships no
CLI — a consuming project wires up its own), and a **field-level config-zone
builder** means consumers express intent, never raw bytes.

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

Pins are `#define`s in `src/main.c` — a consuming project supplies its own.

---

## Requirements

- Raspberry Pi Pico 2 (RP2350). *(RP2040 support is not currently planned;
  the thin HAL could add it later.)*
- [pico-sdk](https://github.com/raspberrypi/pico-sdk)
- ATECC608 on the I2C bus
- *(planned)* Microchip cryptoauthlib v3.8.0 — **fetched at build time** by
  CMake from `github.com/microchiptech/cryptoauthlib`; **no cryptoauthlib
  source is stored in this repo** (see Licensing).

---

## Building

The first `cmake` configure **fetches cryptoauthlib v3.8.0 from GitHub** (network
needed once; it is cached under `build/` afterward and is never stored in this
repo). For an air-gapped build, point CMake at a local clone instead:
`-DCRYPTOAUTHLIB_SOURCE_DIR=/path/to/cryptoauthlib`.

```sh
# Pico 2, Cortex-M33 cores (default). Needs PICO_SDK_PATH to point at pico-sdk.
mkdir -p build && cd build
cmake .. -DPICO_SDK_PATH="$HOME/Projects/pico-sdk"
make -j

# Flash over USB: drag build/app/pico-atecc608.uf2 to the RPI-RP2 drive,
# or use the `bootrom` console command to re-enter BOOTSEL.
```

The build produces the demo image in `build/app/` (`pico-atecc608.uf2` / `.bin` /
`.elf` / `.map`) and two static libraries in `build/`: **`libatecc608.a`** (the
module) and **`libcryptoauth_core.a`** (the fetched cryptoauthlib core, compiled
for the Pico target).

Console is on both USB CDC serial and UART0 (GP0/GP1).

### Current console commands

| Command | Action |
|---|---|
| `help` | list commands |
| `bootrom` | reset into BOOTSEL (USB bootloader) |
| `probe` | wake handshake at 0x60/0x61 to locate the chip |
| `diag` | I2C bus levels + raw wake-handshake bytes |
| `random` | RANDOM command — 32 random bytes |
| `info` | INFO command — part id + silicon revision |
| `serial` | READ config block 0 — factory serial number |

---

## Repository layout

```
src/atecc608.h/.c     self-contained ATECC608 I2C driver (wake/protocol/CRC + basic
                      commands); becomes the HAL's raw-I2C primitives (Phase 2)
app/                  demo/diagnostic console app (pico-command-line):
                      probe/diag/random/info/serial
include/atecc608/     public `atecc608_*` API header (introduced in Phase 3)
pico-command-line/    submodule — minimal console/CLI framework
CMakeLists.txt        module + demo build; fetches cryptoauthlib at build time
PLAN.md               development plan, decisions, discovery notes, open items
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

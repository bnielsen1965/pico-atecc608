# ATECC608 Pico Module — Development Plan

**Status: LOCKED (2026-10-17).** Decisions are final unless explicitly changed.
"Open items" below are implementation details to settle as each phase starts, not
re-opens of settled decisions.

## Goal

Build a **reusable ATECC608 sub-module** for Raspberry Pi Pico 2 (RP2350)
projects: a C library (driver + HAL + clean `atecc608_*` API) that any Pico
project can embed to provision and use an ATECC608 over I2C, without
re-implementing the wake handshake, I2C protocol, CRC, or command plumbing.

The earlier "dual-vault password store" is **out of scope** — it is a *potential
consumer* (a separate repo). The module exposes primitives; applications build
on top.

## Decisions (locked 2026-10-17)

1. **Foundation = cryptoauthlib v3.8.0.** The module wraps Microchip
   cryptoauthlib through a thin RP2350 I2C HAL. cryptoauthlib is the command
   engine (genkey / KDF / sign / verify / lock / counters); we own the HAL, the
   packaging, and the API surface.
2. **API = curated high-level `atecc608_*` surface.** A thoughtfully chosen,
   stable subset of chip capabilities — **not** a 1:1 mirror of `atcab_*`.
3. **Provisioning = guarded library API only.** Config read/verify/write/lock,
   genkey, and counter init are exposed as a library API with safeguards
   (idempotent, read-back-verify before lock, typed-confirm hook). The module
   **ships no provisioning CLI** — each consuming project wires its own UI.
4. **Config builder = field-level struct.** A structured builder that maps to
   the `calib_device.h` fields and produces the 128-byte array, so consumers
   express *intent*, never raw bytes.
5. **Target = Pico 2 / RP2350 only, blocking-first.** No Pico 1 / RP2040; no
   async/RTOS.
6. **Testing = host unit tests + on-hardware.** Unit-test the pure logic on the
   host (config-builder → 128-byte array, CRC, field decoding) against a mock
   HAL; keep a separate on-hardware validation suite for the I2C path.
7. **cryptoauthlib is fetched at build time — never vendored.** CMake pulls it
   with `FetchContent` from
   `https://github.com/microchiptech/cryptoauthlib`, pinned to tag **`v3.8.0`**
   (release commit `d49c7d57`), and links the core **`cryptoauth`** target
   (no pkcs11/mbedtls/openssl/wolfssl backends). It is **not** a git submodule
   and **no cryptoauthlib source is stored in this repo**: the clone lands in
   the build directory and is discarded, so this repo does not redistribute the
   source (keeps licensing simple — the Microchip project carries its own
   `license.txt`). A local clone at `../cryptoauthlib` is a development
   *reference only*. An `-DCRYPTOAUTHLIB_SOURCE_DIR=<path>` override allows an
   air-gapped build against a local clone without committing it.

## Defaults (assumed — change on request)

- **Retire the standalone `src/atecc608.c`** into the HAL (Phase 2); it is not
  kept as a separate driver.
- **Command-level IO protection** is available via cryptoauthlib but is **not**
  the default and is not in the core API until a consumer asks for it.
- The **password store is a separate repo** that consumes this module.

## Architecture

Layering, bottom-up:

```
consuming Pico app
   │
atecc608_* public API            (our stable surface for other projects)
   │
cryptoauthlib v3.8.0             (iface / device / host: commands, CRC,
   │                               wake handshake, retries)  [fetched at build time]
RP2350 I2C HAL                    (raw I2C: send word-addr+data, two-phase
   │                               read, wake, idle, sleep, delays)  [we implement]
pico-sdk                          (hardware_i2c, stdlib)
```

- **Packaging:** CMake — a static library `atecc608` plus an
  `atecc608::atecc608` INTERFACE target — so a consuming project can
  `add_subdirectory()` this module and link a single target. cryptoauthlib is
  fetched at build time (Decision 7); nothing is vendored.
- **Module layout (target):**
  ```
  include/atecc608/atecc608.h    public API
  src/                           module code (driver/HAL → Phase 2; API → 3; builder → 4)
  app/                           demo/diagnostic console (current src/main.c)
  CMakeLists.txt                 lib + INTERFACE target + FetchContent + demo app
  ```
- **Provisioning** is a guarded library API (idempotent, read-back-verify
  before lock, typed-confirm hook) — not baked into runtime, no CLI.
- The existing `src/atecc608.c` is the reference for correct low-level I2C
  behavior and the source of the raw-I2C primitives the HAL wraps.

### Public API surface (curated)

A single config struct drives init; everything else is a small, stable set.
(Names/prefix and exact signatures are provisional.)

- **Lifecycle / diagnostics**
  - `atecc608_init(const atecc608_cfg_t *cfg)` / `atecc608_deinit(void)`
  - `atecc608_probe(void)` — wake handshake; returns found address + part/rev
  - `atecc608_info(atecc608_info_t *out)` — part id, revision
  - `atecc608_serial(uint8_t out[8])` — factory serial
  - `atecc608_random(uint8_t *out, size_t n)` — chip TRNG
  - `atecc608_last_error(void)` + an error enum
- **Zone / config access**
  - `atecc608_read_config_zone(uint8_t out[128])` /
    `atecc608_write_config_zone(const uint8_t in[128])`
  - `atecc608_is_locked(zone)` — config or data
  - `atecc608_lock_config_zone(void)` / `atecc608_lock_data_zone(void)`
  - `atecc608_read_slot(slot, offset, out, n)` /
    `atecc608_write_slot(slot, offset, in, n)`
  - `atecc608_read_pubkey(slot, out)`
- **Counters**
  - `atecc608_counter_init(...)` / `atecc608_counter_read(...)` /
    `atecc608_counter_incr(...)`
- **Key / crypto pass-through**
  - `atecc608_genkey(slot, out_pub)` — generate pair in slot, return public half
  - `atecc608_kdf(slot, in, in_len, out)` — HMAC-KDF
  - `atecc608_sign(slot, in, in_len, out)` /
    `atecc608_verify(pub, in, in_len, sig, sig_len, bool *ok)`
- **Config builder** — a field-level struct +
  `atecc608_config_build(...)` → 128-byte array, plus
  `atecc608_config_verify(expected, actual, diff)` so consumers never hand-roll
  byte arrays.

## Phases

- **Phase 1 — Module skeleton + build wiring — DONE (2026-10-17).** Restructured
  into the module layout; CMake builds the `atecc608` static lib + an
  `atecc608::atecc608` ALIAS target; the console moved to `app/`; cryptoauthlib is
  fetched at build time and compiled for the Pico target.
  - **Key deviation from the original sketch:** cryptoauthlib's own CMake picks
    its HAL by *build host* — on any UNIX machine it force-adds `hal/hal_linux.c`
    (→ `sys/mman.h`) and links `-lrt`, which is wrong for a bare-metal
    cross-target. So we do **not** `add_subdirectory` cryptoauthlib. Instead:
    `FetchContent_Populate` the source (source only — **CMP0169 pinned OLD** to keep
    that form), generate our own `atca_config.h` (ATECC608/508A/108A/206A + CA
    support; `ATCA_PLATFORM_MALLOC`/`FREE` = malloc/free; **no**
    `ATCA_PLATFORM_STRCASESTR` — newlib lacks `strcasestr`, so cryptoauthlib's
    `lib_strcasestr` fallback in `atca_helpers.c` is used), and build an internal
    `cryptoauth_core` static lib from the portable sources (the default file set
    **minus** `hal/hal_linux.c`). `ATCA_HAL_I2C` stays off until Phase 2 supplies
    the HAL. Air-gapped: `-DCRYPTOAUTHLIB_SOURCE_DIR=<path>`.
  - **Done when (verified):** `cmake` fetches cryptoauthlib from GitHub; builds
    `libatecc608.a` + `libcryptoauth_core.a` + the demo `pico-atecc608.uf2` (in
    `build/app/`); no cryptoauthlib source in the repo (`build/` is gitignored).
    *The demo's hardware run (probe/random/info/serial) is build-verified here;
    confirm on the board.*
- **Phase 2 — RP2350 I2C HAL.** Implement the `atca_hal` I2C interface
  (`hal_i2c_init/post_init/send/receive/control/release` + `hal_delay_ms/us`)
  on the existing driver's raw-I2C primitives (wake 100 kHz, 400 kHz traffic,
  timeouts, sleep re-wake, bus recovery); fold `src/atecc608.c` into it.
  `atecc608_init(cfg)` wires the `ATCAIfaceCfg` (devtype **ATECC608**, address,
  `wake_delay` µs, baud). Decide the wake: proper I2C general-call (0-byte) vs.
  the current 1-byte dummy (SDK rejects zero-length writes).
  - **Done when:** read-only ops through cryptoauthlib (`atcab_info`,
    `atcab_read_config_zone` block 0, `atcab_is_locked`, `atcab_random`) succeed
    and match the standalone driver.
- **Phase 3 — Core API.** `init/deinit`, `probe`, `info`, `serial`, `random`,
  `last_error`, zone read/write, `read_slot`/`write_slot`/`read_pubkey`,
  `is_locked` — thin correct wrappers over `atcab_*`.
  - **Done when:** on hardware, API results match the standalone driver; host
    build is warning-clean.
- **Phase 4 — Provisioning utilities + config builder.** A field-level
  config-builder (from `calib_device.h`) → 128-byte array + `config_verify`;
  guarded provisioning API (read/write with read-back verify, lock_config/lock_
  data, genkey, counter init). **Host unit tests** (mock HAL) assert the
  produced 128-byte array for known-intent configs.
  - **Done when:** unit tests pass on host; on a fresh chip, write→read-back
    verify works and lock is gated behind read-back + typed-confirm.
- **Phase 5 — Crypto pass-through (on demand).** `kdf` / `sign` / `verify` /
  `genkey` / `read_pubkey` wrappers, added as consumers need them.
  - **Done when:** at least a KDF round-trip is validated on hardware.
- **Phase 6 — Sample / diagnostic app.** The `app/` console exercises the
  library API (probe/info/serial/random + a config read-back demo) — it uses the
  module, not the raw driver. It is a demo, **not** a provisioning tool.
  - **Done when:** the demo builds against the lib and runs on hardware.
- **Phase 7 — On-hardware validation + regression + bring-up checklist.**
  Full on-hardware suite; a documented, reusable bring-up checklist.
  - **Done when:** suite green; checklist written.

## Ground rules (provisioning safeguards)

1. **Nothing irreversible without read-back verification.** Write config →
   read it back → byte-compare → only then may a lock be issued.
2. **Write and lock are separate commands.** A power loss in between leaves a
   recoverable state (zone still unlocked; re-run the write).
3. **Typed confirmation for locks** (e.g. type `YES-TO-LOCK` at the caller's UI).
4. **Idempotent / re-runnable** while the relevant zone is unlocked
   (`atcab_is_locked` checked first; "already locked" is a clean exit).
5. Every chip operation goes through the HAL's timeout I2C calls and sleep
   re-wake logic (never unbounded blocking calls).

## Source of truth (discovery, 2026-10-17)

**cryptoauthlib v3.8.0** is the authority for chip interaction — *not* the
summary datasheet, which has no config-zone map, no SlotConfig/KeyConfig
bit-field tables, no counter encoding, and no INFO map (the full 608C datasheet
is under NDA). Canonical source: `github.com/microchiptech/cryptoauthlib` (tag
`v3.8.0`); a local clone at `../cryptoauthlib` is a development reference only
(not part of this repo — Decision 7).

Key facts:

- **v3.8.0 = v3.7.9 + ECC206 support + a CMake restructure.** The ATECC I2C
  protocol, HAL interface, and `atcab_*` API are **unchanged** from 3.7.9.
- **No `ATECC608C` device type exists.** `lib/atca_devtypes.h`:
  `ATECC508A=2`, `ATECC608A/ATECC608B/ATECC608=3`. Use **`ATECC608`** (type 3)
  for the C part.
- **`cryptoauthlib-manual.pdf`** (747 pp, upstream) is the full public
  reference: config field tables, command reference, `atcab_*` API.
- **`lib/calib/calib_device.h`** is the authoritative config-zone byte layout
  and all bit-field definitions.
- **AES is 128-bit only on-chip.** The RP2350 can do AES-256 on the host side
  (chip-side 128 vs. host-side 256 split available if needed).
- **License:** Microchip **source-available** (not MIT/permissive). Redistribu-
  tion is allowed; use is "exclusively with Microchip products." We fetch it at
  build time, so this repo stores/redistributes no cryptoauthlib source.

### Config-zone layout (`atecc608_config_s`, packed little-endian, 128 bytes)

| Bytes | Field | Notes |
|---|---|---|
| 0–3   | SN03 | factory serial |
| 4–7   | RevNum | factory |
| 8–11  | SN47 | factory serial |
| 12    | SN8  | factory serial |
| 13    | AES_Enable | factory region |
| 14    | I2C_Enable | factory region |
| 15    | Reserved1 | |
| 16    | I2C_Address | |
| 17    | Reserved2 | |
| 18    | CountMatch | |
| 19    | ChipMode | |
| 20–51 | SlotConfig[16] | 2 bytes each |
| 52–59 | Counter0 | **config field, not a data slot** |
| 60–67 | Counter1 | **config field, not a data slot** |
| 68    | UseLock | |
| 69    | VolatileKeyPermission | |
| 70–71 | SecureBoot | |
| 72    | KdflvLoc | |
| 73–74 | KdflvStr | |
| 75–83 | Reserved3[9] | |
| 84    | UserExtra | |
| 85    | UserExtraAdd | |
| 86    | LockValue | set only by the Lock command |
| 87    | LockConfig | set only by the Lock command |
| 88–89 | SlotLocked | |
| 90–91 | ChipOptions | IO protection enabled here, not via a slot |
| 92–95 | X509format | |
| 96–127| KeyConfig[16] | 2 bytes each |

The Write command skips the first 16 bytes (factory region, not writable) and
the Lock command owns bytes 86–87.

### Counters

- Counters are **config-zone fields** (`Counter0` bytes 52–59, `Counter1`
  bytes 60–67), **not** data slots 4/15.
- API: `atcab_counter_init` (only while config is unlocked),
  `atcab_counter_read`, `atcab_counter_increment` (no `atcab_incr`).
- `counter_init` requires an unlocked config zone → counter setup belongs to
  the config-provisioning phase.

### IO protection

- In cryptoauthlib, IO protection is **command-level wire protection**
  (SecureBoot / Verify / ECDH variants accepting an `io_key`, 32-byte key in a
  data slot) — **not** transport-level per-byte I2C encryption with a modified
  wake handshake.
- Enabled via **ChipOptions (bytes 90–91)**, not via slot-3 config.
- Reference: `app/secure_boot/secure_boot.c` →
  `bind_host_and_secure_element_with_io_protection`.
- Transport-level per-payload protection would be a custom, HAL-level
  implementation — **out of scope** unless a consumer specifically needs it.

## Current state (verified on hardware, 2026-10-16)

- Chip: **ATECC608C**, I2C **0x60**, unprovisioned, config zone **unlocked**.
  Serial `01 23 06 40 AE B6 B9 B7 EE`. INFO `00 00 60 05` (part 0x60, rev 5).
- RNG streams `FF FF 00 00 ...` pre-provisioning (normal for a fresh chip).
- Firmware: a **self-contained I2C driver** (`src/atecc608.c`) —
  wake/probe/diag + RANDOM/INFO/READ; a **console app** (`src/main.c`) with
  `help/bootrom/probe/diag/random/info/serial`. All responses CRC-validated;
  sleep re-wake and guarded bus recovery work. No cryptoauthlib dependency yet.
- cryptoauthlib **v3.8.0** available locally at `../cryptoauthlib` as a
  development reference only.

## Open items (resolve during implementation — not re-opens)

- **Phase 2:** HAL wake via a proper I2C general-call (0-byte) vs. the 1-byte
  dummy workaround.
- **Phase 4:** exact READKEY/WRITE_KEY (4-bit), KEY_TYPE (3-bit), and the
  counter "special format" encodings — decode against the **manual's field
  tables**, not from memory. ECC private-key slots use a *distinct* SlotConfig
  bit layout (EXT_SIG/INT_SIG/ECDH/WRITE_ECDH + GEN_KEY bit8 / PRIV_WRITE bit9).
- **API:** whether to add a small raw-command escape hatch (default: no).
- **CI:** an automated bring-up check (follow-on, not yet scoped).

## Implementation-time details

- The console's `info` model label currently reads "ATECC608B, revision 5"
  (from the pre-"C" decoding) — update to 608C when the API is in place.

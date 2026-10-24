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
  example/                       proof-of-concept examples (NOT the library):
                                 console/ (bench console), tools/, common/
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
  `atecc608::atecc608` ALIAS target; the console moved to `app/` (since
  re-homed under `example/console/` — see the example/ reorg note below);
  cryptoauthlib is
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
    `build/example/console/` after the example/ reorg; originally `build/app/`);
    no cryptoauthlib source in the repo (`build/` is gitignored).
    *The demo's hardware run (probe/random/info/serial) is build-verified here;
    confirm on the board.*
- **Phase 2 — RP2350 I2C HAL — DONE (2026-10-18).** Implemented the
  `atca_hal` I2C interface (`hal_i2c_init/post_init/send/receive/control/
  release` + `hal_delay_ms/us`) in `src/hal_rp2350.c` (compiled into
  `cryptoauth_core`; ctx travels via `ATCAIfaceCfg.cfg_data`); folded the
  standalone driver's raw-I2C primitives into it and retired `src/atecc608.c`
  as a driver (now just the init/deinit surface over `atcab_init/release`).
  `atecc608_init(cfg)` wires the `ATCAIfaceCfg` (devtype **ATECC608**, 8-bit
  address `addr << 1`, `wake_delay` 1500 µs, `rx_retries` 20, 400 kHz).
  - **Wake decision (settled):** full handshake inside
    `hal_i2c_control(ATCA_HAL_CONTROL_WAKE)` — 100 kHz, 1-byte dummy
    general-call write (never clocked: the chip NACKs 0x00 and the controller
    aborts before the data byte, so the wire trace equals a true 0-byte
    general call), `wake_delay` settle, read 4 bytes, restore baud,
    `hal_check_wake`. `ATCA_HAL_CHANGE_BAUD` → `ATCA_UNIMPLEMENTED`, which
    verified routes `calib_wakeup_i2c` entirely through `CONTROL_WAKE` with
    **no library retry** — so the wake owns its retries: fast read retries,
    then 3 complete re-handshakes on failure (empirically required; without
    it, ~1 in 5 command sequences failed with a NACKed send).
  - **Error semantics match the reference HALs** (ESP32/Harmony):
    `ATCA_COMM_FAIL` on any I2C NACK/timeout.
  - **Done when (verified on hardware, 3 rounds, all green):** `atcab_wakeup`
    ok; `atcab_info` → `00 00 60 05`; `atcab_read_config_zone` block 0 +
    serial `01 23 06 40 AE B6 B9 B7 EE`; `atcab_is_locked` → both zones
    unlocked; `atcab_random` → `FF FF 00 00…` — all matching the Phase-1
    standalone driver exactly.
- **Phase 3 — Core API — DONE (2026-10-18).** Public header moved to
  `include/atecc608/atecc608.h` (module layout); `src/atecc608.h` removed,
  `src/hal_rp2350.*` stays module-internal. The curated surface:
  `init/deinit`, `probe` (atcab_wakeup), `info` (`atecc608_info_t{part,
  revision}` from INFO bytes 2/3), `serial` (atcab_read_serial_number, 9 B),
  `random(n)` (chip RANDOM is fixed 32 B — larger requests are chunked,
  smaller discard the final tail), `read_config_zone`/`write_config_zone`,
  `read_slot`/`write_slot` (v3.8.0 has **no** `atcab_read_slot`/
  `atcab_write_slot` — slots go through `atcab_read_bytes_zone`/
  `atcab_write_bytes_zone` with `ATCA_ZONE_DATA`, offset 0, len 32),
  `read_pubkey` (64 B), `is_locked`.
  - **Error model:** every function returns a curated `atecc608_status_t`
    (OK + 8 error classes); the mapping from `ATCA_STATUS` is total and
    lossless — the raw code of the last failure is always retrievable via
    `atecc608_last_error()`.
  - **`atecc608_zone_t` values deliberately equal the `LOCK_ZONE_*` ids**
    (0x00 config / 0x01 data) and are mapped explicitly to them — not cast,
    and not confused with the `ATCA_ZONE_*` command ids (data zone 0x02).
  - The demo console was rewired to the module API now (pulled forward from
    Phase 6) so the API is exercised on hardware; Phase 6 keeps the config
    read-back demo.
  - **Done when (verified):** on hardware, 3 rounds × (probe/info/serial/
    lock/random) + diag — all results match the Phase-1 standalone driver
    exactly (serial `01 23 06 40 AE B6 B9 B7 EE`, part 0x60 rev 5, both
    zones unlocked, `FF FF 00 00…` RNG). Build is warning-clean for our
    sources (the only warning is the known cosmetic `ATCA_TA_SUPPORT
    redefined` inside cryptoauthlib's own headers).
- **Phase 4 — Provisioning utilities + config builder. Split into 4A/4B
  (2026-10-18, user): 4A is development-only (NO chip writes, per ground
  rule 0); 4B is the actual chip provisioning and is gated on a review of
  scenarios first.**
  - **Phase 4A — Development (no chip writes) — DONE (2026-10-18).**
    `include/atecc608/atecc608_config.{h,c}`: field-level intent struct
    (`atecc608_config_intent_t` — renamed from `atecc608_config_t`, which
    collides with cryptoauthlib's own type in `calib_device.h`) + builder →
    128-byte array + parser + CRC-16 + `atecc608_config_writable_equal`
    (byte-diff over the writable region: everything except the 16 factory
    bytes and the lock bytes 86/87). `include/atecc608/atecc608_prov.{h,c}`:
    guarded provisioning — idempotent `provision_config` (read-back verified,
    preserves the chip's I2C address byte 16), `lock_config_zone`
    (re-verify + CRC-verified Lock), `lock_data_zone` / `lock_data_slot`,
    `genkey`, `counter_read` / `counter_increment`; every irreversible step
    is confirm-hook gated, and a refused confirm still consumes exactly one
    confirm call (confirm runs after the state checks, right before the
    command). **Host tests** in `tests/` (standalone CMake project, same
    v3.8.0 FetchContent): `ca_host` = the library's portable sources,
    `mock_chip` = a HAL that emulates the ATECC608 wire protocol + factory
    state, `test_config` (builder byte-exact golden, round-trip, counter
    encoding vectors, decode of the manual's locked
    `ATECC608_DEVICE_CONFIG_VECTOR`, CRC equivalence with `atCRC`,
    writable-diff) and `test_prov` (provision/lock/genkey/counter flows
    against the mock incl. confirm/state guards). `ctest`: **2/2 green**;
    Pico build warning-clean for our sources. Chip untouched.
    - **Real module bugs found by the harness and fixed:** (1)
      `atecc608_config_crc16` inner loop used `int bit` — 9 shifts per byte
      (0x80<<1 = 0x100 ≠ 0); changed to `uint8_t` so 0x80 wraps, now
      byte-identical to `atCRC` (poly 0x8005, init 0, LSB-first per byte,
      LE16). (2) Counter words are **big-endian** u16 in the zone (builder
      was right; the parser and the mock read little-endian — fixed).
    - **Documented deviation from the library (datasheet wins):** GenKey /
      PrivWrite on ECC private key slots are **bits 13/14** (ATECC508A/608A
      datasheet Tables 2-10/2-11; the library's own ATECC608 test vector
      agrees — slot word 0x208F has GenKey set at bit 13), NOT bits 8/9 as
      cryptoauthlib's `ATCA_SLOT_CONFIG_GEN_KEY_SHIFT` / `PRIV_WRITE_SHIFT`
      define. Builder, parser, and mock all follow the datasheet.
    - **4B verification flags (mock fidelity gaps, documented in
      `atecc608_prov.h`):** UseLock enforcement is not modeled (keep
      `use_lock_en=false` until an auth flow exists); UpdateExtra is
      strictly one-shot in the mock (verify same-value behavior on a real
      chip); factory KeyConfig/SlotConfig words are assumed 0 (the real
      bench chip ships locked-down factory values, e.g. KeyConfig
      0x0033/0x003C, SlotConfig 0x2083/0x8FAF — recorded in RESUME.md;
      the prov path overwrites them all); data-zone READ requires the data
      zone to be locked in the mock (fire-and-forget writes until lock);
      byte 16 (I2C address) and bytes 88..89 (SlotLocked; factory 0xFFFF,
      Lock-managed, bit n = 0 -> slot n locked) are preserved, never
      written.
  - **Phase 4B — Chip provisioning (writes only after user approval) — DONE (2026-10-23).**
    **Provisioning executed at the bench 2026-10-23** (see RESUME.md): config
    zone written (approved plan, read-back verified) + LOCKED (one-way, user
    go-ahead); I/O key in slot 14 (chip ACKed) + saved to littlefs
    `/io_key.bin` (read-back verified); final `prov status` = LOCKED / lock
    bytes 55 00 / chip-zone CRC F6DE; data zone still UNLOCKED. **Scenario
    discussion done 2026-10-22 — config agreed** (see RESUME.md,
    "Agreed 4B config"): one *locked* config usable by all apps — "lock the
    layout, keep the contents open" (all slots `write_config=0`/`req_auth=0`,
    priv slots `gen_key=1`, `lockable=1` where later slot-locks are wanted).
    Slots: 0 fw-validation pub; 1/2 identity pair; 3–6 FIDO2 creds (4 total);
    7 password-store master (unreadable, KDF PRF source, shared by all
    stores); 8–10 spare unreadable secrets (compartmentalized stores /
    future apps); 11 second fw key; 12/13 spare EC pair (ECDH); 14 I/O
    protection key (unreadable secret, same class as 7–10 — the library's
    locked ATECC608 reference config keeps its io key in a type-7 secret
    slot and its ATECC608 KDF test exercises I/O-protected KDF against it;
    **lockable** — dev leaves it unlocked/re-keyable, production
    slot-locks it after the recorded copy is verified, closing the
    bus-attacker re-key hole); 15 data spare. Counters: 0 = FIDO2 sig
    count, 1 = fw anti-rollback. PIN brute-force counter is Pico-side
    (no native chip lockout).
    **I/O protection ON from the start** (`io_prot_en`, `kdf_prot=1`,
    `ecdh_prot=1`, `kdf_aes_en=1`, key slot 14). The io key comes from
    **Pico TRNG**, not the chip RNG: the chip's Random command returns a
    0xFFFF0000 factory pattern until the config zone is locked (v3.8.0
    manual, `atcab_random()`). **Persistence: pico-littlefs** (our own
    lib; SDK 2.x ships no nvs/littlefs) holds `/io_key.bin`, `/vault.db`,
    `/fido2.db`, lockout state. 4B runs as serial-console commands
    (`prov status/randtest/iokey/config/lock`; only `prov lock` is
    irreversible, typed-confirm). Exact byte plan:
    `example/tools/dump_devconfig.c` (builder output, 128 B + summary CRC).
    **Repo reorg (2026-10-22):** the provisioning PoC + demo apps are the
    *examples*, not the library — `app/` → `example/console/`,
    `tools/` → `example/tools/`, new `example/CMakeLists.txt` (+
    `ATECC608_BUILD_EXAMPLES` option, default ON) and `example/README.md`
    (contract: every example checks provisioning state at startup and
    provisions via the module API if needed; shared base in
    `example/common/`). Examples stay **discrete applications** (one
    directory per app: password-store, fido2, …), not one multi-mode app. Before any write: README
    scenario guidance, then the user's explicit go-ahead on the exact byte
    plan (what, where, reversibility):
    write→read-back verify, and lock gated behind read-back + typed-confirm.
    - **Done when:** on the chip, write→read-back verify works and lock is
      gated behind read-back + typed-confirm; README scenario guidance
      committed.
- **Phase 5 — Crypto pass-through (on demand).** `kdf` / `sign` / `verify` /
  `genkey` / `read_pubkey` wrappers, added as consumers need them.
  - **Done when:** at least a KDF round-trip is validated on hardware.
- **Phase 6 — Sample / diagnostic app.** The `example/console/` console
  exercises the library API (probe/info/serial/random were wired in Phase 3;
  add a config read-back demo) — it uses the module, not the raw driver.
  It is a demo, **not** a provisioning tool.
  - **Done when:** the demo builds against the lib and runs on hardware.
- **Phase 7 — On-hardware validation + regression + bring-up checklist.**
  Full on-hardware suite; a documented, reusable bring-up checklist.
  - **Done when:** suite green; checklist written.

## Ground rules (provisioning safeguards)

0. **No writes to a physical chip without an explicit user go-ahead**
   (2026-10-18): the connected chip is irreplaceable in practice (limited
   spares). Hardware validation stays read-only; write APIs are implemented
   but never exercised on hardware until a specific write is reviewed and
   approved with the user.
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

## Current state (verified on hardware, 2026-10-23)

- Chip: **ATECC608C**, I2C **0x60**, **PROVISIONED + config zone LOCKED**
  (Phase 4B, 2026-10-23 — one-way; the config zone can never be re-written).
  Serial `01 23 06 40 AE B6 B9 B7 EE`. INFO `00 00 60 05` (part 0x60, rev 5).
  Config zone = approved plan (chip-zone CRC F6DE, lock bytes 55 00); I/O key
  in slot 14 (chip ACKed) + `/io_key.bin` on littlefs; data zone still
  UNLOCKED (contents open per the agreed layout). See RESUME.md.
- RNG: the `FF FF 00 00 ...` factory pattern was only pre-provisioning
  (before the config lock); a locked chip returns real random.
- Firmware: the **cryptoauthlib v3.8.0 path is live** — `src/hal_rp2350.c`
  (RP2350 I2C HAL, wake handshake incl. full-handshake fallback retries,
  stuck-bus recovery, 10 ms timeouts) + `src/atecc608.c` (the curated
  `atecc608_*` core API over `atcab_*`, public header in
  `include/atecc608/atecc608.h`). The old standalone driver is retired. The
  console (`example/console/main.c`, originally `app/main.c`) exercises the
  module API (`atecc608_probe/info/
  serial/is_locked/random`) plus raw-I2C `diag` and `bootrom`; 3 validation
  rounds match the Phase-1 standalone outputs exactly (Phase 3 exit criteria).
- cryptoauthlib **v3.8.0** fetched at build time; the clone at
  `../cryptoauthlib` is a development reference only.
- **Phase 4A complete (2026-10-18, dev-only):** config builder + guarded
  provisioning API + host unit tests with a mock chip HAL — `ctest` 2/2
  green, Pico build warning-clean.
- **Phase 4B complete (2026-10-23, on-chip):** provisioning executed at the
  bench — config zone written (read-back verified) + LOCKED, I/O key in slot
  14 (chip ACKed) + saved to littlefs. See RESUME.md (run sheet, CRC notes,
  the littlefs flash-lockout fix `d1778af`).

## Open items (resolve during implementation — not re-opens)

- ~~**Phase 2:** HAL wake via a proper I2C general-call (0-byte) vs. the
  1-byte dummy workaround.~~ — **Resolved 2026-10-18:** full handshake in
  `hal_i2c_control(WAKE)`; the 1-byte dummy write is wire-identical to a 0-byte
  general call (chip NACKs 0x00 before any data byte is clocked). See Phase 2.
- ~~**Phase 4:** exact READKEY/WRITE_KEY (4-bit), KEY_TYPE (3-bit), and the
  counter "special format" encodings — decode against the **manual's field
  tables**, not from memory. ECC private-key slots use a *distinct* SlotConfig
  bit layout (EXT_SIG/INT_SIG/ECDH/WRITE_ECDH + GEN_KEY bit8 / PRIV_WRITE
  bit9).~~ — **Resolved 2026-10-18 (Phase 4A):** encodings decoded from the
  manual + datasheet and unit-tested (see the Phase 4A entry). The counter is
  the 8-byte dual linear+binary **BE16** encoding (documented in
  `atecc608_config.h`); the ECC private-key slot GEN_KEY/PRIV_WRITE bits are
  **13/14 per the datasheet**, contradicting the library's 8/9 defines — the
  datasheet wins (see Phase 4A).
- **API:** whether to add a small raw-command escape hatch (default: no).
- **CI:** an automated bring-up check (follow-on, not yet scoped).

## Implementation-time details

- ~~Console `info` model label ("ATECC608B") — update to 608C when the API
  is in place.~~ — **Resolved 2026-10-18 (Phase 3):** the API reports raw
  part/revision (`atecc608_info_t`); the demo console labels part 0x60 as
  ATECC608C (board-specific; the chip on the board is a 608C).

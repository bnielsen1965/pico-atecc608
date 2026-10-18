# Resume notes (pico-atecc608)

Pause point: **2026-10-18, end of Phase 2.** This file is a continuity
snapshot — update it at each pause. The forward plan lives in `PLAN.md`; this
file captures the exact working state and the concrete next steps.

## Where we are
- **Phase 1 DONE** — module skeleton + build wiring.
- **Phase 2 DONE** — RP2350 I2C HAL on cryptoauthlib v3.8.0. Build green,
  hardware-validated (see below). Standalone driver retired.
- **Phase 3 next** — the curated `atecc608_*` core API over `atcab_*`.

## Build (verified green)
```sh
cd build
cmake .. -DPICO_SDK_PATH="$HOME/Projects/pico-sdk"   # fetches cryptoauthlib once
make -j
# outputs: build/app/pico-atecc608.uf2   (+ libatecc608.a, libcryptoauth_core.a)
```
Air-gapped: `-DCRYPTOAUTHLIB_SOURCE_DIR=/path/to/cryptoauthlib`.
**No cryptoauthlib source is in the repo** — fetched into `build/` at
configure time, discarded otherwise. Known cosmetic warning: `ATCA_TA_SUPPORT
redefined` (from cryptoauthlib's own headers, harmless).

## File layout (current)
- `CMakeLists.txt` — module + demo build; FetchContent for cryptoauthlib;
  `cryptoauth_core` static lib (core sources **minus** `hal/hal_linux.c`,
  **plus** `src/hal_rp2350.c` + `pico_stdlib`/`hardware_i2c`); `atecc608` lib
  links `cryptoauth_core` PUBLIC; `atecc608::atecc608` ALIAS.
- `src/hal_rp2350.c/.h` — the RP2350 I2C HAL (Phase 2). `hal_rp2350_ctx_t`
  (i2c instance, sda/scl pins, baud) travels via `ATCAIfaceCfg.cfg_data`.
- `src/atecc608.c/.h` — Phase-2 surface: `atecc608_cfg_t` (bus, sda/scl pins,
  7-bit addr, baud) + `atecc608_init()` (static ctx + `ATCAIfaceCfg`, address =
  `addr << 1`, `wake_delay` 1500 µs, `rx_retries` 20 → `atcab_init`) +
  `atecc608_deinit()` (`atcab_release()`, NULL-safe) + `atecc608_print_hex`.
  The old standalone driver is gone.
- `app/main.c` + `app/CMakeLists.txt` — validation console (pico-command-line)
  over `atcab_*`: probe (atcab_wakeup), info, serial (read_config_zone),
  lock (atcab_is_locked), random, diag (raw I2C), bootrom, help. **Provisional
  for Phase 2** — Phase 6 rewires it to the curated API.
- `pico-command-line/` — submodule (console framework).
- `include/atecc608/` — **not created yet** (Phase 3).
- `../cryptoauthlib` — dev-reference clone (NOT part of this repo).

## Phase 2 — what was built (and why)
- **Wake = full handshake inside `hal_i2c_control(WAKE)`** (decision settled
  2026-10-18): drop to 100 kHz → 1-byte dummy general-call write →
  `hal_delay_us(cfg->wake_delay)` → read 4 bytes (honoring `rx_retries`) →
  restore baud → `hal_check_wake()`. The 1-byte dummy is **never clocked** —
  the chip NACKs the 0x00 address and the I2C controller aborts before the
  data byte — so the wire trace is byte-identical to a true 0-byte general
  call. `ATCA_HAL_CHANGE_BAUD` returns `ATCA_UNIMPLEMENTED`; verified that
  `calib_wakeup_i2c` then routes the whole wake through `CONTROL_WAKE` and
  does **no library-level retry** — all retrying must live in our wake.
- **Wake robustness (empirically required):** the first handshake's read
  occasionally NACKs even after the 1.5 ms settle (missed pulse / slow wake —
  indistinguishable on the wire from "chip already awake"). On read failure we
  re-issue **3 complete handshakes** (fresh pulse + full settle + read),
  mirroring `calib_wakeup_i2c`'s full-handshake retry. Without this, ~1 in 5
  command sequences failed with `ATCA_COMM_FAIL` (send NACKed). With it:
  15/15 command sequences green across 3 validation rounds.
- **Error semantics = reference HALs:** `hal_i2c_send`/`hal_i2c_receive`/
  token sends return `ATCA_COMM_FAIL` on NACK/timeout — exactly what the
  ESP32 and Harmony reference HALs return. (The iface layer treats any
  non-success identically; only the reported code differs.)
- **Wire protocol** (hardware-verified Phase 1 + matches reference HALs):
  I/O token is the FIRST DATA BYTE of write transactions. Command:
  `S 0xC0 03 <count..crc> P`; read token: `S 0xC0 00 P`; read:
  `S 0xC1 <count> P` then `S 0xC1 <data+crc> P`; idle `0x02`, sleep `0x01`.
  `halsend` prepends `word_address` as byte 0; `halreceive` gets the 8-bit
  device address.
- **HAL owns the peripheral:** `i2c_init` + pins + pull-ups + stuck-bus
  recovery in `hal_i2c_init`; `i2c_deinit` in `hal_i2c_release`. 10 ms
  per-transaction timeouts (SDK blocking calls spin forever on a stuck bus).
- **Delays:** `atca_config.h.in` unconditionally `#define`s
  `atca_delay_ms/us → hal_delay_ms/us`, so the HAL provides **only**
  `hal_delay_ms`/`hal_delay_us` (defining `atca_delay_*` too = redefinition).

## Gotchas / decisions to remember
- **cryptoauthlib's CMake is host-keyed** — on a UNIX host it force-adds
  `hal/hal_linux.c` (→ `sys/mman.h`) + `-lrt`, wrong for bare-metal Pico.
  We build the core ourselves as `cryptoauth_core` (FetchContent source only,
  **CMP0169 pinned OLD**; generated `atca_config.h`: ATECC608/508A/108A/206A
  + CA ON, `ATCA_HAL_I2C ON`, `ATCA_USE_ATCAB_FUNCTIONS ON` — the latter or
  the `atcab_*` command functions aren't compiled at all;
  `ATCA_PLATFORM_MALLOC/FREE` = malloc/free; **no**
  `ATCA_PLATFORM_STRCASESTR` — newlib lacks `strcasestr`).
- **Link ordering:** `src/hal_rp2350.c` compiles INTO `cryptoauth_core` (not
  the `atecc608` lib) — `atca_hal.c` in that archive references `hal_i2c_*`
  and a static archive resolves single-pass.
- **`cryptoauth_core` must not pin C99** — pico-sdk headers need
  `static_assert`; project default is C11.
- **`atcai2c.address` is the 8-bit address** (LSB = 0): 0xC0 for 0x60. Field
  name is `address` (not deprecated `slave_address`).
- **C typedef tags are not types:** `typedef struct foo {...} foo_t;` does NOT
  let you write `foo *p` in C — use `struct foo *` or `foo_t`. Cost one build
  cycle to learn the hard way.
- **`atcab_is_locked` takes `LOCK_ZONE_*` ids, not `ATCA_ZONE_*`:**
  `LOCK_ZONE_CONFIG=0x00`, `LOCK_ZONE_DATA=0x01` vs `ATCA_ZONE_CONFIG=0x00`,
  `ATCA_ZONE_DATA=0x02`. Passing `ATCA_ZONE_DATA` (0x02) hits
  `LOCK_ZONE_DATA_SLOT` → `ATCA_BAD_PARAM`.
- **`device_state` bookkeeping:** after every command the lib sets state to
  IDLE and sends the idle token; the next command therefore runs the full
  wake handshake again. A `-48` (ATCA_WAKE_FAILED) wake result is harmless —
  `calib_execute_command` proceeds to the send regardless.
- `make CMakeFiles/.../hal_rp2350.c.o` reports "No rule to make target" —
  use full `make -j`.

## Reference locations
- `../cryptoauthlib/lib/hal/atca_hal.h` — HAL interface, `ATCA_HAL_CONTROL_*`,
  `hal_check_wake`, polling constants (1 ms init / 2 ms freq / 2500 ms max)
- `../cryptoauthlib/lib/hal/hal_esp32_i2c.c`, `hal_i2c_harmony.c` — reference
  HALs (modern API; both return ATCA_COMM_FAIL on I2C failure)
- `../cryptoauthlib/lib/calib/calib_execution.c` — send/receive/poll flow;
  **only `ATCA_RX_NO_RESPONSE` from a send triggers re-wake retry**
- `../cryptoauthlib/lib/calib/calib_basic.c` — `calib_wakeup_i2c`
  (CHANGE_BAUD → UNIMPLEMENTED → CONTROL_WAKE fallback), `calib_idle`
- `../cryptoauthlib/lib/atca_iface.h` — `ATCAIfaceCfg` (8-bit `address`,
  `wake_delay`, `rx_retries`, `cfg_data`)
- `../cryptoauthlib/lib/atca_config.h.in` — delay macros, `#cmakedefine`s
- `/tmp/opencode/cab_manual.txt` — extracted cryptoauthlib manual (747 pp)
- `/tmp/opencode/atecc608_ds.txt` — summary-datasheet text

## Hardware / validation baseline (verified 2026-10-18)
- Board: **Pico 2 (RP2350, arm-s)**. I2C0 = GP20(SDA)/GP21(SCL);
  UART0 = GP0/GP1 → ttyUSB0; console also on USB CDC (ttyACM0).
- Chip: **ATECC608C @ I2C 0x60, unprovisioned, config zone UNLOCKED**.
  Serial `01 23 06 40 AE B6 B9 B7 EE`; INFO `00 00 60 05` (part 0x60, rev 5).
  RNG streams `FF FF 00 00 …` pre-provisioning (normal).
- **Phase 2 validation: PASS (3 rounds, all commands).** Through
  cryptoauthlib: `atcab_wakeup` ok; `atcab_info` → `00 00 60 05`;
  `atcab_read_config_zone` → block 0 + serial match Phase-1 standalone
  exactly; `atcab_is_locked` → config unlocked, data unlocked;
  `atcab_random` → `FF FF 00 00…`. HAL trace showed 100% ACK on every
  send/read; every wake handshake returned the genuine `04 11 33 43` packet.
- Flashing: send `bootrom` over the CDC console (needs a **persistent** raw
  port open — stty/printf open-close drops DTR and the console won't reply),
  wait for `/run/media/burnin/RP2350`, copy the uf2. Pico 2 runtime PID is
  `2e8a:0009`; BOOTSEL PID is `2e8a:000f` (NOT 0009).

## HARD RULE (user, 2026-10-18): no chip writes without an explicit go-ahead
The user has a limited number of spare ATECC608 chips and does NOT want the
connected chip put into an unintended state. Until the user explicitly
approves a specific write:
- Hardware validation is **read-only** (probe / info / serial / lock status /
  random). Write APIs may be *implemented* as code, never *exercised* on the
  chip.
- When a step genuinely requires writing to the chip (Phase 4 provisioning
  first), **STOP and review with the user first**: what is written, to which
  bytes, and whether it is reversible.

## Next steps (Phase 3 — core API)
1. `include/atecc608/atecc608.h` — public surface (move/rename from
   `src/atecc608.h`): lifecycle (`init`/`deinit`), `probe`, `info`,
   `serial`, `random`, `last_error`, zone read, `is_locked`.
2. Thin, correct wrappers over `atcab_*` in `src/atecc608.c`; keep the HAL
   internal (`src/hal_rp2350.*` stays private to the module).
3. Wire the console to the new API (or keep `atcab_*` until Phase 6 — decide
   when starting).
4. Host build check: module compiles warning-clean for the target; document
   the consumer-facing CMake usage (`add_subdirectory` + link
   `atecc608::atecc608`).

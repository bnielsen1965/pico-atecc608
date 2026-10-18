# Resume notes (pico-atecc608)

Pause point: **2026-10-18, end of Phase 3.** This file is a continuity
snapshot — update it at each pause. The forward plan lives in `PLAN.md`; this
file captures the exact working state and the concrete next steps.

## Where we are
- **Phase 1 DONE** — module skeleton + build wiring.
- **Phase 2 DONE** — RP2350 I2C HAL on cryptoauthlib v3.8.0.
- **Phase 3 DONE** — curated `atecc608_*` core API. Build green,
  hardware-validated (3 rounds, see below). Console now uses the module API.
- **Phase 4 next** — provisioning utilities + config builder. **This is the
  first phase that can write to the chip — the HARD RULE below applies: stop
  and review the exact write plan with the user before anything touches it.**

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
redefined` (from cryptoauthlib's own headers, harmless; our sources are
warning-clean).

## File layout (current)
- `CMakeLists.txt` — module + demo build; FetchContent for cryptoauthlib;
  `cryptoauth_core` static lib (core sources **minus** `hal/hal_linux.c`,
  **plus** `src/hal_rp2350.c` + `pico_stdlib`/`hardware_i2c`); `atecc608` lib
  (PUBLIC include `include/`, PRIVATE `src/`) links `cryptoauth_core` PUBLIC;
  `atecc608::atecc608` ALIAS.
- `include/atecc608/atecc608.h` — **the public API** (Phase 3): cfg/init/
  deinit, probe, info, serial, random, config-zone read/write, is_locked,
  slot read/write, read_pubkey, last_error, status_str, print_hex. Constants:
  `ATECC608_CONFIG_ZONE_LEN` 128, `ATECC608_DATA_SLOT_LEN` 32,
  `ATECC608_MAX_DATA_SLOT` 15, `ATECC608_PUBKEY_LEN` 64,
  `ATECC608_SERIAL_LEN` 9, `ATECC608_INFO_LEN` 4, `ATECC608_RNG_CHUNK_LEN` 32.
- `src/atecc608.c` — implementation: the wrappers + the ATCA_STATUS →
  `atecc608_status_t` mapping (static `s_last_error` holds the raw code).
  The old `src/atecc608.h` is **gone** (moved to `include/atecc608/`).
- `src/hal_rp2350.c/.h` — the RP2350 I2C HAL (Phase 2), module-internal
  (PRIVATE include only). ctx travels via `ATCAIfaceCfg.cfg_data`.
- `app/main.c` + `app/CMakeLists.txt` — validation console (pico-command-
  line) over the **module API**: probe/info/serial/lock/random (atecc608_*),
  diag (raw I2C), bootrom, help. Phase 6 adds a config read-back demo.
- `pico-command-line/` — submodule (console framework).
- `../cryptoauthlib` — dev-reference clone (NOT part of this repo).

## Phase 3 — what was built (and why)
- **Curated error enum** (PLAN's "error enum"): every `atecc608_*` call
  returns `atecc608_status_t` — `ATECC608_OK`, `ATECC608_ERR` (catch-all),
  `ERR_BAD_PARAM`, `ERR_NOT_INIT`, `ERR_WAKE`, `ERR_COMM`, `ERR_RX`,
  `ERR_EXEC`, `ERR_CHIP_STATE`. The mapping in `src/atecc608.c`
  (`atecc608_map_status`) is total; the raw `ATCA_STATUS` of the last
  failure is always available via `atecc608_last_error()`, so no diagnostic
  info is lost. Rationale: a small, stable surface for consumers, while
  cryptoauthlib's 30+ codes stay reachable for debugging.
- **`atecc608_zone_t` = the `LOCK_ZONE_*` ids** (0x00 config, 0x01 data),
  mapped explicitly in `atecc608_is_locked` — deliberately NOT the
  `ATCA_ZONE_*` command ids (data zone is 0x02 there; passing it gives
  `ATCA_BAD_PARAM`). This is the Phase-2 `lock` bug, now structurally
  impossible at the API boundary.
- **Slot access:** v3.8.0 has **no** `atcab_read_slot`/`atcab_write_slot`.
  `atecc608_read_slot`/`write_slot` use `atcab_read_bytes_zone`/
  `atcab_write_bytes_zone(ATCA_ZONE_DATA, slot, 0, data, 32)`.
- **`atecc608_info_t {part, revision}`** from INFO (revision) response
  bytes 2/3 (bytes 0-1 reserved 0x00). The library reports raw data; the
  demo console's "ATECC608C" label is board-specific (part 0x60).
- **`atecc608_random(n)`**: the chip's RANDOM command always returns 32 B —
  the wrapper chunks larger requests and discards the final tail for smaller
  ones (documented in the header).
- **Write wrappers implemented, never exercised** (HARD RULE):
  `atecc608_write_config_zone` (chip skips the first 16 factory bytes),
  `atecc608_write_slot`. No lock functions in Phase 3 — locks belong to the
  Phase-4 guarded provisioning API.
- **Console rewired to the module API now** (pulled forward from Phase 6 —
  the Phase 3 exit criteria require on-hardware API validation, and the
  console is that harness). It no longer includes `cryptoauthlib.h` or
  `string.h`; `atca_status.h` comes in via the public header.

## Phase 3 — hardware validation (PASS, 3 rounds, read-only only)
Through the module API: `atecc608_probe` ok (wake handshake);
`atecc608_info` → part 0x60, revision 5; `atecc608_serial` →
`01 23 06 40 AE B6 B9 B7 EE`; `atecc608_is_locked` → config unlocked, data
unlocked; `atecc608_random` → `FF FF 00 00…` (normal pre-provisioning).
Raw-I2C `diag` normal (general call NACK; wake-read NACK right after a
command = chip awake). All values match the Phase-1 standalone driver
exactly. Chip remains in factory state — **nothing has been written to it**.

## Gotchas / decisions to remember
- **Console scripting (CDC):** the console framework **echoes typed
  characters** and prints a `\n` after every CR — so a command like
  `probe\r` replies with `probe\n<output>`. Use bounded reads (read until
  ~1.2 s of silence with a per-command budget) — do NOT loop on "read until
  empty" (a port left half-open by a killed session can replay a big
  backlog of `\n` bytes once; observed once in Phase 3, drained, did not
  recur). `pyserial` is available (v3.5) and is the cleanest driver.
- **CDC port number changes after re-enumeration** (ttyACM0 → ttyACM1 …) —
  always re-detect the node after a reboot (`ls /dev/ttyACM*`), don't
  hard-code it.
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
  let you write `foo *p` in C — use `struct foo *` or `foo_t`.
- **`atcab_is_locked` takes `LOCK_ZONE_*` ids, not `ATCA_ZONE_*`** — now
  encapsulated in `atecc608_is_locked` (explicit switch), so callers can't
  trip over it.
- **`device_state` bookkeeping:** after every command the lib sets state to
  IDLE and sends the idle token; the next command therefore runs the full
  wake handshake again. A `-48` (ATCA_WAKE_FAILED) wake result is harmless —
  `calib_execute_command` proceeds to the send regardless.
- **Wake = full handshake inside `hal_i2c_control(WAKE)`**: 100 kHz, 1-byte
  dummy general-call write (never clocked — wire-identical to a 0-byte
  general call), `wake_delay` 1500 µs, read 4 bytes (fast retries), **3
  complete re-handshakes on read failure** (empirically required; without it
  ~1 in 5 command sequences failed with a NACKed send), restore baud.
  `ATCA_HAL_CHANGE_BAUD` → `ATCA_UNIMPLEMENTED` so the library does no wake
  retry of its own — the wake owns all retries.
- **Error semantics = reference HALs (ESP32/Harmony):** `ATCA_COMM_FAIL` on
  any I2C NACK/timeout. `calib_execute_command`'s send-retry loop only
  re-wakes on `ATCA_RX_NO_RESPONSE`.
- `make CMakeFiles/.../x.c.o` reports "No rule to make target" — use full
  `make -j`.

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
- `../cryptoauthlib/lib/atca_status.h` — all ATCA_STATUS codes (the mapping
  target in `src/atecc608.c`)
- `../cryptoauthlib/lib/atca_basic.h/.c` — `atcab_*` signatures:
  `atcab_info(uint8_t[4])`, `atcab_read_serial_number(uint8_t[9])`,
  `atcab_random(uint8_t[32])` (fixed 32 B),
  `atcab_read_bytes_zone(zone, slot, offset, data, len)`,
  `atcab_read_pubkey(slot, uint8_t[64])`, `atcab_is_locked(LOCK_ZONE_*, bool*)`
- `../cryptoauthlib/lib/calib/calib_info.c` — INFO (revision) = 4-byte
  response; bytes 2/3 = part id / silicon revision
- `/tmp/opencode/cab_manual.txt` — extracted cryptoauthlib manual (747 pp)
- `/tmp/opencode/atecc608_ds.txt` — summary-datasheet text
- `/tmp/opencode/validate_phase3.py` — the CDC validation script (bounded
  per-command reads; pyserial)

## Hardware / validation baseline (verified 2026-10-18)
- Board: **Pico 2 (RP2350, arm-s)**. I2C0 = GP20(SDA)/GP21(SCL);
  UART0 = GP0/GP1 → ttyUSB0 (silent — stdio is USB-only by default); console
  on USB CDC (ttyACM*, node number changes across re-enumerations).
- Chip: **ATECC608C @ I2C 0x60, unprovisioned, config zone UNLOCKED**.
  Serial `01 23 06 40 AE B6 B9 B7 EE`; INFO `00 00 60 05` (part 0x60, rev 5).
  RNG streams `FF FF 00 00 …` pre-provisioning (normal).
- **Phase 3 validation: PASS (3 rounds, all commands, read-only).** API
  results match the Phase-1 standalone driver exactly (see Phase 3 section
  above).
- Flashing: send `bootrom` over the CDC console (needs a **persistent** raw
  port open — stty/printf open-close drops DTR and the console won't reply),
  wait for `/run/media/burnin/RP2350`, copy the uf2. Pico 2 runtime PID is
  `2e8a:0009`; BOOTSEL PID is `2e8a:000f` (NOT 0009).
  `/tmp/opencode/flash_phase3.py` does the full flash sequence.

## HARD RULE (user, 2026-10-18): no chip writes without an explicit go-ahead
The user has a limited number of spare ATECC608 chips and does NOT want the
connected chip put into an unintended state. Until the user explicitly
approves a specific write:
- Hardware validation is **read-only** (probe / info / serial / lock status /
  random). Write APIs are implemented (`atecc608_write_config_zone`,
  `atecc608_write_slot`) but have **never been exercised** on the chip.
- When a step genuinely requires writing to the chip (Phase 4 provisioning
  first), **STOP and review with the user first**: what is written, to which
  bytes, and whether it is reversible.

## Next steps (Phase 4 — provisioning utilities + config builder)
1. Config builder: field-level struct from `calib_device.h`
   (`atecc608_config_s`) → 128-byte array + `atecc608_config_verify`;
   consumers express intent, never raw bytes.
2. Guarded provisioning API: idempotent write with read-back verify before
   any lock, `lock_config_zone`/`lock_data_zone` behind a typed-confirm hook,
   genkey, counter init.
3. **Host unit tests (mock HAL)** asserting the produced 128-byte array for
   known-intent configs (this is where the "host build warning-clean"
   criterion gets a real host build).
4. **WRITE CHECKPOINT:** before any on-hardware provisioning test, stop and
   present the exact write plan (which bytes, why, reversibility) for user
   approval. On-hardware write→read-back verification only after approval.

# Resume notes (pico-atecc608)

Pause point: **2026-10-17, end of Phase 1.** This file is a continuity
snapshot — update it at each pause. The forward plan lives in `PLAN.md`; this
file captures the exact working state and the concrete next steps.

## Where we are
- **Phase 1 DONE** — module skeleton + build wiring. Build is **green**.
- **Phase 2 next** — the RP2350 I2C HAL. Not started. Needs the board to validate.

## Build (verified green)
```sh
mkdir -p build && cd build
cmake .. -DPICO_SDK_PATH="$HOME/Projects/pico-sdk"   # fetches cryptoauthlib once
make -j
# outputs: build/app/pico-atecc608.uf2   (+ libatecc608.a, libcryptoauth_core.a in build/)
```
Air-gapped: `-DCRYPTOAUTHLIB_SOURCE_DIR=/path/to/cryptoauthlib`.
**No cryptoauthlib source is in the repo** — it's fetched into `build/` at
configure time and discarded.

## File layout (current)
- `CMakeLists.txt` — module + demo build; FetchContent for cryptoauthlib; the
  `cryptoauth_core` static lib; the `atecc608` lib + `atecc608::atecc608` ALIAS.
- `src/atecc608.c/.h` — standalone I2C driver (wake/CRC/poll/re-wake/bus-recovery
  + RANDOM/INFO/READ). Becomes the HAL's raw-I2C primitives in Phase 2.
- `app/main.c` + `app/CMakeLists.txt` — demo console (pico-command-line):
  probe/diag/random/info/serial.
- `pico-command-line/` — submodule (console framework).
- `include/atecc608/` — **not created yet** (Phase 3).
- `../cryptoauthlib` — dev-reference clone (NOT part of this repo).

## Phase 2 concrete next steps (the HAL)
1. New `src/hal_rp2350.c` implementing the `atca_hal` I2C interface:
   `hal_i2c_init / hal_i2c_post_init / hal_i2c_send / hal_i2c_receive /
   hal_i2c_control / hal_i2c_release` + `hal_delay_ms / hal_delay_us`.
   - Wrap the existing driver's raw-I2C primitives (wake @100 kHz, 400 kHz
     traffic, timeouts, sleep re-wake, bus recovery).
   - `hal_i2c_control(ATCAHAL_WAKEUP)` = the wake handshake.
   - **Start from the legacy template** `../cryptoauthlib/lib/hal/hal_i2c_start.c`.
2. Turn **ON** `ATCA_HAL_I2C` in the generated `atca_config.h` (root CMakeLists).
3. Link `cryptoauth_core` into `atecc608` (PUBLIC) in the root CMakeLists.
4. `atecc608_init(const atecc608_cfg_t*)` — build the `ATCAIfaceCfg`
   (devtype **ATECC608**, slave_address 0x60, `wake_delay` µs, baud) + `atcab_init`.
5. Fold `src/atecc608.c`'s raw-I2C helpers into the HAL.
6. **Validate read-only** through cryptoauthlib and cross-check vs standalone:
   `atcab_info` (part 0x60, rev 5), `atcab_read_config_zone` block 0
   (serial `01 23 06 40 AE B6 B9 B7 EE`), `atcab_is_locked` (unlocked),
   `atcab_random`.

## Gotchas / decisions to remember
- **cryptoauthlib's CMake is host-keyed** — on a UNIX build host it force-adds
  `hal/hal_linux.c` (→ `sys/mman.h`) and links `-lrt`, which can't build for a
  bare-metal Pico. So we do **NOT** `add_subdirectory` it. We build the core
  ourselves as the `cryptoauth_core` target:
  - `FetchContent_Populate` (source only) — **CMP0169 pinned OLD** to keep that form.
  - Generate `atca_config.h` with: ATECC608/508A/108A/206A + CA support ON;
    `ATCA_PLATFORM_MALLOC=malloc`, `ATCA_PLATFORM_FREE=free`; **no**
    `ATCA_PLATFORM_STRCASESTR` (newlib lacks `strcasestr` → cryptoauthlib uses its
    own `lib_strcasestr` fallback in `atca_helpers.c`).
  - Core = the default file set **minus** `hal/hal_linux.c`.
  - Cosmetic warning `ATCA_TA_SUPPORT redefined` comes from cryptoauthlib's own
    headers — harmless.
- **`ATCA_HAL_I2C` is OFF right now** (Phase 1) — no undefined-symbol problem
  because nothing links cryptoauthlib yet. Phase 2 turns it on + supplies the HAL.
- **Wake mechanism (open design decision):** the existing driver issues a
  **1-byte dummy** write because the pico-sdk I2C rejects true 0-length writes.
  cryptoauthlib expects the wake inside `hal_i2c_control(ATCAHAL_WAKEUP)`.
  Decide: keep the 1-byte dummy, or attempt a real I2C general-call.

## Reference locations
- `../cryptoauthlib/lib/hal/atca_hal.h` — HAL interface (`hal_i2c_*`, control opts, delays)
- `../cryptoauthlib/lib/hal/hal_i2c_start.c` — legacy embedded I2C HAL template (start here)
- `../cryptoauthlib/lib/atca_iface.h` — `ATCAIfaceCfg` (devtype, slave_address, wake_delay, baud)
- `../cryptoauthlib/lib/atca_basic.h` — `atcab_*` API
- `../cryptoauthlib/lib/calib/calib_device.h` — config-zone layout (Phase 4)
- `/tmp/opencode/cab_manual.txt` — extracted cryptoauthlib manual (747 pp)
- `/tmp/opencode/atecc608_ds.txt` — summary-datasheet text
- `/tmp/opencode/pico_p1_build*.log` — Phase 1 build logs

## Hardware / validation baseline
- Board: **Pico 2 (RP2350, arm-s)**. I2C0 = GP20(SDA)/GP21(SCL); UART0 = GP0/GP1.
- Chip: **ATECC608C @ I2C 0x60, unprovisioned, config zone UNLOCKED**.
  Serial `01 23 06 40 AE B6 B9 B7 EE`; INFO `00 00 60 05` (part 0x60, rev 5).
  RNG streams `FF FF 00 00 …` pre-provisioning (normal for a fresh chip).
- The standalone driver already does probe/diag/random/info/serial correctly —
  Phase 2's cryptoauthlib path must **match** these outputs.

## The one decision to settle before writing the HAL
**Wake mechanism** — 1-byte dummy (current, SDK-forced) vs. a real I2C
general-call in `hal_i2c_control`. Pick this first, then implement Phase 2.

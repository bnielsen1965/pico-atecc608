# Resume notes (pico-atecc608)

Pause point: **2026-10-22, after the example/ reorg — about to implement
the 4B `prov` console command set.** This file is a continuity snapshot —
update it at each pause. The forward plan lives in `PLAN.md`; this file
captures the exact working state and the concrete next steps.

## ⏸ Where the conversation stopped (read this first on resume)
HEAD is `4f6b211` (working tree clean). The 4B application-scenario
discussion is **DONE (2026-10-22)**; the full config is agreed (below) and
the exact byte plan exists (see "I/O key generation" +
`example/tools/dump_devconfig.c`, summary CRC **4FE8**). On resume, do NOT
re-litigate scenarios and do NOT jump to chip writes. The **scenario
guidance is user-reviewed** (2026-10-22, "all looking pretty good") and
lives in `example/README.md`. **Repo reorg (2026-10-22, committed as
`4f6b211`):** the provisioning PoC + demo apps are the *examples*, not the
library — `app/` → `example/console/`, `tools/` → `example/tools/`,
new `example/CMakeLists.txt` (+ `ATECC608_BUILD_EXAMPLES`, default ON)
and `example/README.md`. Examples are **discrete applications** (one
directory per app: password-store, fido2, …); every example's startup
contract = "is the chip provisioned? if not, provision via the module API,
then run" (shared base in `example/common/`, to be factored out of the
console in 4B). Pico build + host ctest green after the reorg; the uf2 is
now at `build/example/console/pico-atecc608.uf2`.

**Immediate next work (no chip writes involved):** implement the `prov`
console command set in `example/console/main.c` + wire pico-littlefs into
`example/console/CMakeLists.txt` for `/io_key.bin` (see the concrete task
list under "Next steps"). THEN the WRITE CHECKPOINT: present the exact
byte plan (which bytes, values, reversibility) for the approval the HARD
RULE requires. The config write is reversible while the zone is unlocked;
the lock is not — approval covers both.

## Agreed 4B config (scenario discussion, 2026-10-22)
Principle: **lock the layout, keep the contents open.** The config zone is
locked during provisioning; key material stays (re)writable per the frozen
rules until a slot is individually locked (slot-lock freezes contents, not
use — KDF/sign from a locked slot still works). All slots: `write_config=0`,
`req_auth=0`; priv slots `gen_key=1`; `lockable=1` on 0, 7, 8, 9, 10, 11,
14; `use_lock_en=false` (no auth flow yet).

Slots (16): 0 = EC pub, firmware validation (primary); 1 = EC priv + 2 = EC
pub, device identity; 3–6 = EC priv ×4, FIDO2 credentials; 7 = non-ECC
unreadable secret, password-store master (shared by all stores); 8–10 =
non-ECC unreadable secrets, spare compartments (claim = GenKey → use →
individual slot lock, repeatable per slot); 11 = EC pub, second firmware
key; 12 = EC priv + 13 = EC pub, spare pair (ECDH / 2nd identity);
14 = non-ECC unreadable secret, I/O protection key (same class as 7–10),
**lockable** (user decision 2026-10-22 — see "I/O key generation" below);
15 = data, spare.

Counters: 0 = FIDO2 signature count (CTAP global); 1 = firmware
anti-rollback (must be chip-side — a flash counter is reset by the same
attacker it defends against). PIN brute-force counter is **Pico-side
(littlefs, see "Persistence layer")**:
the chip has no native lockout, so enforcement lives in the Pico unlock flow
(5 failures → locked until deliberate reset).

Password store: master = on-chip random in slot 7 (`is_secret`, no reads at
all). Use = KDF (v3.8.0 KDF, PRF mode, source = slot 7, input = 16B vault
salt ‖ PIN ‖ context, target = output buffer) → 32B derived key → Pico does
AES-256-GCM (RP2350 hw AES). PIN: **8–16 hex digits** (32–64 bits).
Per-entry keys = same master + per-entry salt in KDF input (different
PIN/salt = different derived key, so one master serves unlimited stores;
slots 8–10 remain for full master-level compartmentalization if ever
wanted). Salt: 16B from chip RNG at vault creation, stored in the vault
header on Pico flash (not secret). Wrong PIN → wrong derived key → GCM tag
fails.

I/O protection: **ON from the start** (user-approved 2026-10-22) —
`io_prot_en=1`, key in slot 14 (Pico keeps a copy in littlefs), `kdf_prot=1`
(derived keys never in clear on the bus), `ecdh_prot=1`, and
**`kdf_aes_en=1`** (required for KDF; the library's ATECC608 KDF test
checks it). Command-level wire protection, not transport-level. Open for
the byte plan: whether the request direction (KDF input / PIN) is also
covered; and `kdf_prot`/`ecdh_prot` enforce(1) vs opt-in(0) — the
reference config uses 0 and the test opts in per-command via
`KDF_MODE_TARGET_OUTPUT_ENC`; enforce is our choice, verify 2-bit semantics
against the NDA datasheet. Mock does NOT model I/O protection → 4B hardware
verification item. Evidence (2026-10-22, user review of slot-14 type):
the library's locked ATECC608 reference config (manual's
`ATECC608_DEVICE_CONFIG_VECTOR`, ChipOptions 0x4006 = io_prot_en +
kdf_aes_en + io key slot 4) keeps its I/O key in a **type-7 non-ECC
secret slot** (KeyConfig 0x007C, SlotConfig 0x0F8F: is_secret + enc_read),
and the library's ATECC608-only KDF test exercises I/O-protected KDF
against it (`atcab_kdf` TARGET_OUTPUT_ENC → `atcah_io_decrypt` with
`g_slot4_key`). So: no AES slot *type* exists to require on the 608
(key_type is only 4=ECC / 7=non-ECC, rest RFU — Phase-4A datasheet
finding); what matters is `is_secret=1` on the io-key slot, which is why
slot 14 is now an unreadable secret slot. Reference:
cryptoauthlib `app/secure_boot`
(`bind_host_and_secure_element_with_io_protection`).

**I/O key generation — chip RNG is unavailable before the lock
(2026-10-22).** The v3.8.0 manual's `atcab_random()` docs: "if the
configuration zone isn't locked yet (LockConfig) then it will return a
0xFFFF0000 repeating pattern instead." So the chip TRNG yields a
deterministic factory pattern on our unlocked chip (the library's basic
random test only asserts status, so it never exposed this). The I/O key
therefore comes from **Pico-side entropy (RP2350 hw TRNG)**: 32B random →
Write slot 14 **while it is still a plain factory slot** → **read-back
verify** (the last chance to verify it — `is_secret` after the config
write) → **print the hex on the serial console** (durable record in case
flash is wiped by a full reflash) → save to littlefs → config write →
lock. Alternative (chip RNG *after* the config lock, slot 14 stays
writable) is possible but leaves an unverified key and a zero-io-key
window; not preferred.

**Losing the I/O key is NOT bricking — in development.** It is a
transport key (bus encryption of KDF/ECDH output), not an input to vault
derivation — re-keying slot 14 leaves the derived key and all vault data
untouched. Slot 14 is **lockable but left unlocked in the dev config**,
so its contents are re-writable at any time, config-locked or not: lost
copy → new random → Write slot 14 → re-record. **Production hardening
(user decision 2026-10-22):** slot-14 gets slot-locked as the final step,
*after* proving the recorded copy decrypts a live KDF — that closes the
bus-attacker re-key hole (a writer on the bus could otherwise rewrite the
io key to one they know). Once slot-locked, a lost copy IS fatal for the
I/O-protected flows (is_secret = unreadable + locked = unfreezeable),
which is the accepted production trade; the console print is the durable
backup. The only unrecoverable secret either way is the slot-7 master,
which by design never leaves the chip — no copy to lose; chip death =
vault death.

FIDO2: resident/discoverable — private keys always on-chip; the credential
DB (credID, user handle, RP ID hash, slot index) lives in Pico flash, so
chip config is unaffected. **4 slots = 4 discoverable credentials total**
(all RPs combined) — the cost of halving the budget; state in README. Pico
reflash loses the DB only; slots survive and can be re-bound
(`gen_key=1`).

**Persistence layer: pico-littlefs (user decision 2026-10-22).** SDK 2.x
ships neither `pico_nvs` nor `pico_littlefs`, so all Pico-side state goes
into our own `pico-littlefs` library (~/Projects/pico-littlefs,
github.com/bnielsen1965/pico-littlefs) — drop-in CMake static lib,
LittleFS v2.9.3, `pico_lfs_init/mount/write_file/read_file/remove/stat/
list/space`, LFS_NO_MALLOC, default layout = FS at flash offset 0x80000,
384 × 4 KB blocks (1.5 MB), which clears a small app on the RP2350's
4 MB flash (no override needed). Files: `/io_key.bin` (32B key +
magic/len/CRC header), `/vault.db` (salt, header, entries), `/fido2.db`
(credID / user handle / RP ID hash / slot index), lockout-counter state.
Power-loss safety (littlefs crash consistency) matters for the vault
specifically. Flash-dump exposure of the io key is accepted: without the
PIN (never stored) it unlocks nothing.

**4B runs as serial-console commands** (existing pico-command-line
console; `bootrom` → BOOTSEL command already in the app). Every step
idempotent and safe to re-run; only `prov lock` is irreversible and
gates on a typed confirm (the module API already takes a confirm
callback):

| command        | does                                                        | reversible |
|----------------|-------------------------------------------------------------|------------|
| `prov status`  | chip state + factory-zone dump + diff vs planned image      | read-only  |
| `prov randtest`| `atcab_random` ×2, print — expect 0xFFFF0000 pattern        | read-only  |
| `prov iokey`   | Pico TRNG → Write slot 14 → read-back verify → print 64 hex → save `/io_key.bin` | yes (re-run re-keys) |
| `prov config`  | build intent → write zone (byte 16 preserved) → read-back verify | yes |
| `prov lock`    | re-verify zone vs intent → typed confirm → Lock w/ summary CRC | **no** |

4B hardware verification items (mock fidelity gaps): factory-zone diff
before any write (first step); Random command on the unlocked chip
returns the documented 0xFFFF0000 pattern (confirms the Pico-entropy
path above); GenKey fill size on non-ECC slots (16 vs 32 bytes — if 16,
accept a 128-bit master or fill via Pico-entropy+Write); KDF from an
`is_secret` slot; I/O protection end-to-end incl.
request direction; `kdf_aes_en`/`kdf_prot` settings; UpdateExtra same-value
behavior; byte-16 write behavior; factory KeyConfig words (mock assumes all
0); UseLock enforcement; GenKey/PrivWrite bit 13/14 behavior.

## Where we are
- **Phase 1 DONE** — module skeleton + build wiring.
- **Phase 2 DONE** — RP2350 I2C HAL on cryptoauthlib v3.8.0.
- **Phase 3 DONE** — curated `atecc608_*` core API. Build green,
  hardware-validated (3 rounds, see below). Console now uses the module API.
- **Phase 4A DONE** — config builder + guarded provisioning API + host unit
  tests with a mock chip HAL. `ctest` 2/2 green; Pico build warning-clean.
  **Chip untouched.** See "Phase 4A — what was built (and why)" below.
- **Phase 4B next (STOP BOUNDARY)** — the actual chip provisioning.
  Scenario discussion done 2026-10-22; the agreed config is in "Agreed 4B
  config" above (locked layout / open contents, usable across all apps,
  I/O protection on). Exact byte plan exists: `example/tools/dump_devconfig.c`
  (builder output: 128 B image + summary CRC; slot 14 lockable per the
  2026-10-22 decision). Before ANY write: README scenario guidance → the
  byte plan (what, where, reversibility) for explicit approval. HARD RULE
  below applies.

## Build (verified green)
```sh
cd build
cmake .. -DPICO_SDK_PATH="$HOME/Projects/pico-sdk"   # fetches cryptoauthlib once
make -j
# outputs: build/example/console/pico-atecc608.uf2
#          (+ libatecc608.a, libcryptoauth_core.a)
# examples are ON by default; -DATECC608_BUILD_EXAMPLES=OFF skips them
```
Air-gapped: `-DCRYPTOAUTHLIB_SOURCE_DIR=/path/to/cryptoauthlib`.
**No cryptoauthlib source is in the repo** — fetched into `build/` at
configure time, discarded otherwise. Known cosmetic warning: `ATCA_TA_SUPPORT
redefined` (from cryptoauthlib's own headers, harmless; our sources are
warning-clean).

## Host unit tests (Phase 4A)
```sh
cmake -S tests -B tests/build -DCRYPTOAUTHLIB_SOURCE_DIR=/home/burnin/Projects/cryptoauthlib
cmake --build tests/build -j
ctest --test-dir tests/build --output-on-failure   # 2/2: test_config, test_prov
# or run directly: ./tests/build/test_config  ./tests/build/test_prov
```
`tests/` is a standalone host CMake project: FetchContent of the same
v3.8.0, `ca_host` = cryptoauthlib's portable sources (minus
`hal/hal_rp2350.c` — the mock defines those 8 HAL symbols), `mock_chip`,
`atecc608_host` (the three Phase-4A module sources). Executables link
`-Wl,--start-group atecc608_host mock_chip ca_host -Wl,--end-group` (plain
order fails: `test_config` references no mock symbols, so the linker never
pulls in the mock objects and leaves the HAL symbols unresolved);
`add_test` uses `$<TARGET_FILE:...>`.

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
- `include/atecc608/atecc608_config.h` + `src/atecc608_config.c` (4A) —
  intent struct `atecc608_config_intent_t` (slot/key cfg, counters,
  count_match, chip mode, secure boot, KDF level, extras, lock/slot-lock,
  chip options, x509) + `atecc608_config_build()` → 128 B,
  `atecc608_config_parse()`, `atecc608_config_crc16()` (== `atCRC`),
  `atecc608_config_writable_equal()` (diff bitmap, 32-byte words; skips
  factory [0:16) + lock bytes [86:88)). Builder validation: key_type ∈
  {4,7}; private ⇒ ECC + is_secret + normal fields clear; enc_read/
  write_config ⇒ is_secret; req_auth ↔ auth_key 1..15; x509_id ≤ 3 only on
  a public ECC key slot; counter ≤ 0x1FFFFF; sb_mode ∈ {0,2,3} (+
  pubkey/digest slots 1..15 when enabled); count_match/use_lock/io_prot
  keys 1..15; ecdh/kdf_prot ≤ 1; clk_div ≤ 31; user_extra_add even or 0.
- `include/atecc608/atecc608_prov.h` + `src/atecc608_prov.c` (4A) — guarded
  provisioning over `atcab_*` (see the header for guarantees + limitations:
  byte-16 preservation, UpdateExtra one-shot, UseLock not modeled, data-zone
  slot 0/3 API restriction).
- `src/atecc608_status.c` + `src/atecc608_int.h` (4A) — the shared
  `atecc608_map_status` (moved out of `src/atecc608.c` for the host build).
- `tests/` (4A) — `CMakeLists.txt` (generates its own `atca_config.h` from
  cryptoauthlib's `atca_config.h.in`, same feature set as the top level),
  `mock_chip.{h,c}`, `test_golden.h` (the golden G intent),
  `test_config.c`, `test_prov.c`.
- `example/console/main.c` + CMakeLists — validation console
  (pico-command-line) over the **module API**: probe/info/serial/lock/
  random (atecc608_*), diag (raw I2C), bootrom, help; Phase 4B adds the
  `prov` command set. Phase 6 adds a config read-back demo.
- `example/` — proof-of-concept examples (NOT part of the library):
  `console/`, `tools/dump_devconfig.c` (the byte-plan host tool),
  `common/` (shared provision-on-first-boot base, to be factored out in
  4B); contract + scenarios + slot layout in `example/README.md`.
- `example/pico-command-line/` — submodule (console framework, used by
  examples only; wired in via `example/CMakeLists.txt`).
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

## Phase 4A — what was built (and why)
- **Type rename (build-forced):** cryptoauthlib's `calib_device.h` defines
  its own `atecc608_config_t`; our intent type is
  `atecc608_config_intent_t` everywhere (7 files).
- **Counter encoding (final, unit-tested):** for value v, the 8 zone bytes
  are BE16(lin_a) BE16(lin_b) BE16(bin_a) BE16(bin_b) with
  `lin_a = 0xFFFF>>(v%32)`, `lin_b = v>=16 ? 0xFFFF>>((v-16)%32) : 0xFFFF`,
  `bin_a = v/32`, `bin_b = v>=16 ? (v-16)/32 : 0`. **Big-endian in the zone**
  (library `calib_write_config_counter` byte order); the COUNTER *command*
  returns the 4-byte LE binary value. Vectors: 0 → `FF FF FF FF 00 00 00 00`;
  5 → `07 FF FF FF 00 00 00 00`; 32 → `FF FF 00 00 00 01 00 00`;
  0x1FFFFF → `00 00 00 01 FF FF FF FF`.
- **CRC:** `atecc608_config_crc16` is byte-identical to `atCRC`
  (poly 0x8005, init 0, LSB→MSB per byte, LE16 out;
  `calib/calib_command.c:706`). A real bug the harness caught: the inner
  loop used `int bit` → 9 iterations/byte (0x80<<1 = 0x100 ≠ 0); fixed to
  `uint8_t bit`.
- **GenKey/PrivWrite bits = 13/14 (documented deviation).** The datasheet
  (ATECC508A/608A Tables 2-10/2-11) puts GenKey at bit 13 and PrivWrite at
  bit 14 of an ECC private-key slot word; cryptoauthlib's
  `ATCA_SLOT_CONFIG_GEN_KEY_SHIFT`/`PRIV_WRITE_SHIFT` (8/9) contradict the
  datasheet AND the library's own ATECC608 test vector (slot words
  0x208F/0x2087/0x2082 have bit 13 set = GenKey). Datasheet wins; builder,
  parser, mock, and docs all follow 13/14.
- **Vector decode (authoritative):** `ATECC608_DEVICE_CONFIG_VECTOR` from
  the cryptoauthlib manual (`/tmp/opencode/cab_manual.txt`, ~line 21030) —
  a fully provisioned, LOCKED device: LockValue/LockConfig = 0x00/0x00,
  SlotLocked = 0xFFFF, ChipOptions = 0x4006 (io_prot_en, kdf_aes_en,
  io_prot_key 4), UserExtra/Add = 0, counters 0, keys
  `[0033,001C,0013,0013,007C,001C,003C,0033,003C,003C,003C,0030,003C,003C,003C,0030]`
  (key2 = 0x0013 HAS pub_info; key15 = 0x0030 — not 0x105C, that's the
  golden G). `t_vector_decode` asserts the parse against it.
- **Confirm semantics (verified vs. the prov code):** every lock attempt
  that passes the state checks consumes exactly one confirm() call —
  including refused attempts; already-locked checks happen BEFORE confirm.
- **Mock chip contract** (`tests/mock_chip.{h,c}`): emulates the wire
  protocol (frame = [count][opcode][p1][p2lo][p2hi][payload][crc_lo][crc_hi];
  count includes count+CRC; command frames count=7; READ/WRITE param1 =
  zone|0x80, param2 = word address = byte/4; receive = two partial reads;
  WAKE token handshake {04 11 33 43}, absent chip → COMM_FAIL on all
  paths). Factory state: serial [0:4]=01 23 06 40, [4:8]=00 00 60 05,
  [8:13]=AE B6 B9 B7 EE, [13]=01, [14]=01, [16]=0xC0, counters 0, **KeyConfig
  words 96..127 = 0 (documented assumption — verify on the real chip in
  4B)**. `atcab_write_config_zone` = 13 WRITEs (words 84–87 skipped) +
  2 UPDATE_EXTRA(84,85); UPDATE_EXTRA is one-shot (target≠0 → 0x0F even for
  the same value). LOCK 0x17: 0=config (verifies atCRC over the full zone ==
  param2, →[87]=0), 1=data (needs config locked, →[86]=0),
  2|(slot<<2)=slot (needs KeyConfig bit5 Lockable); already-locked → 0x0F.
  COUNTER 0x24: read+increment → 4-byte LE value; ≥0x1FFFFF increment → 0x0F;
  no lock precondition. GENKEY 0x40 (mode 0x04 only): needs KeyConfig bit0,
  SlotConfig bit13 (GenKey), and data zone unlocked; fake pubkey
  `pub[i] = (slot*7 + i*3 + 1) & 0xFF`. Data zone: WRITE rejected if data
  locked, slot secret, or (unlocked && word write-protected); READ requires
  data locked AND not secret AND not private (fire-and-forget writes until
  lock).
- **Golden G** (`tests/test_golden.h`, byte-exact in `t_golden`): intent
  [18]=0x51, [19]=0x12; slot0 = 0x6085 (ext_sig|ecdh|is_secret|gen_key
  13|priv_write 14), slot2 = 0x208B, slot3 = 0x00D3, slot15 = 0x2280
  (is_secret); counters c0=5, c1=0; [68]=0x81, [69]=0x8C, [70:72]=13 F7,
  [72]=02, [73:75]=03 00; [84]=A5, [85]=C4, [86:88]=55 55; SlotLocked=0x0005;
  ChipOptions=0x4107; x509=11 22 33 44; keys: key0=0x0033, key1=0xC692
  (pub_info|ECC|req_auth|auth_key 6|x509 3 — x509 is a 2-bit field at
  14:15), key2=0x0053, keys3–14=0x001C, key15=0x105C
  (NON_ECC|req_random|persist_dis).
- **UseLock finding:** the mock does NOT model UseLock enforcement; 4B
  scenarios must keep `use_lock_en=false` until an auth flow exists
  (documented in `atecc608_prov.h` + PLAN.md).

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
- **C printf argument evaluation order is unspecified** (cost real time in
  4A debugging): never mix a function call with reading side-effect state in
  the same `printf` (produced false `wakes=0` / `locked=86` readings).
- **Wake counts: never assert an exact number** — the library issues
  multiple WAKE handshakes per calib command (wrapper + inner); tests assert
  `wakes >= 1`.
- **`atcab_is_locked` on CA2** → `calib_is_locked_ext` →
  `calib_ca2_is_config_locked` → **Info LockStatus command**, not a Read of
  byte 87 (calib_helpers.c). The mock handles it.
- **Data zone access:** `atcab_read_data_zone`/`atcab_write_data_zone` do
  NOT exist; the `*_bytes_zone` family maps to ECC204-validated
  `calib_ca2_read_bytes_zone` (slot 0..3 check) — do NOT use. Use
  `atcab_read_zone(zone, slot, block, offset, data, len)` /
  `atcab_write_zone(...)`: data zone slot 1..15 with **0 and 3 rejected by
  the library**, len must be 32 (config: 16). Secret-slot read test uses
  slot 15 (is_secret in golden G), not slot 3.
- **Host test link order:** plain library order fails (`test_config`
  references no mock symbols → mock objects never load → hal_* unresolved
  in ca_host); use `--start-group`/`--end-group`, and `add_test` must use
  `$<TARGET_FILE:...>`.
- **x509_id is a 2-bit field** (values 0..3):
  `ATCA_KEY_CONFIG_X509_ID_SHIFT 14`, `MASK 0x03<<14` (calib_device.h:273).
- **Debugging pitfall when comparing zones:** dump the zone AND print the
  first differing byte index — two dumps can look identical at a glance
  (the golden had a 2-byte-shifted UseLock/VKP/SB/KDF region).

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
- `/tmp/opencode/cab_manual.txt` — extracted cryptoauthlib manual (747 pp);
  the ATECC608 config vectors + field dicts are around lines 20960–21060
  (`ATECC608_DEVICE_CONFIG` / `..._VECTOR`)
- `/tmp/opencode/atecc608a_ds.txt` — full ATECC608A datasheet text
  (DS40002138A): config zone table ~790–1092, TFLXTLS slot policy tables
  ~1600–1900
- `/tmp/opencode/atecc508a_ds.txt` — full ATECC508A datasheet text
  (DS20005927A): **Tables 2-10/2-11 (~line 1810) = the authoritative
  GenKey bit 13 / PrivWrite bit 14 definitions**
- `../cryptoauthlib/lib/calib/calib_command.c:706` — `atCRC` (ground truth
  for `atecc608_config_crc16`)
- `../cryptoauthlib/lib/calib/calib_helpers.c` — `calib_ca2_is_config_locked`
  (Info LockStatus path behind `atcab_is_locked`)
- `../cryptoauthlib/lib/calib/calib_read.c` / `calib_write.c` —
  `calib_ca2_read/write_zone` (slot 0/3 rejection, len 32)
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
  random). Write APIs are implemented (Phase-3 raw wrappers + the Phase-4A
  guarded provisioning API in `atecc608_prov.h`) but have **never been
  exercised** on the chip — the 4A tests run against the mock HAL only.
- When a step genuinely requires writing to the chip (Phase 4 provisioning
  first), **STOP and review with the user first**: what is written, to which
  bytes, and whether it is reversible.

## Next steps (Phase 4B — chip provisioning; STOP BOUNDARY)
**Status (2026-10-22): scenario discussion complete — config agreed (see
"Agreed 4B config" above). `use_lock_en=false` until an auth flow exists.**
1. ~~Scenario walkthrough~~ — **done 2026-10-22.**
2. ~~Draft README scenario guidance~~ — **done + user-reviewed 2026-10-22.**
   After the example/ reorg (`4f6b211`) the scenario guidance ("Application
   scenarios — provisioning guidance", slot table, locking discipline)
   lives in `example/README.md`; the top-level README is module-centric and
   points there.
3. **Implement the `prov` console command set (NEXT TASK — no chip writes
   involved, build-only work).** The command table is above ("4B runs as
   serial-console commands"); the concrete implementation plan:
   - **Wire pico-littlefs** into `example/console/CMakeLists.txt`:
     `add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../pico-littlefs
     <binary dir>)` (console is at `<repo>/example/console`;
     pico-littlefs is a *sibling of the repo* at
     `~/Projects/pico-littlefs` — three levels up), link **`pico-littlefs`**
     (hyphen — the CMake target; the header is `pico_littlefs.h` with
     underscores) into the console target. Optional `PICO_LFS_USE_FREERTOS`
     stays OFF (bare-metal). LFS_NO_MALLOC (static
     buffers); default layout (FS @ flash 0x80000, 384×4 KB) needs no
     override on this 4 MB app. Init/mount at startup (before the console
     loop); print a warning if the FS is fresh (first boot / after reflash
     = `/io_key.bin` gone — re-run `prov iokey` and re-record).
   - **`prov status`** (read-only): chip state via the module API (info,
     serial, lock status, config-zone lock byte), dump the current 128-byte
     config zone (Read with the config zone start; first 16 factory bytes
     included), print a byte-by-byte diff vs the planned image (embed the
     agreed G intent — same builder call as
     `example/tools/dump_devconfig.c`, via `atecc608_config_build` with the
     agreed field values; byte 16 compared as "chip keeps own").
   - **`prov randtest`** (read-only): `atecc608_random` ×2 (32 B each),
     print hex; annotate whether the 0xFFFF0000 factory pattern is present
     (expected while the zone is unlocked — manual-cited).
   - **`prov iokey`** (WRITE — gated by the user checkpoint): Pico TRNG —
     **confirmed API (SDK 2.x, 2026-10-22): `get_rand_32()` from
     `pico/rand.h`** (8 calls → 32 B). SDK 2.x has NO `hardware_rng` /
     `get_32bit_random()` module (that was SDK 1.x); on RP2350 `pico_rand`
     uses the hardware TRNG as entropy source by default
     (`PICO_RAND_ENTROPY_SRC_TRNG`, gated on `HAS_RP2350_TRNG`). →
     WriteCommand to
     slot 14 **while it is still a plain factory slot** (pre-config) →
     read-back verify (only chance — post-config slot 14 is is_secret and
     unreadable) → print the 64 hex chars on the console (durable record) →
     save `/io_key.bin` (littlefs; 32 B key + magic/len/CRC header per the
     Persistence-layer section). Re-running re-keys (dev flow).
   - **`prov config`** (WRITE — gated): build the G intent → call
     `atecc608_provision_config()` (already: unlocked check → read zone →
     preserve byte 16 → write → read-back verify). Prints the verify
     result + summary CRC.
   - **`prov lock`** (WRITE, IRREVERSIBLE — gated + typed confirm):
     re-verify zone vs intent (full byte compare, byte 16 excluded) →
     typed confirm via the existing confirm-callback API (reuse the
     pattern the Phase-4A prov API already takes; on the console that is a
     type-to-confirm prompt) → `atecc608_lock_config_zone()` (Lock command
     with the summary CRC computed from the chip's ACTUAL zone at lock
     time — NOT the builder CRC 4FE8, which differs in the factory bytes
     0–15).
   - Reuse the `bootrom` command's registration pattern in
     `example/console/main.c` for all five.
   - **Then:** Pico build green, host ctest still 2/2, flash the uf2
     (`/tmp/opencode/flash_phase3.py` sequence or manual BOOTSEL drag of
     `build/example/console/pico-atecc608.uf2`).
4. **Bench, read-only first:** `prov status` (factory-zone dump + diff vs
   planned image) and `prov randtest` (expect the 0xFFFF0000 pattern —
   confirms the manual note on this silicon).
5. **WRITE CHECKPOINT (hard rule):** present the exact byte plan — which
   bytes, their values, why, and reversibility (config write is reversible
   while unlocked; locks and counter increments are not) — and get explicit
   user approval BEFORE any chip write. On-hardware write→read-back
   verification and the lock sequence only after approval:
   `prov iokey` → (record the 64-hex io key) → `prov config` →
   `prov lock` (typed confirm).
6. **4B verification items** (mock fidelity gaps — check on the real chip):
   UpdateExtra same-value behavior; byte-16 write behavior; factory
   KeyConfig words (mock assumes all 0); UseLock enforcement; GenKey/
   PrivWrite bit 13/14 behavior on real hardware; I/O protection coverage
   of the request direction (mock does NOT model I/O protection at all);
   kdf_prot/ecdh_prot 2-bit semantics (enforce vs opt-in) per NDA
   datasheet.

Then per PLAN.md: Phase 5 (crypto pass-through: kdf/sign/verify) and Phase 6
(config read-back console demo), then Phase 7 (on-hardware validation +
bring-up checklist).

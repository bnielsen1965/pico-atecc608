# Resume notes (pico-atecc608)

Pause point: **2026-10-23 — EXECUTING the re-ordered write sequence at
the bench; step 2 (`prov config`) is DONE — the config zone holds the
approved planned image, read-back verified, chip-zone CRC **CDC7**
(the planned-image CRC stays 822F — the gap is the zeroed factory
region 0–15 in the planned image; see the CRC note). Next: `prov
status` (step 3) → `prov lock` dry (step 4) → **`prov lock CONFIRM`
(step 5, ONE-WAY — explicit user go-ahead)** → `prov iokey` (step 6,
record the printed key) → `prov status` (step 7).** The byte plan
(bytes, CRC 822F) is unchanged and stays approved. Original discovery
behind the order: the ATECC608 refuses any data-zone write while the
config zone is unlocked — so `prov iokey` (a data write) can only run
AFTER `prov lock CONFIRM`.
The I/O-protection bricking concern is RESOLVED (see the new findings
section): I/O protection protects the I/O of ECDH/KDF/Verify/SecureBoot,
not the I2C transport — the chip stays reachable with plain commands
after the lock, so the approved config needs no change. Every failed
`prov iokey` (pre-re-order) was refused by the chip with no commit —
the factory-zone backup below is the pre-write record. **The chip is
no longer factory-fresh: `prov config` has written the planned image
to the config zone (step 2); the zone stays re-writable until `prov
lock CONFIRM`.** This file is a continuity snapshot — update it at
each pause. The forward plan lives in `PLAN.md`; this file captures
the exact working state and the concrete next steps.

## ⏸ Where the conversation stopped (read this first on resume)
HEAD is `45cb322` (working tree clean). **The config zone has been
written + verified at the bench (run-sheet step 2, 2026-10-23) but is
NOT locked** — the one-way step is still ahead. On resume: do NOT
re-litigate the byte plan (approved 2026-10-23, unchanged, planned
image CRC 822F); continue the run sheet below: `prov status` (step 3 —
expect chip-zone CRC CDC7, no writable-region diff) → `prov lock`
(step 4 — dry, aborts without CONFIRM, prints the CRC it will use:
CDC7) → **`prov lock CONFIRM` (step 5, ONE-WAY — explicit user
go-ahead)** → `prov iokey` (step 6 — **RECORD the printed 64-hex key**)
→ `prov status` (step 7 — expect `config zone: LOCKED`, lock bytes 00
00, chip-zone CRC 6F47). Scenario guidance is user-reviewed (2026-10-22)
and lives in `example/README.md`.

State at the pause:
- **The write sequence is RE-ORDERED: config → lock → iokey** (was
  iokey → config → lock). Root cause: the ATECC608 refuses any
  data-zone write while the config zone is unlocked (bench: 32-byte
  Write to plain factory slot 14 → ATCA_EXECUTION_ERROR; every
  Microchip data-write conformance test runs config-locked). Full
  details: the "Data-zone writes before the config lock" section below.
- **The I/O-protection bricking risk is RESOLVED (no config change, no
  re-approval of the bytes needed):** `io_prot_en` protects the I/O of
  the ECDH/KDF/Verify/SecureBoot command families (output encryption /
  MAC), not the I2C transport — plain commands keep working after the
  config lock, so writing the I/O key into slot 14 after the lock is
  possible with the current firmware. Evidence: app note 00002589A
  scopes I/O protection to those four command families; Microchip's own
  `app/secure_boot` binds the I/O key to an already-configured
  (config-locked) chip with plain `atcab_*` calls; cryptoauthlib's I2C
  HAL sends no I/O key at all (there is no per-transaction key
  protocol).
- **Code is fixed for the new order** (`48d14cc`):
  `atecc608_write_iokey` precondition flipped (config zone must now be
  LOCKED — with a "run `prov config` + `prov lock CONFIRM` first"
  message); `mock_chip.c` models the real access matrix (config
  unlocked → data writes refused; data unlocked → 32-byte writes only;
  data locked → 32B + 4B writes to non-individually-locked slots;
  individually locked slots refuse writes); `t_iokey` restructured,
  `t_lock_data_zone` / `t_lock_data_slot` updated; console messages +
  help updated. Pico build green, host ctest 2/2.
- ~~The console uf2 on the bench predates `48d14cc` — reflash
  `build/example/console/pico-atecc608.uf2` first~~ **DONE at the bench
  2026-10-23** (manual BOOTSEL drag; drive label **RP2350** on the
  Pico 2; the littlefs wipe was harmless — nothing was stored on it,
  the I/O key had not been generated).
- Read-only bench steps done: probe / info / serial / lock +
  `prov status`. The factory-zone dump below is the recorded output;
  **verified** — its CRC-16 = 4AB4 = the device's own print, and the
  device's 38-byte diff list matches a recomputation from the dump + the
  builder image exactly. It is the pre-write backup (the config zone
  has since been re-written by `prov config` — step 2; the zone stays
  re-writable until Lock).
- **`prov config` done at the bench (2026-10-23, run-sheet step 2):**
  output = planned image CRC 822F → one write pass → "verified: chip
  zone matches the planned image" → chip-zone CRC **CDC7**. The CDC7
  vs 822F gap is EXPECTED and host-reproduced the same day (4AB4 /
  4FE8 / 822F / CDC7 all match the bench prints): the planned image
  zeroes the factory region 0–15 (the builder does not model it) while
  the chip keeps its real factory bytes there; the read-back verify
  (`writable_equal`) skips 0–15 and 86–87, both CRCs cover all 128
  bytes. `prov lock` will lock with **CDC7** — the chip re-verifies
  the CRC against its own zone, so a wrong value is rejected by the
  chip itself.
- **`prov randtest`: CONFIRMED by the user (2026-10-23)** — it printed
  the 0xFFFF0000 factory pattern, as expected for an unlocked zone (4B
  verification item: resolved).
- **The SlotLocked (88–89) issue is found + fixed** (`d6cf44d`, details
  below).
- **The `prov iokey` read-back-guard bug is fixed** (`009df06`, details
  in the "Data-zone reads while unlocked" section): the write is
  confirmed by the chip's write ACK only; the key is verified
  functionally by an I/O-protected transaction (Phase 7).
- **The byte plan was presented and APPROVED by the user (2026-10-23,
  full sequence: iokey + config + lock).** The approval covers the
  BYTES (the 36-byte config image, CRC 822F, + the slot-14 key write);
  the ORDER is now revised (config → lock → iokey) and must be
  re-presented before the one-way lock step.

**Write sequence — RE-ORDERED 2026-10-23 (bytes unchanged; the byte
plan stays approved — the NEW ORDER needs the user's go-ahead before
the one-way step, step 5). Progress (check off as the bench proceeds;
every step is idempotent except the lock):**
- [x] 0. BOOTSEL-reflash `build/example/console/pico-atecc608.uf2`
  (the flashed image predates `48d14cc` — required before step 1;
  littlefs wipe is harmless, nothing is stored on it yet).
  DONE at the bench 2026-10-23.
- [x] 1. `prov status` (read-only) — pin down the chip state before any
  write: factory (36-byte diff vs the planned image, chip-zone CRC
  4AB4) → start at step 2. "writable region: matches the planned
  image" + chip-zone CRC CDC7 → a `prov config` already landed → skip
  to step 4. Anything else → STOP and report.
  DONE 2026-10-23: factory state confirmed (dump = pre-write backup,
  36-byte diff, CRC 4AB4).
- [x] 2. `prov config` — expect: "planned image (chip's byte 16 = 0xC0,
  bytes 88..89 = FF FF): summary CRC 822F", one write pass, "verified:
  chip zone matches the planned image", chip-zone CRC **CDC7** — NOT
  822F (the planned image zeroes the factory region 0–15; the chip
  keeps its real factory bytes there; the read-back verify skips 0–15
  and 86–87 while the CRC covers all 128 bytes — host-verified
  2026-10-23: CDC7 = CRC(factory 0–15 + planned 16–127)).
  DONE 2026-10-23: actual output matches this exactly (822F / verify OK
  / chip-zone CRC CDC7).
- [ ] 3. `prov status` — expect: "writable region: matches the planned
  image", "summary CRC: chip zone CDC7  planned image 822F".
- [ ] 4. `prov lock` — verifies the zone, then aborts (no confirm typed).
  It prints the CRC it will use: CDC7.
- [ ] 5. `prov lock CONFIRM` — **ONE-WAY**: Lock with summary CRC
  **CDC7** (the chip's actual zone CRC — the chip re-verifies it
  against its own zone, so a wrong value is rejected by the chip
  itself) → OK. The config zone can never change again (the data zone stays
  UNLOCKED — contents open per the agreed layout). After this step the
  data zone becomes writable.
- [ ] 6. `prov iokey` — expect: "I/O protection key written to slot 14
  (write ACKed by the chip)" + the NOTE (no read-back possible) + **the
  printed 64-hex I/O key — RECORD IT** (the durable backup; `/io_key.bin`
  on littlefs is lost on reflash) + "saved to littlefs: /io_key.bin
  (read-back verified)". If it failed, re-run — the data zone is still
  unlocked and slot 14 still clear-writable (no lock was consumed).
- [ ] 7. `prov status` — expect: `config zone: LOCKED`, lock bytes 00
  00. The chip-zone CRC will differ from BOTH earlier values: Lock
  flips the lock bytes 55 55 → 00 00 (excluded from the compare, inside
  the CRC). Expected chip-zone CRC after the lock: **6F47**
  (host-computed). Expected, not a failure.

### The SlotLocked (88–89) issue — found + fixed (`d6cf44d`)
- The factory zone holds **FF FF** at 88–89 (SlotLocked); the builder
  emits 00 00. The library's write path (calib_write.c: writes 16..127,
  only 84–87 skipped — 84/85 via UpdateExtra, 86/87 lock-only) DOES send
  88–89, but whether the chip honors the write is undocumented. If it
  ignores the write, both the `prov config` read-back verify and the
  `prov lock` re-verify would fail (image 00 00 vs chip FF FF).
- **Polarity — confirmed from cryptoauthlib's own code, two independent
  sources:** bit n = 0 → slot n LOCKED; bit n = 1 → unlocked; the Lock
  command clears the bit. `calib_helpers.c calib_is_slot_locked()`:
  `is_locked = (slot_locked & (1u << slot)) == 0`. Hardware test
  `test/api_atcab/atca_tests_write.c write_upper_slots()` skips a slot
  when the bit is 0 ("Slot is locked and can't be written to"). Factory
  FF FF = nothing locked, consistent.
- **Fix:** the prov path preserves the chip's 88–89 in the planned image
  (exactly like byte 16). Touched: `src/atecc608_prov.c` (both
  `provision_config` and `lock_config_zone`), `example/console/main.c`
  (`planned_image()` now takes the chip zone; `prov status` prints the
  preserved bytes; `prov config` reads the zone before building the
  image), `tests/mock_chip.c` (factory 88–89 = FF FF; Lock handler
  polarity flipped: lock CLEARS the bit), `tests/test_prov.c`
  (`t_lock_data_slot` expectations), `include/atecc608/atecc608_prov.h`
  (contract note), `example/tools/dump_devconfig.c` (note), README /
  example README / PLAN.md. Robust in both worlds: if the chip honors
  the write, we write back exactly what it holds (no-op); if it ignores
  the write, the verify still sees the same bytes.
- **CRCs:** host tool (zeroed variant) = **4FE8** (unchanged); on-device
  planned image (chip's byte 16 = C0 + 88–89 = FF FF) = **822F** — what
  `prov status` / `prov config` print as the *planned image's* CRC. The
  chip's **actual zone** CRC after `prov config` is **CDC7, not 822F**:
  the planned image zeroes the factory region 0–15 (the builder does
  not model it) while the chip keeps its real factory bytes there, and
  the read-back verify (`writable_equal`) skips 0–15 and 86–87, so
  "verified: matches" and the two CRCs differ simultaneously — both
  true. `prov lock` locks with the chip's actual zone CRC (**CDC7**).
  All four values (4AB4 / 4FE8 / 822F / CDC7) host-reproduced
  2026-10-23 against the bench output. (AA8F was the pre-fix on-device
  value — obsolete.)

### Data-zone reads while unlocked — impossible (found at the bench 2026-10-23, fixed `009df06`)
- **Symptom:** first `prov iokey` attempt printed "slot 14 is not
  clear-readable (not a plain factory slot), so the write could not be
  verified — no write issued." The old guard test-read slot 14 to prove
  it was a plain slot before writing. **No write was issued — the chip
  is still factory-fresh.**
- **Root cause:** the ATECC608 **refuses data-slot reads while the data
  zone is unlocked.** Confirmed by Microchip's own conformance test
  `cryptoauthlib/test/api_atcab/atca_tests_read.c`:
  `TEST_ASSERT_EQUAL(locked ? ATCA_SUCCESS : ATCA_EXECUTION_ERROR,
  status)` with the comment "data zone cannot be read unless the data
  zone is locked". The mock modeled this correctly (mock_chip.c:204);
  the guard's premise was wrong, and the iokey console path was never
  exercised by the host tests (they cover the prov layer only).
- **Consequence:** the I/O-key read-back verify is impossible at ANY
  point in the flow — pre-config the data zone is unlocked (reads
  refused); post-config slot 14 is is_secret (reads refused); the data
  zone is never locked in our flow. **New verification model:** the
  chip's write ACK (the Write commits atomically, OK response only
  after commit) + a functional I/O-protected transaction after
  `prov lock` (an existing 4B/Phase-7 verification item — a wrong or
  missing key fails every protected command).
- **Fix (`009df06`; the config-zone precondition was later FLIPPED in
  `48d14cc` — see "Data-zone writes before the config lock"):** new
  prov-layer API `atecc608_write_iokey(slot, key)` with the preconditions
  as then understood: config zone unlocked (the then-believed risk:
  post-lock, I/O protection makes the chip unreachable without the key —
  that premise turned out wrong), data zone unlocked, and the slot
  accepts a clear Write in the CURRENT config (not an ECC private key
  slot; write_key = 0; write_config = 0 — parsed from the config zone,
  which is always readable). Then the write; the chip's OK commits it.
  The console `prov iokey` runs the same prechecks for its user-facing
  messages, generates the key (Pico TRNG), calls the API, prints the
  64-hex key, saves `/io_key.bin`.
  Touched: `include/atecc608/atecc608_prov.h`, `src/atecc608_prov.c`,
  `example/console/main.c`, `tests/test_prov.c` (new `t_iokey`:
  unlocked data read refused, write committed, preconditions refused,
  post-config re-key of an is_secret slot, config/data-lock refusal).
  Pico build green, host ctest 2/2.
- **Ordering consequence — SUPERSEDED 2026-10-23:** this section
  assumed iokey could run before the config lock. The bench proved the
  data zone is not WRITABLE at all until the config zone is locked
  (see "Data-zone writes before the config lock" below). `prov iokey`
  now runs AFTER `prov lock CONFIRM`; the precondition in
  `atecc608_write_iokey` was flipped in `48d14cc`.

### Data-zone writes before the config lock — impossible (found at the bench 2026-10-23, fixed `48d14cc`)
- **Symptom:** `prov iokey` on the new firmware passed its guards and
  issued the Write; the chip rejected it: "WRITE SLOT 14 failed: chip
  execution error (ATCA_STATUS -12)" (ATCA_EXECUTION_ERROR). No commit
  — the chip is still factory-fresh.
- **Root cause:** the ATECC608 **refuses any data-zone write while the
  config zone is unlocked** (the read side of the same gate was already
  known from `atca_tests_read.c`). Evidence: (a) the bench — 32-byte
  Write to plain factory slot 14 → ATCA_EXECUTION_ERROR with the config
  zone unlocked, even though the chip's own factory config marks slot
  14 plain-writable (SlotConfig 0x0000); (b) EVERY data-zone write test
  in `cryptoauthlib/test/api_atcab/atca_tests_write.c` calls
  `test_assert_config_is_locked()` first; (c) ATECC608 provisioning
  documentation: "Before we can begin populating (i.e. read from or
  write to) data or OTP zones, we have to lock the config zone."
- **Access matrix (now modeled in `mock_chip.c`):**

  | config zone | data zone | data reads       | 4B writes | 32B writes              |
  |-------------|-----------|------------------|-----------|-------------------------|
  | unlocked    | unlocked  | refused          | refused   | refused (bench)         |
  | locked      | unlocked  | refused          | refused   | allowed (per slot policy) |
  | locked      | locked    | allowed (policy) | allowed   | allowed (per slot policy) |

  Individually locked slots (SlotLocked bit cleared) refuse writes in
  all states (`write_upper_slots` skips them: "Slot is locked and can't
  be written to"). The slot-14 "validation flag" hypothesis was
  eliminated: that comment is ATECC608C-TFLXTLS-variant-specific; our
  generic ATECC608C (part 0x60) slot 14 is plain — the rejection was
  purely the config-zone-lock gate.
- **The mock was wrong in the same way it had been wrong on reads**
  (and is fixed now): it allowed 32-byte data writes with the config
  zone unlocked, so `t_iokey` passed while the real chip refuses.
- **Consequence for the flow:** `prov iokey` (a data write) can ONLY
  run after `prov lock CONFIRM`. The byte plan is unchanged (same 32
  bytes into slot 14; same 36-byte config image, CRC 822F); only the
  order moved, and the one-way step now comes before the key write.
  Safety of that ordering: if the iokey write ever failed after the
  lock, the remedy is retrying the write (the data zone stays unlocked,
  slot 14 stays clear-writable until individually locked) — never
  "unlocking" the config.
- **The bricking question (I/O-protection enforcement) — RESOLVED, no
  config change needed:** the fear was that `io_prot_en=1` + config
  lock would make every I2C command require the I/O key BEFORE the key
  exists in slot 14 — an unreachable chip (the firmware has no
  I/O-key transmission; cryptoauthlib's I2C HAL sends none, and there
  is no `atcab_io_protect` API). That is not how the ATECC608 works:
  I/O protection (io_prot_en + I/O key slot) protects the I/O of the
  **ECDH, KDF, Verify and SecureBoot** command families (output
  encryption / MACing), not the transport. Evidence: app note
  00002589A ("provides a method to protect I/O transmissions between
  this device and the host MCU for the ECDH, KDF, Verify, and Secure
  Boot commands"); Microchip's own `app/secure_boot`
  (`bind_host_and_secure_element_with_io_protection`) runs against an
  already-configured (config-locked) chip and uses plain
  `atcab_random` / `atcab_write_zone` / `atcab_lock_data_slot` — no I/O
  key on the wire; the pairing flow (random key → host flash → write
  slot → slot lock) presumes exactly this. Plain commands (Info, Read,
  Write, Lock, Rand) work after the config lock regardless. **The
  re-ordered sequence config → lock → iokey is safe with the current
  firmware.** (Consistent with the agreed-config note "Command-level
  wire protection, not transport-level.")
- **Fix (`48d14cc`):** `atecc608_write_iokey` precondition flipped —
  the config zone must now be LOCKED (was: must be unlocked); the
  console message tells the user to run `prov config` +
  `prov lock CONFIRM` first. `mock_chip.c`: data writes refused while
  the config zone is unlocked (the gate); 32-byte-only while the data
  zone is unlocked; 4B + 32B allowed with the data zone locked;
  individually locked slots refuse writes (new `mock_slot_locked`
  helper). Tests: `t_iokey` restructured to the new order (prov layer +
  chip both refuse before the lock; OK after; re-key after the lock;
  slot-policy refusal under a LOCKED config; data-lock refusal);
  `t_lock_data_zone` now asserts the 32-byte write SUCCEEDS after the
  data zone lock ("pass for both locked and unlocked case") with a
  read-back verify; `t_lock_data_slot` pins the individually-locked-slot
  write refusal. Console `prov iokey` messages + help updated. Pico
  build green, host ctest 2/2.

### Factory config zone (pre-write backup, CRC 4AB4)
```
0000: 01 23 06 40 00 00 60 05 AE B6 B9 B7 EE 61 65 00
0010: C0 00 00 00 83 20 87 20 8F 20 C4 8F 8F 8F 8F 8F
0020: 9F 8F AF 8F 00 00 00 00 00 00 00 00 00 00 00 00
0030: 00 00 AF 8F FF FF FF FF 00 00 00 00 FF FF FF FF
0040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0050: 00 00 00 00 00 00 55 55 FF FF 00 00 00 00 00 00
0060: 33 00 33 00 33 00 1C 00 1C 00 1C 00 1C 00 1C 00
0070: 3C 00 3C 00 3C 00 3C 00 3C 00 3C 00 3C 00 1C 00
```
Decode: serial 01 23 06 40 AE B6 B9 B7 EE = bytes [0:4]+[8:13); part
0x60 rev 5 (bytes 4–7, matches INFO); AES_Enable 0x61 / I2C_Enable 0x65
(bit 0 set + factory feature bits — factory region, never touched);
**byte 16 = C0** (I2C address, 8-bit on-the-wire form of 0x60); factory
SlotConfig (20–51) = 0x2083, 0x2087, 0x208F, 0x8FC4, 0x8F8F, 0x8F8F,
0x8F9F, 0x8FAF, 0×6, 0x8FAF ("secure by default" key-protected layout);
counters both 0 (FF FF FF FF 00 00 00 00); UserExtra / UserExtraAdd
00/00; lock bytes 86–87 = 55 55 (unlocked); **SlotLocked (88–89) =
FF FF**; ChipOptions 00 00; X509 0×4; factory KeyConfig (96–127) =
0x0033 ×3 (ECC priv+pub+lockable), 0x001C ×5 (plain non-ECC), 0x003C ×7
(non-ECC+lockable), 0x001C.

### Byte plan (write checkpoint, presented 2026-10-23)
**Preserved from the chip (the prov path copies them into the planned
image, so they never change):** bytes 0–15 (factory region,
write-protected anyway), byte 16 = C0 (I2C address — writing anything
else would move the bus address), bytes 88–89 = FF FF (SlotLocked,
Lock-command-managed).

**Written** (library write path: Write commands cover 16..127 minus
84–87; 84/85 via UpdateExtra = 00/00, same-value case): the planned
image below — i.e. everything already equal to the factory is re-written
unchanged; the fields that actually change are:
- SlotConfig (20–51): 0x2083, 0x2087, 0x208F, 0x8FC4, 0x8F8F, 0x8F8F,
  0x8F9F, 0x8FAF, 0×6, 0x8FAF → 0x0000, 0x2085, 0x0000, 0x2081 ×4,
  0x0080 ×4, 0x0000, 0x2085, 0x0000, 0x0080, 0x0000
- KeyConfig (96–127): 0x0033, 0x0033, 0x0033, 0x001C ×5, 0x003C ×7,
  0x001C → 0x0032, 0x0013, 0x0012, 0x0013 ×4, 0x003C, 0x003C ×3, 0x0032,
  0x0013, 0x0012, 0x003C, 0x001C
- ChipOptions (90–91): 00 00 → 06 E5 (LE16 0xE506: io_prot_en +
  kdf_aes_en, ecdh_prot = 1, kdf_prot = 1, io_prot_key = slot 14)
- 36 changed bytes total: 0x14 0x15 0x16 0x18 0x19 0x1A 0x1B 0x1C 0x1D
  0x1E 0x1F 0x20 0x21 0x22 0x23 0x24 0x26 0x28 0x2C 0x2D 0x30 0x32 0x33
  0x5A 0x5B 0x60 0x62 0x64 0x66 0x68 0x6A 0x6C 0x6E 0x76 0x78 0x7A
  (this is the post-fix `prov status` diff; the pre-fix firmware listed
  38 bytes incl. 0x58/0x59 and CRC AA8F)
- **Planned image summary CRC (on-device, with the preserved bytes):
  822F.** The chip's **actual zone** CRC after `prov config` is
  **CDC7** (the planned image zeroes the factory region 0–15; the chip
  keeps its own bytes there — bench-confirmed + host-reproduced
  2026-10-23). `prov lock` locks with the chip's actual zone CRC —
  **CDC7**; after the lock the zone CRC is expected to be **6F47**
  (lock bytes 55 55 → 00 00).

**I/O key (run AFTER `prov lock CONFIRM` — the data zone is not
writable before it):** `prov iokey` = 8 × `get_rand_32()` from the
Pico TRNG → 32 B → preconditions (config zone LOCKED, data zone
unlocked, slot 14 accepts a clear Write — parsed from the config
zone) → Write to data slot 14 (the chip's OK commits it — a read-back
verify is impossible: data slots are unreadable while the data zone is
unlocked, and post-config slot 14 is is_secret) → print 64 hex chars
(durable backup) → save `/io_key.bin` (magic 0x494F4B31 'IOK1', len,
key, CRC-32). The key is verified functionally by an I/O-protected
transaction (Phase 7).

**Reversibility:** `prov iokey` — re-runnable (re-run re-keys) while
the data zone is unlocked — including after the config lock (the
printed hex is the record). `prov config` — the config zone stays
re-writable until Lock; re-running is idempotent (no writes when the
zone already matches). `prov lock` — **irreversible**: the config zone
can never change again (the data zone is NOT locked — contents stay
open per the agreed layout). Locking the config zone also makes the
84/85 one-shot bytes final. Order constraint: the lock now comes
BEFORE the iokey write — if the iokey write ever failed after the
lock, the remedy is retrying the write (data zone still unlocked,
slot 14 still clear-writable), never "unlocking" the config.

**Done 2026-10-23 (earlier, `cc51d2a` / `6448a0d` / `d39a65d`):** the
pico-command-line submodule moved into `example/`; the `prov` console
command set implemented (build-only, chip untouched); pico-littlefs
converted to an `example/` submodule (pinned `936c07f`, target
`pico-littlefs`, header `pico_littlefs.h`, init/mount at startup, warns
when `/io_key.bin` is gone); `pico_rand` (`get_rand_32()`) supplies the
I/O-key entropy. The agreed 4B config lives in
**`example/common/dev_config.h`**, shared by console + host byte-plan
tool. **Typed-confirm design:** `prov lock` verifies then aborts,
`prov lock CONFIRM` carries the confirm (both via the module's
confirm-callback API) — the command handlers run core1 while
pico-command-line's stdin loop runs core0, so an interactive prompt
would have its keystrokes split. Pico build green/warning-clean (app
98.5 KB, well under the 512 KB littlefs boundary at 0x80000); host
ctest 2/2.

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
Write slot 14 (after `prov lock CONFIRM` — the data zone is not writable
before it; the read-back verify that was planned here turned out
impossible: data slots are unreadable while the data zone is unlocked)
→ **print the hex on the serial console** (durable record in case flash
is wiped by a full reflash) → save to littlefs. The key is verified
functionally by an I/O-protected transaction (Phase 7). (The 2026-10-22
"write before the config" ordering was superseded by the bench
discovery — see "Data-zone writes before the config lock".)

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
| `prov iokey`   | Pico TRNG → prechecks (config zone LOCKED — data zone unwritable before it) → Write slot 14 (chip ACK; no read-back possible) → print 64 hex → save `/io_key.bin` | yes (re-run re-keys while the data zone is unlocked) |
| `prov config`  | build intent → write zone (byte 16 + SlotLocked 88..89 preserved) → read-back verify | yes |
| `prov lock`    | re-verify zone vs intent → typed confirm → Lock w/ summary CRC | **no** |

4B hardware verification items (mock fidelity gaps): ~~factory-zone diff
before any write~~ **DONE 2026-10-23** (dump recorded + CRC-verified, see
"Factory config zone" above); Random command on the unlocked chip
returns the documented 0xFFFF0000 pattern (confirms the Pico-entropy
path above) — **CONFIRMED 2026-10-23** (`prov randtest` showed the
pattern; user-reported); GenKey fill size on non-ECC slots (16 vs 32
bytes — if 16, accept a 128-bit master or fill via Pico-entropy+Write);
KDF from an `is_secret` slot; I/O protection end-to-end incl.
request direction — **this is now also the functional verification of
the `prov iokey` write** (a wrong/missing slot-14 key fails every
protected command after `prov lock`); `kdf_aes_en`/`kdf_prot` settings;
UpdateExtra
same-value behavior (we send 00 00 → 00 00); byte-16 write behavior;
~~factory KeyConfig words (mock assumes all 0)~~ **KNOWN 2026-10-23**:
the real factory ships 0x0033 ×3 / 0x001C ×5 / 0x003C ×7 / 0x001C (mock
still all-0 — recorded, the prov path overwrites them all);
**SlotLocked: resolved** (factory FF FF, polarity bit 0 = locked, mock
+ prov path fixed in `d6cf44d`); UseLock enforcement; GenKey/PrivWrite
bit 13/14 behavior.

## Where we are
- **Phase 1 DONE** — module skeleton + build wiring.
- **Phase 2 DONE** — RP2350 I2C HAL on cryptoauthlib v3.8.0.
- **Phase 3 DONE** — curated `atecc608_*` core API. Build green,
  hardware-validated (3 rounds, see below). Console now uses the module API.
- **Phase 4A DONE** — config builder + guarded provisioning API + host unit
  tests with a mock chip HAL. `ctest` 2/2 green; Pico build warning-clean.
  **Chip untouched.** See "Phase 4A — what was built (and why)" below.
- **Phase 4B in progress (STOP BOUNDARY: SEQUENCE RE-APPROVAL)** — the
  actual chip provisioning. Scenario discussion done 2026-10-22; the
  agreed config is in "Agreed 4B config" above (locked layout / open
  contents, usable across all apps, I/O protection on). Console uf2
  flashed; read-only bench steps done (factory zone recorded +
  verified); SlotLocked (88–89) issue found + fixed (`d6cf44d`). The
  byte plan was approved 2026-10-23 (bytes unchanged, planned image CRC
  822F); the write SEQUENCE was re-ordered by a bench discovery (config
  → lock → iokey — the data zone is unwritable until the config zone is
  locked) and the code is fixed for it (`48d14cc`). **The new order
  awaits the user's go-ahead before the one-way lock step.** HARD RULE
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
  `console/` (probe/diag + the Phase 4B `prov` command set; littlefs via
  the pico-littlefs submodule for `/io_key.bin`, `pico_rand` for the
  I/O-key entropy), `tools/dump_devconfig.c` (the byte-plan host tool),
  `common/dev_config.h` (the agreed 4B config intent, shared by console +
  tool; the provision-on-first-boot base is factored out here in 4B);
  contract + scenarios + slot layout in `example/README.md`.
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
  `pub[i] = (slot*7 + i*3 + 1) & 0xFF`. Data zone (access matrix,
  verified vs. the bench + Microchip's conformance tests 2026-10-23,
  `48d14cc`): WRITE rejected if the CONFIG zone is unlocked (the gate),
  or (data zone unlocked && 4-byte word write), or the slot is
  individually locked (SlotLocked bit cleared); 32B + 4B writes allowed
  with the data zone locked (per slot policy); READ requires data
  locked AND not secret AND not private.
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
3. ~~Implement the `prov` console command set~~ — **done 2026-10-23**
   (`6448a0d`): all five commands implemented per the plan below
   (littlefs + `pico_rand` wired; shared config in
   `example/common/dev_config.h`; typed confirm = the command line
   `prov lock CONFIRM` — see "Where the conversation stopped" for the
   rationale). The command table is above ("4B runs as
   serial-console commands"); the plan (kept as the record of what was
   built):
   - **Wire pico-littlefs** into `example/console/CMakeLists.txt`:
     `add_subdirectory(...)` (as built: the `example/pico-littlefs`
     **submodule** — `../pico-littlefs` from the console dir; originally
     planned as the *sibling of the repo* at
     `~/Projects/pico-littlefs`, later converted to a submodule),
     link **`pico-littlefs`**
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
     agreed field values; bytes 16 and 88..89 patched from the chip — the
     prov path preserves them, so the compare sees them as "chip keeps
     own").
   - **`prov randtest`** (read-only): `atecc608_random` ×2 (32 B each),
     print hex; annotate whether the 0xFFFF0000 factory pattern is present
     (expected while the zone is unlocked — manual-cited).
   - **`prov iokey`** (WRITE — gated by the user checkpoint): Pico TRNG —
     **confirmed API (SDK 2.x, 2026-10-22): `get_rand_32()` from
     `pico/rand.h`** (8 calls → 32 B). SDK 2.x has NO `hardware_rng` /
     `get_32bit_random()` module (that was SDK 1.x); on RP2350 `pico_rand`
     uses the hardware TRNG as entropy source by default
     (`PICO_RAND_ENTROPY_SRC_TRNG`, gated on `HAS_RP2350_TRNG`). →
     preconditions via `atecc608_write_iokey()` (config zone LOCKED —
     the data zone is not writable before it, bench-verified 2026-10-23;
     data zone unlocked; slot accepts a clear Write in the current
     config) → WriteCommand to slot 14 — the chip's OK commits it;
     **NO read-back verify: data slots are unreadable while the data
     zone is unlocked (Microchip conformance test), and post-config
     slot 14 is is_secret** → print the 64 hex chars on the console
     (durable record) → save `/io_key.bin` (littlefs; 32 B key +
     magic/len/CRC header per the Persistence-layer section). Re-running
     re-keys (dev flow; while the data zone is unlocked — including
     after the config lock). The key is verified functionally by an
     I/O-protected transaction (Phase 7; see the "Data-zone writes
     before the config lock" section for the ordering + bricking
     resolution).
   - **`prov config`** (WRITE — gated): build the G intent → call
     `atecc608_provision_config()` (already: unlocked check → read zone →
     preserve byte 16 + SlotLocked 88..89 → write → read-back verify).
     Prints the verify result + summary CRC.
   - **`prov lock`** (WRITE, IRREVERSIBLE — gated + typed confirm):
     re-verify zone vs intent (full byte compare, byte 16 + 88..89
     preserved) → typed confirm via the existing confirm-callback API
     (reuse the pattern the Phase-4A prov API already takes; on the
     console that is a type-to-confirm prompt) →
     `atecc608_lock_config_zone()` (Lock command with the summary CRC
     computed from the chip's ACTUAL zone at lock time — NOT the builder
     CRC 4FE8, which differs in the factory bytes 0–15).
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
   user approval BEFORE any chip write. **APPROVED 2026-10-23** (the bytes;
   planned image CRC 822F). The SEQUENCE was re-ordered 2026-10-23 by a
   bench discovery — the data zone is not writable until the config zone is
   locked (see "Data-zone writes before the config lock") — so the
   on-hardware sequence after the new order is re-approved is:
   `prov config` → `prov lock` (dry) → `prov lock CONFIRM` (typed confirm,
   ONE-WAY) → `prov iokey` → (record the 64-hex io key).
6. **4B verification items** (mock fidelity gaps — check on the real chip):
   UpdateExtra same-value behavior (we send 00 00 → 00 00); byte-16
   write behavior; ~~factory KeyConfig words (mock assumes all 0)~~
   known 2026-10-23: real factory ships 0x0033 ×3 / 0x001C ×5 /
   0x003C ×7 / 0x001C (mock still all-0, prov path overwrites them
   all); ~~factory SlotLocked~~ resolved 2026-10-23 (`d6cf44d`):
   factory FF FF, polarity bit n = 0 → locked (confirmed from
   cryptoauthlib's own `calib_is_slot_locked` + hardware write test),
   prov path now preserves the chip's 88–89 like byte 16; UseLock
   enforcement; GenKey/PrivWrite bit 13/14 behavior on real hardware;
   I/O protection coverage of the request direction (mock does NOT
   model I/O protection at all); kdf_prot/ecdh_prot 2-bit semantics
   (enforce vs opt-in) per NDA datasheet.

Then per PLAN.md: Phase 5 (crypto pass-through: kdf/sign/verify) and Phase 6
(config read-back console demo), then Phase 7 (on-hardware validation +
bring-up checklist).

# Bring-up checklist — ATECC608C on Pico 2

Reusable checklist for bringing up a **fresh ATECC608C** on a Pico 2 and
provisioning it to the agreed layout
(`example/common/dev_config.h` — the config the bench chip carries;
`example/README.md` has the slot map and the reasoning). The tool is the
console example (`example/console/`); its `help` command documents every
step.

Two parts:

1. **First contact** — wiring, flashing, and the expected output of a
   factory-fresh chip (nothing provisioned yet).
2. **Provisioning** — the PROVEN sequence in the exact order that worked
   on the bench chip, with the order constraints explained.

**Ground rule:** every chip write in this document is an EXPLICIT console
command you type. The console never writes on its own, and the irreversible
steps gate on a typed `CONFIRM`. The project HARD RULE (no chip writes
without explicit go-ahead) applies to the bench chip — it is already
provisioned and frozen; do NOT run this checklist against it.

---

## 1. Hardware and wiring

| Signal | Pico | ATECC608C | Notes |
|---|---|---|---|
| SDA | GP20 | SDA | I2C0; pull-ups to 3V3 |
| SCL | GP21 | SCL | I2C0; pull-ups to 3V3 |
| 3V3 | 3V3 out | VDD | |
| GND | GND | GND | |

- Console: **USB CDC** (no wiring — the Pico's USB port) and/or **UART0**
  (GP0 TX, GP1 RX on a USB-serial adapter; 115200 8N1, the pico-sdk
  `stdio_init_all()` default).
- The chip's I2C address is 0x60 (ADR pin low) — the console probes 0x60/0x61.

## 2. Flash the console

```sh
cmake -S . -B build -DPICO_SDK_PATH="$HOME/Projects/pico-sdk"
cmake --build build -j
# → build/example/console/pico-atecc608.uf2
```

- Enter BOOTSEL (hold BOOTSEL while plugging in USB — or run `bootrom`
  from a previous firmware) and copy the uf2.
- **First boot** formats the littlefs volume (flash @ 0x80000): the boot
  banner prints `littlefs: no formatted volume — formatting …` and can
  take a while. A **normal uf2 reflash never does this** — the app region
  and the littlefs volume are disjoint (see §6, reflash interplay).

## 3. First contact — what a factory-fresh chip reports

Boot banner, then these commands (all read-only):

| Command | Expected on a fresh chip |
|---|---|
| boot banner | `pico-atecc608 ready: ATECC608 on I2C0 GP20/GP21 @ 0x60, 400000 Hz.` |
| `probe` | `ATECC608 found at I2C address 0x60 (wake handshake ok)` |
| `info` | part `0x60`, revision `5` |
| `serial` | 9 factory bytes — **record them** (they are the chip's identity; the config-zone CRC depends on them) |
| `random` | 32 bytes of the **`FF FF 00 00 …` factory pattern** — EXPECTED while the config zone is unlocked (the chip's documented factory behavior, not a fault) |
| `lock` | config zone: unlocked, data zone: unlocked |
| `config` | decodes the FACTORY layout (SlotConfig `83 20 87 20 8F 20 C4 8F …`) — NOT the agreed layout yet; this is normal before `prov config` |
| `prov status` | config zone unlocked, lock bytes `55 55`, a 38-byte diff vs the planned image (the factory vs agreed layout) |
| `selftest generic` | **fails by design** on a fresh chip (config not the agreed layout, RNG pattern, …) — it validates a PROVISIONED chip, not a fresh one |

If `probe` fails: run `diag` (I2C bus levels + raw wake-handshake bytes)
before suspecting the chip — the usual causes are missing pull-ups, a
swapped SDA/SCL, or no 3V3.

## 4. The proven provisioning sequence

Exact order, as executed on the bench chip (2026-10-23 → 2026-10-26).
Each step is read-back verified by the console; re-running a reversible
step is idempotent.

| # | Command | Does | Reversible? |
|---|---|---|---|
| 1 | `prov status` | pre-flight: confirm the chip is fresh/unlocked | read-only |
| 2 | `prov config` | write the agreed config zone (byte 16 + SlotLocked 88..89 preserved) | yes (zone still unlocked) |
| 3 | `prov lock CONFIRM` | **LOCK the config zone** | **no** |
| 4 | `prov iokey` | Pico TRNG → slot 14 (I/O key) → **print 64 hex chars** → save `/io_key.bin` | yes until slot 14 is locked |
| 5 | `prov genkey 1` `prov genkey 3` … `prov genkey 12` | fresh P-256 pairs in the six ECC private slots — **record the six public keys** | yes (data zone still unlocked) |
| 6 | `prov lockdata CONFIRM` | **LOCK the data zone** | **no** |
| 7 | `prov iokeytest` | functional I/O-key check (must PASS: slot 14 == `/io_key.bin`) | read-only |
| 8 | `prov kdf 7` (×2) | record the slot-7 KDF value (must be identical both runs) | read-only |
| 9 | `prov lockslot 14 CONFIRM` | **individually LOCK slot 14** (PRODUCTION ONLY) | **no** |
| 10 | `prov status` | final verification: locked, diff 0, CRC, counters 0/0 | read-only |
| 11 | `selftest` | the full read-only validation suite (green = done) | read-only |

**The order constraints (why the sequence is shaped this way):**

- **`prov iokey` is after `prov lock CONFIRM`.** The ATECC608 refuses
  data-zone writes until the CONFIG zone is locked — step 4 would fail
  before step 3 (bench discovery, 2026-10-23).
- **`prov genkey` is before `prov lockdata CONFIRM`.** A fresh ECC private
  key can only be generated while the DATA zone is unlocked; once locked,
  GenKey mode 0x04 is permanently refused (mode 0x00, recompute the public
  key from the stored private key, keeps working — that is what
  `prov pubkey` and `selftest` use).
- **`prov iokeytest` is after `prov lockdata CONFIRM`.** The KDF
  (target=output) is gated on the data-zone lock — before it the command
  fails with `ATCA_STATUS -12` (an execution error, NOT a key mismatch).
- **`prov lockslot 14` is last, and is PRODUCTION ONLY.** It freezes the
  I/O key: a lost `/io_key.bin` can no longer be recovered by re-keying
  slot 14. For a DEVELOPMENT chip, stop at step 8 (slot 14 stays
  re-keyable; note that `selftest`/`selftest generic` then expect the ONE
  difference — SlotLocked `FF FF` instead of `FF BF` — see §5).

**Record at each step (the per-chip goldens, §5):** the `prov iokey`
console print (the I/O key — keep it out-of-band; it is on the bus-adjacent
console and in littlefs), the six `prov genkey` public keys, the `prov
kdf 7` value, and the `prov status` chip-zone CRC.

## 5. Record the per-chip goldens

After step 10, the chip's identity values are fixed forever (config locked,
keys generated, slot 14 locked). Record, per chip:

1. **Serial** (9 B) — `serial`.
2. **The six public keys** (64 B each) — `prov pubkey 1` … `12`.
3. **The slot-7 KDF value** (32 B) — `prov kdf 7` (fixed zero nonce +
   fixed `00..0F` message, so deterministic forever).
4. **The config-zone CRC-16** — `prov status`. Note it differs from chip
   to chip: the CRC covers the whole 128-B zone including the factory
   region, so every chip's CRC is unique (bench chip: `C904` after full
   lock; `F6DE` was its pre-data-lock value).

The console's `selftest` full mode hard-checks the **bench chip's**
goldens (the `BENCH_*` table at the top of the Phase 7 section of
`example/console/main.c` — dev-only, not part of the library). A different
chip passes `selftest generic` (the invariants) but hard-FAILS the
goldens (as it should — it is not the bench chip). If a new chip becomes
the reference bench chip, update that table from its recorded values.

## 6. Known failure modes (all seen and root-caused on the bench)

| Symptom | Cause | What to do |
|---|---|---|
| `probe` fails | no wake handshake | `diag` first: bus levels, SDA/SCL swap, pull-ups, 3V3 |
| `random` prints `FF FF 00 00 …` | factory pattern — EXPECTED while the config zone is unlocked | not a fault; disappears after `prov lock CONFIRM` |
| `prov iokey` (or any data-zone write) refused before the config lock | the ATECC608 gates data-zone writes on the CONFIG-zone lock | run `prov lock CONFIRM` first (step order above) |
| `prov iokeytest` / `prov kdf` → `ATCA_STATUS -12` | KDF target=output is gated on the DATA-zone lock | run `prov lockdata CONFIRM` first; −12 is NOT a key mismatch |
| `prov iokeytest` → “decrypted KDF != clear KDF” | the chip ENFORCES I/O protection (kdf_prot=1): the clear call's output is encrypted too | the console already decrypts both sides (fixed 2026-10-25); a mismatch after that fix means the key in `/io_key.bin` ≠ slot 14 |
| `/io_key.bin` save fails / “littlefs init FAILED” | flash lockout not initialized on the core doing the write (bug fixed in `d1778af`) | rebuild from a tree containing the fix; the save is read-back verified |
| boot says “no formatted volume” + “/io_key.bin not found” | a FULL-flash erase wiped the littlefs volume (a normal uf2 reflash does not touch it) | if the chip is provisioned and slot 14 is NOT yet locked: re-run `prov iokey` and re-record the key. If slot 14 IS locked: the I/O key is unrecoverable from the chip — use the out-of-band recorded copy |
| I2C bus stuck (no chip, `diag` shows SCL low) | a chip mid-transaction | power-cycle the ATECC608C (or the whole board); a stuck SDA needs a 9-clock SCL pulse sequence |

**Reflash/littlefs interplay (the rule to remember):** a uf2 reflash writes
only the app region (flash `0x0..~0x19000`) and NEVER touches the littlefs
volume (flash `0x80000+`) — the volume and `/io_key.bin` survive, and the
boot banner reports “mounted existing”. Only a full-flash erase (e.g. the
Raspberry Pi Imager writing a full image, or a chip-erase) formats a fresh
volume. The `selftest` littlefs check reports which case you are in.

## 7. Validation — `selftest`

- **`selftest`** (full): the 8 generic invariants (probe+info, TRNG,
  config zone, counters, six ECC pubkeys, KDF determinism, I/O-key
  round-trip, littlefs) **plus** the bench-chip goldens (serial, six
  public keys, slot-7 KDF value, config-zone CRC). Green on the bench
  chip = the module + the chip are in the recorded production state.
- **`selftest generic`**: invariants only — the check for a fresh chip
  that completed §4 on steps 1–8 (slot 14 unlocked). Expected result on
  such a dev chip: everything PASS except the config-zone check showing
  `SlotLocked FF FF (want FF BF)` — everything else must be green.
- READ-ONLY end to end — safe at any time, including on the frozen
  production chip.

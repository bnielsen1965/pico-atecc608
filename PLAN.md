# ATECC608C Provisioning & Development Plan

Goal: provision the ATECC608C at I2C 0x60 for the dual-vault password-store
application, in the user-defined order:

```
[Open]  -> write config + LOCK CONFIG   (one-shot, irreversible)
[Mixed] -> generate/inject keys         (repeatable while data zone is open)
[Sealed]-> LOCK DATA ZONE               (final, only when everything is set)
```

The data zone stays **unlocked** for the entire development period so slots can
be re-populated freely. Only the config-zone lock is a near-term point of
no return.

## Current state (verified on hardware, 2026-10-16)

- Chip: ATECC608C (per user; note cryptoauthlib v3.7.9 predates the "C" — it
  only defines ATECC608A/B, both mapped to the same device type 3), I2C 0x60,
  unprovisioned. Config zone **unlocked**.
  Serial `01 23 06 40 AE B6 B9 B7 EE`. INFO `00 00 60 05` (part 0x60, rev 5).
- **Datasheet:** `ATECC608C-CryptoAuthentication-Summary-Data-Sheet-DS40002513.pdf`
  in the repo root. Not yet read — Phase 0 starts from its config-zone and
  slot bit-field tables (read it before touching the config array).
- RNG streams `FF FF 00 00 ...` — normal for a fresh, unconfigured chip.
- Firmware: smoke-test console works end-to-end (probe/random/info/serial/diag),
  all responses CRC-validated. Driver handles sleep re-wake and has guarded
  bus recovery.
- Reference: cryptoauthlib v3.7.9 (Microchip) used as the protocol authority.
  Its factory "standard config" array for the ATECC608 is available as a
  known-good comparison baseline.

## Decisions (settled 2026-10-16)

1. **Chip library:** cryptoauthlib (v3.7.9) as a submodule + our own thin
   RP2350 I2C HAL built on the existing `src/atecc608.c` wake/transaction
   code.
2. **Provisioning vehicle:** console commands in the current build
   (`cfgshow` / `cfgverify` / `cfgwrite` / `cfglock`), typed confirmation for
   locks, watchable live on the serial console.
3. **No dry-run chip:** spare ATECC608s exist but are hard to set up, so the
   one-shot config write happens on the real chip with the extra safeguards
   listed in Phase 2.
4. **IO protection:** IO protection is the slot-based, transport-level mode:
   with a key in the designated slot, the device encrypts and signs
   (AES-CTR + HMAC per payload, modified wake handshake) every I2C payload
   over the otherwise-standard I2C bus. The slot-3 key is written only in
   Phase 5, once our HAL implements that transport wrapping — see the note
   below on what v3.7.9 can and cannot speak.

### cryptoauthlib v3.7.9 capabilities (verified in source)

- **No Pico/RP2350 HAL** exists in the library. A thin RP2350 I2C HAL must be
  written (init / send / receive / wake / idle / sleep / release / delay).
  The existing `src/atecc608.c` wake + transaction code is most of the
  backend for it.
- **IO protection exists only at command level in this version** (VERIFY /
  ECDH / secure-boot variants that accept an `io_key`), **not** as I2C
  transport wrapping: the HAL interface has no IO-protection path. Once a key
  is in the IO-protection slot the device requires transport-level protection
  on every I2C exchange (including the wake handshake), which this library's
  standard I2C path cannot speak. Because our custom HAL *is* the transport
  layer, implementing the wrapping there lets cryptoauthlib's upper layers
  (KDF, genkey, lock, sign, ...) run unmodified over the protected channel.
  Consequence: the slot-3 key is written in Phase 5, after that HAL work.
- API differs from the README sketches: `atcab_lock_config_zone(void)` takes
  no response argument in v3.7.9; `ATECC608C` does not exist (use `ATECC608`);
  `atcab_write_bytes_zone(zone, slot, offset_bytes, data, length)`.

## Ground rules (apply to every phase)

1. **Nothing irreversible without read-back verification.** Write config →
   read it back → byte-compare → only then may a lock be issued.
2. **Write and lock are separate commands.** A power loss in between leaves
   the chip in a recoverable state (zone still unlocked, re-run the write).
3. **Typed confirmation for locks** (e.g. type `YES-TO-LOCK` at the console).
4. **Idempotent, re-runnable** while the relevant zone is unlocked
   (`atcab_is_locked` checked first; "already locked" is a clean exit).
5. Every chip operation goes through the driver's timeout I2C calls and
   sleep re-wake logic (never the unbounded SDK blocking calls).

## Phase 0 — Config freeze: byte-level review (no chip writes)

The config zone is written exactly once, so this phase exists to make the
array correct before it touches hardware.

1. Read the ATECC608C datasheet (DS40002513, PDF in the repo root) and work
   through its config-zone maps (SlotConfig bit fields, KeyConfig bit fields,
   Use & Counter Flags, LastKeyUse, slot sizes, counter mode, IO protection)
   against `custom_atecc608_config` in README.md, slot by slot, using the
   factory standard config as the known-good comparison baseline.
2. Resolve the red flags below (each needs a datasheet answer before
   proceeding):
   - **Counter slots 4 & 15 are `00 00`/`00 00`.** The factory counter slot
     (slot 4) is SlotConfig `8F 0F` / KeyConfig `7C 00`. All-zero likely
     disables the slot entirely, which would break the PIN brute-force
     counter design. Must use the datasheet's counter-mode encoding.
   - **SlotConfig high byte `0x8F`** on slots 1–3, 11–13, and `0x80` on
     9–10. In the factory config, high-byte bit 7 is never set (max `0x44`).
     Verify what bit 7 selects — if it is invalid or enables something
     unintended, these slots misbehave permanently.
   - **`FF FF` for "unused" slot 0** (both SlotConfig and KeyConfig) —
     confirm it means "disabled" and is a legal value.
   - **KeyConfig `04 00` on ECC passkey slots 11–13** — verify this selects
     ECC-P256 private-key generation (the factory ECC slots use other values;
     `04` decodes ambiguously from memory and must be checked).
   - **KeyConfig `10 00` on public-key slots 9–10** — verify "ECC public key
     / write-protected" encoding.
   - **Bytes 52–95 all zero**, while the factory has `FF` patterns in
     52–67. Verify whether those defaults matter (key-use / counter flags).
   - **Bytes 17–19**: factory has `00 00 01`; user array has `00 00 00`.
     Verify byte 19's function.
   - **Slot sizes**: README says slots 0–8 are "36 Bytes". Confirm actual
     sizes from the datasheet (affects how much can be stored per slot).
   - **Slot 3 as IO protection**: verify `0x8F 8F`/`0x13 00` marks it as the
     I2C IO-protection slot. (Even if we defer *writing* the key, the config
     must mark the slot correctly now — config is one-shot.)
3. Output: a final, annotated `custom_atecc608_config` (as a C header,
   e.g. `src/atecc608_config.h`) with a comment per byte-range, and a
   written one-page "why each byte has its value" review note.
4. Decide the architecture questions (library, provisioning vehicle,
   IO-protection timing) — see Open Questions.

## Phase 1 — Chip library & RP2350 HAL (read-only chip access only)

1. Add cryptoauthlib (v3.7.9, matching the reference at hand) as a git
   submodule, build only the core (no pkcs11/mbedtls/wolfssl extras).
2. Write `hal/hal_rp2350_i2c.c` implementing the `ATCA_HAL` I2C interface on
   top of the existing driver (wake at 100 kHz, 400 kHz traffic, 10 ms
   timeouts, sleep re-wake, guarded bus recovery).
3. Verify the HAL with **read-only** operations only (safe while the chip is
   open): INFO, READ config block 0 (must match the value we read with the
   home-grown driver), `atcab_is_locked` (both zones: expect false),
   `atcab_random` (expect the FF FF 00 00 pattern pre-provisioning — this is
   also our canary: it must change to real random bytes after Phase 2).
4. Keep the existing smoke-test commands in the same build.

## Phase 2 — Config provisioning (ONE-SHOT)

Console commands, each individually re-runnable:

| Command | Action |
|---|---|
| `cfgshow` | Read + print the full 128-byte config zone and both lock states |
| `cfgverify` | Read config back, byte-compare with the intended array, print a diff. No writes. |
| `cfgwrite` | Write the 112 bytes at offset 16 (skipping the factory-burned bytes 0–15), then read back + compare, print result. **Does not lock.** |
| `cfglock` | Refuses unless `cfgverify` would pass right now; requires typed `YES-TO-LOCK`; calls the lock; prints result |

Sequence on the day: `cfgshow` (confirm open state) → `cfgwrite` →
`cfgverify` → `cfglock` → `cfgshow` (confirm locked).

**Extra safeguards (no dry-run chip available — this is the one-shot
procedure on the real chip):**
- The intended 128-byte array is committed to git *before* it is ever
  flashed, so the exact bytes are on record and reviewable.
- `cfgshow` first: snapshot and print the chip's current (factory) config so
  the before/after diff is visible on the console.
- `cfgwrite` reports the read-back comparison as a per-byte diff, not just
  "ok"; any mismatch aborts before any lock is possible.
- `cfglock` re-runs the full read-back comparison itself (does not trust an
  earlier `cfgverify` result) and requires the typed `YES-TO-LOCK`.
- Power stays on the Pico for the whole sequence (USB, no flapping).
- After the lock, the Phase 2 post-lock verification suite runs immediately;
  if anything is wrong, that is the moment it is discovered — with the chip
  still responsive on the console for diagnosis.

Post-lock verification:
- INFO still answers; `is_locked(config)` == true; `is_locked(data)` == false.
- READ config block 0 == intended array.
- `atcab_random` → **real random bytes now** (confirms the chip left its
  fresh-chip state; per README the RNG only works once configured).
- Re-run `probe`/`info`/`serial` from the smoke-test suite (regression).

## Phase 3 — Key provisioning (config locked, data open — repeatable)

Order inside this phase (all repeatable while data zone is unlocked):

1. **KDF secrets — slots 1 & 2:** `atcab_genkey(1)`, `atcab_genkey(2)`.
   Secrets never leave the chip.
   Verify: run KDF (HMAC-SHA256) with a known test PIN against each slot —
   deterministic output for the same PIN, different output for a different
   PIN. (This is the primitive the vaults will use: PIN ⊕ slot secret →
   AES-256 key.)
2. **Firmware-verification public keys — slots 9 & 10:** generate ECC P-256
   key pairs with the private half held by the host/Pico (these verify signed
   firmware images). Write the public halves into the slots.
   **These slots are write-protected: one write each, get them right.**
3. **Passkey identities — slots 11, 12, 13:** `atcab_genkey` (ECC). The chip
   keeps the private keys; capture the returned public keys and store them on
   the Pico/host for FIDO2 registration.
4. **IO-protection key — slot 3: DEFERRED to Phase 5** (see Ground rules /
   Phase 5). Until then slot 3 stays empty; the bus runs unencrypted.
   When we do write it: 32 bytes from the RP2350 TRNG (`pico_rand`/
   `rand_get_bytes`, never libc `rand()`), persisted to Pico flash in the
   same step, and only after the driver can speak IO-protected I2C.
5. **Counters — slots 4 & 15:** verify read/increment works
   (`atcab_read`/`atcab_incr`), including wrap/lock behavior, only if Phase 0
   got the counter encoding right. (Feeds the brute-force design in Phase 4.)
6. Leave slots 0, 5, 6, 7, 8, 14 empty (future encrypted storage / TOTP).

Throughout Phase 3: no data-zone lock. Any slot can be re-written or re-
generated while developing.

## Phase 4 — Password-store application (develop against the mixed state)

The actual product logic, developed while the chip is in the mixed state:

1. **Vault A / Vault B:** PIN → KDF(slot 1 / slot 2) → AES-256 key.
   PIN verification design (decide during implementation): KDF-derive,
   decrypt a small stored "vault token" block, check a magic value.
2. **Password records:** where they live (Pico flash vs. encrypted storage
   slots 5–8/14) and their on-media format (encryption, integrity, vault
   tagging).
3. **Brute-force protection:** on PIN failure, increment the chip counter
   (slot 4); Pico compares it against its own stored counter; refusal
   threshold; admin connection + recovery phrase to resync the Pico-side
   counter. (Depends on Phase 0 counter config being correct.)
4. **Firmware verification:** sign the UF2/firmware image with the Phase 3
   private keys; verify with slots 9/10 during boot (later hardening; can be
   a follow-on phase).
5. Optional: TOTP seed storage in slots 5–8 (the "future" slots the README
   reserved).

## Phase 5 — (deferred) I2C IO protection

Transport-level IO protection (per the datasheet): with the key present in
the designated slot, the master and device derive per-session crypto from the
32-byte IO key (per-payload AES-CTR encryption + HMAC-SHA256 authentication,
modified wake handshake) while the I2C bus itself stays standard.

1. Implement the protocol in **our RP2350 HAL** — the HAL's send/receive/wake
   are the raw transport layer, so wrapping there leaves cryptoauthlib's
   upper layers unchanged. (Cross-check whether a newer cryptoauthlib
   release adds a HAL-level IO-protection hook before writing it by hand; if
   so, prefer the upgrade.)
2. Generate the 32-byte key on the RP2350 TRNG, write it to slot 3, and
   persist it to Pico flash in the same step (format + protection decided
   then).
3. From that moment every session (including the boot probe) must use the
   protected protocol — no fallback to plaintext. If the persisted key is
   ever lost from the Pico, the chip is unreachable by that Pico: the
   flash-storage design must make loss unlikely (and note the recovery
   path, if any, before locking the data zone in Phase 6).
4. Re-run the full smoke suite over the protected channel.

## Phase 6 — (final, deferred) Data-zone lock

Only after Phase 4 is functionally complete and Phase 5 is either done or
consciously skipped:

1. `datashow`-style audit: every slot's intended state (key present / empty /
   counter value / write-protected slots already written).
2. Re-run the full functional test suite.
3. Typed confirmation, `atcab_lock_data_zone`, verify locked.
4. Full regression after lock (the chip is now permanently sealed).

## README.md fixes to fold in (inconsistencies found)

- First code sketch writes `&custom_atecc608_config` (offset 0!) while the
  second correctly uses `[16]` — the first one is wrong and must not be used.
- "Step 2" prose and code say the IO key goes to **slot 2**, but the slot map
  (and config array) put it in **slot 3** (slot 2 is KDF Vault B).
- `PIN_SDA 4 / PIN_SCL 5` — this project uses GP20/GP21.
- `devtype = ATECC608C` — the chip is indeed an ATECC608C, but that
  identifier does not exist in cryptoauthlib v3.7.9 (it predates the "C");
  use `ATECC608` (device type 3, same as A/B) until a newer library is
  adopted.
- `atcab_lock_config_zone(&lock_response)` — v3.7.9 signature takes no
  argument.
- Slot sizes ("36 Bytes" for 0–8) — confirm against datasheet.

## Implementation-time details to settle as each phase starts

- Phase 0: the Phase 0 red-flag list (counter encodings, SlotConfig high-byte
  bit 7, slot sizes, bytes 17–19 / 52–95 meanings) — datasheet answers. The
  firmware's `info` model decoding (taken from v3.7.9, which predates the "C")
  currently labels this chip "ATECC608B, revision 5"; update it once the
  datasheet's INFO byte map for the 608C is confirmed.
- Phase 3: how the KDF-derived AES key is used for PIN verification (stored
  "vault token" design) and where password records live (Pico flash vs.
  encrypted storage slots).
- Phase 5: IO-key flash format on the Pico and its protection.

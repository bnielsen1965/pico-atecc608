# Resume notes (pico-atecc608)

Pause point: **2026-10-27 — the `vault` example is BUILT +
HOST-VERIFIED (both diagnosed GCM bugs fixed; host ctest 4/4; bench
demo run pending — the newest "Latest state" paragraph below), and
Phase 4B is COMPLETE (2026-10-23), Phase 5
is COMPLETE (KDF round-trip validated on hardware 2026-10-26), and
Phase 6 is COMPLETE (2026-10-26: the `config` read-back demo ran on
hardware; the decoded zone matches the agreed plan, SlotLocked FF BF).
The bench sequence is COMPLETE — including the production-only
`prov lockslot 14 CONFIRM` (executed 2026-10-26; the chip config is
now frozen for production). Phase 7 is SCOPED (2026-10-26 — read-only
`selftest` on-hardware suite + `docs/BRINGUP.md` bring-up checklist;
scope in PLAN.md). Sub-steps 7.1–7.3 are ALL BUILT (2026-10-26:
`0242df2` selftest generic invariants + shared round-trip core;
`c1708f6` bench-chip goldens + full/generic modes; `0d312a5`
`docs/BRINGUP.md` bring-up checklist + example/README pointer).
**Phase 7 is COMPLETE (2026-10-26): the 7.4 bench run was GREEN —
`selftest` 12/12 PASS, `selftest generic` 8/8 PASS on the chip** (the
C904 config-zone CRC golden — host-computed and cross-checked against
both recorded CRCs — confirmed on the real chip). The 238,080 B uf2
(`c1708f6`) is LIVE on the chip. All seven phases are done; the chip
is provisioned, frozen, and regression-gated. Bench record: the ECC slots (1, 3–6, 12) are
GenKey'd
(all six public keys recorded and verified in the "⏸ Where the
conversation stopped" section below), the DATA ZONE IS LOCKED (one-way
step executed 2026-10-25, verified by re-read), and **`prov iokeytest`
PASSED** (2026-10-25, output + host cross-check recorded in the
"Latest state" paragraph in that section) — the I/O key is
functionally VERIFIED end-to-end. The chip ENFORCES I/O protection
(kdf_prot=1): every target=output KDF returns encrypted output + a
32-B nonce and must be `atcah_io_decrypt`-ed with the I/O key (Phase 7
design fact). **Phase 5's KDF wrapper is IMPLEMENTED, host-tested, and
VALIDATED ON HARDWARE** (2026-10-26: `prov kdf 7` ran twice with
IDENTICAL 32-B output — determinism + the enforced-mode decrypt with
/io_key.bin through the wrapper; the value and a host cross-check note
are in the newest "Latest state" paragraph; the Phase 5 done criterion
is met). The last bench item — `prov lockslot 14 CONFIRM` (PRODUCTION
ONLY) — was APPROVED by the user and EXECUTED 2026-10-26 (slot 14
locked, verified by re-reading SlotLocked = FF BF): the bench sequence
is done and the chip config is frozen for production. Phase 4B:
the chip is fully PROVISIONED. The config zone holds the approved
planned image and
is LOCKED (the one-way step ran after explicit user go-ahead); the
I/O key is in slot 14 (chip ACKed) AND saved to littlefs
(`/io_key.bin`, read-back verified). The one bug found along the way —
the littlefs save failed because flash lockout was never initialized
on either core — was root-caused + fixed (`d1778af`), the fix was
flashed, and the save now succeeds. Final `prov status` (run-sheet
step 7): `config zone: LOCKED`, data zone unlocked, lock bytes
`55 00` (byte 87 = config-zone lock flipped 55→00; byte 86 = data-zone
lock stays 55), chip-zone CRC **F6DE**. The durable I/O key is
recorded in the state list below. The chip RNG now returns real random
(config zone locked), resolving that 4B verification item.
Since then (2026-10-24): `prov iokeytest` was run (−12, the expected
data-zone-lock gate — NOT a key mismatch); the littlefs persistence
check landed (`f52eb35`) and PASSED its first live test — after
flashing `f52eb35`, `prov status` reported the volume "mounted existing
(survived the last reflash)" and "/io_key.bin: present and valid (32 B
key, magic + len + CRC ok)", and the config zone was verified
byte-identical to the approved plan (all 32 SlotConfig/KeyConfig values
match, CRC F6DE, data zone still unlocked, counters 0/0).
**`f52eb35` was the firmware live on the chip at that point** (current:
the Phase 6 build, the 226,304 B uf2, flashed 2026-10-26 for the
lockslot + config bench steps — see the newest "Latest state"
paragraph below).
**Since (2026-10-26 night; FIXED 2026-10-27):** the `vault` example
(console-based PIN-gated password-store demo, `example/vault/`) is
BUILT and HOST-VERIFIED — all files, the CMake wiring, the console
refactor onto the shared `example/common/iokey_file.h`, and a 12-check
host test; the two diagnosed GCM bugs (`xtime` mask that never yields
0xFF; `gcm_core` hashing plaintext instead of ciphertext on the decrypt
path) are FIXED 2026-10-27 (the `ctr_xcrypt` + `gcm_tag` restructure +
the xtime sign-bit fix — details in the newest "Latest state"
paragraph below): host ctest is 4/4 GREEN (the OpenSSL-verified NIST
KATs pass), both Pico uf2s build warning-clean (console unchanged at
238,080 B — identical to the live build; vault 196,096 B), and the
docs are in (example/README vault section, PLAN.md scope note). The
bench demo run was GREEN 2026-10-27 (the user flashed the vault uf2
and verified add / get / wrong-PIN / list / rm — see the newest
"Latest state" paragraph below); the read-only `dump <name>` demo
command (raw stored entry as text, non-printables as `?`) was added
the same day, and its bench run was GREEN the same day (the ct region
read as pure `?` noise — the plaintext-leak demo confirmed on
hardware). The vault demo is COMPLETE end-to-end (add/get/dump/
wrong-PIN/list/rm all verified on the frozen chip). The chip is
FROZEN and untouched by this work (the vault runtime uses KDF + RNG
only).

**The functional I/O-key test `prov iokeytest` was BUILT (`8aa8922`),
flashed, and RUN (2026-10-24): `clear KDF failed: ATCA_STATUS -12`
(execution error), data zone UNLOCKED — the KNOWN-RISK case, now
CONFIRMED on the real chip. It is NOT a key mismatch: the ATECC608 gates
the KDF (target=output) on the data-zone lock. The finding carried
forward: the VAULT's KDF also uses target=output, so the data zone MUST
be locked for the password store to work (revising the agreed "data zone
unlocked" layout); and GenKey makes a fresh ECC private key only while
the data zone is UNLOCKED, so the ECC pairs (slots 1, 3–6, 12) must be
generated BEFORE the data zone is locked. The I/O-key verification is
deferred to the Phase 5+ flow: GenKey the ECC pairs → lock the data zone
(byte 86, one-way) → run `prov iokeytest` → (production) slot-lock slot
14. For now the I/O key is verified to the extent the chip allows (write
ACK + littlefs read-back). See "⏸ Where the conversation stopped".**
The byte plan (bytes, CRC 822F) is unchanged and stays approved.
Original discovery behind the write order: the ATECC608 refuses any
data-zone write while the config zone is unlocked — so `prov iokey`
(a data write) can only run AFTER `prov lock CONFIRM`. The
I/O-protection bricking concern is RESOLVED (see the findings
section): I/O protection protects the I/O of ECDH/KDF/Verify/
SecureBoot, not the I2C transport — the chip stays reachable with
plain commands after the lock, so the approved config needed no
change. This file is a continuity snapshot — update it at each pause.
The forward plan lives in `PLAN.md`; this file captures the exact
working state and the concrete next steps.

## ⏸ Where the conversation stopped (read this first on resume)
Working tree is clean. **Phase 4B is COMPLETE — the chip is fully
provisioned** (config zone written + LOCKED; I/O key in
slot 14, chip ACKed, and saved to littlefs `/io_key.bin` read-back
verified; final `prov status` = run-sheet step 7 confirmed LOCKED /
lock bytes 55 00 / chip-zone CRC F6DE). On resume: do NOT
re-provision the chip — the config zone is locked one-way (it can
never be re-written), and re-running `prov iokey` would re-key slot
14 (only do that if you deliberately want a fresh key; the previous
key is then void). The durable I/O key is recorded in the state list
below (and in `/io_key.bin` on the Pico).

**Latest state (2026-10-24, after the `f52eb35` reflash + `prov status`
review):** `f52eb35` is flashed and LIVE on the chip. `prov status` was
reviewed byte-for-byte the same day: the config zone is byte-identical
to the approved plan (all 16 SlotConfig + 16 KeyConfig values match;
factory region, I2C address, UpdateExtra, SlotLocked, ChipOptions and
counters all as recorded; chip-zone CRC F6DE), the data zone is still
UNLOCKED, and — the point of the reflash — the NEW littlefs persistence
check PASSED LIVE: "littlefs volume: mounted existing (survived the last
reflash)" + "/io_key.bin: present and valid (32 B key, magic + len + CRC
ok)". The reflash did NOT wipe the volume (the app region
0x0..~0x19000 and the volume 0x80000..0x200000 are disjoint).
**Next work as of this pause (Phase 5+, design recorded in PLAN.md;
COMPLETED 2026-10-25 — see the next paragraph):** implement
`atecc608_get_pubkey(slot, pub)` (library wrapper over
`atcab_get_pubkey` — GenKey mode 0x00; the public key of an on-chip ECC
private key slot is not stored in any data slot) + mock support + host
test, then the console commands `prov genkey <slot>` / `prov lockdata` /
`prov lockslot <slot>` (thin wrappers over the existing Phase 4A prov
API); after that the bench sequence: genkey 1, 3–6, 12 (record the
public keys) → lockdata CONFIRM (one-way) → iokeytest (must pass) →
lockslot 14 CONFIRM. The GenKey bit (SlotConfig 0x2000) is confirmed
SET on slots 1, 3–6, 12 in the locked config, so the GenKey step is
config-legal.

**Latest state (2026-10-25): the Phase 5+ implementation is complete —
built + host-tested, but NOT yet on the chip** (`f52eb35` is still
live there). What landed:
- `atecc608_get_pubkey(slot, pub)` in `atecc608_prov.{h,c}`: wraps
  `atcab_get_pubkey` (GenKey mode 0x00 — recompute the public key from
  the stored private key). READ-ONLY, no confirm gate, works at any
  time including with the data zone locked. Lived in the prov header on
  purpose: the host build compiles only the HAL-agnostic sources
  (config/prov/status), so it is testable there, and it is the mode
  0x00 sibling of `atecc608_genkey`. `atecc608_read_pubkey` (atecc608.h)
  got a cross-reference comment: it is a data-zone READ of a 72-B
  STORED public key (slots 8–15, off-chip signers) — the wrong
  primitive for a private slot's public key.
- Mock (`tests/mock_chip.c`): `mock_handle_genkey` now models BOTH
  modes — 0x00 works at any time (even data-zone-locked) and needs only
  the slot to be an ECC private key slot (NOT the GenKey bit — that bit
  gates private-key REGENERATION only, per the 608A-TFLXTLS fixed
  config); 0x04 keeps the GenKey-bit + data-zone-unlocked gates. Same
  deterministic fake public key in both modes, so 0x00 "recomputes"
  exactly what 0x04 just generated.
- New host test `t_get_pubkey` (tests/test_prov.c): recompute,
  consistency with the genkey response, still works after BOTH zone
  locks (and mode 0x04 is refused there), non-private-slot refusal,
  bad params. ctest 2/2 green.
- Console (`example/console/main.c`): `prov genkey <slot>` (allowlist
  1, 3–6, 12 + data-zone-UNLOCKED guard + the chip's actual config
  check: ECC private slot with the GenKey bit; prints the 64-B public
  key; warns that re-running REPLACES the key), `prov lockdata
  [CONFIRM]` (typed token; one-way; the new lock state is verified by
  re-reading it), `prov lockslot <slot> [CONFIRM]` (typed token;
  pre-checks already-locked / not-Lockable for readable refusals; the
  chip re-enforces Lockable; verified by re-reading SlotLocked), and —
  a small ADDITION to the PLAN sketch — read-only `prov pubkey <slot>`
  (makes mode 0x00 verifiable on hardware and re-fetches recorded
  public keys after lockdata). Help text + usage line + top-of-file
  command list updated, including the agreed bench order.
- uf2 built: `build/example/console/pico-atecc608.uf2`, 215,040 B.

**Next, at the bench (needs the user's go-ahead at each step — ground
rule 0):** flash the new uf2 → `prov status` (expect the littlefs check
to pass again) → `prov genkey 1`, `prov genkey 3`, `prov genkey 4`,
`prov genkey 5`, `prov genkey 6`, `prov genkey 12` (RECORD every
printed public key in RESUME.md) → `prov lockdata CONFIRM` (ONE-WAY) →
`prov iokeytest` (must now PASS — the KDF target=output gate) →
(production only) `prov lockslot 14 CONFIRM`. **Progress 2026-10-25:
flash + status + all six genkeys + `prov lockdata CONFIRM` +
`prov iokeytest` (PASS, host cross-checked) ALL DONE — records in the
paragraphs below; the `prov kdf 7` wrapper round-trip is DONE 2026-10-26
(two identical runs — see the "Latest state (2026-10-26)" paragraph
below); remaining: (production only) `prov lockslot 14 CONFIRM` — the
user decides when (slot 14 stays re-keyable until then).**

**Latest state (2026-10-25, bench in progress): flash + GenKey DONE.**
The Phase 5+ uf2 (215,040 B, `build/example/console/pico-atecc608.uf2`)
was flashed at the bench; `prov status` then confirmed: config zone
LOCKED + byte-identical to the approved plan (all SlotConfig/KeyConfig
values match, chip-zone CRC F6DE, lock bytes 55 00, SlotLocked FF FF,
counters 0/0), data zone UNLOCKED, and the littlefs check passed a
SECOND time live ("mounted existing (survived the last reflash)" +
"/io_key.bin: present and valid"). `prov genkey` then succeeded on all
six ECC slots — 1, 3, 4, 5, 6, 12 — each printing a 64-B public key
(X || Y big-endian; the private keys never leave the chip). **All six
public keys were verified host-side as valid, distinct points on the
P-256 curve** (Y² = X³ − 3X + b mod p, X,Y < p) — a garbled or
truncated key would fail this with probability ≈ 1 − 2⁻²⁵⁶, so the
printed values are what the chip holds. They are re-fetchable at any
time (even after the data-zone lock) with `prov pubkey <slot>`. The
chip now holds fresh P-256 pairs in every ECC private slot the config
allows: slot 1 (device identity), slots 3–6 (FIDO2 pre-generation —
4 resident credentials max; `MakeCredential` assigns the next unused
one), slot 12 (spare pair).

**ECC public keys generated 2026-10-25 (record of choice; private
keys on-chip only):**
- **slot 1 (device identity):**
  `1E E5 07 EC FC 0D B2 10  35 54 32 BC 2E 63 AB 84  36 C3 04 F8 C9 54 73 95  7F 02 C4 BF 57 A2 C9 4E`
  `DF B3 A3 A2 2D 3E 00 8E  89 B8 82 BA 28 9D C0 E5  96 2D BE F9 90 79 00 DE  22 41 9F A0 AC 2D 1A DB`
- **slot 3 (FIDO2 pre-gen 1):**
  `82 B4 7D 03 D3 11 A5 06  DB E7 7B 00 AD 09 BC 31  DC 54 EF AC 19 0C CB 12  48 C3 25 81 CD 33 02 F6`
  `D0 B8 C8 8A A9 D8 B3 40  6C 74 FA 4B 76 61 20 5C  F4 54 05 C1 95 D0 CC 8C  3E E0 7A 17 A1 4B 69 00`
- **slot 4 (FIDO2 pre-gen 2):**
  `63 1C E7 86 3B 57 38 C4  AA C3 DC F1 D7 51 69 45  BA E5 BE 47 1B D3 91 9C  32 36 81 87 A6 D8 BD 14`
  `14 A7 25 76 9F FE 6B 96  2B BF 2D CB D6 94 F4 66  46 2B E6 A2 EA 75 38 59  EE 00 2D 3E 0D 83 3C 7E`
- **slot 5 (FIDO2 pre-gen 3):**
  `14 C5 66 85 EF 86 E3 2E  60 20 DC 09 9C E1 21 83  2D 0C 95 7C CE A0 C8 4B  7A 52 44 95 89 7D BF A7`
  `5F A0 76 8E FC 9B 4B DD  AF 6D 45 BF FB FB 6B AE  4B 56 0D 07 1C AB 38 8C  8E 5B 4F 83 77 22 B2 B4`
- **slot 6 (FIDO2 pre-gen 4):**
  `23 0A 88 5B 6D 79 44 1A  53 CF 18 3A B2 F5 ED 3E  8D DD D8 F7 7A 6E 0C 92  81 E8 37 0B 05 53 5B F0`
  `E6 93 23 8C 36 AD 9C 9D  BA 9B AE E0 7F 25 11 73  6F C7 C8 60 46 12 C0 71  3D EE E7 D8 42 0B FD EB`
- **slot 12 (spare pair):**
  `1F BB 53 79 05 9B FD 17  2C 7F 25 A1 6E EC 7E C6  BA EA 85 5F 69 0D 73 E9  A0 93 F2 AB 2B 39 DF 92`
  `25 3F 69 9B 4E E2 50 BE  AF 24 5C 5A A7 7E CA 6A  EA 9E BB 6B 1F FF 7F 3A  EC 43 59 7A 21 0F 93 63`

**`prov lockdata CONFIRM` was EXECUTED (2026-10-25 — one-way, byte 86;
outcome in the next paragraph).** After it: fresh GenKey (mode 0x04)
is permanently refused, but `prov pubkey <slot>` keeps working (mode
0x00) and plain slots stay writable; the KDF target=output gate is
satisfied by the lock.

**Latest state (2026-10-25, bench continued): data zone LOCKED;
iokeytest PASSED (fixed build flashed) — the I/O key is functionally
VERIFIED end-to-end; the earlier failure was the test's premise (chip
enforces I/O encryption), NOT a key mismatch.**
- `prov lockdata CONFIRM` executed at the bench (one-way, byte 86;
  re-read-verified: "data zone LOCKED (irreversible)"). The first real
  `prov iokeytest` run (the −12 gate is gone; the KDF executes) FAILED
  with "decrypted KDF != clear KDF". The firmware's "key mismatch"
  conclusion was NOT proven by that symptom — three candidates: (A)
  chip key ≠ file key; (B) the chip did not encrypt the enc call; (C)
  the chip ENFORCED encryption on the clear call; plus (E) file key ≠
  the recorded key (the file's CRC proves integrity, not identity).
- **Verdict (instrumented run + host keystream reconstruction): (C),
  and ALL keys match.** The instrumented run (one shared tempkey
  nonce, raw enc output + both response nonces captured, file key
  printed) showed: (1) the CLEAR response carried a trailing 32-B
  nonce — the chip encrypted the clear call AGAINST THE REQUEST; (2)
  the printed file key is byte-identical to the recorded durable key
  (E excluded); (3) the host recomputed `atcah_io_decrypt` exactly
  (per 32-B block: XOR with `SHA256(io_key ‖ 16-B nonce half)` — NOT
  AES) and BOTH `enc ⊕ H(K_file, N_enc) == decrypted` and
  `clear ⊕ H(K_file, N_clear) == decrypted` held (accidental equality
  probability ≈ 2⁻²⁵⁶). Therefore the chip's slot-14 I/O key == the
  file key == the recorded key, the chip applies it correctly, and the
  Pico decrypts with the saved key: **the I/O key is functionally
  verified and the I/O-protection path works end-to-end.** The first
  failure was ciphertext (the "clear KDF") compared with plaintext.
- **Open datasheet item RESOLVED by bench evidence: with `kdf_prot=1`
  this chip ENFORCES I/O protection on KDF — EVERY target=output KDF
  returns encrypted data + a 32-B response nonce.** (Microchip's
  reference test only works with `kdf_prot=0`, where the plain call
  is plain.) Related finding: `atcab_nonce` is a PASS-THROUGH
  nonce-LOAD (the buffer's CONTENTS are what tempkey gets), not random
  generation — the reference test's "fresh nonce" is actually its fixed
  buffer pattern, which is why its two calls share a PRF input.
- **Fix (this build):** `provIokeyTest`'s PASS criterion now decrypts
  the clear copy with the saved key when the clear response carries a
  nonce (enforced mode), then compares; with no nonce it reduces to
  the original direct compare — correct under BOTH semantics; a true
  key mismatch still fails with probability 1 − 2⁻²⁵⁶. The tempkey
  input is Pico-TRNG random, shared by both calls (a prerequisite of
  the comparison).
- **Phase 7 consequence:** every KDF with target=output from this chip
  (including the vault's slot-7 KDF) must be `atcah_io_decrypt`-ed
  with the I/O key from /io_key.bin before use — the agreed
  "kdf_prot=1 (derived key never in clear on the bus)" setting is
  exactly this behavior.
- **`prov iokeytest` PASSED (2026-10-25, fixed build `0130207`
  flashed):** "I/O key test PASSED: slot 14 matches /io_key.bin and
  the I/O-protection path works end-to-end" + the enforced-mode NOTE
  (both KDF outputs arrived encrypted; both decrypted with the saved
  key). Full run values (record of choice): tempkey nonce
  `85 6C 17 99 14 FF 11 F9 F4 6C 0E F7 6D AA 90 71 4F 81 3D D4 F7 92 42 51 A5 03 0E 19 38 F1 31 23`;
  clear KDF `08 A8 6D C4 A1 4F 6C 9F D2 2D 8A 98 6E 71 AF 55 44 55 87 41 31 C0 B4 4F 01 49 A2 84 C9 43 4E B6 EE 47 FC CD 72 25 CC 89 FF 39 1D F6 6E DA 4E 8F E7 ED EE AF F3 E3 86 2E A6 46 9E 53 47 43 AF C3`;
  clear resp nonce `9D EE F2 6A 92 78 F7 D6 91 95 A4 38 C8 28 24 2D F8 E1 58 D4 DE 5A 8F 0F 33 EF 6C F7 56 C2 37 A4`;
  enc KDF raw `80 A2 77 67 EA 20 48 87 3B 2F A9 9F 3F AA 2B 50 D8 3B 0D 8E 79 9B 7F 93 40 DD A1 52 59 33 1C 86 5C 82 64 56 2B D0 05 1C 3F 94 7D 9D C2 28 8F 83 77 DE 5E 1F 22 02 A8 3F 60 F4 61 08 E5 16 20 8F`;
  enc resp nonce `57 B1 B1 3A 03 9A D6 35 1B 46 DD 08 AD 7E D8 CD A1 00 70 2B 5A D2 05 31 5A 80 ED 67 7E CD 4B 29`.
  **Host cross-check (same H(K,N) recipe): both calls decrypt to the
  SAME true PRF output — PASS independently confirmed:**
  `54 2C B9 5B 04 45 43 7A D3 93 23 19 DC 28 3E 29 0D F9 1F 66 18 71 A0 F7 BF 85 B2 6F 8C E8 0D B1 B4 35 AE A0 40 C4 D7 60 B7 4B BA 95 DE 98 4B 33 6F 89 BF 5C 5C 4B B1 68 32 C2 91 44 E4 4E AC 1A`.
- **Bench sequence status: ALL DONE (2026-10-26)** (flash, status,
  genkey ×6, lockdata, iokeytest PASS, `prov kdf 7` wrapper round-trip,
  `prov lockslot 14 CONFIRM`). Slot 14 is now LOCKED (SlotLocked
  FF BF — only the slot-14 bit cleared; one-way, verified by re-read)
  — the chip config is frozen for production: no ECC re-gen (data zone
  locked), no I/O-key change (slot 14 locked). (Historical note:
  before the slot-14 lock, slot 14 stayed re-keyable — a 32-B write to
  a non-individually-locked slot stays allowed with the data zone
  locked; `prov iokey` itself would refuse — its precondition still
  says the data zone must be unlocked — so re-keying would have needed
  a new command.)

**Latest state (2026-10-26): the Phase 5 KDF wrapper is IMPLEMENTED +
host-tested; the console gains read-only `prov kdf <slot>`; the uf2 is
rebuilt — NOT yet on the chip (the `0130207` build was live then;
superseded — see the newest paragraphs).**
- `atecc608_kdf_prf(slot, nonce, msg, msg_len, io_key, out)` in
  `include/atecc608/atecc608_crypto.h` + `src/atecc608_crypto.c` (NOT
  added to atecc608.h, which is not host-testable — the prov-header
  pattern): PRF mode, source = data slot `slot`, target = output, 32-B
  derived value; details word = PRF key-len 32 | target-len 32 | AEAD
  mode 0 | msg_len<<24. The TempKey nonce is loaded (pass-through —
  the buffer's CONTENTS go into tempkey) right before the KDF; the
  caller supplies it (NULL = 32 bytes of zero). A FIXED nonce is what
  makes the output DETERMINISTIC — the vault must re-derive the same
  key on every unlock, so uniqueness comes from msg (salt ‖ PIN ‖
  context); a random nonce per call would derive a different key every
  time.
- Enforced I/O-protection detection: `resp_nonce` is ZERO-INITIALIZED
  and the library fills it only if the response carried a trailing
  nonce (calib_kdf.c copies it out only when the response is long
  enough); ANY non-zero byte ⇒ the output arrived encrypted ⇒ `io_key`
  is required (else ATECC608_ERR_BAD_PARAM — the value cannot be
  recovered) and the 32 B are decrypted IN PLACE with
  `atcah_io_decrypt` (SHA256 keystream XOR — declared in
  `lib/host/atca_host.h`, NOT via cryptoauthlib.h; include it
  explicitly). With a chip that does not enforce I/O protection the
  response carries no nonce, the data is already clear, and io_key is
  unused (may be NULL). The zero-init is load-bearing: an
  uninitialized resp_nonce gave a false "encrypted" detection →
  spurious ATECC608_ERR_BAD_PARAM (found + fixed while writing the
  host tests).
- Mock (`tests/mock_chip.{h,c}`): NONCE (0x16, pass-through load of the
  32-B payload into tempkey) and KDF (0x56, PRF / source-slot /
  target-output only; gates: data zone locked + slot ≤ 15 + KeyConfig
  ≠ 0) handlers; deterministic fake PRF
  `out[i] = key[i%32] ^ nonce[i%32] ^ msg[i%msg_len] ^ i`; the
  I/O-protection OUTPUT side (kdf_prot=1: encrypt the 32-B output +
  append a 32-B response nonce, via the symmetric `atcah_io_decrypt`
  with a deterministic non-zero nonce) is toggled with
  `mock_chip_set_kdf_io_prot` / `mock_chip_clear_kdf_io_prot`. The
  request direction is NOT modeled (documented in mock_chip.h).
  `MOCK_MAX_RESP` bumped 75 → 99: the KDF response is 32-B target +
  32-B nonce framed (the real chip does the same; the library buffer
  CA_MAX_PACKET_SIZE=198 fits; ATCA_RSP_SIZE_MAX=75 only covers
  GenKey/Verify).
- New host test `tests/test_crypto.c` (t_kdf_gate / t_kdf_basic /
  t_kdf_io_prot / t_kdf_source_slot / t_kdf_params — 51 checks, 0
  failures): gate refusal (data zone unlocked), deterministic
  re-derivation, enforced mode (decrypts with the right key; refuses
  without an io_key), source-slot config gate, bad params. The test's
  `fake_prf` mirrors the mock formula — keep in sync if either
  changes. ctest 3/3 green (test_config, test_prov, test_crypto).
- Build wiring: `src/atecc608_crypto.c` added to the `atecc608` lib
  (top `CMakeLists.txt`) and to `atecc608_host` (+ the new
  `test_crypto` target) in `tests/CMakeLists.txt`.
- Console (`example/console/main.c`): `prov kdf <slot>` (READ-ONLY —
  NONCE + KDF only, safe under the HARD RULE): fixed ZERO nonce, fixed
  16-B message 0x00..0x0F (same as iokeytest) → the output is
  deterministic; the I/O key is loaded from /io_key.bin (iokeytest's
  inline loader was factored into `load_io_key_file()`, now shared by
  `prov iokeytest` and `prov kdf`); prints the 32-B derived value +
  "run it again: identical output = deterministic". Help + usage +
  top-of-file command list updated; the old "the module API has no KDF
  wrapper yet" comment is updated (iokeytest still uses the raw
  command — it needs the 64-B target + the opt-in enc variant the
  curated 32-B wrapper does not cover).
- uf2 rebuilt: `build/example/console/pico-atecc608.uf2`, 218,112 B
  (Pico build green; warning-clean apart from the known cosmetic
  ATCA_TA_SUPPORT note).

**BENCH DONE (2026-10-26): the Phase 5 KDF round-trip is VALIDATED ON
HARDWARE — the done criterion is met.** The rebuilt uf2 was flashed
and `prov kdf 7` was run twice — both runs printed the SAME 32 bytes
(record of choice):
`6F FF 7D D6 41 75 60 3F  83 05 CE A6 20 F0 B9 32  57 29 50 26 D9 B4 DF 6B  CC 8D 6C 9D C1 31 4C 65`
What the run proves: (1) the WRAPPER works end-to-end on the real
chip — command framing (mode/details words), parsing of the 96-byte
encrypted response (32-B target + 32-B nonce + overhead), the zero-init
encrypted-detection, and the in-place `atcah_io_decrypt` with the
/io_key.bin key; (2) DETERMINISM — fixed zero nonce + fixed message →
identical re-derivation, the vault's core requirement; (3) slot 7 is
an acceptable KDF source in the locked config. The I/O key used is the
one iokeytest already functionally verified (wrong-key margin 2^-256).
**Host cross-check NOTE (why the value is not host-computable):** the
datasheet names PRF mode = the TLS 1.2 PRF (RFC 5246, P_SHA256), but
the exact (secret, label, seed) mapping of the command's (key, nonce,
msg) inputs is NOT public ("contact Microchip Sales"); nine host
recomputation candidates with slot 7's known-zero key (HMAC-SHA256
with nonce‖msg / msg‖nonce seeds, SHA-256 concatenation, plus
role-swapped, counter-byte and unkeyed variants) do NOT match the
printed value. The verdict therefore rests on
determinism + the verified I/O key + the exercised wrapper path — NOT
on a host model of the PRF. Do not "fix" the wrapper to match any such
model; there is none. **Remaining bench item: `prov lockslot 14
CONFIRM` (PRODUCTION ONLY — APPROVED by the user 2026-10-26; see the
next paragraph for the bench order).**

**Latest state (2026-10-26, after the KDF bench): Phase 6 BUILT —
decoded config read-back demo (`config`) + dev-only `prov iokeyshow`;
uf2 rebuilt 226,304 B (`84edf05`); that build is now LIVE on the chip
(reflashed 2026-10-26 for the bench steps in the next paragraph).**
- Phase 6 demo: top-level `config` in `example/console/main.c` — reads
  the zone with the module API (`atecc608_read_config_zone`) and decodes
  it with the Phase 4A builder (`atecc608_config_parse`): I2C address,
  lock bytes, SlotLocked + locked-slot list, ChipOptions, ChipMode,
  UseLock/VolKeyPerm/SecureBoot/KDF-IV/UserExtra/X509, decoded
  counters, and the per-slot policy table (raw SlotConfig/KeyConfig
  words + decoded flags, "slot policy | key policy"). READ-ONLY; a demo
  of the module API, not a provisioning tool (`prov status` keeps the
  raw dump + planned-image diff). The printer was host-verified against
  the agreed dev_config intent (build → parse → print; every slot
  decodes to the agreed layout: 1/12 secret+ext-sig+ecdh+gen-key,
  3–6 secret+ext-sig+gen-key, 7–10/14 secret non-ECC lockable, 0/11
  lockable ECC pubs).
- `prov iokeyshow` — DEV-ONLY (the command, its help line and its
  output all say so; a production application must not expose the I/O
  key on the console): reads /io_key.bin (magic/len/CRC-32 checked) and
  prints the 32-B key so the operator can compare it against the
  out-of-band durable copy (the `prov iokey` console print / dev notes).
  Chip-free (littlefs read only).
- uf2 rebuilt: `build/example/console/pico-atecc608.uf2`, 226,304 B
  (Pico build green, warning-clean apart from the known cosmetic
  ATCA_TA_SUPPORT note; host tests 3/3).
- **Bench order (user action) — ALL EXECUTED 2026-10-26:** flash the
  226,304 B uf2 → `prov iokeyshow` (compare with the dev notes) →
  `prov lockslot 14 CONFIRM` (one-way, SlotLocked slot-14 bit FF→00;
  after this the chip config is frozen for production) → `config`
  (Phase 6 demo, read-only; closes the Phase 6 done criterion).
  Results in the next paragraph.

**BENCH DONE (2026-10-26): the bench sequence is COMPLETE —
`prov lockslot 14 CONFIRM` EXECUTED (the production-only one-way step)
and the Phase 6 `config` demo RAN ON HARDWARE. The Phase 6 done
criterion is MET; the chip config is frozen for production.**
- `prov lockslot 14 CONFIRM`: "slot 14 LOCKED (irreversible; verified
  by re-reading SlotLocked)". SlotLocked is now **FF BF** (byte 88 =
  FF: slots 0–7 all unlocked; byte 89 = BF: only the slot-14 bit
  cleared) — exactly the expected one-bit change. Consequences: no ECC
  re-gen (data zone locked), no I/O-key re-key (slot 14 locked); the
  chip config is frozen for production.
- `config` (Phase 6 demo, first hardware run): the decoded zone
  matches the agreed plan in EVERY field — I2C 0xC0 (7-bit 0x60), lock
  bytes 00 00 (config + data locked), ChipOptions (I/O protection ON,
  key slot 14; KDF AES on; ecdh_prot=1 forced; kdf_prot=1 forced; POST
  off), CountMatch/UseLock/VolKeyPerm/SecureBoot off, KDF IV source
  location 0 slot 0, UserExtra 00/00, X509 00 ×4, counters 0/0 (KDF and
  NONCE do not touch the counters — as expected), and all 16 slot rows
  are byte-identical to the host-verified layout (1/12
  secret+ext-sig+ecdh+gen-key, 3–6 secret+ext-sig+gen-key, 7–10/14
  secret non-ECC lockable, 0/11 lockable ECC pubs, 2/13 ECC-pub
  pub-info, 15 plain non-ECC). The demo works end-to-end on the real
  chip through the module API.
- The 226,304 B uf2 (`84edf05`) is the firmware LIVE on the chip.
- `prov iokeyshow` output CONFIRMED to match the user's out-of-band
  dev notes (2026-10-26, confirmed in chat): the littlefs copy, the
  console print in the state list above, the dev notes, and slot 14 on
  the chip are all the same key.

**Latest state (2026-10-26, Phase 7.1): the `selftest` command is
BUILT — the read-only on-hardware validation suite (generic
invariants, sub-step 7.1). Awaiting its first hardware run (the 7.4
bench).**
- `selftest` (top-level console command; READ-ONLY — safe on the
  frozen production chip, HARD RULE compliant): 8 ordered checks,
  `[PASS]/[FAIL]` + one detail line each, final verdict (`SELFTEST:
  n/n checks PASSED` or the failure count): (1) probe + info (wake
  ok, part 0x60 rev 5 — a dead chip aborts the suite); (2) random ×2
  (not the 0xFFFF0000 factory pattern, fetches differ); (3) config
  zone (parse ok, lock bytes 00 00, SlotLocked FF BF, I2C 0xC0,
  writable region byte-identical to the agreed dev_config image — the
  planned-image diff is 0); (4) counters 0/0 via
  `atecc608_counter_read` (first hardware exercise of that API);
  (5) the six ECC public keys (slots 1, 3–6, 12) via
  `atecc608_get_pubkey` — 64 B, non-zero, pairwise distinct; (6) two
  `atecc608_kdf_prf` (slot 7, zero nonce, msg 00..0F) identical;
  (7) the I/O-key round-trip (slot 14 == /io_key.bin, quiet form);
  (8) littlefs volume mounted at boot + /io_key.bin valid
  (magic/len/CRC-32).
- Refactor (single source of truth for the round-trip procedure): the
  I/O-key round-trip is now `iokey_roundtrip(verbose, detail, size)`
  — `prov iokeytest` is its verbose form (same prints as before,
  including the lock-state context), `selftest` the quiet form. The
  quiet `iokey_file_valid()` (magic/len/CRC-32, reason in `detail`)
  backs both `load_io_key_file()` (printing) and the selftest's own
  [FAIL] detail lines.
- **Scope fix (PLAN.md, 2026-10-26):** the config-zone CRC is NOT a
  generic invariant — `atecc608_config_crc16` covers the whole 128-B
  zone including the chip-unique factory region (serial), so the CRC
  is chip-specific and moved to the bench-chip goldens. The recorded
  F6DE was the PRE-DATA-LOCK value (lock bytes 55 00); after
  lockdata + lockslot 14 the zone changed at byte 86 (55→00) and byte
  89 (FF→BF). The CURRENT fully-locked zone CRC is **C904**,
  host-computed 2026-10-26 from the recorded factory bytes (0–15,
  the pre-write dump above) + the dev_config image + the current lock
  bytes/SlotLocked. The reconstruction was verified against BOTH
  recorded CRCs first: post-write (55 55 / FF FF) → **CDC7** ✓ and
  config-locked-only (55 00 / FF FF) → **F6DE** ✓ — so C904 is
  byte-exact and is the 7.2 golden.
- Build: uf2 `build/example/console/pico-atecc608.uf2` 233,984 B
  (`0242df2`), Pico build warning-clean apart from the known cosmetic
  ATCA_TA_SUPPORT note; host tests 3/3. The 226,304 B build
  (`84edf05`) is still LIVE on the chip until the 7.4 bench reflash.

**Latest state (2026-10-26, Phase 7.2 + 7.3 BUILT): `selftest` full
mode (bench-chip goldens) and `docs/BRINGUP.md` are in. Only the 7.4
bench run remains — Phase 7 is one user action from COMPLETE.**
- 7.2 (`c1708f6`): the `BENCH_*` golden table at the top of the Phase 7
  section of `example/console/main.c` (dev-only, NOT the library):
  serial `01 23 06 40 AE B6 B9 B7 EE`, the six recorded ECC public keys
  (slots 1, 3–6, 12), the slot-7 KDF value `6F FF 7D D6 …`, and the
  fully-locked config-zone CRC `C904`. `selftest` (full mode) now runs
  the 8 generic invariants and then 4 golden checks (serial, six
  pubkeys, KDF value, config CRC) — HARD FAIL on any mismatch: the
  regression gate proving the chip in front of you IS the recorded
  bench chip, not just a correctly provisioned one. `selftest generic`
  runs the invariants only (a fresh chip during bring-up; unknown extra
  arguments are rejected with a usage line). The golden section reuses
  data the generic checks already fetched (the zone for the CRC, the
  first KDF derivation, the six public keys); a failed generic fetch
  shows up in the golden as its own failure (e.g. a zeroed pubkey slot
  mismatches), never as a read of uninitialized memory.
- **Golden transcription verified host-side (2026-10-26):** a script
  parsed both the `BENCH_*` table in main.c and the RESUME.md
  record-of-choice entries and compared byte-for-byte — all six 64-B
  public keys, the 9-B serial, the 32-B KDF value, and the CRC match.
- 7.3 (`0d312a5`): `docs/BRINGUP.md` — the reusable fresh-chip
  checklist: wiring table, flashing, first-boot expectations on a
  factory-fresh chip (the `0xFFFF0000` RNG pattern is EXPECTED while
  the config is unlocked; `selftest generic` fails by design on a fresh
  chip — it validates a PROVISIONED chip), the proven provisioning
  sequence in the exact bench order with the order constraints
  explained (`prov iokey` after the config lock — data-zone writes are
  gated on it; `prov genkey` before `prov lockdata` — fresh GenKey is
  refused once the data zone locks; `prov iokeytest` after — the KDF
  −12 gate; `prov lockslot 14` LAST and PRODUCTION ONLY), per-chip
  golden recording (a new chip's CRC differs from C904 — the CRC
  covers the chip-unique factory region), the known failure modes
  (wake NACK, the littlefs flash-lockout bug `d1778af`, the KDF −12
  data-zone gate, the 0xFFFF0000 pattern, the reflash/littlefs
  interplay — a uf2 reflash never touches the volume at 0x80000, only
  a full-flash erase does), and the dev-chip note: stop before
  `lockslot 14` and expect exactly ONE selftest difference
  (SlotLocked `FF FF` vs `FF BF`). Pointers added to example/README.md
  (console section + locking-discipline section).
- Build: uf2 now 238,080 B (`c1708f6`), Pico build warning-clean
  apart from the known cosmetic ATCA_TA_SUPPORT note; host tests 3/3.
  The 226,304 B build (`84edf05`) is still LIVE on the chip.
- **7.4 bench run (user action, closes Phase 7):** flash the 238,080 B
  uf2 → `selftest` — expect **12/12 PASS** (8 generic + 4 goldens);
  optionally `selftest generic` (expect 8/8). Read-only throughout —
  HARD RULE safe. If any check FAILs, the detail line names it; do NOT
  re-provision — bring the output back.

**BENCH GREEN (2026-10-26, 7.4): Phase 7 is COMPLETE — `selftest`
12/12 PASS and `selftest generic` 8/8 PASS on the chip.**
- `selftest` (full, first hardware run of the suite): ALL 12 checks
  PASS — probe+info (part 0x60 rev 5), random (real TRNG, fetches
  differ), config zone (00 00 locks, SlotLocked FF BF, I2C C0, zero
  writable-region diff vs the agreed image), counters 0/0 via
  `atecc608_counter_read` (first hardware exercise of that API —
  correct), six ECC pubkeys (non-zero, pairwise distinct), kdf
  determinism, io key round-trip, littlefs ("volume survived the last
  reflash, /io_key.bin valid"), and the four goldens: serial, all six
  pubkeys, the KDF value `6F FF 7D D6 …`, and **config CRC C904 —
  confirming the host-computed golden on the real chip** (the
  factory-bytes + agreed-image reconstruction is proven byte-exact end
  to end).
- `selftest generic`: 8/8 PASS (invariants only, goldens skipped —
  the mode switch works).
- The 238,080 B uf2 (`c1708f6`) is the firmware LIVE on the chip.
- **All seven phases are COMPLETE.** The chip is provisioned, frozen
  for production, and now regression-gated: any future `selftest` run
  on it must stay 12/12 — a golden mismatch means the chip in front of
  you is not the recorded bench chip, or the config drifted.

**Latest state (2026-10-26, night — `vault` example WIP, host KATs
RED, two bugs diagnosed + fix plan written down):** the user asked for
a console-based PIN-gated password-store demo in `example/vault/`
alongside the console ("basic components … stored password encryption
and decryption", the ATECC608 as KDF master — this supersedes the
earlier "vault = separate repo" note; the PLAN.md scope note is still
to add).
- **Design (implemented):** the chip is the KDF master only (no bulk
  crypto on the chip): `derived = atecc608_kdf_prf(slot 7, NULL
  nonce, salt[16] ‖ PIN-ascii, io_key, key[32])`; wrong PIN ⇒ wrong
  key ⇒ GCM tag failure. AES-256-GCM is pure-C demo code in
  `example/vault/vault_gcm.{h,c}` (this pico-sdk fork 2.3.1 has NO
  `hardware_crypto` module; forward-only AES-256). Storage: FLAT
  littlefs `/v_<name>` (littlefs has no mkdir; the `v_` prefix at the
  root next to `/io_key.bin`, `list` filters it), fixed 96-B entry =
  magic `'VAU1'` + salt[16] + nonce[12] (one 28-B `atecc608_random`)
  + pt_len u32 + ct[40] + tag[16] + crc32 (standard reflected, over the
  preceding bytes); AAD = entry name; `add` overwrites with fresh
  salt+nonce. Commands: `add <name> <pin> <password>`, `get <name>
  <pin>`, `list`, `rm <name>` (+ `help`/`probe`/`bootrom`); limits:
  name `[A-Za-z0-9._-]` 1..16, PIN 1..24, password 1..40 no spaces.
  Startup contract mirrors the console: probe + config AND data zone
  locked + valid `/io_key.bin` (shared `example/common/iokey_file.h`);
  never provisions. Wrong PIN vs corrupt entry are NOT distinguished;
  a CRC pre-check reports "corrupt … rm and re-add".
- **Files (all written):** `example/common/iokey_file.h` (shared
  `/io_key.bin` layout, pure C — the console was refactored onto it,
  behavior identical, selftest must stay 12/12), `example/vault/{
  vault_gcm.h, vault_gcm.c, main.c, CMakeLists.txt}`,
  `tests/test_vault_gcm.c` (12 host checks). CMake: littlefs hoisted to
  `example/CMakeLists.txt` (target names are build-wide unique — a
  per-app `add_subdirectory(pico-littlefs)` was the collision that
  killed the last Pico build attempt; console/vault CMakeLists keep
  only the link + comment), `COMMAND_LINE_LEN=128` INTERFACE
  definition (max vault line 86 ≤ 128), new test target in
  tests/CMakeLists.txt (compiles `vault_gcm.c` directly, no
  cryptoauthlib link).
- **Crypto validation state:** the Python GCM reference model is
  FULLY VERIFIED (5 GCM vectors + 2000-pair `gf_mult` cross-check
  against a CARRYLESS-POLYNOMIAL integer reference — the earlier
  "reference" failed because Python integer mult + `%` is carry
  arithmetic, not GF(2)); the 16 S-box rows were generated by a
  verified script; `gf_mult` convention = read X's bits directly from
  the original (bit k = position k from the left = coefficient of
  x^k, NO shifting of X), V = Y advances by right-shift with the 0xE1
  reduction into the LEFTMOST byte when the shifted-out LSB is set.
  All test vectors in `tests/test_vault_gcm.c` are OpenSSL-verified —
  trust them (zero-key empty tag `530f8afbc74536b9a963b4f1c4cb738b`;
  16-B PT CT `cea7403d…` tag `d0d1c8a7…`; 32-B CT + `726003ca…` tag
  `d1d3084c…`; FEFF-key/IV `cafebabefacedbaddecaf888` 64-B vector;
  AAD variant tag `2df7cd67…`; zero-key H = E(0^16) =
  `dc95c078a2408989ad48a21492842087` — NOT F32C7EEB…).
- **Bugs found + fixed this session:** (1) `gf_mult(X, H, X)`
  aliasing — the `memset(Z, 0)` + accumulation destroyed the aliased
  X; fixed with a local copy `xb[16]` in `gf_mult`. (2) xtime — my
  first "fix" was itself still wrong (see bug 1 below).
- **Host ctest right now: `test_vault_gcm` 5/12 PASS** — FAIL 1–6
  (all NIST KATs, incl. the empty tag ⇒ E(J0) wrong) + FAIL 11 (33-B
  round-trip); PASS 7, 8, 9, 10, 12 (size rejections + tamper /
  wrong-key rejection). The other 3 host tests are green. Progression
  sanity: pre-fix FAIL {1–5, 9, 10} / PASS {6,7,8,11,12}; post-fix
  FAIL {1–6, 11} / PASS {7,8,9,10,12}. The Pico firmware build has NOT
  yet been run with the vault in (last attempt died at the CMake
  littlefs collision, now fixed).
- **TWO BUGS REMAIN — both diagnosed (fixing them is tomorrow's job
  #1):**
  1. `xtime()` (`example/vault/vault_gcm.c` ~line 59): `uint8_t m =
     (uint8_t)(-(int)(a & 0x80u));` — with the high bit set,
     `-(int)(128) = -128`, which truncates to uint8_t as **0x80, NOT
     0xFF** → `0x1b & 0x80 = 0` → the 0x1B reduction is NEVER applied
     (MixColumns silently does `a << 1`). Same bug family as the
     original: an all-ones mask requires the TESTED BIT to be the LSB
     of the sign computation. Fix: `uint8_t m = (uint8_t)(-(int)(a >>
     7));` → 0 or -1 → 0x00 or 0xFF.
  2. `gcm_core` (~line 186) hashes the WRONG data on the decrypt path:
     it always GHASHes `blk = in ^ ks`. Encrypt: in = pt ⇒ blk = ct
     ✓. Decrypt tag check: in = ct ⇒ blk = ct ^ ks = **PT** ✗ — GCM
     requires GHASH over the CIPHERTEXT. This is why the round-trip
     (11) started FAILING exactly when the gf_mult fix made the tag
     data-dependent (before it, X stayed 0 and every tag was the same
     constant, so 11 "passed").
  After both fixes, all 12 should pass: KATs 1–6 are encrypt-side
  (xtime suffices), 11 + the 64-B decrypt round-trip need the gcm fix,
  7–10 + 12 already pass.
- **Fix plan (tomorrow, in order):** (a) restructure: split gcm_core
  into `ctr_xcrypt(key, nonce, in, len, out)` (out = in ^ ks,
  keystream from counter 2) + `gcm_tag(key, nonce, aad, aad_len, ct,
  ct_len, tag)` (H, J0, ekJ0; GHASH over the RAW ct blocks — no
  keystream inside); encrypt = ctr_xcrypt then gcm_tag over ct;
  decrypt = gcm_tag over raw ct → constant-time compare → ctr_xcrypt.
  (b) fix xtime as above. (c) host ctest → expect 4/4 (12/12 vault
  checks). (d) Pico `cmake --build build -j` — both `pico-atecc608`
  and `pico-atecc608-vault` warning-clean (known cosmetic
  ATCA_TA_SUPPORT ignored). (e) Docs: vault section in
  example/README.md (slot-7-zero note, commands, flat naming, `get`
  echoes the password — bench-demo caveat), PLAN.md scope note,
  RESUME.md. (f) commit. (g) bench procedure for the user: flash the
  vault uf2 (`/io_key.bin` survives a reflash), then `add` / `get` /
  `list` / `rm`.
- **Debug harness recipe (only if the fixes don't land cleanly):**
  throwaway host file with `#include "vault_gcm.c"` (pulls in the
  statics); spot-check `sbox[0]/[1]/[0x10]/[0xff] = 63/7c/ca/16`;
  `E_K(0^16)` with the zero key must be
  `dc95c078a2408989ad48a21492842087`; `E(J0)` =
  `530f8afbc74536b9a963b4f1c4cb738b`; FIPS-197 C.3 (key 00..1f, PT
  00112233…ff → CT `8ea2b7ca516745bfeafc49904b496089`).
- **Chip: FROZEN, untouched by this work** (vault runtime = KDF + RNG
  only — no chip writes; HARD RULE observed; slot 7 is all-zeros on
  the bench chip — use as-is, never re-key). The uf2 LIVE on the chip
  is still the console 238,080 B (`c1708f6`).
- **WIP committed at this pause** (single commit of the vault files +
  console refactor + CMake + test + this RESUME update; the commit
  message says the host KATs are red on purpose, two diagnosed bugs)
  so the night cannot lose the work.

**Latest state (2026-10-27): the two diagnosed GCM bugs are FIXED —
host ctest 4/4 GREEN, both Pico uf2s warning-clean, docs in, committed.
Only the bench demo run remains (user action).**
- **Bug 1 (xtime):** the mask `(uint8_t)(-(int)(a & 0x80u))` yields
  0x80 (not 0xFF) when the high bit is set — `0x1b & 0x80 = 0`, so the
  reduction was never applied and MixColumns silently did `a << 1`.
  Fixed to the sign-bit form `(uint8_t)(-(int)(a >> 7))` (0 or -1 →
  0x00/0xFF), with a comment explaining the tested-bit-must-be-the-sign-
  bit requirement.
- **Bug 2 (decrypt GHASH over the wrong data):** `gcm_core` always
  GHASHed `blk = in ^ ks` — correct for encrypt (that is the
  ciphertext) but for the decrypt tag-check pass `in` is the ciphertext,
  so it hashed the *plaintext*. Restructured per the written plan:
  `gcm_core` split into `ctr_xcrypt(key, nonce, in, len, out)` (pure
  keystream XOR, counter 2 onward — no hashing) + `gcm_tag(key, nonce,
  aad, aad_len, ct, ct_len, tag)` (H/J0/ekJ0 + GHASH over the RAW
  ciphertext blocks + length block + `X ^ E_K(J0)`). Encrypt =
  ctr_xcrypt then gcm_tag over the fresh ct; decrypt = gcm_tag over the
  stored ct → constant-time compare → ctr_xcrypt. A small `gcm_j0`
  helper is shared. The decrypt path does two key expansions (tag, then
  xcrypt) — same cost class as the old double `gcm_core` call.
- **Host ctest: 4/4 GREEN (12/12 vault checks)** — the OpenSSL-verified
  NIST KATs (empty tag, 16/32/64-B ciphertexts + tags, AAD variant)
  and both round-trips now pass; test_config / test_prov / test_crypto
  unchanged and green. The KATs are ground truth, so the GCM is now
  externally-verified on the exact code the Pico runs (same translation
  unit on host and device).
- **Pico build:** both targets warning-clean (only the known cosmetic
  ATCA_TA_SUPPORT note from cryptoauthlib's own headers). The console
  uf2 is **238,080 B — the same size as the live `c1708f6` build**
  (the `iokey_file.h` refactor is behavior-identical, and the console
  source is unchanged by the fix, so the chip's live console is
  unchanged); the vault uf2 is **196,096 B**
  (`build/example/vault/pico-atecc608-vault.uf2`).
- **Docs:** `example/README.md` gains the "Vault example" section
  (division of labour, flat `/v_<name>` storage + entry layout, startup
  contract, command table, limits, the `get`-echoes-password and
  slot-7-all-zeros bench caveats) + a "What's here" bullet + the vault
  uf2 in the build list; `PLAN.md` gains the Goal scope note (the
  in-repo demo supersedes the "vault = separate repo" note) and the
  Phase 7 out-of-scope note is annotated.
- **Committed 2026-10-27** (fix + docs + this RESUME update; the WIP
  commit `d97214e` remains the audit trail for the diagnosed state).
- **Chip: FROZEN, untouched.** The console 238,080 B uf2
  (`c1708f6`) is still the firmware LIVE on the chip.
- **Bench demo run: GREEN (2026-10-27, user)** — the 196,096 B vault
  uf2 was flashed (BOOTSEL drag; `/io_key.bin` survived, as proven —
  the app region and the 0x80000 volume are disjoint) and `add` /
  `get` (correct PIN — the password came back) / `get` with a WRONG
  PIN ("wrong PIN or corrupted entry") / `list` / `rm` were all run
  and verified as expected by the user. The vault works end-to-end on
  the FROZEN chip: KDF (slot 7, target=output — the data zone is
  locked, so it works) + chip RNG + littlefs only — NO chip writes;
  HARD RULE observed.

**Latest state (2026-10-27, after the bench): the read-only `dump
<name>` command is BUILT (the plaintext-leak demonstration); the
counters question is answered (a wrong-PIN `get` touches NOTHING —
chip or Pico). Awaiting the reflash + `dump` bench run.**
- `dump <name>` (READ-ONLY — a littlefs read only; no PIN, no chip
  access; HARD RULE safe): prints the raw stored 96-B entry as TEXT —
  printable ASCII (0x20..0x7E) as-is, every other byte as `?` — in
  16-byte offset rows, with a layout legend
  ([0:4] magic | [4:20] salt | [20:32] nonce | [32:36] pt_len |
  [36:76] ct | [76:92] tag | [92:96] crc32) and a record summary
  (magic/pt_len/CRC — the same checks `get` uses before the tag
  check; a bad record is reported CORRUPT). The demonstration: the
  salt/nonce are in the clear BY DESIGN (random, not secret —
  uniqueness comes from salt ‖ PIN); the ct field — where the
  password is — must read as `?`-ish noise, and any plaintext leak
  would stand out as readable text. (Pure-hex was considered and
  rejected for this purpose — the point is visual.) Help + usage +
  top-of-file command list + the example/README vault command table
  updated.
- **Counters (user question, answered from bench evidence):** the
  wrong-PIN `get` did NOT affect any chip counter — the KDF and
  NONCE commands never increment them (selftest check 4: counters
  0/0 after many KDF runs; only the explicit COUNTER command moves
  them). The chip cannot even tell a wrong PIN from a right one — it
  derives whatever key `salt ‖ PIN` maps to; "wrong" is a Pico-side
  GCM tag failure. The agreed Pico-side brute-force lockout (littlefs
  fail count, "5 failures → locked until deliberate reset") is BY
  DESIGN but NOT IMPLEMENTED in this demo — so nothing is counted
  anywhere today (a possible follow-up if wanted).
- Build: vault uf2 now **203,776 B**, warning-clean (only the known
  cosmetic ATCA_TA_SUPPORT note); host ctest 4/4 (unchanged — `dump`
  lives in main.c, Pico-only). **The 196,096 B vault uf2
  (`b5bafaf`) is the firmware LIVE on the chip** (the user's bench
  flash); it will be superseded by the 203,776 B build when `dump`
  gets its bench run.
- **Bench run for `dump`: GREEN (2026-10-27, user)** — see the
  "BENCH GREEN (2026-10-27, dump)" paragraph below.

**BENCH GREEN (2026-10-27, dump): the plaintext-leak demonstration is
CONFIRMED ON HARDWARE — the vault demo is COMPLETE end-to-end.** The
203,776 B vault uf2 (`526c810`) was flashed (entries + `/io_key.bin`
survived the reflash). Record of choice (user):
```
add mytest 1234 asdf
stored 'mytest' (4 B password, fresh salt/nonce)
dump mytest
raw entry /v_mytest (96 B) as stored in flash — non-printable bytes as '?':
layout: [0:4] magic | [4:20] salt | [20:32] nonce | [32:36] pt_len
        [36:76] ct (the password, GCM-encrypted) | [76:92] tag | [92:96] crc32
  00: VAU1p?X??Q?~????
  16: ?????Un#Z g?^2??
  32: ????????????????
  48: ????????????????
  64: ????????????????
  80: X??{&au7I?<S????
record: magic OK, pt_len 4, CRC OK — the password text must NOT appear above
```
The ct region (rows 32–64 = bytes 32–75, i.e. pt_len + ct) is pure
`?` — the 4-B password "asdf" appears nowhere. The scattered
printables in the salt/nonce rows (00–16) are random noise, as
expected (≈37% of random bytes fall in the printable range —
0x20..0x7E of 256); the printables at the end of row 80 are tag /
crc32 bytes. `get mytest 1234` still returns the password
(user-confirmed). The 203,776 B uf2 (`526c810`) is the firmware LIVE
on the chip. **All vault commands (add / get / dump / wrong-PIN get /
list / rm) are now bench-verified on the frozen chip** — the demo
works end-to-end: KDF (slot 7, enforced I/O protection) + chip RNG +
littlefs, no chip writes.

**`prov iokeytest` was BUILT (`8aa8922`), flashed, and RUN (2026-10-24)
— it returned `clear KDF failed: ATCA_STATUS -12` (execution error) with
the data zone UNLOCKED: the KNOWN-RISK case, now CONFIRMED on the real
chip.** `prov iokeytest` is **READ-ONLY**: an I/O-protected KDF round-trip
(clear KDF vs the decrypted output-encrypted KDF, key read from
`/io_key.bin`); it issues no data-zone READ/WRITE and no write/lock, so it
is safe to run any time. The −12 is **NOT a key mismatch** — the ATECC608
gates the KDF (target=output) on the data-zone lock. Evidence:
(1) this bench result (−12, data zone unlocked); (2) EVERY KDF test in
cryptoauthlib (PRF/AES/HKDF, plain + I/O-encrypted — all target=output)
calls `test_assert_data_is_locked()` before the command; (3) `provIokeyTest`
in `example/console/main.c` is byte-for-byte the cryptoauthlib reference
(`kdf_prf_output_encrypted`) — same details word, mode, 16-B message, nonce
reload, out_nonce hand-off, `atcah_io_decrypt` — so it will **PASS** once the
data zone is locked, provided the key matches.

**The finding to carry forward (2026-10-24):** (1) the VAULT's KDF also uses
target=output (source = slot 7 → 32-B derived key to the Pico for
AES-256-GCM), so the **data zone MUST be locked** for the password store to
work — this REVISes the agreed "data zone unlocked (contents open)" layout,
which was built before we knew the KDF needed it. (2) On a first-gen
ATECC608, GenKey generates a fresh ECC private key only while the data zone
is UNLOCKED; when locked it only recomputes the public key from the existing
private key (cryptoauthlib genkey test lines 35–38; its `data_is_unlocked`
assert is gated to CA2/second-gen parts, NOT our 608). So the ECC pairs
(slot 1 identity, slots 3–6 FIDO2, slot 12 spare) **must be GenKey'd BEFORE
the data zone is locked**. Slot 7 (vault master) and slot 14 (I/O key) are
unaffected — both non-ECC, Pico-entropy + Write, no GenKey. Locking the data
zone does NOT close "the contents open": 32-byte writes to a
non-individually-locked slot stay allowed (the access matrix below), so slots
remain re-keyable until individually slot-locked. **Phase 5+ sequence:**
GenKey the ECC pairs (data zone still unlocked) → lock the data zone (byte 86,
one-way, typed confirm) → run `prov iokeytest` (passes) → (production)
slot-lock slot 14 (after the verification, so it stays re-keyable until
proven). The I/O-key verification is DEFERRED to that flow; for now the I/O
key is verified to the extent the chip allows (write ACK + littlefs
read-back). → **EXECUTED 2026-10-25: iokeytest PASSED** (enforced
I/O protection; host cross-checked — see the "Latest state"
paragraph); slot-14 lock still pending (production only).

**2026-10-24 (this session):**
(1) **The "a Pico reflash wipes the littlefs copy" warning was WRONG —
verified against the flash layout.** The app uf2 covers only the app region
(flash 0x0..~0x19000, ~100 KB) and the littlefs volume is
0x80000..0x200000 (384 × 4 KB blocks, `PICO_LFS_FLASH_OFFSET = 0x80000`);
a normal BOOTSEL reflash writes only the app's uf2 blocks, so the volume —
and `/io_key.bin` — SURVIVE a reflash. Only a full-flash erase (or an app
growing past 0x80000) wipes it. `f52eb35` fixes the two misleading messages
(`prov iokey` output + the boot warning) and adds the test: `prov status`
now reports the littlefs volume state (existing = survived the last reflash,
recorded at boot from `pico_lfs_mount_existing()` success/failure, vs fresh
= formatted at boot) and the `/io_key.bin` state (present+valid / present
but corrupt / missing). **DONE + PASSED (2026-10-24):** the flash loaded
`f52eb35` and `prov status` reported exactly that — "mounted existing" +
"present and valid" (the check's first live test; the reflash did not
wipe the volume).
(2) **The Phase 5+ sketch is recorded in PLAN.md (Phase 5 section):**
`prov genkey <slot>` / `prov lockdata` / `prov lockslot <slot>` — thin
console wrappers over the existing Phase 4A prov API — plus a new library
`atecc608_get_pubkey(slot, pub)` wrapping `atcab_get_pubkey` (GenKey mode
0x00: the public key of an on-chip ECC private key slot is NOT stored in any
data slot; the existing `atecc608_read_pubkey` wraps `atcab_read_pubkey`, a
72-B stored-key slot read for slots 8–15 — the wrong primitive), and the
FIDO2 pre-generation design (slots 3–6 generated before the data-zone lock;
`MakeCredential` assigns pre-generated slots; littlefs DB tracks
credID/handle/RP-hash/slot).
(3) **Datasheet memory-map finding (recorded in PLAN.md):** the ATECC608
data zone is 1,208 bytes with VARIABLE slot sizes — slots 0–7 = 36 B,
slot 8 = 416 B, slots 9–15 = 72 B (DS40002138A / DS40002515B; identical
across A/B/C) — NOT 16×32. The repo's 32-byte read/write convention
(first 32 bytes of a slot) works for all our slots (bench-verified: the
32-B I/O-key write to 72-B slot 14 committed). A stored 72-B public key
(4 pad + 32 X + 4 pad + 32 Y) fits only in the 72-B slots 9–15, so slot 0
(36 B, "firmware validation primary") cannot hold the firmware-validation
public key — on-chip Verify must use slot 11 (72 B) or verification moves
Pico-side (decision deferred to the firmware-signing phase).
(4) **Chip identity correction:** part 0x60 rev 5 maps to **ATECC608B
(CA2, second-gen)** in cryptoauthlib's part/rev table
(`lib/pkcs11/pkcs11_token.c`: part 0x60, rev > 2 → 608B) — the "first-gen"
note above was a misread. It changes nothing operationally: the CA2
data-zone gates (KDF target=output needs the data zone locked; fresh GenKey
needs it unlocked) apply to this chip and match every bench observation.

**RNG (user-reported 2026-10-24):** with the config zone now LOCKED,
`random` / `prov randtest` return real random numbers (the 0xFFFF0000
factory pattern is gone) — the documented behavior (the pattern appears
only while the config zone is unlocked). This resolves the 4B
hardware-verification item "Random command on the (now) locked chip".
Scenario guidance is user-reviewed (2026-10-22) and lives in
`example/README.md`.

State at the pause:
- **Config zone LOCKED (2026-10-23, run-sheet step 5, ONE-WAY —
  executed after explicit user go-ahead):** `prov lock` dry run passed
  first (chip-zone CRC CDC7, zone re-verified vs the intent, aborted
  without the token), then `prov lock CONFIRM` → "config zone
  LOCKED (irreversible)." The chip re-verified CDC7 against its own
  zone before committing. The config zone can never change again;
  SlotLocked 88–89 stays FF FF (the DATA zone is NOT locked — contents
  open per the agreed layout); 84/85 (UpdateExtra) are final at 00 00.
- **DURABLE I/O key in slot 14 + littlefs (2026-10-23, run-sheet
  step 6, after flashing the `d1778af` littlefs fix):** chip ACKed the
  write AND the save succeeded — "saved to littlefs: /io_key.bin
  (read-back verified)". The key (the one Phase 7 uses; also in
  `/io_key.bin` on the Pico):
  `FB D2 14 BA F2 76 35 9D  BF 27 71 02 8C C9 A3 8E  DC 5C 25 CB C7 22
  8F 5C  F1 D7 C4 B4 63 48 C3 99`. An earlier key `ECE2 A982 5B88
  0E69 … 629C D88B` was written on the first `prov iokey` attempt but
  is **VOID** — the re-run re-keyed slot 14 (recorded only for the
  audit trail).
- **littlefs save bug — found, fixed (`d1778af`), FLASHED + CONFIRMED
  at the bench (2026-10-23):** the first `prov iokey` wrote the key to
  the chip (ACKed) but then "saving /io_key.bin FAILED". Root cause:
  the command handlers run on core1 (core0 runs the stdin loop);
  littlefs flash program/erase go through `flash_safe_execute()`, which
  on bare-metal RP2350 requires the OTHER core to have called
  `flash_safe_execute_core_init()` (`multicore_lockout_victim_init()`)
  — neither core did, so every flash write from core1 returned
  PICO_ERROR_NOT_PERMITTED → LFS_ERR_IO → the save failed (reads are
  XIP and were unaffected; the boot-time format worked because core1
  had not started yet — `PICO_MULTICORE_LOCKOUT_BEFORE_CORE1_STARTED`).
  Fix: `flash_safe_execute_core_init()` on core0 in `main()` (before
  `multicore_launch_core1`) and on core1 in a `core1_main()` wrapper
  around the library's `commandProcessor()`. After flashing `d1778af`
  the re-run saved successfully ("read-back verified"). Details: the
  "littlefs saves from the console fail" section below.
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
  has since been re-written by `prov config` — step 2 — and LOCKED —
  step 5).
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
  the ORDER was revised (config → lock → iokey), re-presented, and the
  one-way step 5 was executed with explicit user go-ahead (2026-10-23).

**Write sequence — RE-ORDERED 2026-10-23 (bytes unchanged; the byte
plan stays approved). Progress (check off as the bench proceeds;
every step is idempotent except the lock):**
- [x] 0. BOOTSEL-reflash `build/example/console/pico-atecc608.uf2`
  (the flashed image predates `48d14cc` — required before step 1;
  littlefs wipe is harmless, nothing is stored on it yet).
  DONE at the bench 2026-10-23. (A SECOND reflash — the littlefs fix
  `d1778af` — was also done at the bench 2026-10-23; it is what made
  the `prov iokey` save succeed.)
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
- [x] 3. `prov status` — expect: "writable region: matches the planned
  image", "summary CRC: chip zone CDC7  planned image 822F".
  COVERED by step 4's output (the dry run printed chip-zone CRC CDC7
  and re-verified the zone against the intent before aborting — the
  stronger of the two checks); no separate `prov status` run.
- [x] 4. `prov lock` — verifies the zone, then aborts (no confirm typed).
  It prints the CRC it will use: CDC7.
  DONE 2026-10-23: "chip zone summary CRC: CDC7 ... about to: lock
  config zone (irreversible) ... NOT locked ... lock aborted — nothing
  was written or locked."
- [x] 5. `prov lock CONFIRM` — **ONE-WAY**: Lock with summary CRC
  **CDC7** (the chip's actual zone CRC — the chip re-verifies it
  against its own zone, so a wrong value is rejected by the chip
  itself) → OK. The config zone can never change again (the data zone
  stays UNLOCKED — contents open per the agreed layout). After this
  step the data zone becomes writable.
  DONE 2026-10-23, after explicit user go-ahead: "config zone LOCKED
  (irreversible)."
- [x] 6. `prov iokey` — expect: "I/O protection key written to slot 14
  (write ACKed by the chip)" + the NOTE (no read-back possible) + **the
  printed 64-hex I/O key — RECORD IT** (the durable backup; `/io_key.bin`
  on littlefs is lost on reflash) + "saved to littlefs: /io_key.bin
  (read-back verified)". If it failed, re-run — the data zone is still
  unlocked and slot 14 still clear-writable (no lock was consumed).
  DONE 2026-10-23: key written + ACKed, printed (the durable key is in
  the state list above), and "saved to littlefs: /io_key.bin (read-back
  verified)". (The FIRST `prov iokey` attempt — before the `d1778af`
  fix was flashed — wrote the chip but the littlefs save FAILED; the
  re-run after the fix re-keyed slot 14 and saved cleanly. The key
  printed on the first attempt is void.)
- [x] 7. `prov status` — DONE 2026-10-23: `config zone: LOCKED`, data
  zone unlocked, "writable region: matches the planned image", lock
  bytes [86:88] **55 00**, chip-zone CRC **F6DE** (planned image 822F).
  NOTE (corrected prediction): the config-zone Lock flips only byte 87
  (the config-zone lock) 55→00; byte 86 (the data-zone lock) STAYS 55
  because the data zone is not locked — so the post-lock zone is 55 00
  / F6DE, NOT 00 00 / 6F47 (my original, wrong guess). Both bytes are
  excluded from the writable compare but inside the CRC.

### littlefs saves from the console fail — root cause + fixed (`d1778af`)
- **Symptom (bench, 2026-10-23):** `prov iokey` wrote the key to slot 14
  (chip ACKed, key printed) but then: "saving /io_key.bin FAILED — the
  key is on the chip; re-save later." Reads (boot-time stat, XIP) were
  unaffected; the boot-time littlefs format/mount had succeeded.
- **Root cause:** the console's command handlers run on **core1**
  (core0 runs the stdin loop — see the comment above the command table
  in `example/console/main.c`). LittleFS flash program/erase go through
  `flash_safe_execute()` (pico_littlefs.c `bd_prog`/`bd_erase`). On
  bare-metal RP2350, `flash_safe_execute()` (pico-sdk
  `src/rp2_common/pico_flash/flash.c`) must lock the OTHER core out via
  the multicore lockout, and `multicore_lockout_ready()` requires the
  other core to have called `multicore_lockout_victim_init()` — i.e.
  `flash_safe_execute_core_init()`. **Neither core ever called it**, so
  every flash write from core1 returned `PICO_ERROR_NOT_PERMITTED`
  (graceful in this release build; a debug build would assert —
  `PICO_FLASH_ASSERT_ON_UNSAFE=1`) → `LFS_ERR_IO` → the save failed.
  The boot-time format worked only because it runs on core0 BEFORE
  `multicore_launch_core1()` (the
  `PICO_MULTICORE_LOCKOUT_BEFORE_CORE1_STARTED=1` special case: from
  core0 with core1 not yet running, the lockout is considered ready).
  The SDK documents the requirement: "This is not necessary for FreeRTOS
  SMP, but should be used when launching via multicore_launch_core1"
  (`pico/flash.h`).
- **Fix:** `flash_safe_execute_core_init()` on core0 at the top of
  `main()` (before `multicore_launch_core1()`) and on core1 in a
  `core1_main()` wrapper launched instead of the library's
  `commandProcessor()`. The lockout is interrupt-driven (FIFO IRQ
  handler on the victim core), so core0 can be anywhere in the stdin
  loop when core1 needs it.
- **Consequence for the bench run:** the first I/O key (printed,
  recorded in the state list) is on the chip but has NO littlefs copy.
  The re-run of `prov iokey` after flashing the fix generates a FRESH
  key and saves it atomically (write → print → save → read-back
  verify); the first printed key is void. (Typing a 64-hex key into a
  new "save" command was rejected as the recovery path: typo-prone, and
  a wrong key in `/io_key.bin` is worse than no file.)
- **Note (uf2 vs littlefs):** the app uf2 covers only the app region
  (~100 KB at the start of flash); the littlefs volume (0x80000..
  0x180000) is NOT touched by a normal BOOTSEL reflash — the
  "a Pico reflash wipes the littlefs copy" warning in the code is
  conservative (a FULL flash erase would wipe it). The boot prints
  which case actually happened: silence = existing volume mounted;
  "fresh volume formatted" = it was erased.

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
  **CDC7**; after the lock the zone CRC is **F6DE** (confirmed at the
  bench 2026-10-23) — the config-zone Lock flips only byte 87
  (config-zone lock) 55→00, byte 86 (data-zone lock) stays 55, so the
  post-lock lock bytes are 55 00, NOT the 00 00 I first guessed (which
  would have been 6F47).

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

**REVISION (2026-10-24, from the `prov iokeytest` bench finding):** the
"data zone left UNLOCKED (contents open)" part of the layout is being
revised — the **data zone MUST be locked** for the password store to work,
because the vault's KDF (and the I/O-key verification KDF) use target=output,
which the ATECC608 gates on the data-zone lock. Locking the data zone does NOT
close "the contents open": 32-byte writes to a non-individually-locked slot
stay allowed (the access matrix), so slots remain re-keyable until individually
slot-locked. The catch: GenKey generates a fresh ECC private key only while the
data zone is UNLOCKED, so the ECC pairs (1, 3–6, 12) must be generated BEFORE
the data zone is locked. See "⏸ Where the conversation stopped".

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
`KDF_MODE_TARGET_OUTPUT_ENC`; enforce is our choice. **Resolved by bench
evidence 2026-10-25: `kdf_prot=1` = ENFORCE — this chip returns
encrypted output + a 32-B response nonce for EVERY target=output KDF,
even a plain `KDF_MODE_TARGET_OUTPUT` call (see the "Latest state"
paragraph in the stopped-section above).** Mock does NOT model I/O
protection → 4B hardware verification item (now closed for kdf_prot;
request-direction coverage still open). Evidence (2026-10-22, user review of slot-14 type):
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
- **Phase 4B DONE (at the bench 2026-10-23; the Phase 5+ bench 2026-10-25
  extended it)** — the actual chip provisioning: config zone written
  (approved plan, CRC 822F) + LOCKED, I/O key in slot 14 + saved to
  littlefs, final `prov status` verified (LOCKED, lock bytes 55 00,
  chip-zone CRC F6DE). The write sequence was re-ordered by a bench
  discovery (config → lock → iokey — the data zone is unwritable until
  the config zone is locked); then the Phase 5+ bench: six ECC slots
  GenKey'd, data zone LOCKED, `prov iokeytest` PASSED (enforced I/O
  protection, host cross-checked — see "⏸ Where the conversation
  stopped"). HARD RULE below applies.
- **Phase 5 DONE (2026-10-26)** — crypto pass-through, on demand:
  the KDF wrapper `atecc608_kdf_prf` is implemented, host-tested
  (mock KDF/NONCE + the enforced I/O-protection output side; ctest 3/3),
  and VALIDATED ON HARDWARE (2026-10-26: `prov kdf 7` twice → identical
  32-B output — the Phase 5 done criterion "at least a KDF round-trip
  validated on hardware" is met; value + host cross-check note in the
  "Latest state (2026-10-26)" paragraph). The console has read-only
  `prov kdf <slot>`. `sign` / `verify` wrappers come on demand.
  HARD RULE below applies.
- **Phase 6 DONE (2026-10-26)** — the `config` read-back demo ran on
  hardware: the decoded zone matches the agreed plan in every field
  (I2C 0xC0, locks 00 00, SlotLocked FF BF, all 16 slot rows); the
  dev-only `prov iokeyshow` matched the out-of-band dev notes.
- **Phase 7 DONE (2026-10-26)** — 7.1–7.3 BUILT
  (`0242df2` `selftest`'s 8 generic invariants, read-only, shared
  I/O-key round-trip core; `c1708f6` bench-chip goldens +
  full/generic modes; `0d312a5` `docs/BRINGUP.md`) and 7.4 BENCH
  GREEN (`selftest` 12/12, `selftest generic` 8/8 on the chip; the
  host-computed C904 CRC golden confirmed on hardware). **ALL SEVEN
  PHASES ARE COMPLETE.** HARD RULE below still applies (the whole
  selftest suite is read-only, so it stays safe to run).
- **Vault example (in-repo demo) — BENCH-VERIFIED (2026-10-27):** the
  console-based PIN-gated password-store demo in `example/vault/`
  (chip = KDF master only; pure-C AES-256-GCM; flat `/v_<name>`
  littlefs entries; `add`/`get`/`dump`/`list`/`rm`) — the two
  diagnosed GCM bugs are FIXED; host `test_vault_gcm` 12/12 (ctest
  4/4); the bench demo run is GREEN — **every command (add / get /
  dump / wrong-PIN / list / rm) verified by the user on the frozen
  chip**, including the `dump` plaintext-leak demonstration (ct region
  pure `?` noise on hardware; 203,776 B uf2 `526c810` live on the
  chip). Chip untouched (frozen; KDF + RNG only at runtime). Docs in
  (example/README "Vault example" section, PLAN.md scope note).

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
ctest --test-dir tests/build --output-on-failure   # 4 tests: test_config, test_prov, test_crypto, test_vault_gcm
# or run directly: ./tests/build/test_config  ./tests/build/test_prov  ./tests/build/test_crypto  ./tests/build/test_vault_gcm
```
As of the 2026-10-27 pause: 4/4 green — `test_vault_gcm` (the
vault example's AES-256-GCM KATs, 12 checks) passes: the two
diagnosed GCM bugs (the xtime mask, the decrypt GHASH-over-plaintext)
are fixed; see the newest "Latest state" paragraph in the stopped
section for the fix record.
`tests/` is a standalone host CMake project: FetchContent of the same
v3.8.0, `ca_host` = cryptoauthlib's portable sources (minus
`hal/hal_rp2350.c` — the mock defines those 8 HAL symbols), `mock_chip`,
`atecc608_host` (the four HAL-agnostic module sources: config/prov/
status + the Phase 5 crypto wrapper). Executables link
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
- `include/atecc608/atecc608_crypto.h` + `src/atecc608_crypto.c` (Phase 5,
  2026-10-26) — `atecc608_kdf_prf(slot, nonce, msg, msg_len, io_key, out)`:
  PRF KDF from a data slot to a 32-B output; caller-supplied TempKey nonce
  (NULL = zeros → deterministic) and in-place `atcah_io_decrypt` when the
  response carries a nonce (enforced I/O protection, kdf_prot=1); HAL-
  agnostic like the prov sources (host-testable).
- `src/atecc608_status.c` + `src/atecc608_int.h` (4A) — the shared
  `atecc608_map_status` (moved out of `src/atecc608.c` for the host build).
- `tests/` (4A) — `CMakeLists.txt` (generates its own `atca_config.h` from
  cryptoauthlib's `atca_config.h.in`, same feature set as the top level),
  `mock_chip.{h,c}`, `test_golden.h` (the golden G intent),
  `test_config.c`, `test_prov.c`, `test_crypto.c` (Phase 5 KDF wrapper).
- `example/console/main.c` + CMakeLists — validation console
  (pico-command-line) over the **module API**: probe/info/serial/lock/
  random (atecc608_*), diag (raw I2C), bootrom, help; Phase 4B adds the
  `prov` command set. Phase 6 adds a config read-back demo.
- `example/` — proof-of-concept examples (NOT part of the library):
  `console/` (probe/diag + the Phase 4B `prov` command set; littlefs via
  the pico-littlefs submodule for `/io_key.bin`, `pico_rand` for the
  I/O-key entropy), `vault/` (the PIN-gated password-store demo:
  `vault_gcm.{h,c}` pure-C AES-256-GCM — NIST-vector-verified via
  `tests/test_vault_gcm` (12 checks) — + `main.c` console app over
  flat `/v_<name>` entries; host-verified 2026-10-27, bench demo run
  pending), `tools/dump_devconfig.c` (the byte-plan
  host tool), `common/dev_config.h` (the agreed 4B config intent,
  shared by console + tool; the provision-on-first-boot base is
  factored out here in 4B), `common/iokey_file.h` (the shared
  `/io_key.bin` layout — magic/len/key/CRC-32, pure C — used by
  console + vault); contract + scenarios + slot layout in
  `example/README.md`.
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
**Status (2026-10-23): Phase 4B COMPLETE at the bench.** Config zone
written (approved plan) + LOCKED (one-way step, user go-ahead); I/O
key written to slot 14 (chip ACKed) AND saved to littlefs
`/io_key.bin` (read-back verified) after flashing the littlefs fix
(`d1778af`); final `prov status` = run-sheet step 7 confirmed
(LOCKED, lock bytes 55 00, chip-zone CRC F6DE). The durable I/O key
is recorded in the state list at the top. Scenario discussion
complete — config agreed (see "Agreed 4B config" above).
`use_lock_en=false` until an auth flow exists.**
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
   locked (see "Data-zone writes before the config lock") — and EXECUTED
   2026-10-23: `prov config` (✓) → `prov lock` dry (✓) → `prov lock
   CONFIRM` (✓, ONE-WAY, explicit user go-ahead) → `prov iokey` (✓ chip
   write; the littlefs copy is pending the `d1778af` reflash + re-run).
6. **4B verification items** (mock fidelity gaps — check on the real chip):
   ~~UpdateExtra same-value behavior (we send 00 00 → 00 00)~~ resolved
   2026-10-23: `prov config` completed and the read-back verify (which
   INCLUDES bytes 84/85) matched the plan — same-value UpdateExtra
   accepted, 84/85 = 00 00 on the chip; ~~byte-16 write behavior~~
   resolved 2026-10-23: the write path preserves byte 16, the read-back
   shows 0xC0 unchanged, and the chip stayed reachable at 0xC0 through
   the lock and the iokey write; ~~factory KeyConfig words (mock assumes
   all 0)~~
   known 2026-10-23: real factory ships 0x0033 ×3 / 0x001C ×5 /
   0x003C ×7 / 0x001C (mock still all-0, prov path overwrites them
   all); ~~factory SlotLocked~~ resolved 2026-10-23 (`d6cf44d`):
   factory FF FF, polarity bit n = 0 → locked (confirmed from
   cryptoauthlib's own `calib_is_slot_locked` + hardware write test),
   prov path now preserves the chip's 88–89 like byte 16; UseLock
   enforcement; GenKey/PrivWrite bit 13/14 behavior on real hardware;
   I/O protection coverage of the request direction (mock does NOT
   model I/O protection at all); ~~kdf_prot/ecdh_prot 2-bit semantics
   (enforce vs opt-in) per NDA datasheet~~ resolved 2026-10-25 by
   bench evidence: kdf_prot=1 = ENFORCE (every target=output KDF
   returns encrypted output + 32-B nonce, even plain calls).

Then per PLAN.md: ~~Phase 5 (crypto pass-through: kdf/sign/verify)~~ —
COMPLETE 2026-10-26 (KDF wrapper implemented, host-tested and validated
on hardware; the sign/verify wrappers remain on demand for Phase 7),
Phase 6 (config read-back console demo) — COMPLETE 2026-10-26
(`84edf05`: top-level `config` demo + dev-only `prov iokeyshow`; first
hardware run 2026-10-26, decoded zone matches the agreed plan,
SlotLocked FF BF) together with the final bench step `prov lockslot 14
CONFIRM` (EXECUTED 2026-10-26 — the chip config is frozen for
production); next is Phase 7 — SCOPED 2026-10-26 (read-only `selftest`
suite: generic invariants + bench goldens; `docs/BRINGUP.md`
bring-up checklist; scope in PLAN.md Phase 7).

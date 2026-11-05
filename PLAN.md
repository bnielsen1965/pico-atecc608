# Plan: FIDO2 example — passkey authenticator

This file is the forward plan **and** the continuity snapshot. Development
history lives in the git log — this file was committed at every phase, so
keep entries forward-looking: when a phase lands, compress its narrative
into a one-line History bullet.

## Ground rules (2026-11-03 — in force for all further work)

1. **USB timing is critical.** Core 1 is dedicated to stable USB
   communications (`fido_usb_core1_task()`); the card/CTAP logic runs on
   core 0. Never block the USB core.
2. **Flash writes pause all cores.** Only initiate a littlefs/flash write
   from a stable point (no in-flight USB transaction, queues drained).
3. **Spec of record:** `example/fido2/fido-client-to-authenticator-protocol-
   v2.3-ps-2026-0226.pdf` (CTAP v2.3 PS). Verify protocol details against
   it, not memory.
4. **FIDO2/CTAP2 only — no U2F assumptions.** Do not carry U2F command
   values or outside-CTAP knowledge into the CTAP2 path; the U2F/FIDO2
   mix-ups have broken the wire before. When the spec and a browser seem
   to disagree, re-read the spec section — the transport chapter matters
   (USB HID §11.2 vs BLE §11.4).
5. **Debug tools live in `example/fido2/tools/`** so they survive across
   sessions (new FIDO2 host-side tool scripts go there; the existing
   bench harness stays in `bench/`).
6. **Serial console = a separate USB device.** A CP2102 USB-serial
   bridge (10c4:ea60) is wired to the Pico's UART0 (GPIO0 TX / GPIO1
   RX) and appears as `/dev/ttyUSB0`. It is a separate USB device from
   the Pico itself (2e8a:000b HID) — reflashing/replugging the Pico
   does not re-enumerate the bridge (and vice versa). Console
   commands: `up` (user presence — a level flag, consumed by the next
   makeCredential) and `wipe` (erase the credential store).
7. **How to talk to the console (verified 2026-11-03).** Do NOT touch
   termios: rewriting the port settings with Python/termios left the
   exchange dead (the firmware never answered), while `screen` (which
   leaves the port in a working raw state) works. Use plain shell I/O
   with CR-terminated lines — what `screen` sends on Enter (the
   firmware accepts CR and LF; CR is the proven one):
       ( timeout 5 cat /dev/ttyUSB0 > /tmp/opencode/crx & ); sleep 0.5
       printf 'wipe\r' > /dev/ttyUSB0; sleep 5; cat /tmp/opencode/crx
   To test console liveness without side effects, send a garbage line
   (`zz` → "unknown console command"). Never send a test `up` outside a
   live round — the flag is level, not edge, and it would silently
   short-circuit that round's UP. **One reader per port:** a serial
   port delivers received bytes to whoever is reading — if the agent
   runs a background console logger (`cat /dev/ttyUSB0`), it STEALS
   every device response from the user's terminal (C12, 2026-11-03:
   the user's `up`/`zz` got no visible reply in their screen while all
   the responses landed in the agent's log — the user concluded the
   console was dead). Never run the console logger while the user is
   working the console; during user rounds the usbmon capture is the
   only device view and the logger is omitted entirely.
   **Port state resets when the bridge re-enumerates (2026-11-04):** a
   bridge replug / hub reset makes the kernel re-probe /dev/ttyUSB0 at
   its defaults — 9600 baud + cooked mode with local ECHO. At 9600 the
   exchange is dead in BOTH directions (the firmware is 115200; the
   device reads our bytes as framing-error garbage, our reads get
   nothing), and a live ECHO port is worse: the device's reply is
   echoed back into its RX and it chews its own console output forever
   (an infinite "unknown console command" loop that self-sustains with
   NO host reader at all). If the console is silent, FIRST check
   `stty -a -F /dev/ttyUSB0 | head -1` (must say 115200 baud) and
   recover with `stty -F /dev/ttyUSB0 115200 cs8 -cstopb -parenb
   -echo -opost` (minimal change — no full termios rewrite), then
   verify with a garbage line.
8. **sudo: ask the user.** The agent's shell has no TTY and cannot
   answer a sudo password prompt. If a command needs root, ask the user
   to run it. (`burnin` is in `dialout` + `wireshark` and has ACL rw on
   the FIDO hidraw node — probes and usbmon captures work without
   sudo.)
9. **USB capture analysis: filter to our HID device FIRST.** usbmon
   captures contain every device on the bus (hub, FIDO key, Pico USB
   Ethernet cafe:4020, CP2102…). In this tshark build `-Y`/`-e` USB
   field extraction is broken (`-Y "usb.device_address == N"` silently
   returns 0 frames). The working procedure (verified 2026-11-03 on
   roundC11):
       # 1. list the devices in the capture:
       tshark -r <f>.usb -V | grep -oE '^    Device: [0-9]+$' | sort | uniq -c
       #    the FIDO key is the device whose frames carry `HID Data:`
       #    lines (cross-check `lsusb | grep 2e8a` if the address was
       #    recorded at capture time — it renumbers on every replug)
       # 2. filter to that device (this awk build chokes on dynamic
       #    regex interpolation — use the string comparison):
       tshark -r <f>.usb -V | awk -v dev=N '
         /^Frame [0-9]+: / { frame = $0; keep = 0; next }
         $0 == "    Device: " dev { if (frame != "") print frame; frame = ""; keep = 1 }
         keep { print }
       ' > /tmp/opencode/<f>.devN.txt
       # 3. decode from the `HID Data:` lines (report =
       #    [CID 4B][CMD 1B][BCNT 2B][DATA 57B]; continuation =
       #    [CID 4B][SEQ 1B][DATA 59B]).
   Sanity check: the first frames must be the broadcast INIT request
   (CID 0xFFFFFFFF, CMD 0x86) and the 17-byte INIT response — the INIT
   response also carries the firmware version (the flash fingerprint:
   1.0.1 expected).
10. **The dev board is a Raspberry Pi Pico 2 (RP2350) — NOT an RP2040.**
    The build targets `rp2350-arm-s` (two Cortex-M33 cores); the BOOTSEL
    drive is `RPI-RP2350`. Never import RP2040-era assumptions (drive
    name, core architecture, clocks, flash geometry) into this work.
11. **The serial console port is ALWAYS 115200 baud — never 9600.**
     The CP210x bridge re-enumerates on every reflash/reset and can come
     back at 9600; a dead/silent console at 9600 is the symptom (see the
     C13-prep round-2 record: `up` never arrived because the port had
     reset to 9600+echo). Before any console work after a reflash,
     apply: `stty -F /dev/ttyUSB0 115200 cs8 -cstopb -parenb -echo
     -opost`.
12. **Settled analyses get recorded — do not re-litigate.** When a
     detailed analysis (spec of record + our code + the browser/client
     source) settles a question about how the code should be written,
     record the conclusion AND its primary-source evidence in the
     **Settled decisions** register (topic, conclusion, evidence with
     spec section / file:line, date, round). Before re-opening any
     encoding / format / "which table" question, check the register
     FIRST. This project has re-derived the same answers across rounds
     (GET_INFO key numbering, makeCredential framing, COSE labels); the
     register exists so each question is answered once, against the
     primary source, and then treated as fixed. A register entry is only
     superseded by new primary-source evidence, never by memory.

## Current state (2026-11-05) — **BROWSER REGISTRATION PASSES ON BOTH HARNESS: C18 (webauthn.io) and C19 (xorengineering.com/fido2/) on fw 1.0.5.** The C17 `UserActionTimeout` was round timing, not firmware (the fix: `up` within ~2 s of the Register click). The temporary diagnostic scaffolding (the `diag` console command + the `DBG mc:` prints) is removed and rebuilt (uf2 md5 `b837ed7f5f6754e67b05ac0aab6372b9`, ctest 9/9; the wire is unchanged — still fw 1.0.5). The register half of the demo is DONE. **NEXT: Phase 4 — getAssertion + RESET (login).** PAUSED here.

- **C16 root cause (FIXED in code):** Firefox's authenticator-rs `COSEKeyVisitor` expects the **5-entry** COSE key `{1:kty, 3:alg, -1:crv, -2:x, -3:y}`; we were emitting the RFC 9053 **4-entry** `{1:kty, 3:crv, -1:x, -2:y}`. Firefox read our label `−1` (x, a byte array) where it expects the curve **i64** → the exact C16 RUST_LOG error `invalid type: byte array, expected i64`. Fix: emit the 5-entry layout `a5 01 02 03 26 20 01 21 58 20 <x32> 22 58 20 <y32>` (kty=2, alg=−7, crv=1, x, y). `FIDO_COSE_ES256_LEN` 75→77; authData 162→164 B; makeCredential response 252→254 B (BCNT 0x00FC→0x00FE). **This SUPERSEDES SD-3** (the 4-entry "canonical" form is precisely what Firefox rejects) — the correct layout is now **SD-5**.
- **Flashed + verified (fw 1.0.5, uf2 md5 `24df233af54519a4043c2691381b74b7`):** `bench/fido_probe.py` FULL PASS (fw=1.0.5, caps=0x07, 81-B GET_INFO KAT). `bench/fido_mc.py` E2E **PASS**: 254-B response over 5 packets, 5-entry COSE key passes every structural assert, packed signature **VALID** under the raw-digest P-256 ECDSA verify (the C15 false-alarm trap avoided). Store wiped at the end. (Bench bug fixed this round: `fido_mc.py` called an undefined `sha256(...)` → now `hashlib.sha256(...).digest()`; the bench stays dependency-free.)
- **C17 browser round (webauthn.io, `RUST_LOG=authenticator=debug firefox 2> /tmp/opencode/c17_fx.log`):** the C16 parse error is **GONE** (0 hits for `byte array, expected i64`). New, earlier failure: `[WARN authenticator::ctap2] ... CommandError: Unexpected code: UserActionTimeout (None)` = CTAP2 status **0x0A** = the **30-s user-presence window expired** before `up` reached the device (the gap between the dialog opening and the agent's `up` exceeded 30 s). The device's UP mechanism is sound (E2E passes; it acks `up`), so this is a **round-timing issue, not a firmware/COSE bug.** The `up` the agent sent after the timeout had no pending makeCredential to complete (it just set the presence flag). **Open observation:** the user reported the Pico LED was NOT blinking when the dialog opened — yet the device WAS in the UP-wait phase (it returned UserActionTimeout after 30 s), so check whether the makeCredential keep-alives drive the LED at all (WINK does; keep-alives may not — cosmetic, not the failure cause).
- **Flash learning (operational):** the Pico **reboots the moment the uf2 write completes** — the BOOTSEL volume disappearing right after `cp` is the SUCCESS signal, not a failure. Do NOT read the volume back after the copy (it's already gone). Verify the flash via the INIT fw version (the probe), not a volume read-back. The `[ -d /run/media/burnin/RP2350 ]` check is unreliable (the automounter creates a transient placeholder); trust `findmnt -t vfat` + the post-reboot HID enumeration.

**C18 round record (2026-11-05, webauthn.io, fw 1.0.5, `RUST_LOG=authenticator=debug firefox 2> /tmp/opencode/c18_fx.log`):** preconditions per the prior NEXT list — the console port had reset to 9600 again (bridge re-enumeration) and was recovered per ground rules 7/11, probe FULL PASS (fw 1.0.5, caps 0x07, 81-B KAT), store wiped (0 records). User clicked Register → agent sent `up` ~2 s later. Device: `genkey slot=3 -> OK`, `sign slot=3 -> OK`, `cred_save /f2_3 -> OK`; the browser consumed the 254-B response. webauthn.io reported **registration success** (it verifies the attestation server-side). RUST_LOG: zero `byte array, expected i64`, zero `UserActionTimeout`; the trailing `Statemachine was cancelled` / `Transaction was cancelled` lines are the post-success teardown, not an error. **The page then offers an AUTHENTICATION test — do NOT click it until Phase 4:** getAssertion is unimplemented; the dispatch `default:` answers a clean 1-byte `INVALID_COMMAND` (0x14) (fido_ctap.c:913). The store now holds 1 credential (slot 3) — wipe before the next round.

**C19 round record (2026-11-05, xorengineering.com/fido2/, fw 1.0.5, same RUST_LOG Firefox — log delta from byte 1284 of c18_fx.log):** store wiped first (1 record — C18’s webauthn.io credential); user clicked Register → agent `up` ~2 s later; device `genkey/sign/cred_save OK` (slot 3); the page reports **success** (fido2-lib server-side verification — a different client path than C18’s py_webauthn). Log delta clean: device found, register process started, zero errors/warnings. **Both harnesses now pass — the register half of the demo is done.**

**NEXT (register passes on both harness — Phase 4 = login):**
1. **Phase 4 — getAssertion + RESET** per the Phase 4 section: lookup by (rpIdHash, credId) or resident enumeration for an empty allowList; authData = rpIdHash ‖ flags(UP|CRED_ID) ‖ counter ‖ credIdLen(**1** B — getAssertion, unlike makeCredential’s 2) ‖ credId; counter increment BEFORE building authData; chip-signs SHA-256(rpIdHash ‖ clientDataHash); RESET wipes the littlefs DB. Bench: the webauthn.io page offers its **authentication test right after a register** — the natural first Phase 4 E2E (same fast-`up` pattern), then the xorengineering.com login, replug + reflash survival, strictly increasing counter.
2. After Phase 4: Phase 5 (hardening + docs). Commit per phase; keep this file’s Current state current.
- **Chip identity:** ATECC608C (part 0x60, rev 0x05). **Console routing:** FIDO2 printf → UART0/CP210x (/dev/ttyUSB0), NOT USB HID. **YubiKey 5** (user-provided) is available as a comparison capture if a real 5-entry COSE key from a shipping token is wanted (its own webauthn.io/fido2-demonstration failures are separate, higher-level — NotAllowedError/NotAllowed, not COSE).

## Settled decisions (do not re-litigate — check here BEFORE re-deriving)

Per ground rule 12. Each entry: the question, the settled conclusion,
the PRIMARY-source evidence (spec section and/or file:line), and the
round/date it was proven. These were each verified against the spec of
record and/or the client source at the time. Do not re-derive them from
memory or from a single secondary source; supersede an entry only with
new primary-source evidence.

### SD-1 — makeCredential response framing = 3-entry map (CTAP 2.3 wire), NOT the 2-entry "attestationObject" byte string (C14, 2026-11-04)
- **Question:** is the response `map(3) {fmt, authData, attStmt}` (what
  we emit) or `map(2) {fmt, attestationObject}` where
  attestationObject = `bstr(authData‖attStmt)`?
- **Settled:** `map(3)`. `authData` (0x02) is a **byte string**;
  `attStmt` (0x03) is a **CBOR map**; they are separate fields. This is
  what we emit and it is correct. Do NOT "fix" it into a 2-entry form.
- **Primary-source evidence:**
  - CTAP 2.3 spec of record
    (`example/fido2/fido-client-to-authenticator-protocol-v2.3-ps-20260226.pdf`;
    text /tmp/opencode/ctap23.txt lines 1475–1489): the
    `authenticatorMakeCredential` response table = `fmt (0x01)` String,
    `authData (0x02)` **Byte String**, `attStmt (0x03)` **CBOR Map**
    (+ optional epAtt 0x04, largeBlobKey 0x05,
    unsignedExtensionOutputs 0x06).
  - Firefox wire parser (`make_credentials.rs`,
    `MakeCredentialsResultVisitor::visit_map` ~L139): reads
    0x01→format, 0x02→auth_data, 0x03→att_stmt; unknown keys skipped.
    `AuthenticatorData` deserializes via `visit_bytes`
    (`attestation.rs:288`, `expecting "a byte array"`) → 0x02 is a byte
    string. Spec and client agree.
- **Why it was confused:** the **WebAuthn L3** *abstract*
  `attestationObject = authData ‖ attStmt` (concatenated byte string) is
  the platform-facing representation; the **CTAP 2.3 wire** protocol
  *decomposes* it into separate fields. The concatenated 2-entry form is
  the older CTAP 2.0–2.2 wire encoding. We are built to 2.3.
- **The actual C14 defect was unrelated:** COSE_Key `crv` (−1 → 1, RFC
  8152 §13.1). See Current state + SD-3.

### SD-2 — GET_INFO key numbering = the CTAP 2.1+ table, NOT the 2.0 table (C13, 2026-11-04)
- **Question:** which GET_INFO key table do we emit?
- **Settled:** the **2.1+** numbering — 0x01 versions, 0x02 extensions,
  0x03 aaguid, 0x04 options, 0x05 maxMsgSize, 0x06 pinUvAuthProtocols,
  0x07 maxCredCountInList, 0x08 maxCredIdLength, 0x09 transports,
  0x0A algorithms. (firmwareVersion is a 2.1+ UINT key 0x0E; we drop it
  from the map — the fw version stays in the INIT response.) The CTAP
  2.0 table (aaguid=0x01, versions=0x02, …) is what NO shipping device
  or client uses.
- **Primary-source evidence:** Firefox `AuthenticatorInfo`
  deserializer (`get_info.rs`) parses the 2.1+ table (unknown keys
  warned+skipped, not fatal); the YubiKey vector in Firefox's own suite
  (from python-fido2) uses 2.1+; CTAP 2.1/2.2/2.3 spec tables all use
  2.1+. C13 wire: our 2.0-numbered map (AAGUID bytes under 0x01) failed
  to parse as `versions` → whole GetInfo rejected → U2F fallback.
- **Note:** this is the SAME class of issue as SD-1 — the spec of
  record is 2.3, but we emit the encoding the *deployed* client parses.
  For GET_INFO that is the 2.1+ table; for makeCredential framing (SD-1)
  the 2.3 and the client happen to agree.

### SD-3 — COSE_Key for ES256/P-256 = canonical 4-entry map, crv = 1 (C14, 2026-11-04)
> **SUPERSEDED by SD-5 (C16, 2026-11-04):** the 4-entry "canonical" form is
> exactly what Firefox's authenticator-rs **rejects** (`invalid type: byte
> array, expected i64`). The correct CTAP2-wire layout is the **5-entry**
> `{1:kty, 3:alg, -1:crv, -2:x, -3:y}` — see SD-5. The one part of this
> entry that STANDS is the crv VALUE (P-256 = 1, not −1); only the entry
> count / labels were wrong.
- **Settled (historical):** `{ 1: 2, 3: 1, -1: X, -2: Y }` (75 B) — kty EC2, **crv
  P-256 = 1**, x under −1, y under −2, keys in ascending byte order
  (0x01, 0x03, 0x20, 0x21). crv is **1**, NOT −1 (−1/0x20 is the x
  coordinate's *key* byte; a copy-paste-class bug that shipped in 1.0.4).
- **Primary-source evidence:** RFC 8152 §13.1 / RFC 9053 (P-256 = 1,
  2 = P-384, 3 = P-521, 4 = X25519, 6 = Ed25519). Firefox `Curve` enum
  (`crypto/mod.rs`: `SECP256R1 = 1`; `try_from(_)` → `UnknownKeyType`
  otherwise) rejects −1. C14 wire bytes `a4 01 02 03 20 …` proved the
  −1 was on the wire.
- **Lesson (general):** byte-pinned KATs/verifiers derived from the
  firmware's own output cannot catch spec-conformance bugs — the
  fido_mc.py verifier asserted the firmware's own (wrong) crv constant.
  Verifier logic must be spec-derived.

### SD-4 — ATECC608 external-digest `Sign` signs the 32-B MD buffer AS-IS; verify off-chip with a RAW-digest ECDSA (no re-hash) (C15, 2026-11-04)
- **Question:** how do we verify off-chip a signature the ATECC608 made over a
  pre-computed digest (external-digest `Sign`)?
- **Settled:** use a **raw-digest** P-256 ECDSA verify: `e = int(digest) mod n`,
  then `u1 = e·s⁻¹, u2 = r·s⁻¹`, and `(u1·G + u2·Q).x mod n == r`. The ATECC608
  signs the 32-byte Message Digest Buffer **as-is** (it does NOT hash it), so the
  value to verify is the SAME 32 bytes placed in the buffer — for the packed
  attestation, SHA-256(authData‖clientDataHash).
- **The trap:** `cryptography`'s `pk.verify(sig, data, ECDSA(hashes.SHA256()))`
  ALWAYS hashes `data` first, so it verifies against SHA-256(digest) — the WRONG
  value. That double-hash is what made every valid ATECC608 signature read as
  "INVALID" in C15 (the false alarm). Same trap with `openssl dgst -verify`
  unless `-rawin` is used.
- **Primary-source evidence:** ATECC608 datasheet — external-digest Sign
  operates on the 32-byte Message Digest Buffer contents with no further
  hashing. Empirical proof: a self-tested raw-digest verifier
  (valid-sig→True, wrong-digest→False) validates ALL captured chip signatures
  (diag slot3/slot4) AND the real C15 browser signature over
  SHA-256(authData‖cdh) (digest `e9a53583…a96797`). `bench/fido_mc.py` now
  ships this verifier (pure-Python, no third-party deps) so the bench is a true
  cryptographic check, not a length check.
- **Lesson:** a signature verifier that re-hashes a pre-hashed input is silently
  wrong; when the signer uses an external digest, the verifier must consume the
  raw digest.

### SD-5 — COSE_Key for ES256/P-256 on the CTAP2 wire = the 5-entry map {1:kty, 3:alg, -1:crv, -2:x, -3:y} (C16, 2026-11-04)
- **Question:** what COSE key layout does the browser's CTAP2 layer parse in
  makeCredential's authData (the attested credential data)?
- **Settled:** the **5-entry** map `{ 1: 2, 3: -7, -1: 1, -2: X(32), -3: Y(32) }`
  (77 B) — kty=EC2(2), **alg=ES256(−7)** under 3, **crv=P-256(1)** under −1,
  x under −2, y under −3. Wire bytes:
  `a5 01 02 03 26 20 01 21 58 20 <x32> 22 58 20 <y32>`. This is NOT the
  RFC 9053 minimal 4-entry form `{1:kty, 3:crv, -1:x, -2:y}` (75 B) — that
  4-entry form is what Firefox's authenticator-rs **rejects**.
- **Primary-source evidence:**
  - **Firefox authenticator-rs `COSEKeyVisitor`**
    (`dom/webauthn/authenticator/src/crypto/mod.rs`): reads a 5-entry COSE key —
    label 1→kty(i64), 3→alg(i64), −1→curve(i64), −2→x(bytes), −3→y(bytes).
    Feeding it our 4-entry key put x (a byte array) under −1 where it expects
    the curve **i64** → the exact C16 RUST_LOG error
    `invalid type: byte array, expected i64`.
  - **CTAP 2.3 spec of record** — `getPublicKey()` (the COSE key carried in
    authData) uses labels 1=kty, 3=alg, −1=crv, −2=x, −3=y (the 5-entry form
    with alg).
  - **Yubico python-fido2 `tests/test_cose.py`** ES256 vector:
    `A5 01 02 03 26 20 01 21 58 20 <x32> 22 58 20 <y32>` — the same 5-entry
    layout (map(5), kty=2, alg=−7, crv=1, x, y).
- **Why it was confused:** RFC 9053 (COSE) defines the *minimal* EC2 key as the
  4-entry `{1:kty, 3:crv, -1:x, -2:y}` (alg optional), and SD-3 had settled on
  that "canonical" form. But the CTAP2 **wire** — and the browser's parser —
  carries the 5-entry form **with alg**. The spec of record (CTAP 2.3) + the
  deployed client (authenticator-rs) + the reference (python-fido2) all agree on
  5-entry.
- **Consequence:** `FIDO_COSE_ES256_LEN` 75→77; authData 162→164 B;
  makeCredential response 252→254 B (BCNT 0x00FC→0x00FE). KATs re-pinned
  (tests/test_ctap.c `s_mc_authdata[164]`, `s_mc_resp[254]`, `t_mc_cose`);
  bench fido_mc.py asserts updated (77-B map(5); x=cose[10:42], y=cose[45:77]).
- **Lesson:** the "canonical" COSE form (RFC 9053 minimal) is not what the CTAP2
  wire carries — the wire adds `alg`. When a browser rejects a
  structurally-valid COSE key, check the ENTRY COUNT / LABELS against the
  client's actual visitor, not just the RFC.

**C12b root-cause record (2026-11-03; supersedes the "emit both key
numberings" caveat in the C11 analysis below — dual keys are impossible,
see fix). PARTIALLY SUPERSEDED (2026-11-04, C13):** the "emit 2.0–2.2
keys" half of the fix below was WRONG — the CTAP 2.0 spec table is what
no one uses; every shipping device and client (including this Firefox)
parses the 2.1+ numbering, and 1.0.4 re-keys the map to it. The caps
0x07 half was right and stands. See the C13 root-cause record in the
resume section.** the C12b capture (/tmp/opencode/roundC12_firefox.usb, 17:53,
dev 25) on the verified 1.0.1 firmware shows INIT (fw 1.0.1 ✓, caps 0x0D),
GET_INFO (84 B, byte-identical KAT), then a U2F version-check (MSG 0x83,
APDU `00 03 00 00` padded to 7 B) answered `69 86` — and NO makeCredential
ever. Two gates, each alone fatal, both encoding mismatches (the 2.3 spec
of record itself defines the new numberings — GET_INFO table §6.4
lines ~2285–2400 of /tmp/opencode/ctap23.txt: versions 0x01, extensions
0x02, aaguid 0x03, options 0x04, maxMsgSize 0x05, …, transports 0x09,
algorithms 0x0A, firmwareVersion 0x0E uint; INIT caps §11.2.9.1.3: WINK
0x01, CBOR 0x04, NMSG 0x08):
 1. **caps 0x0D**: 2.0–2.2 clients put CBOR at 0x02 → clear in 0x0D →
    U2F-only classification → U2F probe → `69 86` → give up.
 2. **GET_INFO 2.3 keys**: 2.0–2.2 clients read 0x09 as `algorithms` →
    get `["usb"]` (type-matches as an array, content invalid) → "no
    usable algorithms" → no makeCredential.
 Command numbers are FINE (0x10 CBOR / 0x11 CANCEL / 0x3B KEEPALIVE /
 0x06 INIT / 0x08 WINK are the 2.1/2.2/2.3 values; the C12b capture proves
 Firefox sends 0x90). **Fix: emit the 2.0–2.2 wire encoding** (every
 shipping client parses it; no shipping 2.3 client exists as of 2026-11):
 caps 0x07 (WINK 0x01 | CBOR 0x02 | NMSG 0x04); GET_INFO map(9):
 aaguid 0x01, versions 0x02 `["FIDO_2_0"]`, options 0x03 `{rk,up}`,
 maxMsgSize 0x04 256, maxCredentialCountInList 0x06 128,
 maxCredentialIdLength 0x07 64, transports 0x08 `["usb"]`, algorithms
 0x09 `[{alg:-7,type:"public-key"}]`, firmwareVersion 0x0D `[1,0,2]`
 array — 85 bytes (map(9) is the 1-byte CBOR form 0xA9; bstr(16) is
 0x50), 2 packets 57+28. A future 2.3-only client reading 0x07 sees
 WINK|CBOR without NMSG and may probe CTAPHID_MSG — we answer `69 86`, it
 falls back to CTAP2 (harmless); its GET_INFO parse finds none of our
 fields (harmless while no such client ships). **7-byte `0x83` anomaly
 RESOLVED: not a bug.** tshark verbose (c12b_verbose.txt): frame 41 =
 URB_SUBMIT, Endpoint 0x01 **Direction OUT** — the 7-byte report is
 Firefox's own U2F version-check request; frame 44 = URB_COMPLETE IN with
 our 2-byte `69 86`. The earlier "device emits a 7-byte reply" attribution
 came from /tmp/opencode/usbmon_seq.py, which had a broken usbmon
 header layout (the 64-bit record is 16-B timestamp + 36-B header + 36-B
 URB; the file is PCAP-framed) and had never run successfully.
 **Pre-browser validation plan (SUPERSEDED by the record below —
 libfido2 1.16 is a 2.3 client; use `bench/fido_mc.py` instead):** after
 reflash, `fido2-cred -n xorengineering.com /dev/hidrawN` (libfido2 1.16
 reference client, 2.0–2.2 numberings) + agent-sent `up` via console = a
 full E2E makeCredential before spending a browser round; wipe afterwards.

**C10 status-byte regression + libfido2 1.16 findings — RESOLVED
 (2026-11-03):** after the 1.0.2 reflash the probe FULL-PASSED (fw=1.0.2,
 caps=0x07, 85-B KAT), but `FIDO_DEBUG=7 fido2-token -I` exposed the THIRD
 bug: libfido2 sends GET_INFO (the caps fix works — the device is now
 classified CBOR-capable), receives all 85 bytes, then
 `cbor_parse_reply: blob[0]=0xa9` → `fido_dev_cbor_info_wait: 169` →
 `falling back to u2f`. The source is decisive (obtained with
 `dnf download --source libfido2` — the Fedora SRPM worked where
 GitHub/Yubico were blocked; extracted at /tmp/opencode/libfido2-1.16.0/):
   * `src/cbor.c cbor_parse_reply()`: `if (blob[0] != FIDO_OK) { r =
     blob[0]; goto fail; }` — the 0x00 CTAP status byte BEFORE the CBOR
     payload is REQUIRED; any other first byte is returned as the error
     code (0xA9 = 169).
   * Spec of record §11.2.9.1.2 CTAPHID_CBOR "Response at success":
     `DATA = CTAP status code, DATA+1 = n bytes of CBOR encoded data`.
 So the C10 change to "bare CBOR" was a misdiagnosis (the third stacked
 bug, after the C11/C12 stale-firmware process failures and the 2.3
 encoding). The error paths were already correct (a single status byte —
 exactly what cbor_parse_reply reads as the error code).
 **Fix (fw 1.0.3):** `resp[0] = FIDO_CTAP2_OK` + encode the CBOR at
 resp+1, `*resp_len = 1 + e.len` on BOTH success paths (handle_get_info,
 mc_create in fido_ctap.c); GET_INFO 86 B (57+29), makeCredential 252 B
 (57+59+59+59+18); KATs re-pinned (test_ctap.c: 86-B GET_INFO byte KAT
 `00 a9 … 0d 83 01 00 03` + field test, 252-B MC KAT, authData now at
 resp+13; fido_probe.py 86 B / 57+29 / fw [1,0,3]); ctest 9/9; the host
 `/tmp/opencode/dbg_getinfo` helper (recompiled) prints the
 byte-identical `00 a9 … 0d 83 01 00 03`.
 **libfido2 1.16 is a CTAP 2.3 client — the `fido2-cred` E2E is
 unusable:** `src/fido/param.h` FIDO_CAP_WINK 0x01 / FIDO_CAP_CBOR 0x04 /
 FIDO_CAP_NMSG 0x08 (2.3 positions); `src/info.c parse_reply_element`
 uses the 2.3 GET_INFO key numbers (versions=1, extensions=2, aaguid=3,
 options=4, maxMsgSize=5, …, transports=9, algorithms=10, fwVersion=14)
 with NO legacy fallback — `cbor_map_iter` aborts on the first mismatch,
 and our 2.0–2.2 key 1 = aaguid bytes(16) → `decode_string_array` -1 →
 parse failure → U2F fallback, ALWAYS. The dual-key impossibility has
 materialized in a real client. Consequences: (a) the browsers (2.0–2.2
 clients) are unaffected — the acceptance test stands; (b)
 `fido2-cred`/`fido2-token` will always classify the key U2F-only —
 EXPECTED, not a firmware failure; (c) caps 0x07 remains the right single
 value: 2.0–2.2 clients see WINK|CBOR|NMSG, and libfido2 1.16 sees CBOR
 set at 0x04 (our legacy NMSG bit overlaps its 2.3 CBOR position —
 without it, 1.16 would not even attempt GET_INFO). **The fido2-token
 display quirk is fully explained (cosmetic only):**
 `fido_dev_is_fido2()` = `flags & 0x04`; on the parse failure
 `fido_dev_force_u2f()` clears 0x04 → fido2-token prints
 `0x03 (wink, nocbor, msg)` with the 2.3 legend. Never trust the display
 string; trust FIDO_DEBUG traces + the probe. **Replacement E2E:
 `bench/fido_mc.py`** (new): INIT (asserts fw 1.0.3, caps 0x07) →
 GET_INFO (86-B KAT) → makeCredential with the EXACT 190-B Firefox C1
 request (byte-verified against s_firefox_c1_req in test_ctap.c) →
 console `up` at ~2 s → the 252-B response over 5 packets (BCNT 0x00FC,
 SEQ 0–3) → full attestation validation (packed, flags 0x41, AAGUID,
 32-B credId, 75-B COSE_Key, attStmt alg -7 / sig 64 B) → `wipe`.
 Verified offline before pausing: syntax, MC_REQ == KAT, and the
 validation block passes verbatim against the 252-B KAT. Note: the
 firmware computes rpIdHash = SHA-256(rp.id) from the rp.id string
 (fido_ctap.c:600-601) and IGNORES the provided rpIdHash field — the
 E2E asserts SHA-256("xorengineering.com") in authData.

**C11 capture analysis (the evidence):** the 13-s capture contains NO
makeCredential exchange at all — only the initial probe: INIT req/resp
(CID=3, proto 2, **FW 1.0.0**, caps 0x0D), a 1-byte CBOR `0x04`
(INVALID_SEQ) reply, the 84-B GET_INFO (57+27 split, byte-identical to
the KAT), a 7-B `0x83` U2F reply `00 03 00 00 00 00 00`, and a 2-B `0x83`
`69 86` U2F reply. Two of those five wire artifacts CANNOT be produced by
the current source: (a) the 1-byte CBOR `0x04` — fido_ctap_dispatch never
returns CTAP2_ERR_INVALID_SEQ; (b) the 7-B U2F reply —
`send_u2f_status()` emits exactly 2 bytes (69 86). The device is running
an intermediate C5–C10-era build; the 15:11 flash did not take (BOOTSEL
not held / stale file). **The rk/PIN hypothesis is dead on the evidence:**
the "rk": true bytes seen in the capture are the GET_INFO `options` map —
CORRECT per the CTAP 2.3 spec, which renumbered the GET_INFO keys
(options=0x04, maxMsgSize=0x05, pinUvAuthProtocols=0x06,
maxCredentialCountInList=0x07, maxCredentialIdLength=0x08, transports=0x09,
algorithms=0x0A, firmwareVersion=0x0E,
remainingDiscoverableCredentials=0x14; our 84-B KAT matches the 2.3 table
exactly). Firefox (a 2.0–2.2 client) does not parse the 2.3 keys, so it
never saw rk:true; its own makeCredential request carried options
{rk:false}; and our authData flags are 0x41 (UP|AT) with the RK/ED bit
CLEAR. No "Firefox requires a PIN for resident keys" rule was found (web
search; PIN-less YubiKey resident keys work in Firefox). **Interop
caveat:** because we emit ONLY the 2.3 key numbers, 2.0–2.2 browsers read
NONE of our capability fields (options/maxMsgSize/transports/algorithms
all land on wrong-typed keys and are ignored); if a browser round ever
fails for GET_INFO-related reasons, emit BOTH key numberings (dual keys in
one CBOR map is legal). **2.3 command numbering verified against the spec
of record** (TOC + body): INIT=0x06, PING=0x01, WINK=0x08, CBOR=0x10,
CANCEL=0x11, KEEPALIVE=0x3B, ERROR=0x3F — the firmware already follows
2.3 (the 0xBB keep-alive and 0x90 CBOR seen in the C11 wire are the 2.3
values, not stale 2.0 values). **PIN decision: DEFER** (concrete plan in
the Phase 6 section) — it is not the cause of this hang and the demo runs
UV "preferred" / rk not required; revisit only if a verified-firmware
round still fails.

**C9 history (superseded context) —** the C9 wire (/tmp/opencode/roundC9_firefox.usb; the key renumbered to **bus 5 dev 15** = tshark `5.15.1`, UART still `5.5.1`) is device-clean all the way through: open at 4.0 s, INIT (17-B resp, CID=3, proto 2, caps 0x0d), GET_INFO (85 B, 2 pkts), the 190-B makeCredential in 4 OUT pkts (4.081–4.093 s, SEQ 0,1,2), then two keep-alives `00 00 00 03 82 02 00 00 …` at 4.117 s / 4.601 s (484 ms apart) — and **Firefox stopped polling at 4.604 s, 2.5 ms after keep-alive #2, with NO CANCEL on the wire** (abrupt teardown, not a user-cancel). The user's `up` (UART `u`,`p`,`\r` at 6.77–7.87 s) then completed fully on the device (`fido2: user presence ('up')`, `genkey slot=3 -> OK`, `sign slot=3 -> OK`, `cred_save /f2_3 -> OK`) — the 252-B response went to an endpoint nobody polled (the round-B stale-client pattern). **Root cause — two compounding keep-alive defects, both proven against Firefox's vendored CTAP2 stack in `dom/webauthn/authenticator/` of the `mozilla-firefox/firefox` GitHub repo (a modified authenticator-rs; sparse clone at /tmp/opencode/fxrepo):** (1) **the keep-alive IS a normal BCNT-framed CTAPHID message** — `U2FHIDInit::read` (u2ftypes.rs) reads frame[5..7] as a 2-byte BE BCNT and frame[7..] as data; the spec's "contains a single byte" means a 1-byte *payload*, not an omitted BCNT. Our C8 "fix" (BCNT-less `82 02 …`) makes Firefox read BCNT = 0x0200 = **512**: after keep-alive #1, `u2f_read` blocks demanding a continuation with SEQ 0, and keep-alive #2's CMD byte (0x82) is then read as the SEQ → `Err("invalid sequence number")` → the `?` aborts the transaction with no CANCEL (exactly the 2.5-ms-after-ka#2 wire signature; ka#1 was "tolerated" only because the client was blocked waiting for its phantom continuation). (2) **this Firefox build's keep-alive command is 0xBB, not the spec's 0x82**: consts.rs `CTAPHID_KEEPALIVE: u8 = TYPE_INIT | 0x3b` (= 0xBB), and the `From<u8>` match is EXACT, so `0x82` → `HIDCmd::Unknown(0x82)` → returned from the `sendrecv` loop as a "response" → `send_cbor_cancellable` sees `cmd != Cbor` → `Err(UnexpectedCmd(0x82))`. This single constant explains ALL THREE rounds: C7 `bb 00 01 3b` → 0xBB = Keepalive → tolerated 22 s (later aborted by the unrelated SEQ bug); C8 `82 00 01 02` → Unknown(0x82) with a clean BCNT=1 parse → `UnexpectedCmd` → immediate abort, no dialog; C9 `82 02 00 00` → Unknown(0x82), BCNT=512 → continuation hang → dead on ka#2 with the dialog up. **The C8 "no BCNT / status read as 0x00 RFU" diagnosis was WRONG** — the C8 wire `82 00 01 02` had the RIGHT framing; only the command byte was wrong for this Firefox. **Fix (QUEUED, not implemented): restore the BCNT=1 framing `[CID 4B BE][CMD][0x00 0x01][status][zeros]` (status at p[7]) AND set the keep-alive command to 0xBB → wire `00 00 00 03 bb 00 01 02 00 …` to match this Firefox.** **OPEN RISK before committing to 0xBB:** it deviates from the FIDO spec (0x82) — and real tokens send 0x82 and (presumably) work in Firefox, which this code reading does NOT explain (a 0x82 keep-alive during a real token's UP wait should hit the same `Unknown(0x82)` → `UnexpectedCmd` path). Verify before flashing: the user's exact Firefox version vs the tip code in /tmp/opencode/fxrepo (the clone is depth-1, no history), a web search for a Firefox keep-alive 0x82/0xBB bug report, and whether a 0x82-tolerant read path exists elsewhere in the tree (only `transport/hid.rs`, `u2ftypes.rs`, `consts.rs` were read). Chrome (the later round) probably follows the spec's 0x82 — 0xBB could break Chrome, which decides whether the command byte must be browser-aware. **Housekeeping: the C9 round LEFT A CREDENTIAL IN THE STORE** (`/f2_3` — the device completed + saved on the user's `up` even though Firefox was already gone) → wipe before the next round. All code changes remain uncommitted (including the C9 BCNT-less keep-alive framing now to be reverted); tests/test_ctaphid.c keep-alive checks are pinned to the BCNT-less shape (status at p[5], p[6]==0) and must be re-pinned with the fix. Flashed uf2 is still md5 `302c211baaed653f01c9d8b36ba1a962` (the C9 build). The 600-s fd watcher has expired.

A fresh usbmon capture of BOTH browsers, decoded with a clean CTAPHID
framer, exposed **five** independent defects. Bugs 1–2 are response
*content*; bug 3 is the *transport* root cause of the C7 abort (the
continuation SEQ — fixed 2026-11-03, see the corrected bullet); bug 4 is a
*keep-alive* spec defect (malformed on the wire, but TOLERATED by the
browser — not the abort cause); bug 5 is a *delivery* bug (the valid
response split across 30 s because the host stops polling mid-response):

- **CTAPHID continuation SEQ (THE BLOCKER — resolved 2026-11-03 after two
  misreadings).** ACT 1: `resp_send()` emitted an incrementing SEQ
  (`pkt[4] = r->seq++`) — which was SPEC-CORRECT all along. ACT 2: a
  C3-era observation ("the host stops after the first continuation, on
  `0x01`") was misread as "continuations must be `0x00`" (citing a
  nonexistent "§6.1" rule), and `pkt[4] = 0x00` was forced for every
  continuation. ACT 3: the C7 capture settled it — CTAP 2.0 §8.1.5.4
  (Packet sequencing) / ITU-T X.1278 require the continuation byte to be
  a sequence number **starting at 0, incrementing by one to 0x7f**
  (bit 7 always clear). The C7 wire shows pkt 2 SEQ `0x00` (accepted) and
  pkt 3 SEQ `0x00` (should be `0x01`); Firefox aborted reassembly exactly
  there (175 B of the 252-B response, fd closed 82 µs later). The ACT-2
  premise is re-read in light of bug 5: in that era the device's own 1 ms
  / `DBG-TMP` gaps let the host's tight re-poll read a ZLP, and the stop
  was (mis)attributed to the `0x01`. GET_INFO (85 B) always had a single
  `0x00` 1st continuation — valid in BOTH acts — which is why short
  responses looked fine throughout. **Fix (final): `resp_send()` emits
  SEQ 0, 1, 2, … (& 0x7f)**; the input parser (`input_continuation`)
  already required the incrementing SEQ, so both directions are now
  symmetric. test_ctaphid.c PING-echo verifier re-pinned to the
  incrementing SEQ; `t_ping_multipacket` (200 B / 7609 B) is the live
  regression guard.
- **COSE_Key `crv` was `1` (0x01), not `−1` (0x20).** fido_cose.c emitted
  `fido_cbor_enc_uint(&e, 1)` for the crv *value*. P-256 is crv `−1` per
  RFC 8152; a browser validating the EC2 key rejects an unknown curve.
  Fixed → `fido_cbor_enc_negint(&e, -1)`. Same length (1 B).
- **attStmt used integer keys `{1: alg, 2: sig}`.** WebAuthn L3 and the
  FIDO-certified reference (pico-fido2 `cbor_make_credential.c:641-644`)
  both use **text** keys `"alg"` / `"sig"`. Fixed → text keys. Grows the
  response 248 → 254 B.
- **Keep-alive was malformed on BOTH counts (fixed 2026-11-03; NOT the C7
  abort cause).** The C7 wire carried `… bb 00 01 3b …`: CMD **0xBB** and
  status **0x3B**. The spec defines a dedicated CTAPHID **KEEPALIVE
  command 0x02** (wire `0x82`) with its own 1-byte status — **PROCESSING
  0x01 / UP_NEEDED 0x02** (CTAP 2.1/2.2; the same status table appears in
  the 2.0 id spec). The intermediate "fix" recorded in this file (statuses
  `0x21`/`0x3B` as "CTAP2 error codes", citing "§8.1.9.1.5") was a
  misreading — in the 2.0 PS that section is CTAPHID_CANCEL, and the CTAP2
  error codes are not keep-alive statuses; it produced the wire
  `… bb 00 01 3b …`, still non-conformant (wrong CMD AND wrong status).
  **Fix: fido_ctaphid.h `FIDO2_CMD_KEEPALIVE` 0x3B→0x02 and statuses
  0x21/0x3B→0x01/0x02** (the `82 00 01 02` wire shape recorded here was itself the later-found
C8 abort cause — the 2-byte BCNT the spec's KEEPALIVE does not have;
final wire `… 82 02 00 00 …`, see the C8 history bullet); the tests use
  the symbolic names and `rep_cmd()` strips the 0x80 bit, so no test
  edits were needed. C7 shows Firefox TOLERATED all 6 malformed
  keep-alives (it aborted only on the SEQ mismatch, 629 ms after the last
  keep-alive), so this was spec debt, not the blocker. (Note: yubikit
  maps keepalive to 0x3B — the likely source of our original 0x3B value;
  fido2, the CTAP 2.1/2.2 specs, and real tokens use 0x02, so we follow
  the spec.)

- **Multi-packet delivery stalled: the main loop slept 1 ms between reports
   (LAST BLOCKER).** fido_hid.c enqueues the 5 response reports and
   `outq_drain()` (in `fido_hid_tick()`) releases one per host-ACK; main.c
   then `sleep_ms(1)`. So there is a ~1 ms gap between the host ACKing report
   N and the device arming report N+1. Firefox, staying in its CTAPHID
   reassembly loop (valid `0x00` continuations), re-polls tightly right after
   reading report N and lands in that gap, reading a **zero-length report**.
   Firefox treats a ZLP as end-of-message, **stops polling the IN endpoint**,
   and the remaining reports sit in the FIFO until the channel resets. Wire
   (roundC3, Firefox): reports 1–3 at 655.429–655.465, a ZLP at 655.465, then
   **no HID IN tokens for 30.6 s** until Chrome's INIT at 686.134 flushes
   reports 4–5. 30 s = Firefox's WebAuthn operation timeout. (With the old
   incrementing-SEQ bug Firefox *exited* the loop on the invalid `0x01` before
   polling into a gap, so all 5 drained in 76 ms — which is why the stall only
   appeared once continuations became valid `0x00`.) Chrome's `.dummy`
   probe makeCredential also delivered all 5 in 76 ms (its driver tolerates
   the gap), which is why Chrome's delivery looked fine while its real
   registration never even sent a makeCredential. Fixed → main.c spins (no
   `sleep_ms`) while `fido_hid_tx_pending()` is true, so the next report is
   armed the instant the host ACKs the previous one; idle time still sleeps.
   New accessor `fido_hid_tx_pending()` in fido_hid.c/.h.

   **The spin fix was INSUFFICIENT (round C4 still stalled).** The 16–20 ms
   inter-packet gap was NOT the host's poll interval — it was the device's
   own `DBG-TMP` `printf` in `outq_drain()` (a 64-byte hex dump ≈ 200 chars
   at 115200 baud ≈ 17 ms) blocking the main loop. The loop wasn't sleeping;
   it was stuck in UART transmit, so the next report was never armed inside
   the host's ~80 µs tight re-poll window. **Real fix → strip the `DBG-TMP`
   prints** (the `DBG OUT` trace in `outq_drain()`, the `DBG IN` trace in
   `tud_hid_set_report_cb()`, and the `dbg_dispatch()` wrapper). `outq_drain()`
   now arms the next report in ~1–10 µs (main-loop iteration, no blocking).
   The spin-while-TX-pending (`fido_hid_tx_pending()`) is KEPT as the fast
   idle path. The usbmon capture (not the UART trace) is the wire trace of
   record.

With bugs 1–5 fixed, the on-wire response is complete (254 B),
structurally correct, and its attestation signature **verifies**
(ECDSA over SHA-256(authData ‖ clientDataHash) against the COSE public key
— confirmed offline). flags=0x41 (UP|AT) and 2-B credIdLen remain correct
and unchanged.

The "incompatible" (earlier round) vs "hung on insert/touch" (this round)
difference is NOT a code regression — both rounds had the SEQ bug and both
delivered a 116-B truncation; it is just Chrome's varying handling of an
unparseable response. flags=0x41 (UP|AT) and 2-B credIdLen remain correct
and unchanged.

**Resolved (2026-11-03):** the INPUT parser validates an incrementing
continuation SEQ (`input_continuation`) — which is what the spec requires
(§8.1.5.4), so it was always right; the OUTPUT side was the non-conformant
one (constant `0x00`) until the `resp_send()` SEQ fix above. Both
directions are now spec-correct and symmetric. The old "latent INVALID_SEQ
on long requests" concern was the misreading speaking: a host sending
constant-`0x00` continuations would be the non-conformant party.

**Done:** fido_ctaphid.c continuation SEQ fix (incrementing 0..0x7f per
§8.1.5.4 — supersedes the C3-era constant-`0x00` "fix"); fido_cose.c crv
fix; fido_ctap.c attStmt text keys; fido_ctaphid.h keep-alive CMD 0x02 +
statuses 0x01/0x02 (later C8 fix: framed without the BCNT, wire
`… 82 02 …`); main.c spin-while-TX-pending +
fido_hid.c/.h `fido_hid_tx_pending()`; fido_hid.c `DBG-TMP` prints stripped
(delivery-stall fix — the `printf` was blocking the main loop ~17 ms/report);
test_ctap.c KATs re-pinned; test_ctaphid.c PING-echo verifier re-pinned to
the incrementing SEQ. ctest 9/9.

**Then the DUAL-CORE delivery fix** (C5 showed the print-strip alone left a
fatal ZLP at +87 µs after pkt 3): fido_hid.c/.h split into `fido_usb_core1_task()`
(core 1 tight spin: `tud_task()` + `outq_drain()`) and `fido_card_tick()` (core 0:
CTAP dispatch, ATECC608, CTAPHID timeouts, console, LED); the old single
`fido_hid_tick()`/`fido_hid_tx_pending()` are gone. `s_outq`/`s_cmdq` are now
lock-free SPSC ring queues (acquire/release atomics) — `tud_hid_set_report_cb`
(core 1) enqueues into `s_cmdq` instead of dispatching CTAP inline; `tud_umount_cb`
(core 1) only raises `s_umount_flag` and core 0 does the channel/CTAP reset +
queue flush. main.c `multicore_launch_core1(fido_usb_core1_task)` then runs the
core-0 loop (`fido_card_tick()` + `sleep_ms(1)`). CMakeLists links `pico_multicore`.
Build clean (no warnings), ctest 9/9. uf2 rebuilt:
`example/fido2/pico-atecc608-fido2.uf2` md5 **`0238c052a3707bac982528858f9328a4`**
(172544 B — the dual-core build).

**Resume / next steps (PAUSED 2026-11-04 with fw 1.0.4 BUILT — C13
failed, root-caused (GET_INFO 2.0-key numbering), map re-keyed to
2.1+, ctest 9/9; order: user 8, agent 9, user 10, agent 11):**

Steps 1–3 of the prior list are DONE (2026-11-03):
1. **Keep-alive command byte — RESOLVED in favor of the spec (0x3B/0xBB),
   which also matches Firefox.** CTAP 2.3 §11.2.9.1.7 (USB HID) defines
   `CTAPHID_KEEPALIVE (0x3B)`, BCNT=1, DATA = a single status byte
   (PROCESSING 0x01 / UP_NEEDED 0x02). The `0x82` we had been emitting is
   the *Bluetooth LE* keep-alive from §11.4.4.3 — a different transport
   (the C9 "spec says 0x82" premise was a misread of that BLE table).
   Firefox's `consts.rs` (`CTAPHID_KEEPALIVE = TYPE_INIT | 0x3b` = 0xBB)
   and its `device.rs` comment (citing this exact §11.2.9.1.7) confirm the
   browser expects 0xBB. No spec-vs-Firefox conflict: the 2.3 spec and the
   browser agree. (Not a U2F/FIDO2 mix-up — 0x3B is the spec's own
   USB-HID value in 2.3.)
2. **Fix implemented:** `fido2_ctaphid_keepalive()` now frames
   `[CID 4B BE][0xBB][0x00 0x01][status][zeros]` (BCNT=1, status at p[7]);
   `FIDO2_CMD_KEEPALIVE` 0x02→0x3B; fido_ctaphid.h doc re-cited to
   §11.2.9.1.7; the two test_ctaphid.c keep-alive checks re-pinned to
   BCNT=1 + status-at-p[7]. ctest 9/9.
3. **uf2 rebuilt:** `example/fido2/pico-atecc608-fido2.uf2` md5
   `dc6641399604554a929c09a61ca855d5`.

Steps 4–6 of the prior list are DONE (2026-11-04):
 4. **DONE (2026-11-04):** User reflashed `build/example/fido2/
    pico-atecc608-fido2.uf2` (md5 `8923c842464ff69d82f2e652f98dd5a7`,
    fw 1.0.3) via BOOTSEL (the RPI-**RP2350** drive — ground rule 10).
 5. **DONE (2026-11-04):** `bench/fido_probe.py` FULL PASS on the
    verified 1.0.3 firmware — fw=`01 00 03`, caps=**0x07**, 86-B
    GET_INFO KAT (0x00 status + 85-B 2.0–2.2 map, 57+29 split). The
    flash took; the round is live.
 6. **DONE (2026-11-04):** `bench/fido_mc.py` E2E PASS on the verified
    1.0.3 firmware — the exact 190-B Firefox C1 request, agent-sent
    `up` at ~2 s (genkey/sign/cred_save OK, slot 3), 252-B response
    over 5 packets with 5 keep-alives, full attestation validated
    (packed, flags 0x41, AAGUID, 32-B credId, 75-B COSE_Key, 64-B
    sig), `wipe` (store ends empty). Its first attempt exposed a
    HOST-side trap, not a firmware bug: the reflash's bridge
    re-enumeration had reset /dev/ttyUSB0 to 9600 + echo → `up` never
    arrived → the device correctly ran the 30-s UP timeout (61
    keep-alives, then 1-byte 0x2F USER_ACTION_TIMEOUT — reproduced and
    decoded; recovery recipe now in ground rule 7).
    NOTE: `fido2-cred`/`fido2-token` are NO LONGER usable for this —
    libfido2 1.16 is a CTAP 2.3 client and will always fall back to U2F
    on our 2.0–2.2 device (see the record above; "falling back to u2f"
    in a FIDO_DEBUG trace is now EXPECTED, not a failure).
 7. **DONE (2026-11-04) — C13 = Firefox round: FAILED.** Dialog opened,
    user typed `up`, nothing happened. Decode of
    /tmp/opencode/roundC13_firefox.usb (5139 B, 54 frames; FIDO key =
    usbmon dev 7, CP210x UART = dev 5): INIT (fw 1.0.3 ✓, caps 0x07 ✓)
    → GET_INFO (86-B, byte-identical KAT) → **U2F version check** (MSG
    0x83, APDU `00 03 00 00`) → our `69 86` → **Firefox stopped; NO
    makeCredential, no keep-alives**. The user's `up` (UART) arrived
    t≈16.2–16.6 s, 2.4–2.9 s AFTER Firefox gave up; the Pico's console
    was healthy and it did respond. The device behaved correctly on the
    wire — the browser rejected our GET_INFO.

**C13 root cause (2026-11-04, proven from Firefox's source):** the
GET_INFO key NUMBERING. Firefox's `AuthenticatorInfo` deserializer
(`dom/webauthn/authenticator/src/ctap2/commands/get_info.rs`, fetched
2026-11-04 from mozilla-firefox/firefox main) parses the **CTAP 2.1+**
table: 0x01 versions (array of text), 0x02 extensions, 0x03 aaguid
(bytes(16)), 0x04 options, 0x05 maxMsgSize, 0x06 pinUvAuthProtocols,
0x07 maxCredCountInList, 0x08 maxCredIdLength, 0x09 transports, 0x0A
algorithms, …; unknown keys are warned + skipped (NOT fatal — so the
0d firmwareVersion was never the poison). Our 1.0.2/1.0.3 map put the
AAGUID bytes under 0x01 (the CTAP **2.0** spec table) → Firefox
deserialized bytes(16) as `versions: Vec<text>` → type error → the whole
GetInfo rejected → U2F fallback → version check → `69 86` → no
makeCredential. The CTAP 2.0 spec's table was NEVER used by shipping
hardware: the YubiKey test vector in Firefox's own suite (from
python-fido2) and the CTAP 2.1/2.2/2.3 spec tables all use the 2.1+
numbering. So C12b's real root cause was only the caps bits (0x0D); the
"switch to 2.0–2.2 keys" was a harmful side change.

**1.0.4 fix (2026-11-04, BUILT):** `handle_get_info` now emits the 2.1+
map(8): 01 versions ["FIDO_2_0"], 03 aaguid, 04 options {rk,up},
05 maxMsgSize 256, 07 maxCredCountInList 128, 08 maxCredIdLength 64,
09 transports ["usb"], 0A algorithms [{alg:-7,type:"public-key"}];
firmwareVersion dropped (a 2.1+ UINT key at 0x0E — the fw version stays
in the INIT response, which is the flash fingerprint). GET_INFO = 81 B
(0x00 status + 80-B map), 2 packets 57+24. fw bumped 1.0.3 → 1.0.4.
KATs re-pinned: tests/test_ctap.c (field test + 81-B byte KAT
`00 a8 01 81 68 … 0a 81 a2 … 6b 65 79`), bench/fido_probe.py (81-B KAT,
57+24, NEW explicit fw 1.0.4 assert on INIT — the map no longer carries
the fw), bench/fido_mc.py (81-B KAT, fw assert 1.0.4). ctest 9/9. uf2
rebuilt: `example/fido2/pico-atecc608-fido2.uf2` md5
`55d5b14f37686e21b3c3d57c7277e22d` (173056 B).

**C14 round (2026-11-04, executed; capture
/tmp/opencode/roundC14_firefox.usb, 8394 B, 84 frames, 10:34:29.7–10:34:39.0,
dev 9, verbose dump /tmp/opencode/c14_verbose.txt):** enumeration at t0;
INIT (fw 1.0.4 ✓, caps 0x07) → GET_INFO (81 B) → **makeCredential ARRIVED**
(190 B, 4 OUT packets, 10:34:36.3) — the C13 fix works. 5 keep-alives
(~500 ms) while the dialog waited; on `up` (3 DBG mc prints:
genkey/sign/cred_save all OK) the full 252-B response went out in 5 IN
packets (57+59+59+59+18, within 17 ms) — then NOTHING on the bus: the
browser rejected the CONTENT. rpIdHash on the wire =
SHA-256("xorengineering.com") ✓. C14 left one credential stored
— wipe it before the C15 E2E.

**C14 root cause (2026-11-04, proven from the wire + Firefox's source):**
the COSE_Key `crv`. The response framing was EXONERATED first: Firefox's
`MakeCredentialsResult` deserializer (`make_credentials.rs`, fetched
2026-11-04) and its own test vector `MAKE_CREDENTIALS_SAMPLE_RESPONSE_CTAP2`
parse exactly what we send — `map(3) {1: fmt, 2: bstr(authData),
3: attStmt-map}` (the wire-only "attestationObject must be the single
bstr(authData‖attStmt)" hypothesis was WRONG — that bstr shape is the
browser's internal L3 representation, not the CTAP wire shape; the
fetched `make_credentials.rs` imports
`AttestationObject/AuthenticatorData/AttestedCredentialData/
AttestationStatementFidoU2F`, confirming the standard path). The defect:
`fido_cose_encode_es256` encoded crv as −1 (CBOR 0x20 — the x-coordinate's
key byte, a copy-paste-class bug), with a comment asserting −1 was the
registry value. The COSE registry (RFC 8152 §13.1 / RFC 9053) has
P-256 = **1**; Firefox's `Curve` enum (`crypto/mod.rs`: `SECP256R1 = 1`,
`try_from(_)` → `UnknownKeyType` for anything else) rejects it → the COSE
key fails → the whole response is dropped. Wire bytes: `a4 01 02 03 20
20 58 20 <x> 21 58 20 <y>` — must be `03 01`. The offline fido_mc.py
verifier "passed" because it asserted the firmware's own (wrong) constant.
**Lesson: byte-pinned KATs and verifiers derived from the firmware's own
output cannot catch spec-conformance bugs — verifier logic must be
spec-derived.** (The framing + COSE conclusions are now pinned in the
**Settled decisions** register as SD-1 and SD-3 — ground rule 12.)

**1.0.5 fix (2026-11-04, BUILT):** `fido_cose.c` emits crv 1 (one byte:
`03 20` → `03 01`); `fido_cose.h` doc comment corrected. Response size
UNCHANGED: 252 B, 5 packets 57+59+59+59+18, BCNT 0x00FC — only payload
byte 104 flips (0x20 → 0x01). KATs re-pinned OFFLINE (python hashlib,
independent of the C code; the old KAT was verified self-consistent
first): tests/test_ctap.c s_mc_authdata[91] 0x20→0x01, s_mc_resp (byte
104 + mock sig = SHA-256(authData‖cdh)‖itself recomputed — old
`10789ce2…`, new `9c1ac1a1…`), bench/fido_mc.py crv assert 0x01, both
bench scripts' fw assert → 1.0.5. ctest 9/9. uf2 rebuilt:
`example/fido2/pico-atecc608-fido2.uf2` md5
`a2589242f411e46596c6c06f54a63da9` (173056 B).

**C16 prep (2026-11-04; C15 is CLOSED as a false alarm — the wire is
sound).** The device is healthy on 1.0.5 and `bench/fido_mc.py` now does
real ECDSA (raw-digest) verification. The open question is the BROWSER's
actual verdict, so C16's job is to capture it. Two changes vs C15:

1. **Capture Firefox's real CTAP-level error.** The DevTools console shows
   nothing for WebAuthn (only the JS DOMException on the page). Launch
   Firefox from a terminal with `RUST_LOG=authenticator=debug firefox`
   (or `=trace`); authenticator-rs logs the full CTAP exchange and the
   specific rejection. A RELEASE Firefox caps Rust logging at INFO, but the
   WARN/ERROR lines that carry the cause are still printed (cf.
   mozilla/authenticator-rs#346: a Pico Keys device failing with
   "Error while parsing: trailing data at offset N"). Redirect stderr:
   `RUST_LOG=authenticator=debug firefox 2> /tmp/opencode/c16_fx.log`.
2. **Second harness: webauthn.io** (Duo Labs, py_webauthn-backed; rp.id
   "webauthn.io"; strict server-side attestation verification). It is a
   deliberate second opinion — if the device passes webauthn.io but not
   xorengineering.com the delta is RP config; if it fails both, the wire is
   the cause. Config for our device: attestation "none", user verification
   "discouraged" (no UV), resident key as the site offers. webauthn.io
   verifies the attestation server-side and reports the exact failure —
   more diagnostic than fido2-demonstration's opaque page error.

Round flow (user drives the browser, agent decodes):
- User: `stty -F /dev/ttyUSB0 115200 cs8 -cstopb -parenb -echo -opost`
  FIRST (ground rule 11).
- User: launch Firefox with `RUST_LOG=authenticator=debug firefox 2>
  /tmp/opencode/c16_fx.log`.
- User: `sudo tcpdump -i usbmonN -w /tmp/opencode/roundC16_<harness>.usb`
  (start before the dialog; `lsusb | grep 2e8a` gives the bus number N —
  the key renumbers on every replug).
- User: open the harness (webauthn.io first, then
  xorengineering.com/fido2/), Register, type `up` on /dev/ttyUSB0 within
  ~30 s, wait ~10 s, Ctrl-C. NO console logger during the round (one
  reader per port, ground rule 7).
- Agent: decode the usbmon (ground rule 9) AND read /tmp/opencode/c16_fx.log
  for the authenticator-rs verdict. The wire is known-sound, so THIS ROUND
  THE LOG IS THE PRIMARY EVIDENCE.

**On a passing round (webauthn.io AND xorengineering.com):** remove the
`DBG mc:`/`DBG-TMP` diagnostic prints + the temporary `diag` console
command, then commit the code + PLAN.md separately (all changes since
bench round 2 are uncommitted; HEAD `0dd7cc1`).

**Agent decode (after the round): tshark is the ground-truth decoder**
(`decode_ctaphid.py` is unreliable for this usbmon format).
`tshark -r <file> -V` + python regex parsing for the timeline;
`tshark -r <file> -Y frame.number==N -x` for full hex (the 64-B report is
at offset 0x40; the `HID Data:` lines trim trailing zeros; this tshark
build's `-e`/`-Y` USB field extraction is broken — use `-V`/`-x` only).
Expected in C15: FIRST the INIT response version = 1.0.5 (the
flash fingerprint) and caps = 0x07; then the makeCredential request,
keep-alives `00 00 00 <ch> bb 00 01 02 00 …` (0xBB, BCNT=1, status at
p[7]) every ~500 ms and the dialog STAYS, then on `up` the 252-B
response (BCNT 0x00FC, 5 packets: 57+59+59+59+18) with continuation
SEQ `00 01 02 03`, **all 5** packets read back-to-back (no
fd close / -ENOENT before packet 5) — and the wire now shows the COSE
key `a4 01 02 03 01 20 58 20 …` (crv 1). The C14 wire (roundC14) had the
identical shape with crv `03 20` — the single-byte delta is the fix.

**On a passing round:** remove the `DBG mc:`/`DBG-TMP` diagnostic prints,
then commit the code + PLAN.md separately (all changes currently uncommitted).

**fido2-demonstration local vs deployed (user question, ANSWERED):** the
local uncommitted diff = port 8080→8888, origin→localhost:8888,
attestation "none"→"direct", UV "preferred"→"required".
`authenticatorRequireResidentKey` is **false in BOTH** (unchanged in the
diff) — the rk:false seen in the captures is the SHARED config, not a
local-only change, and it is NOT a problem (the device stores every
credential resident regardless; rk only changes overwrite semantics). The
deployed xorengineering.com config = the committed one (attestation
"none", UV "preferred" — API-verified). **Caveat for LOCAL testing:** UV
"required" makes the browser send uv:true → our device answers
UNSUPPORTED_OPTION; keep local runs on "preferred".

**Harness (2026-11-01):** fido2-demonstration runs at
https://xorengineering.com/fido2/ (real cert, reverse-proxied at /fido2/).
DEPLOYED config verified via the live register-begin API: rp.id
"xorengineering.com", origin "https://xorengineering.com",
userVerification "preferred", attestation "none", algs [−7,−257].

**Bench round B (usbmon capture, decoded):** after a mid-capture
renumeration at 16:53:40 — **confirmed by the user as a manual device
reset, not a fault** — a fresh session (INIT + GET_INFO + 91-B
makeCredential) was processed at 16:54:17, completed on the user's `up`
at 16:54:21, and the full 247-B response (5 packets, status 0x00) went
out on the wire. Chrome's dialog stayed hung because its 16:45 hidraw fd
was DEAD after the reset (node recreated; the old fd is bound to the gone
instance) — the response had no live reader. That is stale-client-session
behavior, exactly what round C's A/B is built to confirm.

## BENCH ROUND C — controlled browser A/B (C1 DONE: 0x2A → CTAP 2.2 extensions root cause, fixed. C1b DONE: device completes the registration, 247-B response out, Firefox rejects the RESPONSE — AT-bit flags investigation, **PAUSED 2026-11-01**; C1c pending after the flags fix)

Goal: localize the hang to (a) Chrome profile/session state, (b) Chrome's
CTAP2 stack in general, or (c) the firmware.

**Invariants for every round (agent does 1–3, user does 4–7):**
1. Agent: `wipe` the store via /dev/ttyUSB0 → "credential store wiped
   (N record(s))" (fresh 4 slots, no cross-round state).
2. Agent: `bench/fido_probe.py` → FULL PASS (device sane).
3. Agent: start the /proc fd watcher (600 s → /tmp/opencode/
   hidraw_fd_watch_roundC?.log) + 600-s console logger (→ /tmp/opencode/
   console_roundC?.log; round B's 120 s expired 6 min BEFORE the `up`
   and lost the device view — the logger must outlive the user round).
   Agent stays OFF the key (no hidraw/ttyUSB0 writes after step 1).
4. User: `sudo modprobe usbmon` (if not loaded), then `sudo tcpdump -i
   usbmon5 -w /tmp/opencode/roundC?_NAME.usb`. (Optional: `sudo dmesg -w`
   to a log — "USB disconnect" vs "reset … USB device" distinguishes a
   physical unplug from a device-initiated reset if the key ever vanishes
   mid-round again.)
5. User: browser → https://xorengineering.com/fido2/ → Register.
6. User: type `up` on the serial console when the dialog says
   insert/touch — **within ~20 s** (device UP window is 30 s).
7. User: wait ~10 s whatever the dialog does, Ctrl-C tcpdump.

**C1 — Firefox (a different CTAP2 implementation), at the NEW origin
https://xorengineering.com/fido2/ (real cert, fresh permission state):**
- Success ⇒ firmware OK, problem is Chrome-specific → go to C2.
- Immediate NotAllowedError again ⇒ browser permission state, not
  device: check the site's WebAuthn permission (shield icon — Firefox
  remembers a denial per origin) and about:config
  `security.webauthn.enable`.
- Hang ⇒ firmware suspect (e.g. multi-packet OUT reassembly of a real
  ~200-B request, GET_INFO content) → diff this round's trace against the
  round-B capture before C2.

**C1 RESULT (2026-11-01):** none of the three branches — an immediate
NotAllowedError that WAS the device: the 190-B makeCredential (4 OUT
packets, reassembled clean) got an instant 0x2A PIN_AUTH_INVALID because
Firefox 2026 sends the CTAP **2.2** `extensions` map in slot 0x06 (v2.2
renumbered the table; pinUvAuthToken → 0x08). The pre-round "permission
state" hypothesis is dead — the request reached the device and was
rejected by our parser. Fix in fido_ctap.c case 6 (MAP in slot 6 is
skipped; BYTES still PIN_AUTH_INVALID) + the exact request pinned as a
host-test fixture. **C1b = reflash + re-run with the fixed uf2.**
Evidence: /tmp/opencode/console_roundC1.log (the `DBG MSG (190 B)` line +
the 0x2A answer), /tmp/opencode/hidraw_fd_watch_roundC1.log (only Firefox
pid 102786 opened the key), /tmp/opencode/roundC1_firefox.usb.

**C1b RESULT (2026-11-01, PAUSED after):** the extensions fix WORKED —
full device-side success on the wire (190-B request reassembled, UP wait
with keep-alives, `up`, 247-B response status 0x00 with correct
rpIdHash/COSE/sig). Firefox still fails with the same NotAllowedError →
the rejection moved from the REQUEST (C1) to the RESPONSE (C1b). Leading
hypothesis: authData flags 0x01 lacks the AT bit; L3 (REC 2026-08-25)
puts AT at 0x40 (the pre-round-2 0x41 was L3-correct), L2 at 0x04 —
which one 2026 browsers expect is the open question. See Current state
for the full trace decode, the evidence files, and the resume steps.
Evidence: /tmp/opencode/roundC1b_firefox.usb (full trace incl. the
device DBG via the UART channel), /tmp/opencode/hidraw_fd_watch_roundC1b.log
(only Firefox pid 102786), /tmp/opencode/console_roundC1b.log (EMPTY —
the user's serial terminal held /dev/ttyUSB0; usbmon's UART channel is
the reliable device view in that case).

**C2 — Chrome incognito (fresh session state):**
- FIRST close every normal Chrome window that has localhost:8888 open
  (kills any cached CTAP2 device session from the dead 16:45 handle).
  Incognito window → accept the self-signed-cert warning → Register.
- Success ⇒ normal-Chrome profile state was the culprit (stale CTAP2
  session) → C3: full Chrome restart + normal window should now pass.
- Hang ⇒ Chrome's CTAP2 stack in general mishandles this device → diff
  C2's wire trace against C1's (request shape, packet counts, response
  handling).

**Decision matrix:**
| C1 Firefox | C2 Chrome-incog | Conclusion                     |
|------------|-----------------|--------------------------------|
| pass       | pass            | stale Chrome profile state     |
| pass       | hang            | Chrome CTAP2 stack quirk       |
| hang       | pass            | re-check device (unlikely)     |
| hang       | hang            | firmware — deep-dive the traces|

**Per-round evidence:** the pcap (decode with **tshark** —
`/usr/bin/tshark -r <file> -V`; on bus 5: **dev 7 = FIDO key** (tshark
`5.7.1`), **dev 5 = CP210x UART** (`5.5.1`) — the numbers renumber after
each replug; the 2026-11-03 pair is from the C8 decode), the console DBG
(device view: did the browser's mc
arrive complete? did the 252-B response go out?), the watcher log (only
the browser should open the key), and the node server (credential stored
with rpIdHash = SHA256("xorengineering.com") = 0879ff55…).

**Real-request fingerprint (OBSERVED in C1, not just expected):**
rpIdHash 0879ff556478909709cb3912e15ebfcc7392908283d9eef62f48b6316d2b9685
(SHA256("xorengineering.com")), 32-byte user.id, user.name
"nobody@mail.com", algs [−7,−257], **slot 6 = the CTAP 2.2 `extensions`
map {"hmac-secret": false}**, options {rk:false} — 190 B = 4 OUT
packets. 4-packet reassembly is now PROVEN (the `DBG MSG (190 B)` line).

## Bench environment (facts)

- Host: Fedora 44, kernel 7.2, user `burnin`. Pico at USB port 5-1.4.1;
  bus 5 = `usbmon5`. On bus 5 (addresses renumber on every replug —
  look them up per capture, ground rule 9): FIDO key 2e8a:000b =
  **dev 22** (2026-11-03, post-reflash; it was **dev 19** in the C11
  capture — the old "5.4.1"/"5.7.1" notes were port paths, not device
  numbers), CP210x UART 10c4:ea60 = **dev 5** → `/dev/ttyUSB0` @115200
  (console commands: `up`, `wipe`; ground rules 6–7). tcpdump uses the
  bus, so the capture command is unaffected by renumbering.
- Harness: `../fido2-demonstration` (Node/Express + fido2-lib), now
  deployed at https://xorengineering.com/fido2/ (real cert; the local
  repo copy still points at localhost:8888 and is stale). rp.id
  "xorengineering.com", uv "preferred" (deployed config, API-verified).
- `bench/fido_probe.py` — must FULL PASS at the start of every round
  (INIT/PING/WINK/GET_INFO 81-B KAT; asserts fw 1.0.5).
- `/tmp/opencode/fido_sigcheck2.py` — agent-only raw-CTAP2 sigcheck
  harness (rp.id b".dummy", 91-B request, writes `up` to the same
  console). It is the source of every ".dummy" session seen in traces —
  NOT a third client. Agent stays off the key during user rounds.
- **Device view of record: usbmon, not the tty logger.** The serial
  port has exactly one effective reader: when the user's own serial
  terminal holds /dev/ttyUSB0 (to type `up`), an agent-side logger gets
  nothing — and the REVERSE is nastier: an agent-side logger running
  steals every response FROM the user's terminal (C12: the user saw a
  "dead" console). So: no console logger during user rounds, ever; the
  usbmon capture is the authoritative device view (this is also how
  C1b's trace was recovered).
- Credential store: 4 slots (littlefs /f2_3../f2_6; survives power
  cycles and reflashes). Any makeCredential the device COMPLETES stores
  a record — even when the client later rejects the content. A full
  store answers 0x28 KEY_STORE_FULL; console `wipe` resets it.

## Design decisions (in force)

- **Attestation:** self ("surrogate") packed — NO `x5c`; `sig` = the
  CREDENTIAL key (slot 3–6, just generated) signs SHA-256(authData ‖
  clientDataHash). (fido2-lib treats an empty x5c array as truthy →
  "basic" path → fails; WebAuthn §8.2 defines the x5c-absent self
  branch. Slot 1 (identity) is a provisioning marker only.)
- **Response shape:** the v2.1 map {1:"packed", 2:authData,
  3:{1:−7, 2:sig}} is emitted even though we advertise versions
  ["FIDO_2_0"] — Chrome's ReadCTAPMakeCredentialResponse and python-fido2
  require exactly that shape unconditionally.
- **authData:** rpIdHash(32) ‖ flags(1) ‖ signCount(4 BE) ‖ AAGUID(16)
  ‖ credIdLen(2 BE) ‖ credId(32) ‖ COSE_Key(77) = 164 B; response = 254 B
  (FIDO_CTAP_MC_RESP_MAX 288). **FLAGS = 0x41** (UP bit 0 | AT bit 6), the
  WebAuthn L3 layout (AT=0x40) — confirmed against the FIDO-certified
  pico-fido2 reference and the W3C REC. The AT bit is REQUIRED when
  attested credential data follows; credIdLen is 2 bytes per L3 §6.5.1.
- **COSE_Key:** the 5-entry CTAP2-wire map {1:2, 3:−7, −1:1, −2:X(32),
  −3:Y(32)} — kty=EC2(2), alg=ES256(−7), crv=P-256(**1**), x, y — 77 B.
  Settled as **SD-5**: the RFC 9053 minimal 4-entry form (no alg entry)
  is what Firefox’s authenticator-rs rejects; the CTAP2 wire carries alg.
- **Counter:** littlefs `/f2_cnt` by default (dev-friendly, resettable
  by RESET); build flag `FIDO2_COUNTER_CHIP` → chip Counter 0
  (hardware-monotonic; exercised deliberately, never in dev). Phase 3
  READS counter 0 (no increment); Phase 4 increments BEFORE building
  authData.
- **User presence:** UART0 `up` console command (the key has no
  button); 30-s UP timeout (FIDO_CTAP_UP_TIMEOUT_MS), 500-ms keep-alive
  throttle (status 0x02 UP_NEEDED).
- **Lenient user sub-fields:** user.id/name/displayName all OPTIONAL (no
  UV on this device — the user entity is storage metadata); a missing
  user.id is synthesized from the chip TRNG.
- **AAGUID:** 65f5107f-31a6-4785-9301-6788e10ec776 (demo uuid4, NOT
  FIDO-registered — a real product must register one).
- **TinyUSB:** pinned 0.21.0 via our own `lib/tinyusb` submodule +
  `PICO_TUSB_PATH` (never `<PICO_SDK_PATH>/lib/tinyusb`).

## History (one line per milestone; the full narrative is in the git log)

- **Phase 0** (257226b): ATECC608 sign/verify wrappers + mock-chip host
  tests + `prov counter` console subcommand.
- **Phase 1** (0979244 → 11a1f1b): CTAPHID transport over pure-HID USB
  (2E8A:000B, usage page 0xF1D0, two raw 64-B reports, no report IDs,
  17-B INIT response, 8-slot LRU channels, 750-ms busy timeout). Bench
  bugs found and fixed, all on our side: usbhid −22 (HID class descriptor
  referenced the report descriptor with type byte 0x21, not 0x22),
  UART0 silence (missing `stdio_init_all()`), dead WINK LED (`led_init`
  never set the pin's function select — pad stuck on GPIO_FUNC_NULL),
  handler wipe on unplug (`tud_umount_cb` must call
  `fido2_ctaphid_reset()`, not a full re-init).
- **Phase 2** (a3de401, 5f1502e, f1608d5, e8145b8): CBOR codec + CTAP2
  dispatch + GET_INFO; outgoing-report queue (TinyUSB allows one IN in
  flight per EP — back-to-back `tud_hid_report()` dropped the
  continuation); GET_INFO `algorithms` as `[{"alg":−7,"type":"public-key"}]`
  objects (bare ints fail Chromium's GetInfo parser → U2F fallback);
  85-byte GET_INFO KAT frozen in test_ctap + the probe.
- **Phase 3** (abc92ed + 98fc707, e31e40d, 250b41e): makeCredential end
  to end — parse per v2.0 §5.1 (deferred UP-wait transaction,
  keep-alives, 30-s timeout), on-chip GenKey into slots 3–6, packed
  self-attestation, 4-slot littlefs cred DB (persist-first save), U2F
  commands answered 0x6986 SW_COMMAND_NOT_ALLOWED, `up` console command,
  lenient user sub-fields. Two real bugs caught by the host tests before
  the bench: a CBOR container count clobbered the top-level loop
  variable; the cred-record CRC was byte-swapped on little-endian
  (persisted DB could never reload).
- **Bench round 1** (2026-10-31): 0x14 MISSING_PARAMETER = the sigcheck
  harness omitted user.id — transport exonerated (the 91-B 2-packet
  request reassembled fine); fix = lenient user sub-fields.
- **Bench round 2** (2026-10-31): Chrome rejected the 248-B response;
  decoding found the real bugs: credIdLen emitted as 2 bytes (spec: 1
  octet), flags 0x41 (a nonexistent "AT" bit; spec: 0x01), and the COSE
  labels encoded as 0xD1/0xD2/0xD3 — CBOR *tag* bytes, not the integers
  −1/−2/−3. (The round-2 note's "drop crv, move x/y to −1/−2" re-reading
  was itself wrong: RFC 8152 puts crv=−1, x=−2, y=−3, so the fix keeps
  map(5) and corrects the label bytes to 0x20/0x21/0x22.) Response is
  247 B post-fix.
- **Bench rounds 3–5** (2026-10-31 → 11-01): the credential store filled
  (4 slots; the device completes + stores even when the client later
  rejects the content) → 0x28 KEY_STORE_FULL; added the console `wipe`
  command. The mysterious ".dummy" third client = our own sigcheck
  harness (rp.id b".dummy", 91-B request, writes `up` to the same
  console — its print says "dummy" without the dot, which is how it
  hid). A /proc fd watch proved Chrome's main process is the only opener
  of the key.
- **Bench round B** (2026-11-01): see Current state — device proven on
  the wire; the 16:53:40 renumeration was the user's manual reset (not a
  bug); Chrome's stale 16:45 hidraw fd left the valid response with no
  reader.
- **Bench round C1** (2026-11-01): the first real-browser request
  (Firefox 2026, 190 B, 4 OUT packets — reassembly exonerated) was
  rejected INSTANTLY with 0x2A: Firefox is a CTAP 2.2 client and puts the
  renumbered `extensions` map ({"hmac-secret": false}) in slot 0x06,
  which v2.0 defines as pinUvAuthToken; the parser now skips a MAP there
  (BYTES still PIN_AUTH_INVALID), and the exact 190-B request is a
  pinned host-test fixture (t_mc_firefox_c1).
- **Bench round C1b** (2026-11-01): with the fixed uf2, the FIRST FULL
  BROWSER-SIDE DEVICE SUCCESS — 190-B request, UP keep-alives, `up`,
  247-B response (status 0x00, correct rpIdHash/COSE/sig) — but Firefox
  rejects the RESPONSE: authData flags 0x01 lacks the AT bit, and WebAuthn
  L3 (W3C REC 2026-08-25) renumbered AT to bit 6 (0x40; L2: 0x04), so the
  pre-round-2 0x41 was L3-correct and round 2's 0x41→0x01 "fix" removed
  the AT bit. PAUSED: which layout 2026 browsers parse is unresolved.
- **C1b resolution** (2026-11-02): settled the flags question by reviewing
  the FIDO-certified **pico-fido2** reference + the W3C WebAuthn L3 REC:
  flags = **0x41** (AT=0x40|UP=0x01), credIdLen = **2 bytes** — both
  confirmed. The round-2 0x01/1-byte "fixes" were uncommitted experiments
  on the L2 misreading that broke a previously-correct response; reverted
  them (HEAD already had 0x41 + 2-B credIdLen), kept the CTAP 2.2
  `extensions` + COSE fixes. Re-pinned the KATs (authData 164 B, response
  248 B), ctest 9/9, rebuilt uf2 md5 `4b285d454175ac88cde67be74e1ddaeb`.
  Awaiting the C1c Firefox / C2 Chrome browser re-test.
 - **Bugs 1–5 + delivery stall root-caused** (2026-11-02): fixed the five
   wire-confirmed bugs (continuation `0x00`, COSE crv −1, attStmt text keys,
   keep-alive `0x21`/`0x3B`, multi-packet delivery). The delivery stall's
   spin fix (no `sleep_ms`) proved insufficient in round C4 — the 16–20 ms
   inter-packet gap was the `DBG-TMP` `printf` in `outq_drain()` blocking the
   main loop (~17 ms/report at 115200), so the host's ~80 µs tight re-poll
   read a zero-length report and Firefox stopped. Stripped the `DBG-TMP`
   prints; `outq_drain()` now arms the next report in ~1–10 µs. ctest 9/9,
   uf2 md5 `ca68092b535b38e10d19bafe0897f4fc`. Awaiting C5 Firefox / Chrome.
  - **C6 flash fix + COSE_Key bug #6** (2026-11-02): the C6 `cred_save`
    failure under dual-core was `flash_safe_execute` bailing because core 1
    never called `flash_safe_execute_core_init()` (multicore lockout not
    ready) → added that init at the top of `fido_usb_core1_task()`; confirmed
    on the wire (genkey/sign/cred_save all OK, full response, status 0x00).
    End-to-end verification of that response then exposed a **malformed
    COSE_Key** (5-entry map, crv/x/y on the wrong labels + spurious alg) that
    Chromium would reject; fixed to the canonical 4-entry EC2 map (75 B),
    re-pinned the KATs offline (model byte-verified against the old KAT),
    ctest 9/9, uf2 md5 `4293034a80e6861751892adb758e76d2`. Awaiting C7.
  - **C7 controlled makeCredential PASS** (2026-11-02): after flashing the
    COSE-fixed uf2, the controlled replay (probe FULL PASS + `mc_test.py`
    re-sending the real C6 Firefox request + console watcher) completed
    end-to-end: `genkey/sign/cred_save OK` (slot 6), a full 252-B response
    (5 packets, status 0x00, no 0x7F), the COSE_Key decoding to the canonical
    4-entry EC2 map `{1:2, 3:-1, -1:x, -2:y}` (75 B), and the attestation
    ECDSA signature verifying offline (raw 64-B R||S over
    SHA-256(authData || clientDataHash)). Awaiting the C7 Firefox browser round.
   - **C7 Firefox round FAILED → root cause found + fixed** (2026-11-03):
     the tshark decode of roundC7_firefox.usb showed the device healthy
     end-to-end, but Firefox read only 3 of the 5 response packets (175 B
     of 252) and closed its hidraw fd 82 µs after packet 3 (-ENOENT on the
     4th read URB = host unlink, not a ZLP; timer ruled out). Root cause:
     `resp_send()` forced `pkt[4] = 0x00` on every continuation (a C3-era
     "fix" based on a misreading — CTAP 2.0 §8.1.5.4 / ITU-T X.1278 require
     the SEQ to start at 0 and *increment* to 0x7f); packet 3 was the first
     continuation with the wrong SEQ (0x00 for expected 0x01) and the host
     aborted exactly there. The keep-alive was a second, independent spec
     defect (wire `… bb 00 01 3b …`; spec: KEEPALIVE 0x02 with PROCESSING
     0x01 / UP_NEEDED 0x02 — the earlier "0x21/0x3B" fix was itself a
     misreading of §8.1.9.1.5, which is CTAPHID_CANCEL). Both fixed
     (fido_ctaphid.c/.h; test_ctaphid.c re-pinned to the incrementing SEQ),
     ctest 9/9, uf2 md5 `9146e094fb52e13e180ed54070cb8b7a`. Awaiting the
     user reflash + C7 retry (roundC8).
   - **C8 Firefox round FAILED (immediate, no UP prompt) → keep-alive
     framing root cause found + fixed** (2026-11-03): the C7-retry
     capture was healthy through makeCredential (190 B, 4 OUT pkts),
     then exactly one keep-alive `00 00 00 03 82 00 01 02 …` and
     silence — Firefox closed the device. The C7 CMD fix (0xBB→0x82)
     made Firefox parse the keep-alive body for the first time: it
     reads the byte after the command as the status → 0x00 = RFU,
     because `fido2_ctaphid_keepalive()` framed it through
     `resp_send()`'s 2-byte BCNT. Spec KEEPALIVE (CTAP 2.0 §8.3.4.3)
     = CMD + a SINGLE status byte (PROCESSING 0x01 / UP_NEEDED 0x02;
     0x00, 0x03–0xFF RFU), NO BCNT — C7's invalid 0xBB had made the
     host ignore keep-alives entirely, hiding the framing defect.
     Fixed: the keep-alive report is framed directly
     `[CID 4B BE][0x82][status][zeros]` (status at p[5]); test_ctaphid.c
     re-pinned; the header citation corrected to §8.3.4.3 (11.4.4.3 is
     the 2.3 numbering). ctest 9/9, uf2 md5
     `302c211baaed653f01c9d8b36ba1a962`. Awaiting reflash + C9.
   - **C9 Firefox round FAILED (dialog appeared, vanished ~500 ms in) →
     keep-alive root cause settled from Firefox's own source; PAUSED
     before the fix** (2026-11-03): the C9 wire was device-clean through
     two keep-alives (`… 82 02 00 00 …`, 484 ms apart), then Firefox
     stopped polling 2.5 ms after keep-alive #2 with no CANCEL; the
     user's late `up` still completed on the device and stored /f2_3
     (response went to an unpolled endpoint). Decoding against Firefox's
     vendored CTAP2 stack (mozilla-firefox/firefox,
     dom/webauthn/authenticator/) proved TWO defects in our keep-alive:
     (1) it IS a BCNT-framed message — the C8 "no BCNT" fix made Firefox
     read BCNT = 0x0200 = 512, demand a continuation whose "SEQ" was the
     next keep-alive's CMD byte (0x82) → "invalid sequence number"
     abort; (2) this Firefox's CTAPHID_KEEPALIVE is **0xBB**
     (consts.rs `0x80 | 0x3b`, exact `From<u8>` match), so the spec
     0x82 reads as `Unknown(0x82)` → `UnexpectedCmd` — which also
     re-explains C8's immediate abort (its `82 00 01 02` framing was
     fine; only the command byte was wrong for this browser) and C7's
     22-s tolerance (0xBB parsed as a keep-alive all along). Fix queued:
     BCNT=1 framing + CMD 0xBB, pending the spec-vs-Firefox verification
     (real 0x82 tokens presumably work in Firefox — unexplained by this
     code reading) and a Chrome-compatibility decision.

    - **C10 CBOR fix + C11 round FAILED → stale-firmware proof, rk/PIN
      hypothesis refuted, fingerprint added** (2026-11-03): C10 fixed the
      CTAP2 success responses to be the bare CBOR (no leading 0x00 status
      byte; GET_INFO 84 B, makeCredential 251 B; KATs re-pinned). The C11
      Firefox round then failed with a NEW symptom (dialog stays open,
      `up` inert, timeout) and was re-diagnosed as a resident-key/PIN
      contradiction — which the capture decode REFUTED: no makeCredential
      in the capture (probe only); GET_INFO byte-identical to the KAT with
      keys verified CORRECT against the CTAP 2.3 table (2.3 renumbered
      the GET_INFO keys — options=0x04, maxMsgSize=0x05, …,
      remainingDiscoverableCredentials=0x14); and two wire artifacts the
      current source cannot produce (a 1-byte CBOR 0x04 INVALID_SEQ
      reply; a 7-B U2F reply vs the 2-B 69 86) → the device was NOT
      running the flashed UF2 (the flash did not take). The "rk:true"
      bytes are the 2.3 `options` map that a 2.0–2.2 Firefox cannot read;
      Firefox's request carried rk:false; authData flags 0x41 has no RK
      bit; no browser rule "resident keys require a PIN" was found. The
      CTAP 2.3 CTAPHID command numbering (INIT 0x06, CBOR 0x10,
      KEEPALIVE 0x3B, ERROR 0x3F, …) was verified against the spec of
      record — the firmware already conforms. Fix: INIT-version
      fingerprint 1.0.0 → 1.0.1 (FIDO2_FW_VERSION_BUILD), new uf2 md5
      `caee4ddd3f6baf1f6912f0de4ee52ceb`, ctest 9/9. PIN implementation
      DEFERRED (Phase 6 plan updated with the concrete design).
- **C12 prep** (2026-11-03, uncommitted): user reflash verified on the
  wire (probe INIT fw=1.0.1); store wiped (0 records); probe FULL
  PASS. Console comms fixed: the Python/termios approach was broken —
  plain shell `printf 'cmd\r'` + `cat` works (the CP2102 bridge on
  UART0 is a separate USB device; `screen` had left the port in a
  working raw state). New ground rules 6–9 added: serial console
  device + protocol, sudo-ask-the-user, and capture-filter-first
  (tshark `-Y` USB fields are broken in this build; the awk
  `Device: N` section filter is the verified method — and this awk
  build chokes on dynamic regex interpolation, so it uses string
  comparison). C11 capture re-identified: the key was dev **19** there,
  not dev 4 (old notes conflated port path 5-1.4.1 with device number).
- **C13 prep round 2** (2026-11-04): 1.0.3 flash verified on the wire
  (probe FULL PASS: fw=1.0.3, caps 0x07, 86-B GET_INFO KAT); new ground
  rule 10 — the dev board is a Raspberry Pi Pico 2 (RP2350), NOT an
  RP2040 (BOOTSEL drive is `RPI-RP2350`; build targets `rp2350-arm-s`).
  `fido_mc.py` E2E then PASSED (252-B attestation validated, 5
  keep-alives, store wiped). Its first attempt exposed a HOST-side
  trap, not a firmware bug: the reflash's bridge re-enumeration had
  reset /dev/ttyUSB0 to 9600 + echo → `up` never arrived → the device
  correctly ran the 30-s UP timeout (61 keep-alives, then 1-byte 0x2F
  USER_ACTION_TIMEOUT — reproduced and decoded with
  /tmp/opencode/mc_diag.py). Port-recovery recipe added to ground rule
  7. Ready for the C13 Firefox round.
- **C13 round FAILED + root cause + 1.0.4 fix** (2026-11-04): the
  Firefox round failed (dialog opened, `up` typed, nothing happened).
  Decode of roundC13_firefox.usb: INIT (fw 1.0.3 ✓, caps 0x07 ✓) →
  GET_INFO (86-B, byte-identical KAT) → U2F version check (0x83) →
  `69 86` → Firefox stopped, NO makeCredential, no keep-alives; the
  user's `up` arrived 2.4–2.9 s AFTER Firefox gave up (device healthy).
  Root cause, proven from Firefox's source
  (`dom/webauthn/authenticator/src/ctap2/commands/get_info.rs`): the
  GetInfo parser uses the CTAP **2.1+** key numbering (versions 0x01,
  aaguid 0x03, …; unknown keys are warned+skipped, not fatal) — our
  2.0-numbered map (AAGUID bytes under 0x01) failed to parse as
  `versions` → the whole GetInfo rejected → U2F fallback. The CTAP 2.0
  spec table was never used by shipping devices (the YubiKey vector in
  Firefox's own test suite uses 2.1+). Fix 1.0.4: map re-keyed to 2.1+
  (map(8), 81 B, 57+24), firmwareVersion dropped from the map (fw stays
  in the INIT response), caps 0x07 unchanged; KATs re-pinned
  (test_ctap.c, fido_probe.py + new explicit fw 1.0.4 INIT assert,
  fido_mc.py); ctest 9/9; uf2 md5 `55d5b14f37686e21b3c3d57c7277e22d`.
  Awaiting the user reflash + C14.
 - **C14 round FAILED + root cause + 1.0.5 fix** (2026-11-04): the
   Firefox round on 1.0.4 proved the C13 fix (makeCredential arrived,
   190 B/4 OUT; 5 keep-alives; on `up` the full 252-B response out in 5
   IN packets) — then the browser rejected the CONTENT (silence after
   packet 5; rpIdHash on the wire = SHA-256("xorengineering.com") ✓).
   Root cause, proven from the wire + Firefox's source
   (`make_credentials.rs` + `crypto/mod.rs`): the COSE_Key `crv` was
   encoded as **−1** (CBOR 0x20) — the COSE registry (RFC 8152 §13.1)
   has P-256 = **1**, and Firefox's `Curve::try_from(−1)` →
   `UnknownKeyType` → the COSE key, hence the whole response, rejected.
   The response FRAMING was exonerated in the same pass: Firefox's
   `MakeCredentialsResult` deserializer + its own test vector parse
   exactly our `map(3) {fmt, bstr(authData), attStmt-map}` (the
   wire-only "bstr(authData‖attStmt)" hypothesis was disproven). Fix
   1.0.5: crv 1 (one wire byte, `03 20` → `03 01`; size unchanged,
   252 B); KATs re-pinned offline (old KAT verified self-consistent
   first; mock sig recomputed), bench crv/fw asserts updated; ctest 9/9;
   uf2 md5 `a2589242f411e46596c6c06f54a63da9`. New ground rule 11
   (serial ALWAYS 115200, never 9600). Lesson: spec-conformance bugs
   are invisible to verifiers derived from the firmware's own output —
   verifier logic must be spec-derived. Also added ground rule 12
   (record settled analyses) + the **Settled decisions** register
   (SD-1 framing, SD-2 GET_INFO numbering, SD-3 COSE crv) so encoding
   questions are answered once against the primary source and not
   re-litigated. Awaiting the user reflash + C15.
  - **C15 CLOSED as a FALSE ALARM** (2026-11-04): the "invalid signature"
    was a bug in the OFF-CHIP verifier (`cryptography` `pk.verify`
    SHA-256-hashes its data arg; the ATECC608 external-digest Sign signs
    the 32-B MD buffer as-is) — a raw-digest P-256 ECDSA verifier proves
    ALL chip signatures VALID (SD-4). `bench/fido_mc.py` now does real
    raw-digest ECDSA (pure-Python, self-tested).
  - **C16 root cause + 1.0.5 fix** (2026-11-04): the browser's
    authenticator-rs `COSEKeyVisitor` expects the **5-entry** COSE key
    `{1:kty, 3:alg, -1:crv, -2:x, -3:y}`; we emitted the RFC 9053
    **4-entry** `{1:kty, 3:crv, -1:x, -2:y}` → Firefox read our −1 (x,
    bytes) where it wants the curve i64 → `invalid type: byte array,
    expected i64` (the C16 RUST_LOG). Fix: emit the 5-entry layout (77 B;
    authData 164 B; response 254 B / BCNT 0x00FE). **Supersedes SD-3** →
    recorded as **SD-5**. KATs re-pinned (test_ctap.c, fido_mc.py); ctest
    9/9; uf2 md5 `24df233af54519a4043c2691381b74b7`.
  - **C16 flash + wire verification + C17 browser round** (2026-11-04):
    1.0.5 flashed (the Pico reboots the instant the uf2 write completes —
    the BOOTSEL volume vanishing after `cp` IS the success signal; verify
    via the INIT fw version, not a volume read-back). `fido_probe.py` FULL
    PASS (fw 1.0.5); `fido_mc.py` E2E **PASS** (254-B response, 5-entry
    COSE, packed signature VALID raw-digest). C17 (webauthn.io,
    `RUST_LOG=authenticator=debug`): the C16 parse error is **GONE**; new
    failure `CommandError: Unexpected code: UserActionTimeout` = CTAP2
    0x0A = the 30-s UP window expired before `up` was delivered (a
    round-**TIMING** issue, NOT firmware/COSE).
   - **C18 webauthn.io PASS — first browser-side registration success**
     (2026-11-05): the C17 `UserActionTimeout` was round timing, not
     firmware — `up` sent ~2 s after the Register click (inside the 30-s
     window) made webauthn.io report registration **success** on fw 1.0.5;
     the fresh RUST_LOG is clean of both the C16 COSE parse error and
     `UserActionTimeout`; no code change. Next: the xorengineering.com
     second harness, then diagnostic removal + commit (Phase 4
     getAssertion still pending — the page's "authentication test" button
     will fail until then).
   - **C19 xorengineering.com PASS + diagnostic cleanup** (2026-11-05):
     the second harness (fido2-lib server verification) also reports
     registration **success** (same fast-`up` pattern; clean log delta)
     — register passes on both webauthn.io and
     xorengineering.com/fido2/. Removed the temporary `diag` console
     command + the `DBG mc:` prints (both browser rounds pass; C15 is
     closed as a verifier false alarm — SD-4); rebuilt uf2 md5
     `b837ed7f5f6754e67b05ac0aab6372b9` (172544 B, wire-identical 1.0.5);
     ctest 9/9; code + PLAN.md committed separately. Next: Phase 4
     (getAssertion + RESET).

## Goal

A minimal but *real* FIDO2 (CTAP2) passkey authenticator as the third
example: a PC browser can **register** a passkey on the Pico and then
**use** it to log in — over USB HID, the standard security-key
interface, so no driver and no custom host tooling (Chrome/Windows/
macOS recognize the device directly).

Same philosophy as the vault example: the chip is the **key vault +
signer** (ECC P-256, monotonic counter), the Pico is the **protocol
engine** (CTAP2 + CBOR), littlefs is the **metadata store**.

## The demo (acceptance test, bench)

1. Flash the fido2 uf2; plug the Pico into a PC.
2. A browser sees a **security key** with up to 4 discoverable
   credentials.
3. **Register** a passkey (MAKE_CREDENTIAL): a fresh EC P-256 key is
   generated on the chip (next free slot 3–6); the browser receives self
   "packed" attestation.
4. **Log in** (GET_ASSERTION): the chip signs the challenge digest with
   the credential key; the CTAP sync counter increments; the browser
   logs in.
5. **Replug or reflash** the Pico: the credential still works — key on
   the chip, metadata + counter in littlefs (outside the app region, so
   a reflash cannot reset it).

> **Test harness:** `../fido2-demonstration` (Node/Express + fido2-lib
> v3.5.6) — register + login over HTTPS on :8888, self-signed cert.
> config.js: rp.id "localhost", userVerification "required" (satisfied
> by auto-UV), cryptoParams [−7,−257] (the key offers −7 only),
> attestation "none" (a conveyance preference — fido2-lib validates
> whatever fmt arrives).

## Ground rules (unchanged)

- **No re-provisioning of the frozen bench chip; no config-zone
  writes.** The example uses only what the frozen config already allows:
  GenKey into slots 3–6; external-digest Sign with slots 3–6 (slot 1
  unused now); read + increment Counter 0 (chip-counter mode only);
  ECDH with slot 12 (PIN stretch only).
- Flashing and every bench run is a **user action**.
- Host KATs are ground truth for the pure-C parts (CBOR, SHA-256, COSE,
  cred records).

## Division of labour

| Concern | Where |
|---|---|
| 4 credential private keys | slots 3–6, on-chip GenKey, never leave the chip |
| Attestation key | the credential key itself (slot 3–6) — self "packed", NO x5c |
| CTAP global counter | littlefs `/f2_cnt` default; chip Counter 0 behind `FIDO2_COUNTER_CHIP` |
| CTAP2 protocol, CBOR, authData, dispatch | Pico |
| SHA-256(authData ‖ clientDataHash) | pure-C SHA-256 (host KAT'd; the RP2350 hardware accelerator is usable on-device but not host-compilable) |
| Credential metadata | littlefs flat files `/f2_<n>` (236-B records + CRC-32) |
| UV | auto-UV (documented caveat); a GPIO button is a stretch item |

**I/O protection note:** the MVP uses only GenKey / Sign / counters —
none I/O-protected, so no `/io_key.bin`. The PIN stretch (ECDH,
`ecdh_prot=1`) *does* need it.

## Scope cuts (what "simple" means)

- CTAP 2.0 only (`"FIDO_2_0"`), one algorithm: ES256 (COSE −7).
- 4 credentials max, all resident-capable/discoverable.
- No cred_prot, no large-blob storage, no PIN protocol in the MVP
  (Phase 6 adds PIN v1 if needed).
- No biometrics; auto-UV. One AAGUID (a fixed demo constant).
- No secure firmware updates, no CTAP 2.1+.

## Phase 4 — GET_ASSERTION (+ RESET)

- **Lookup:** (rpIdHash, credentialID) from the request; for a
  discoverable "get" with no allowList, enumerate resident matches (≤4).
  No match → NO_CREDENTIALS.
- **authData:** rpIdHash ‖ flags(UP|CRED_ID) ‖ counter ‖ credIdLen(1) ‖
  credId.
- **Counter increment BEFORE building authData** (read → increment →
  build with the new value → sign → send), so the first assertion after
  registration never reads as a "rollback" to an RP that compares
  against the stored registration counter (the demo's fido2-lib does
  exactly this). Increment failure → error, never a stale-counter
  assertion. (The littlefs backend enforces monotonicity in software;
  the chip backend is hardware-monotonic.)
- **RESET:** wipe the littlefs DB (on-chip keys remain; the next
  MAKE_CREDENTIAL re-binds the slots). littlefs-counter mode also
  resets the counter to 0 (dev convenience); chip-counter mode does not.
- **Bench:** full register + login cycle in the browser; replug; reflash
  survival (credential works, counter keeps counting); counter strictly
  increasing.

## Phase 5 — hardening + docs

- Error paths: CBOR decode failures, missing params, full store, counter
  increment failure → correct CTAP status codes (no crashes, no hangs,
  keep-alive stays sane).
- Docs: `example/README.md` "FIDO2 example" section (it's a USB device,
  no console app: demo flow, auto-UV caveat, 4-credential limit, slot
  map, reflash/counter behavior); main README examples list + build
  outputs.
- Commit per phase; keep this file's Current state current.

## Phase 6 (stretch, after the MVP works) — PIN protocol v1

**Status (2026-11-03): DEFERRED.** The C11 rk/PIN re-diagnosis was
refuted (no browser rule "resident keys require a PIN" was found; our
rk advertisement is under 2.3 keys a 2.0–2.2 Firefox cannot even read;
the demo runs UV "preferred" / rk not required). Enter Phase 6 only if
(a) a verified-firmware browser round still fails for a
UV/PIN-related reason, (b) the user wants UV=required support, or (c)
FIDO certification is targeted.

Concrete design (the answer to "how do we implement a PIN?"):

- **Surface (CTAP 2.3 numbering, per the spec of record):**
  - GET_INFO: `options` += `clientPin: true`; `pinUvAuthProtocols` = [2]
    (2.3 key 0x06).
  - `authenticatorClientPIN` (command 0x06) with the 2.3 subcommands:
    getPINRetries 0x01, getKeyAgreement 0x02 (→ COSE_Key of our P-256
    ECDH key + `pinUvAuthProtocols` [2]), setPIN 0x03 (→ pinProtocol,
    keyAgreement, pinToken, pinUvAuthParam), changePIN 0x04,
    getPinToken 0x05. (2.0–2.2 clients use a DIFFERENT subcommand table
    — getPinProtocol 0x01 … setPIN 0x06; dual-numbering may be needed
    for browser interop, same caveat as the GET_INFO keys.)
  - `pinAuth` (32 B = 16-byte nonce ‖ 16-byte AES-CCM tag) accepted in
    makeCredential/getAssertion; a valid pinAuth sets the UV bit
    (flags 0x41 → 0x45 UP|UV|AT).
  - getAssertion authData gains the 16-B `pinUvAuthAuth` (AES-CCM MAC
    over the authData prefix, AAD "PIN-Auth", nonce from pinAuth —
    verify the exact prefix length against the FIDO PIN-UV Auth
    Protocol v1.0 spec + fido2-lib at implementation time).
- **Crypto split:**
  - ECDH P-256: on the ATECC608 — non-exportable key-agreement pair in
    slot 12 (GenKey at provisioning; the ECDH command returns the
    32-B shared secret for a client public key; the private key never
    leaves the chip). NOTE the frozen-chip constraint: `ecdh_prot=1`
    means the shared secret arrives I/O-encrypted → needs
    `/io_key.bin` + an `atecc608_ecdh` wrapper (already flagged in the
    I/O protection note).
  - HKDF-SHA256: in SOFTWARE on the Pico (the IKM is the PIN string,
    not a chip slot key, so the chip's HKDF does not fit):
    salt = SHA-256(sharedSecret ‖ 0x02), info = "CTAP2 PIN",
    pinTokenKey = 32 B. Needs HMAC-SHA256 over the existing pure-C
    SHA-256 (~40 lines).
  - AES-CCM: in SOFTWARE on the Pico (the ATECC608 has no CCM).
    Payloads are ≤ 64 B (32-B PIN token, 32-B pinAuth tag over 40-B
    AAD, 16-B pinUvAuthAuth) — trivially fast at 133 MHz. ~250 lines
    (public-domain AES-128/256 core + CCM mode).
- **Storage:** pinTokenKey (32 B) + pinUvAuthParam (16 B) +
  retry/lockout state (8 retries → 300 s lockout) in a littlefs file
  (e.g. `/f2_pin`, +CRC); the KA private key stays in chip slot 12.
  Flash writes only from a stable point (ground rule 2) — setPIN is a
  natural stable point (no in-flight transaction).
- **Effort:** ~600–900 lines of firmware (AES-CCM + HKDF are most of
  it) + host KATs (expected values generated from a reference
  implementation) + the dual-key-numbering interop decision. 1–2 days
  of focused work.

## Open questions (resolve as we go)

1. **PIN-less resident keys — RESOLVED (2026-11-03, C11 decode):** no
   browser rule "resident keys require a PIN" was found (web search;
   PIN-less YubiKey resident keys work in Firefox; the real CTAP rule
   is the inverse — a device WITH a PIN set must require pinAuth, and
   ours has none). Our `rk:true` advertisement sits under the CTAP 2.3
   `options` key (0x04), which 2.0–2.2 browsers do not parse, so they
   never even see it; their makeCredential requests carry rk:false and
   our authData flags (0x41) have no RK bit. The demo exercises the
   non-resident path (browser supplies the credentialID at login),
   which our 4-slot store already serves. Phase 6 stays a stretch.
2. **Counter 0 increment on the frozen chip:** expected to work by
   design (COUNTER is the one config-zone field writable after the
   lock). Confirmed when we flip `FIDO2_COUNTER_CHIP` for the
   chip-counter verification; the littlefs default is unaffected either
   way.

## Risks

- **Chip Counter 0 only ever increases** (monotonic) — correct FIDO
  behavior, not a bug; once exercised, the bench chip's counter will not
  return to 0. This is why the dev default is the littlefs counter.

## Out of scope (explicit)

CTAP 2.1/2.2, FIDO2.1, cred_prot, large-blob storage, biometrics / real
UV, multiple AAGUIDs, key rotation beyond RESET's re-bind, secure
firmware updates, and any config change (the chip is frozen).

## File layout (as built)

```
example/fido2/
  main.c            app: startup contract, USB init, main loop
  tusb_config.h     TinyUSB config (device mode, CFG_TUD_HID, 64-byte EP)
  fido_hid.c/.h     FIDO HID descriptors + TinyUSB glue + ATECC608
                    backend vtable + littlefs cred DB + console commands
                    (up/wipe)
  fido_ctaphid.c/.h CTAPHID transport core: pure-C framing/channel state
                    machine (host-tested)
  fido_cbor.c/.h    minimal CBOR codec (host + device)
  fido_ctap.c/.h    CTAP2 commands: GET_INFO / MAKE_CREDENTIAL
                    (GET_ASSERTION + RESET in Phase 4)
  fido_cred.c/.h    236-B cred record + 4-slot store (persist-first)
  fido_cose.c/.h    COSE_Key ES256 (77 B, 5-entry CTAP2 wire — SD-5)
  fido_sha256.c/.h  pure-C SHA-256 (FIPS KATs)
tests/              test_ctaphid, test_cbor, test_ctap, test_cred,
                    test_sha256 (+ the pre-existing module tests)
```

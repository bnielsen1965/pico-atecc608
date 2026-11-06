# Plan: FIDO2 example — passkey authenticator

This file is the forward plan **and** the continuity snapshot. Development
history lives in the git log — this file was committed at every phase, so
keep entries forward-looking: when a phase lands, compress its narrative
into a one-line History bullet.

(2026-11-05: the settled C7–C17 narrative blocks were pruned per this
rule — their root causes live in the History bullets, the Settled
decisions register, and the git log.)

## Ground rules (2026-11-03 — in force for all further work)

1. **USB timing is critical.** Core 1 is dedicated to stable USB
   communications (`fido_usb_core1_task()`); the card/CTAP logic runs on
   core 0. Never block the USB core.
2. **Flash writes pause all cores.** Only initiate a littlefs/flash write
   from a stable point (no in-flight USB transaction, queues drained).
3. **Spec of record:** `example/fido2/fido-client-to-authenticator-protocol-
   v2.3-ps-20260226.pdf` (CTAP v2.3 PS). Verify protocol details against
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
     The CP210x bridge re-enumerates on every reflash/replug (and hub
     power events) and comes back at the kernel default (9600 + cooked
     + local ECHO); a dead/silent console is the symptom (the C13-prep
     round-2 and the 2026-11-06 C20-prep records: `up` never arrived
     because the port had reset to 9600+echo). Apply the recovery
     BEFORE ANY console work — not only after a reflash, but before
     EVERY open, including programmatic access from the bench scripts:
     `stty -F /dev/ttyUSB0 115200 cs8 -cstopb -parenb -echo -opost`.
     Never open the port assuming its current speed. Never toggle
     DTR/RTS as a "diagnostic" (a CP210x DTR de-assert can
     re-initialize the chip's line config; it is not a fix and can be
     the thing that breaks a working port). A silent console is a
     PORT-STATE bug, not a device bug — run rule 7's
     `stty -a -F /dev/ttyUSB0 | head -1` diagnostic FIRST and recover
     with the stty recipe; do not start diagnosing the wiring, the
     bridge, or the firmware. `bench/fido_mc.py console_cmd` (the
     single console choke point for all bench scripts) enforces the
     recipe on every call.
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
13. **Flash verification.** The Pico **reboots the moment the uf2 write
    completes** — the BOOTSEL volume disappearing right after `cp` is
    the SUCCESS signal, not a failure. Do NOT read the volume back
    after the copy (it's already gone); the `[ -d
    /run/media/burnin/RP2350 ]` check is unreliable (the automounter
    creates a transient placeholder). Verify the flash via the INIT fw
    version (the probe) + post-reboot HID enumeration (`lsusb` / `findmnt
    -t vfat`), never a volume read-back.

## Current state (2026-11-06) — **Phase 5 (hardening + docs): error paths + docs COMPLETE, uncommitted; fw 1.0.9 built, pending the device verification round.** SD-8 (DER signatures) was completed, verified and committed on 1.0.8 (`fa4e139` + `c87b271`; webauthn.io round PASS). Phase 5 audit: the firmware's error paths were already robust — missing params (0x14), type errors (0x11), store-full (0x28), counter-increment failure (0x7F), keep-alive sanity — all KAT-pinned; codec-level CBOR strictness is covered in test_cbor.c. ONE real gap found + fixed: **structurally truncated / malformed CBOR answered 0x11 (CBOR_UNEXPECTED_TYPE) where the spec-correct code is 0x12 INVALID_CBOR** (CTAP 2.3 §11.2.9.1.3) — the 35 conflated decode-failure/type-mismatch sites in parse_make_credential + ga_parse are split (decode fail → 0x12, type mismatch stays 0x11); new `t_dispatch_truncated()` pins 0x12 at EVERY byte cut-point of valid MC/GA requests + a truncated map header — test_ctap 736 → **1189 checks**, ctest 9/9. fw **1.0.9** (happy-path wire format unchanged; uf2 md5 `2df53d9f3700c13bf86fbd92d4a0564f`), bench gates → 1.0.9. Docs: `example/README.md` gained the "FIDO2 example" section (USB device, no console app: demo flow, no-UV/auto-UP-via-console caveat, 4-credential limit, slot map, reflash/counter behavior, the 2.3 PS command table) and the main README the fido2 build outputs, repo layout and the five fido2 host tests. **NEXT: user flashes 1.0.9 → probe gate + offline bench (happy-path regression) → wipe → commit Phase 5.**

- **How we got here (the C13–C17 arc — settled):** C13 re-keyed GET_INFO to the CTAP 2.1+ numbering (fw 1.0.4); C14 fixed the COSE `crv` to 1; C16 fixed the COSE layout to the 5-entry CTAP2-wire form (fw 1.0.5 — **SD-5**); the wire was then verified by probe + `fido_mc.py` E2E (real raw-digest ECDSA check). C17, the first browser round after the C16 fix, failed only on **round timing** — `UserActionTimeout`: the 30-s UP window expired before `up` arrived. No further firmware/COSE bug has been found since. Full narrative: the History section.
- **C18 (webauthn.io) + C19 (xorengineering.com/fido2/): registration SUCCESS on both harnesses** (2026-11-05, fw 1.0.5). The C17 fix was pure protocol: `up` within ~2 s of the Register click (inside the 30-s window). RUST_LOG clean on both (zero `byte array, expected i64`, zero `UserActionTimeout`). Caveat: the webauthn.io page then offers an “authentication test” — getAssertion is Phase 4 (unimplemented; a clean 1-byte `INVALID_COMMAND` today), so do not click it until then.
**NEXT (Phase 5 — wrap-up):**
1. **User flashes 1.0.9** (BOOTSEL) → probe gate (fw 1.0.9) + offline bench (the happy-path regression: MC + GA + stock fido2-lib verify).
2. Wipe (0 creds, counter 0) + probe gate.
3. Commit Phase 5 (firmware 1.0.9 + the split-error KATs + bench gates + both READMEs + this file).
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

### SD-6 — getAssertion wire format: the REQUEST table is the stable CTAP 2.0 one (keys 1–7); the response top level is INTEGER keys 1–5 with TEXT-keyed inner maps; options `uv`/`rk` → 0x2B; `"up": false` is a synchronous preflight (Phase 4, 2026-11-05)
- **Question:** what does the browser SEND in a getAssertion request
  (key numbers/types), and what does it DESERIALIZE from our response —
  including the key form of the nested maps?
- **Settled:**
  - **Request table is STABLE from CTAP 2.0 through 2.3** (NOT the 2.1+
    renumbering): 1=rpId TEXT, 2=clientDataHash BYTES(32),
    3=allowList ARRAY of TEXT-keyed maps `{"id": BYTES, "type":
    "public-key"}` (omitted when empty → resident enumeration),
    4=extensions (skipped), 5=options TEXT-keyed map,
    6=pinUvAuthParam BYTES, 7=pinUvAuthProtocol. Firefox may also send
    optional 2.1+ keys 8 (enterpriseAttestation) / 9
    (attestationFormatsPreference) — unknown top-level keys are skipped.
  - **Response:** top-level INTEGER keys 1=credential, 2=authData,
    3=signature, 4=user, 5=numberOfCredentials (only in the FIRST
    response of a multi-credential enumeration). The nested maps use
    **TEXT keys**: credential = exactly `{"id": bstr, "type":
    "public-key"}` (no other fields — Firefox's deserializer rejects
    unknown fields); user = exactly `{"id": bstr}` (name/displayName are
    never returned without UV — 2.3 step 12.3).
  - **Options** (2.3 §6.2.2 step 4, checked in the order uv → rk → up,
    BEFORE locate/NO_CREDENTIALS and the UP wait): `"uv": true` →
    UNSUPPORTED_OPTION 0x2B (the device advertises FIDO_2_0; the 2.0
    client is the only uv-without-PIN sender, and 2.3's INVALID_OPTION
    0x2C is not a 2.0 code); `rk` present (any value) → 0x2B (2.3 step
    4.4); unknown options ignored; `"up": false` → a **full signed
    assertion served synchronously in dispatch** (flags AT-only 0x40,
    counter still incremented, enumeration state still armed).
  - **pinUvAuthParam** (clientPin is not advertised → dead path for real
    clients; pinned by KAT only): key 6 BYTES present + 7 absent →
    MISSING_PARAMETER 0x14; 6 + 7 present (no protocol supported) →
    CTAP1_ERR_INVALID_PARAMETER 0x02; key 6 as a MAP →
    CBOR_UNEXPECTED_TYPE 0x11; key 7 without 6 → ignored.
  - **Serve order** (no allowList, count > 1): descending slot
    (6,5,4,3) — a documented approximation of "most recent first"
    (the record carries no timestamp). First response carries
    numberOfCredentials (even when = 1); an allowList match →
    4-entry response, no enumeration state.
- **Primary-source evidence:**
  - **CTAP 2.3 spec of record** — §6.2 getAssertion (:1573–2062),
    §6.3 get_next_assertion (:2212), §6.6 RESET (:4317).
  - **CTAP 2.0 PS** — §5.2 request table; EXAMPLE 5 (:1918–1992):
    credential map `{"id","type"}` + user entity TEXT keys
    "id"/"icon"/"name"/"displayName".
  - **Firefox** — `fx_get_assertion.rs` :509–520 (the serializer sends
    keys 1–7 in the 2.0 order); `fx_server.rs` :75–82 (the
    serde-derived `PublicKeyCredentialUserEntity`: `id` required,
    `name`/`displayName` optional) and :202–217 (allowList entries).
- **Lesson:** the 2.1+ renumbering does NOT apply to getAssertion —
  only to GET_INFO (SD-2) and makeCredential framing (SD-1).
  Per-command numbering must be verified per command; never generalize
  one command's table to another.

### SD-7 — the getAssertion / get_next_assertion `authData` EXCLUDES the attested credential data: 37 bytes, flags = UP only (Phase 4, 2026-11-06)
- **Question:** what exactly goes in the assertion's `authData` — the
  same 164-byte makeCredential layout (rpIdHash | flags | counter |
  AAGUID | credIdLen | credId | COSE_Key, AT=1), or something smaller?
- **Settled:** the assertion `authData` is **exactly 37 bytes**:
  `rpIdHash(32) | flags(1) | signCount(4 BE)`, and the flags carry
  **UP only** (`0x01` on the deferred path, `0x00` on the `"up": false`
  preflight). There is **NO AT bit, NO AAGUID, NO credIdLen/credId, NO
  COSE_Key**. The credential itself travels in the response's
  `credential` member (SD-6), not in the authData. `ga_assert()` builds
  the 37-byte buffer, signs `SHA-256(authData … clientDataHash)` with
  the credential key (raw 64-byte R•S), and never calls `get_pubkey`.
  GNA shares `ga_assert`, so one fix covers both. The GA response
  shrinks 330 → **203 bytes** (4 IN packets).
- **Primary-source evidence:**
  - **WebAuthn L3** (W3C REC 2026-08-25) §6.3.3 `authenticatorGetAssertion`
    step 10: "Let authenticatorData be the byte array specified in § 6.1
    Authenticator Data … **excluding attestedCredentialData**." (CTAP 2.3
    PS delegates the GA authData structure to [WebAuthn].)
  - **Firefox** — `dom/webauthn/authenticator/src/ctap2/attestation.rs`
    `Serialize for AuthenticatorData` :257–379 forwards the device's
    authData to the page **verbatim**, including the attested credential
    data when present — so a 164-byte AT=1 authData would reach the page
    and fail the same audit that rejected it offline.
  - **fido2-lib 3.5.6** — its own assertion fixture is 37 B flags 0x05
    (UP|UV); `validateAudit` requires every parsed authnrData key to be
    journaled, so an un-validated `aaguid` (from AT=1 input) fails the
    assertion audit. The ecosystem norm is 37 bytes.
- **Lesson:** the makeCredential and getAssertion authData layouts are
  DIFFERENT. The AT bit and the attested credential data belong to
  registration only. Do not reuse the MC authData builder for the
  assertion. (The old 164-byte AT=1 assertion was a DEVICE BUG — it broke
  fido2-lib's assertion audit and would have failed the browser login the
  same way.)

### SD-8 — ES256 `sig` values MUST be ASN.1 DER `Ecdsa-Sig-Value` (RFC 3279 §2.2.3) — assertion AND packed attestation (2026-11-06, user-confirmed)
- **Question:** the device emitted the ATECC608's raw R‖S (64 B) as the
  ES256 `sig` in getAssertion AND makeCredential (packed attestation).
  webauthn.io (py_webauthn 3.0.0) rejected the login with "Could not
  verify authentication signature". Which encoding is spec-correct?
- **Settled:** **ASN.1 DER** `Ecdsa-Sig-Value` — `SEQUENCE { r INTEGER,
  s INTEGER }` — for BOTH the assertion `sig` and the packed-attestation
  `sig`. The raw R‖S form is the COSE_Sign signature encoding (RFC 9052
  §2.4 / RFC 8152 §3.4), NOT the WebAuthn signature. The device's raw
  output was a **device bug**; the C19/C20-era "raw is spec-correct"
  claim is RETRACTED (it confused COSE_Sign with the WebAuthn signature).
- **Primary-source evidence:**
  - **WebAuthn L3** (W3C REC 2026-08-25) §6.5.5 signature verification:
    the ES256 `sig` MUST be an ASN.1 DER encoded `Ecdsa-Sig-Value`
    (RFC 3279 §2.2.3) — and the section's note: "CTAP2
    authenticators will also produce signatures values in the same
    format." Fetched verbatim 2026-11-06; the CTAP 2.3 PS PDF remains
    the wire spec of record, and it delegates the signature format to
    [WebAuthn].
  - **py_webauthn** (duo-labs; the webauthn.io server, pinned
    `webauthn==3.0.0`): `verify_signature.py` passes the `sig` bytes
    straight to pyca/cryptography's DER `ECDSA` verifier — no raw
    conversion; its own EC2 test vectors are DER (`MEUC…`).
  - **ecdsa.com** (the py_webauthn demo, 3.0.1): fed a raw 64-B sig
    it reproduces the user's exact webauthn.io error.
  - Browsers emit DER: real assertion signatures are 64–72 VARIABLE
    bytes (the INTEGER sign-pad), never a fixed 64.
- **Fix (fw 1.0.8):** `fido_ecdsa_der_encode()` (fido_cose.c) —
  minimal DER INTEGER encoding (leading zero octets stripped; a single
  0x00 sign-pad when the high bit is set — byte-identical to
  OpenSSL/browser output; 10–72 B, 70 B in the common case). Applied
  at the CTAP layer in `ga_assert()` and `mc_create()`; the key-backend
  vtable contract stays raw R‖S 64 B. `FIDO_CTAP_MC_RESP_MAX` 288 →
  296 (the 72-B DER max); `FIDO_CTAP_GA_RESP_MAX` 424 unchanged
  (headroom).
- **Harness correction:** the fido2-lib patch's ECDSA-raw-acceptance
  part was a MISTAKE — it bent the harness to a non-compliant device
  (inverting the ground rule that the spec decides, never the harness
  behaviour). REVERTED: fido2-lib's stock `derToRaw()` + webcrypto
  verify is correct and now works unmodified. The attestationObject
  integer-key normalization (a genuine fido2-lib parser bug) REMAINS;
  patch renamed `fido2-lib-3.5.6-attestation-cbor.patch` (2 files /
  4 hunks, round-trip-verified). The local fido2-demonstration "pass"
  of the C20 era was therefore NOT proof of compliance — the
  webauthn.io round is the compliance check.
- **Lesson:** when a spec-conformant peer rejects the wire, fetch the
  spec section VERBATIM before blaming the peer. "RFC 8152 says raw"
  was true of COSE_Sign and wrong of the WebAuthn `sig` — one section
  (§6.5.5) decides, and it says DER.

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
  (INIT/PING/WINK/GET_INFO 81-B KAT; asserts fw 1.0.7).
- **Bench-round discipline:** the agent wipes + probes before the round
  and stays OFF the key during the user round (the only agent console
  writes are the `up` at "go" and the post-round `wipe`); no console
  logger while the user works (one reader per port, rule 7).
- **fido2-cred / fido2-token (libfido2 1.16) are CTAP 2.3 clients:**
  they parse only the 2.3 GET_INFO keys (no legacy fallback), so they
  always classify our device U2F-only and fall back — EXPECTED, not a
  firmware failure (C10 findings). Use `bench/fido_mc.py` for E2E.
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
- **INIT caps = 0x07** (WINK 0x01 | CBOR 0x02 | NMSG 0x04 — the 2.0–2.2
  bit positions). 2.0–2.2 browsers classify by the 0x02 CBOR bit (caps
  0x0D would read as U2F-only); libfido2 1.16 (a 2.3 client) reads CBOR
  at 0x04 — our legacy NMSG bit satisfies it, so it at least attempts
  GET_INFO.
- **CTAP2 success responses = 1-byte status (0x00) + CBOR at resp+1**
  (CTAP 2.3 §11.2.9.1.2; the clients' cbor_parse_reply requires the
  leading status byte — the C10 "bare CBOR" experiment was reverted in
  1.0.3). Error paths return the single status byte alone.
- **Keep-alive = CTAPHID_KEEPALIVE 0x3B, BCNT=1, status at p[7]**
  (CTAP 2.3 §11.2.9.1.7 — USB HID; the 0x82 value is the BLE
  keep-alive, §11.4.4.3, a different transport). Firefox's exact-match
  `From<u8>` expects 0xBB = TYPE_INIT | 0x3B.
- **rpIdHash is computed, not taken:** the firmware computes
  SHA-256(rp.id) from the rp.id string (fido_ctap.c; WebAuthn §6.1) and
  ignores the request's rpIdHash field; the E2E asserts
  SHA-256("xorengineering.com") in authData.

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
  byte; GET_INFO 84 B, makeCredential 251 B; KATs re-pinned — a
  misdiagnosis, REVERTED in 1.0.3: the leading 0x00 status byte is
  REQUIRED by the clients' cbor_parse_reply, see Design
  decisions). The C11
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
- **C12b — caps 0x07 + GET_INFO re-key (fw 1.0.2, 2026-11-03):** the
  C12b capture (fw 1.0.1) showed Firefox classifying the key U2F-only
  and never sending makeCredential. Two encoding gates, each alone
  fatal: INIT caps 0x0D (the 2.3 bit positions — 2.0–2.2 browsers
  read CBOR at 0x02) and the GET_INFO 2.3 key numbering (a 2.0–2.2
  client reads 0x09 as `algorithms` → gets `["usb"]` → "no usable
  algorithms"). Fix: caps 0x07 (the 2.0–2.2 positions) + the GET_INFO
  re-key — first (wrongly) to the 2.0 table, corrected to the 2.1+
  numbering in 1.0.4 (C13). The "7-byte 0x83 reply" wire anomaly was
  resolved as Firefox's own U2F version-check request (we answer 0x6986
  — not a device bug).
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
- **C20-prep: fw 1.0.6 + offline fido2-lib bench + console 115200 fix**
  (2026-11-06): Phase 4 code complete (GA + GNA + RESET; ctest 9/9,
  test_ctap 632/632 incl. 16 new GA/RESET KATs); fw 1.0.6 built (uf2
  md5 `2a8b584d98c6c204de63f7a46d6db53c`), flashed, probe FULL PASS.
  The local fido2-demonstration round (fido2-lib 3.5.6 on Node 24)
  failed server-side although the device's crypto is spec-correct —
  the root cause is TWO fido2-lib harness bugs, both fixed in the
  harness, the device unchanged: (1) `verifySignature` unconditionally
  `derToRaw()`'d the signature before `subtle.verify` — Node >= 24
  webcrypto wants raw R||S (RFC 8152 §3.4), which is what this device
  (and every real authenticator) sends; the patch converts only
  well-formed DER and passes raw through. (2) attestationObject
  parsing required TEXT top-level keys `fmt`/`authData`/`attStmt`,
  while real CTAP2 authenticators emit INTEGER keys 1/2/3 (CTAP 2.3 PS
  makeCredential table: fmt 0x01, authData 0x02, attStmt 0x03);
  fido2-lib's own fixtures are fabricated TEXT-key objects. The patch
  normalizes CTAP2 1/2/3 (and W3C 0/1/2) to TEXT names after
  `cborX.decode`. Patch file `patches/fido2-lib-3.5.6-raw-ecdsa.patch`
  (fido2-demonstration checkout) now covers 3 files / 6 hunks,
  round-trip-verified against pristine 3.5.6. Offline E2E bench
  `bench/fido_demo_lib.py` + `fido2lib-verify.mjs` replicates the demo
  round without a browser (wipe → INIT gate → MC deferred-UP → GA
  deferred-UP → case JSON → fido2-lib attestationResult +
  assertionResult). **Console incident:** after the overnight unplug
  the CP210x re-enumerated and /dev/ttyUSB0 came back at 9600+echo
  (ground rule 11); `console_cmd` (and the ad-hoc tests) opened the
  port WITHOUT the stty recipe, so every `up`/`wipe` was lost — and
  the agent chased phantoms (DTR toggling, wiring suspicion) instead
  of checking rule 11. The user verified the console was healthy all
  along via `screen` (garbage line `ZZ` → "unknown console command").
  Fix: `console_cmd` now enforces the rule-11 stty recipe on EVERY
  open (the single console choke point for all bench scripts); rule
  11 strengthened (apply before any open, not just after a reflash;
  never toggle DTR/RTS; a silent console is a port-STATE bug —
  `stty -a` first, never hardware diagnostics).
   **SUPERSEDED (2026-11-06, SD-8):** the "raw R||S is what the
   WebAuthn spec mandates" claim in this entry is RETRACTED — W3C L3
   §6.5.5 mandates ASN.1 DER for ES256 `sig` values; the raw-acceptance
   patch part was reverted (see SD-8 + the SD-8 history entry).

 - **C20-prep 2: SD-7 device fix (37-byte assertion authData) + offline
   bench PASS** (2026-11-06): the offline bench's ASSERTION half failed
   fido2-lib's audit ("aaguid was not validated") even after the two
   harness patches — root cause was a DEVICE bug, not the harness: the
   assertion `authData` carried the attested credential data (164 bytes,
   AT=1: AAGUID + credId + COSE_Key). WebAuthn L3 §6.3.3 step 10
   EXCLUDES attestedCredentialData from the getAssertion
   authenticatorData, so the assertion authData must be 37 bytes
   (rpIdHash | flags | signCount) with UP-only flags. Fixed `ga_assert()`
   (drop `get_pubkey` + the AAGUID/credId/COSE emission; flags = UP only);
   GNA shares the path. Settled as **SD-7**. fw **1.0.7** (uf2 md5
   `2b0ca8b73ac7fae0f25c5269a397a874`) built + flashed + probe FULL PASS.
   GA KATs re-pinned offline (37-B authData; responses 330→203 B;
   `fake_sign` = digest•digest); test_ctap 625 checks, ctest 9/9.
   Bench `fido_ga.py` split `parse_authdata` into `parse_att_authdata`
   (164-B, MC) + `parse_assert_authdata` (37-B, GA, asserts no AT bit);
   `fido_demo_lib.py` + `fido_mc.py` + `fido_probe.py` re-pinned to 1.0.7.
   **Offline bench now PASSES end to end:** ATTESTATION OK counter 0 +
   ASSERTION OK counter 1, GA response 203 B, authData 37 B flags 0x01,
   sig raw-verified against the registration key. Next: the browser
   LOGIN round (C20).

 - **C20: browser LOGIN round PASSES** (2026-11-06): on the local
   fido2-demonstration (https://localhost:8888, rpId `localhost`,
   fido2-lib 3.5.6 on Node 24, both harness patches applied):
   **register** (counter 0) → **login** (counter →1) → **replug +
   login** (counter →2, resident credential survives a USB replug)
   → **reflash survival + login** (counter →3, credential + counter
   survive a full firmware reflash — littlefs `/f2_*` intact). The
   counter is strictly increasing across all three assertions; the
   server log shows "Registration successful." + "Authentication
   successful." for each. This is the first full browser round (register
   + login + persistence) to pass end to end. (Harness note: the demo's
   `index.js` validates `prevCounter` but does not write the new counter
   back to `users.json`, so the stored counter stays 0 — a harness
   limitation, not a device issue; the DEVICE counter is what's under
   test and it is strictly increasing.) Post-round: wipe + probe gate +
   `users.json` reset, then the phase commit.
 - **SD-8: webauthn.io diagnosis INVERTED + DER fix (fw 1.0.8)** (2026-11-06):
   the webauthn.io login failed ("Could not verify authentication
   signature") while the local fido2-demonstration passed — fetched W3C
   WebAuthn L3 §6.5.5 verbatim: ES256 `sig` values MUST be ASN.1 DER
   `Ecdsa-Sig-Value` (RFC 3279 §2.2.3), for the assertion AND the packed
   attestation; the raw R‖S form is COSE_Sign (RFC 9052), not a WebAuthn
   signature. The device was non-compliant; py_webauthn/webauthn.io were
   spec-correct (verified: `verify_signature.py` is DER-only, its own EC2
   vectors are DER, ecdsa.com reproduces the exact error). The C19/C20
   "raw is spec-correct" conclusion is RETRACTED (the superseded history
   entry above is annotated). The fido2-lib patch's ECDSA-raw part was a
   mistake (harness bent to the device) → REVERTED; the attestationObject
   key normalization remains (patch renamed
   `fido2-lib-3.5.6-attestation-cbor.patch`, 2 files / 4 hunks,
   round-trip-verified). Fix: `fido_ecdsa_der_encode()` in fido_cose.c
   (minimal INTEGERs: zero-strip + 0x00 sign-pad, OpenSSL-identical,
   10–72 B) used in `ga_assert()` + `mc_create()`; backend vtable stays
   raw; `FIDO_CTAP_MC_RESP_MAX` 288→296; KATs re-pinned (6 sig arrays →
   70-B DER; responses MC 254→260 B, GA 180→186 / 178→184 B) + new
   `t_ecdsa_der()` (pad/trim corners); ctest 9/9, test_ctap 736 checks.
   Bench verifiers parse DER (`parse_ecdsa_der()` in fido_mc.py,
   strict-minimal check); fw refs 1.0.8; uf2 md5
   `d7f8e54261ca06b856d8a39aacf89127`. Settled as **SD-8**
   (user-confirmed). Remaining: flash + probe + offline bench +
   webauthn.io browser round + commit.
- **Phase 5 (hardening + docs) — error paths + docs COMPLETE, uncommitted;
   fw 1.0.9** (2026-11-06): the audit found the firmware's error
   paths already robust (missing params 0x14, type errors 0x11,
   store-full 0x28, counter-increment failure 0x7F, keep-alive
   sanity — all KAT-pinned; codec-level CBOR strictness in
   test_cbor.c). ONE real gap found and fixed: structurally
   truncated / malformed CBOR (a map with fewer pairs than its
   header declares, a string cut mid-payload, a 2-byte-length map
   header with one length byte) answered 0x11
   CBOR_UNEXPECTED_TYPE where the spec-correct code is 0x12
   INVALID_CBOR (CTAP 2.3 §11.2.9.1.3) — the 35 conflated
   decode-failure/type-mismatch sites in parse_make_credential +
   ga_parse are split (decode fail → 0x12, type mismatch stays
   0x11); new `t_dispatch_truncated()` pins 0x12 at EVERY byte
   cut-point of a valid MC/GA request + the truncated map header,
   asserting no deferred transaction survives a parse failure —
   test_ctap 736 → 1189 checks, ctest 9/9. fw 1.0.9 (happy-path
   wire format unchanged; uf2 md5
   `2df53d9f3700c13bf86fbd92d4a0564f`), bench gates → 1.0.9.
   Docs: `example/README.md` gained the "FIDO2 example" section
   (USB device, no console app; demo flow; no-UV + console-`up`
   caveat; 4-credential limit; slot map; reflash/counter behavior;
   the 2.3 PS command table) and the main README the fido2 build
   outputs, repo layout and the five fido2 host tests. Remaining:
   flash 1.0.9 + probe + offline bench (happy-path regression) →
   commit.


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
  No match → NO_CREDENTIALS (0x2E), checked BEFORE the UP wait.
- **authData (identical layout to makeCredential):** rpIdHash ‖
  flags(UP|AT) ‖ counter(4 BE) ‖ AAGUID(16) ‖ credIdLen(**2** BE) ‖
  credId ‖ COSE_Key(77). W3C §6.5.1: the credential public key is part
  of authData on the get side too. (An earlier note here said "1-byte
  credIdLen" — a misread; corrected.)
- **Wire format: SD-6** (stable 2.0 request table; INTEGER top-level
  response keys 1–5; TEXT-keyed inner maps; options `uv`/`rk` → 0x2B;
  pin semantics; `"up": false` = synchronous preflight; descending-slot
  serve order).
- **Counter:** global per authenticator (NOT per RP — each RP compares
  against its own stored value, so a single monotonic counter satisfies
  all of them). Increment BEFORE building authData (read → increment →
  build with the new value → sign → send), so the first assertion after
  registration never reads as a "rollback" to an RP that compares
  against the stored registration counter (the demo's fido2-lib does
  exactly this). Increment failure → error, never a stale-counter
  assertion. Backends: littlefs `/f2_cnt` 4-byte BE (default; the write
  goes through `flash_safe_execute` at the stable card-tick point) vs
  ATECC608 Counter 0 behind `FIDO2_COUNTER_CHIP=ON` (hardware-monotonic,
  never reset; its `counter_zero` hook is NULL).
- **get_next_assertion (0x08):** no parameters (stray bytes must form
  exactly one well-formed CBOR item, else INVALID_CBOR 0x12 — checked
  before the state); state = the GA enumeration (separate from the
  pending transaction; an unmount abort clears it); 30 s window between
  calls (expiry → state discarded + NOT_ALLOWED 0x30, as does
  exhaustion); response = the GA map minus numberOfCredentials.
- **RESET (0x07):** no parameters (same CBOR check); the 10 s power-on
  window is checked FIRST at dispatch (uptime > 10000 ms → NOT_ALLOWED
  0x30); then the UP wait (30 s → USER_ACTION_TIMEOUT 0x2F); on
  completion: erase every store record (persist-first, per record),
  counter → 0 in littlefs mode only, enumeration state cleared; success
  = the bare 0x00 status byte (no CBOR). On-chip key pairs REMAIN; the
  next makeCredential GenKey re-binds the slots. The console `wipe`
  zeroes the counter through the same hook.
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

1. **Counter 0 increment on the frozen chip:** expected to work by
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

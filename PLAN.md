# Plan: FIDO2 example — passkey authenticator

**Current state: PLANNED (2026-10-27). No FIDO2 code yet; the next session
starts at Phase 0.** This file is the plan *and* the continuity snapshot
for this work (there is no separate RESUME.md anymore — the module's
development history lives in the git log, and the completed module plan is
in git history). Keep the "Current state" section current as phases land.

## Goal

A minimal but *real* FIDO2 (CTAP2) passkey authenticator as the third
example: a PC browser can **register** a passkey on the Pico and then
**use** it to log in — over USB HID, the standard security-key interface,
so no driver and no custom host tooling (Chrome/Windows/macOS recognize
the device directly).

Same philosophy as the vault example: the chip is the **key vault +
signer** (ECC P-256, monotonic counter), the Pico is the **protocol
engine** (CTAP2 + CBOR), littlefs is the **metadata store**. The demo
shows the module's remaining primitives in a real, usable application:
on-chip GenKey, external-digest Sign, and the monotonic counter — the
"consumer needs them" moment for the sign/verify wrappers.

The agreed config was built for exactly this (Scenario 2 in
`example/README.md`): slots 3–6 = four credential pairs, slots 1/2 =
identity (attestation) pair, slot 12 = ECDH spare (PIN protocol),
Counter 0 = CTAP global counter.

## Ground rules (unchanged)

- **No re-provisioning of the frozen bench chip; no config-zone writes.**
  The example uses only what the frozen config already allows:
  - GenKey into slots 3–6 (unlocked, `gen_key=1` — the slots' designed
    use; a reflash loses nothing because the keys are on the chip);
  - external-digest **Sign** with slot 1 (attestation) and slots 3–6
    (assertions) — all `ext_sig`;
  - read + increment **Counter 0** — incrementable even with the config
    zone locked (by ATECC design; CountMatch is 0, so increments are
    unconditional);
  - ECDH with slot 12 (PIN protocol only — stretch phase).
- Flashing and every bench run is a **user action**.
- Host KATs are ground truth for the pure-C parts (CBOR, SHA-256 if it
  ends up pure C).

## The demo (acceptance test, bench)

1. Flash the fido2 uf2; plug the Pico into a PC.
2. Chrome (or any browser) sees a **security key** with up to 4
   discoverable credentials.
3. **Register** a passkey on any site (MAKE_CREDENTIAL): a fresh EC P-256
   key is generated on the chip (next free slot 3–6); the browser receives
   basic ("packed") attestation signed by the device identity key (slot 1).
4. **Log out / log in** (GET_ASSERTION): the chip signs the challenge
   digest with the credential key; Counter 0 increments; the browser logs
   in.
5. **Replug or reflash** the Pico: the credential still works — key on the
   chip, metadata in littlefs, and the counter keeps counting from where it
   left off (a reflash cannot reset it — FIDO's clone-detection property).

## Division of labour

| Concern | Where |
|---|---|
| 4 credential private keys | slots 3–6, on-chip GenKey, never leave the chip |
| Attestation key | existing identity pair (slots 1/2), "packed" statement, `x5c: []` |
| CTAP global counter | Counter 0 (chip-side, monotonic) |
| CTAP2 protocol, CBOR, authData, command dispatch | Pico |
| SHA-256(authData ‖ clientDataHash) | RP2350 hardware SHA-256 if this pico-sdk fork exposes it; else a small pure-C SHA-256 (host KAT'd) — resolve in Phase 1 |
| Credential metadata (credID, rpIdHash, userHandle, slot) | littlefs flat files `/f2_<n>` (pico-littlefs has no mkdir) |
| UV (user verification) | **auto-UV** for the demo (documented caveat, like the vault's echo caveat); a GPIO button is a stretch item |

**I/O protection note:** the MVP uses only GenKey / Sign / counters — none
of which are I/O-protected (kdf_prot/ecdh_prot protect KDF and ECDH
outputs only; a signature is not secret). So the fido2 MVP does **not**
need `/io_key.bin`. (First bench run verifies this: if a Sign/GenKey
response carried an unexpected 32-B nonce, revisit.) The PIN stretch phase
(ECDH, `ecdh_prot=1`) *does* need the I/O key.

## Scope cuts (what "simple" means)

- CTAP 2.0 only (versions `"FIDO_2_0"`), one algorithm: ES256 (COSE −7).
- **4 credentials max** (the four slots), all resident/discoverable.
- No cred_prot, no large-blob storage, no PIN protocol in the MVP (Phase 6
  adds PIN v1 if needed — see Open questions).
- No biometrics; auto-UV. One AAGUID (a fixed demo constant).
- No secure firmware updates, no FIDO2.1 / CTAP 2.1+.

## Phases

### Phase 0 — module: the sign/verify wrappers (the "consumer needs them" moment)

- `atecc608_sign(slot, digest32, sig64)` — external-digest ES256 (Sign
  command; `ext_sig` slots: 1, 3–6, 12).
- `atecc608_verify(slot, digest32, sig64)` — Verify command (host
  cross-checks + bench debugging; cheap, completes the pair).
- Both in `atecc608_crypto.h` (KDF already lives there).
- **Host tests:** plumbing against the mock chip (parameter encoding,
  response parsing); host-side ECDSA cross-check where the mock allows it.
- Pico build warning-clean; `ctest` green.
- **Console (tiny):** a `prov counter` subcommand — read counters 0/1;
  `prov counter <n> CONFIRM` increments (monotonic → typed confirm, house
  style). Gives an explicit, repeatable counter check.
- **Bench (user action, needs explicit go-ahead — first chip write since
  the freeze):** one-time Counter 0 increment test (0→1) to confirm the
  frozen chip increments before we build on it. (Expected to work — by
  design. If it fails, see Open question 3.)

### Phase 1 — FIDO HID transport over USB

- New example `example/fido2/` (its own app — USB descriptors are per-app;
  one example directory per app, house contract), target
  `pico-atecc608-fido2`, uf2 in `build/example/fido2/`.
- USB HID with the standard **FIDO HID report layout**: report 0x01
  (4-byte CID init), 0x02 (65-byte message: 1-byte type + 64 payload),
  0x03 (error), 0x04 (keep-alive); vendor usage page; 500 ms keep-alive
  while a transaction is pending; 256-byte message framing (maxMsgSize).
  Follow the FIDO HID spec exactly — browsers match the report shape
  strictly.
- **Transport question to resolve first:** this pico-sdk fork's USB device
  support for a *custom HID* class (the console uses CDC). If the fork
  can't express a 4-report custom HID descriptor, use the TinyUSB backend.
  Decide in this phase.
- **Startup contract (house style):** probe the chip; require config zone
  locked + identity key present (`read_pubkey` slot 2); if not
  provisioned, print "provision with the console" and idle — **never
  provision**.
- **Bench:** a generic HID monitor on the PC sees the 4-report layout;
  channel init (CID echo) works. No browser yet.

### Phase 2 — CBOR + CTAP core + GET_INFO

- **Minimal CBOR codec** (encode + decode): uint, byte string, text
  string, array, map — the definite-length subset CTAP2 actually uses.
  Hand-rolled, no dependency (same spirit as the vault's pure-C GCM).
- **Host KATs:** hand-computed fixed vectors + round-trips.
- CTAP dispatch: 6-byte command header (channel, ins) → handlers, CTAP2
  status codes.
- **GET_INFO**: versions `["FIDO_2_0"]`, aVersion `0x20100`, algs
  `[ES256]`, maxMsgSize 256, maxCredentialCount 4, AAGUID,
  resident-key flag set.
- **Bench:** a PC CTAP tool (or the browser's security-key enumeration)
  sees a valid authenticator.

### Phase 3 — MAKE_CREDENTIAL

- Request: `clientDataHash`, `rp{id,name}`, `user{id,name,displayName}`,
  `pubKeyParams`, `excludeList` (ignore extras; duplicate →
  `CTAP2_ERR_CODE_CREDENTIAL_EXCLUDED`).
- **Slot allocation:** next free slot 3–6 per the littlefs DB (full →
  `CTAP2_ERR_CODE_KEYSTORE_FULL`).
- On-chip **GenKey** → `read_pubkey` → COSE_Key.
- **Attestation:** statement type `"packed"`, alg ES256, attestationKey =
  slot 2 public point, `x5c: []` (basic attestation), `sig` = chip Sign
  by slot 1 over SHA-256(authData ‖ clientDataHash).
- **AAGUID:** fixed 16-byte demo constant (pick a UUID, record it here).
- **authData:** rpIdHash(32) ‖ flags(UP|AT) ‖ counter(4 BE, Counter 0 —
  read, *not* incremented) ‖ AAGUID(16) ‖ credIdLen(2) ‖ credId ‖ COSE
  public key.
- **DB record:** fixed-size littlefs file `/f2_<n>` — slot, rpIdHash,
  credIdLen, credId, userHandle, CRC-32 (standard reflected, same as the
  vault).
- Keep total responses ≤ 256 B (a long credId could push it; the browser
 's typical 32–64 B credId is fine).
- **Host KATs:** authData layout, COSE_Key encoding, DB record round-trip.
- **Bench:** register passkey #1 in the browser.

### Phase 4 — GET_ASSERTION (+ RESET)

- **Lookup:** (rpIdHash, credentialID) from the request; for a discoverable
  "get" with no allowList, enumerate resident matches (≤4 — trivial).
  No match → `CTAP2_ERR_CODE_NO_CREDENTIALS`.
- **authData:** rpIdHash ‖ flags(UP|CRED_ID) ‖ counter ‖ credIdLen ‖
  credId.
- **Counter 0:** read → build authData → chip Sign → **increment**; if the
  increment fails, return an error — never send a stale-counter assertion.
- **RESET:** wipe the littlefs DB (the on-chip keys remain; the next
  MAKE_CREDENTIAL re-binds the slots).
- **Bench:** full register + login cycle in the browser; replug; **reflash
  survival** (credential works, counter keeps counting); counter strictly
  increasing across assertions.

### Phase 5 — hardening + docs

- Error paths: CBOR decode failures, missing params, full store, counter
  increment failure → correct CTAP status codes (no crashes, no hangs,
  keep-alive stays sane).
- Docs: `example/README.md` — "FIDO2 example" section (it's a USB device,
  no console commands: document the demo flow, the auto-UV caveat, the
  4-credential limit, the slot map, reflash/counter behavior); main
  README examples list + build outputs.
- Commit per phase; keep the "Current state" section of this file current.

### Phase 6 (stretch, after the MVP works) — PIN protocol v1

Only if the browser requires a PIN for discoverable credentials, or the
user wants it:

- **Client PIN key:** on-chip ECDH pair in **slot 12** (the config's
  "ECDH with host" spare — the agreed config anticipated this).
- **PIN protocol v1:** key agreement via **on-chip ECDH** (`ecdh_prot=1`
  → the shared secret arrives I/O-encrypted; this phase needs `/io_key.bin`
  and the `atecc608_ecdh` module wrapper), PIN hash derivation, the
  CLIENT_PIN command set. A nice showcase of the module's ECDH path.

## Open questions (resolve as we go)

1. **PIN-less resident keys:** does Chrome accept a PIN-less
   resident-capable (discoverable) authenticator? CTAP2 expects the PIN
   protocol on resident-capable authenticators; if the browser refuses
   discovery without it, Phase 6 becomes mandatory and moves up. (A
   non-resident path — browser supplies the credentialID — is always
   available as a debug fallback.)
2. **Hardware SHA-256:** does this pico-sdk fork expose the RP2350
   cryptoaccel (it does *not* expose hardware AES — the vault went pure
   C)? If not, a small pure-C SHA-256, host KAT'd.
3. **Counter 0 increment on the frozen chip:** expected to work by design
   (the COUNTER command is the one config-zone field writable after the
   lock). The Phase 0 bench check confirms it **before** we build on it;
   if it fails, FIDO2 assertions can't increment and this example is
   blocked (a static counter is spec-noncompliant) — escalate to the user.

## Risks

- **The FIDO HID descriptor is the biggest unknown** (custom HID on this
  pico-sdk fork). Mitigation: minimal descriptor; verify with a generic
  HID monitor in Phase 1 *before* any CTAP work.
- **Browsers are strict** about the FIDO HID report shape — follow the
  FIDO HID spec exactly (report IDs 0x01–0x04, 64-byte payloads,
  keep-alive timing).
- **Counter 0 only ever increases** (monotonic) — correct FIDO behavior,
  not a bug; the bench chip's counter will not return to 0.

## Out of scope (explicit)

CTAP 2.1/2.2, FIDO2.1, cred_prot, large-blob storage, biometrics / real
UV, multiple AAGUIDs, key rotation beyond RESET's re-bind, secure
firmware updates, and any config change (the chip is frozen).

## Planned file layout

```
example/fido2/
  main.c          CTAP app: startup contract, USB init, dispatch
  fido_hid.c/.h   FIDO HID transport (USB device)
  cbor.c/.h       minimal CBOR codec (host + device)
  ctap.c/.h       CTAP2 commands: GET_INFO / MAKE_CREDENTIAL /
                  GET_ASSERTION / RESET
  fido_db.c/.h    littlefs credential store (flat /f2_<n>)
CMakeLists.txt    + pico-atecc608-fido2 target
tests/            + test_cbor (host KATs); test_crypto gains sign/verify
```

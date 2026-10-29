# Plan: FIDO2 example — passkey authenticator

**Current state: Phase 1 CODE is DONE + committed (`0979244`), but the
bench acceptance is BLOCKED on two stacked device-side issues
(2026-10-28, paused mid-debug; resume checklist at the end of this
section). Phase 2 (CBOR + CTAP core + GET_INFO) is ON HOLD until the
key enumerates and the host can talk to it.** Phase 1 code landed:
`example/fido2/` — the pure-HID USB security key (2E8A:000B, usage
page 0xF1D0, two raw 64-byte reports, no report IDs; 34-byte report
descriptor from TinyUSB's own `TUD_HID_REPORT_DESC_FIDO_U2F`
template) on the fork-native TinyUSB backend (marked
`tinyusb_device` target + the app's own `tusb_config.h`; no CDC,
debug on UART0, BOOTSEL flashing), plus the pure-C CTAPHID
transport core `fido_ctaphid.c` (INIT allocate/sync with the
exactly-17-byte response, PING echo up to the 7609-byte max, the
CTAP v2.0 error table, 8-slot LRU channel table, one in-flight
message, 750 ms busy timeout, 500 ms keep-alive throttle) —
host-verified by `tests/test_ctaphid.c` (106 checks). Startup
contract held: probe + config-zone-locked + identity-key check,
never provision; unprovisioned devices still enumerate but answer
nothing (LED slow-blink). `ctest` 5/5 green; Pico build
warning-clean.

**Bench status (paused).** Bench: Fedora 44, kernel 7.2.13, user
`burnin`; Pico at USB `5-1.4.1`; `ttyUSB0` = UART0 capture (verified
working with the console app). Two stacked problems:

1. **Kernel `usbhid` rejects the interface: `can't add hid device:
   -22`** (no `/dev/hidraw*`; `lsusb -d 2e8a:000b` itself is OK).
   Raw-libusb ground truth (`bench/fido_desc_probe.c`, run with
   sudo): `SET_IDLE → ACK`; `GET_DESCRIPTOR(REPORT, len=34) →
   STALL`; `(REPORT, len=4096) → STALL`; `(HID, len=9) → STALL`.
   So the class control callback IS reached (SET_IDLE path works)
   but both GET_DESCRIPTOR paths end in `return false` → usbd.c
   stalls both EP0 IN and OUT. The -22 is -EINVAL from
   `hid_add_device()` (drivers/hid/hid-core.c:2980 via
   `usbhid_parse`); parse failures log only via `dbg_hid`
   (debug-only), which is why dmesg looked silent. Kernel v7.2.13
   sources were fetched to `/tmp/opencode/{usb72_hid-core.c,
   core72_hid-core.c}` (may be gone — refetch from gregkh/linux tag
   via raw.githubusercontent.com; kernel.org is Anubis-protected).
   Static analysis ELIMINATED: descriptor constants, EP0 buffer
   size, SETUP dispatch (SET_IDLE proves routing to
   `hidd_control_xfer_cb`), `dcd_edpt_xfer` (rp2040 port returns
   true unconditionally), and all static descriptor checks
   (bLength=9, report size 34, wTotalLength=41, `_Static_assert`).
   REMAINING SUSPECTS: `p_hid->hid_descriptor == NULL` in the HID
   branch and something preventing the REPORT branch from arming —
   i.e. `hidd_open` (hid_device.c:223) not fully applied, a runtime
   state issue invisible to static analysis. NOTE:
   `get_index_by_itfnum` returns 0xFF on mismatch but the BSS
   default `itf_num=0` coincidentally matches interface 0, so a
   failed open is masked for class requests.

2. **The fido2 firmware prints NOTHING on UART0** — not even a raw
   `uart_putc_raw(uart0, 'B')` placed before any USB/ATECC code.
   The console app prints fine on the same `ttyUSB0` wiring; the
   terminal's own echo (space/CR) works, so the bridge and the
   RX direction are alive — the pico→host TX direction is dead.
   fido2 CMakeLists: `pico_enable_stdio_uart(1)` only; console:
   stdio_usb + stdio_uart + pico-command-line + pico-littlefs +
   pico_multicore. `LIB_PICO_STDIO_UART=1` IS in fido2's compile
   defines, so `stdio_uart_init()` should run via
   `stdio_init_all()` before main — yet a raw write is lost, which
   means either UART0 was never configured (stdio-uart driver path
   in the fork's `src/rp2_common/pico_stdio_uart/stdio_uart.c`),
   `clk_uart` is off, or the flash never landed.

   **Do NOT re-enable `CFG_TUSB_DEBUG` in this fork.** A
   `CFG_TUSB_DEBUG=3` build killed USB enumeration entirely (no
   2e8a in lsusb): TinyUSB's debug logging routes `TU_LOG` through
   plain `printf`, and the fork's RP2040 DCD calls log macros from
   the **USB IRQ path** (`rp2usb_xfer_start` etc.); printf at
   115200 blocks the IRQ handler for milliseconds per line → the
   SIE starves → enumeration dies. Main-context printf (usbd event
   handling in `tud_task`, app code) is safe; only the DCD IRQ-path
   logging is poison.

**Uncommitted working tree (all temporary except bench/):**
- `example/fido2/main.c`: TEMPORARY instrumentation — gpio25 on +
  raw `'B'` at main entry, `'P'` after the first printf, `'T'`
  after `fido_hid_init()`; `#include "hardware/uart.h"`. Remove when
  the bench passes.
- `bench/` (untracked): `fido_desc_probe.c` (raw-libusb
  SET_IDLE/GET_DESCRIPTOR probe, builds on bench with libusb-1.0)
  and `fido_probe.py`. Commit both with the bench-pass.
- `example/fido2/tusb_config.h`: clean — the temporary
  `CFG_TUSB_DEBUG 3` define is already removed; no diff.
- Last built uf2: `build/example/fido2/pico-atecc608-fido2.uf2`,
  84992 bytes (no debug logging, has B/P/T markers).

**Resume checklist (in order):**
1. **Prove the flash landed.** "LED on" is NOT a build fingerprint:
   the old provisioned build also leaves GP25 steady. The lone `B`
   character is the fingerprint — and it never appeared. Check the
   copied uf2's size/md5 on the bench side; or add a fast LED blink
   until the main loop is entered (new build blinks, old build
   steady) and reflash.
2. **If flash is proven and still no `B`:** decisive experiment —
   call `uart_init(uart0, 115200)` explicitly at the top of main()
   before the raw `'B'`. If `B` then appears, the SDK stdio-uart
   init was skipped for this link set (dig: fork's
   `pico_stdio/stdio.c` driver registration, and whether linking
   `pico_stdio_usb` in the console app — which compiles to a
   `#warning` stub here — changes `stdio_init_all()` behavior); if
   `B` is still missing, suspect `clk_uart`/hardware.
3. **Once UART works:** report which of B/banner/P/T appear (B only
   → hang in ATECC608 I2C probe; all → main loop running) plus
   `lsusb | grep 2e8a` (is the key back on the bus?).
4. **GET_DESCRIPTOR STALL (the original -22):** trace with
   main-context-only instrumentation — add targeted `printf()`s to
   the fork's `hid_device.c` (`hidd_open`, `hidd_control_xfer_cb`:
   dump itf_num, hid_descriptor pointer, report_desc_len) and
   `usbd.c` dispatch. Keep `CFG_TUSB_DEBUG` at 0. (Alternative:
   GPIO pin toggles on a logic analyzer, or a RAM ring buffer
   flushed on a host command.) Fix, rebuild, reflash, re-run
   `sudo ./bench/fido_desc_probe` then `sudo python3
   bench/fido_probe.py`.
5. **When the bench passes:** remove the B/P/T instrumentation +
   uart include from `main.c`; commit `bench/`; update this section
   → Phase 2.

Phase 0
landed:
`atecc608_sign(slot, digest32, sig64)` / `atecc608_verify(slot, digest32,
sig64, *is_verified)` in `atecc608_crypto.h/.c` (external-digest Sign /
stored Verify; HAL-agnostic, so they compile in the host build), mock-chip
host tests (the plumbing: digest load into the Message Digest Buffer, Sign
mode/key_id encoding, 64-byte signature parsing, the chip gates — private
key slot / EXT_SIG bit / key present — and the verify-failure path, where
the chip's 0x01 error frame comes back as ATECC608_OK with
is_verified=false), and the `prov counter` console subcommand (read
counters 0/1; `prov counter <n> CONFIRM` increments via the module's
typed-confirm gate). Pico build warning-clean (only the documented
cryptoauthlib `ATCA_TA_SUPPORT` header noise); `ctest` green (test_crypto
now 109 checks). The mock gained a Message Digest Buffer and SIGN/VERIFY
handlers (fake deterministic signature, no P-256 math — house style; the
real-curve cross-check happens on the bench), and GenKey now stores the
fake private key in the data slot so a never-GenKey'd slot cannot sign.
No chip write in Phase 0 (littlefs counter is the dev default). Decisions
made at planning: the CTAP sync counter is
**littlefs-backed by default** (dev-friendly, resettable) with a build flag
(`FIDO2_COUNTER_CHIP`) to switch to the **chip Counter 0** (see Division of
labour) — so development never burns the frozen monotonic counter, and the
chip counter is exercised deliberately at the end. GET_ASSERTION
**increments the counter before** building authData (so the first assertion
after registration is never a "rollback" to the RP). FIDO2 testing uses the
`../fido2-demonstration` Node/Express + fido2-lib server. This file is the
plan *and* the continuity snapshot for this work (there is no separate
RESUME.md anymore — the module's development history lives in the git log,
and the completed module plan is in git history). Keep the "Current state"
section current as phases land.

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
identity (attestation) pair, slot 12 = ECDH spare (PIN protocol), and
Counter 0 = the on-chip CTAP global counter (used when the example runs in
chip-counter mode; the littlefs counter is the dev default — see Division
of labour).

## Ground rules (unchanged)

- **No re-provisioning of the frozen bench chip; no config-zone writes.**
  The example uses only what the frozen config already allows:
  - GenKey into slots 3–6 (unlocked, `gen_key=1` — the slots' designed
    use; a reflash loses nothing because the keys are on the chip);
  - external-digest **Sign** with slot 1 (attestation) and slots 3–6
    (assertions) — all `ext_sig`;
  - read + increment **Counter 0** (chip-counter mode only — behind the
    `FIDO2_COUNTER_CHIP` flag; the dev default is a littlefs counter, so the
    frozen counter is not burned during development). Incrementable even
    with the config zone locked (by ATECC design; CountMatch is 0, so
    increments are unconditional);
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
   digest with the credential key; the CTAP sync counter increments
   (littlefs by default; chip Counter 0 in chip-counter mode); the browser
   logs in.
5. **Replug or reflash** the Pico: the credential still works — key on the
   chip, metadata + counter in littlefs, and the counter keeps counting
   from where it left off (littlefs @ 0x80000 is outside the app region, so
   a reflash cannot reset it — FIDO's clone-detection property; in
   chip-counter mode it lives on the chip, equally reset-proof).

> **Test harness:** `../fido2-demonstration` (Node/Express + fido2-lib
> v3.5.6) — register + login over HTTPS on :8080. Note its config sets
> `authenticatorUserVerification: "required"` (satisfied by auto-UV, which
> sets the UV flag; relax to `"preferred"` if a browser/RP ever complains)
> and it compares each assertion counter against the value stored at
> registration (the "rollback" check the increment-first ordering in
> Phase 4 satisfies).

## Division of labour

| Concern | Where |
|---|---|
| 4 credential private keys | slots 3–6, on-chip GenKey, never leave the chip |
| Attestation key | existing identity pair (slots 1/2), "packed" statement, `x5c: []` |
| CTAP global counter | **littlefs file `/f2_cnt` by default** (dev-friendly, resettable by RESET); a **build flag** `FIDO2_COUNTER_CHIP` switches it to **chip Counter 0** (hardware-monotonic, not reset by RESET, not in a flash dump). One counter shared by all four credentials (CTAP2 is per-authenticator, not per-credential) |
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
- **4 credentials max** (the four slots), all resident-capable/discoverable.
  ("Resident" = the littlefs DB stores the metadata and the authenticator
  supports discovery; the same key also serves a non-resident-style
  assertion where the RP supplies the allowList — the demo's fido2-lib uses
  exactly that path. The resident flag is per-authenticator, so all four are
  resident-capable; there is no per-key resident/non-resident.)
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
- **Counter:** the littlefs counter is the dev default, so Phase 0 does
  **not** require a chip write. The one-time **Counter 0 increment test
  (0→1)** — "first chip write since the freeze" — is deferred to a later
  verification step when we flip `FIDO2_COUNTER_CHIP` (user action, needs
  explicit go-ahead). (Expected to work — by design. If it fails, see Open
  question 3.)

### Phase 1 — FIDO HID transport over USB

- New example `example/fido2/` (its own app — USB descriptors are per-app;
  one example directory per app, house contract), target
  `pico-atecc608-fido2`, uf2 in `build/example/fido2/`.
- **Transport (RESOLVED):** the fork-native TinyUSB backend
  (`pico-sdk/lib/tinyusb`, v0.21), linking the **marked**
  `tinyusb_device` target — it defines `LIB_TINYUSB_DEVICE=1` in the
  app's TUs so pico_stdio_usb stands down (no default descriptors, no
  auto-init, no background task) and the app supplies its own
  `tusb_config.h` (device mode, `CFG_TUD_HID 1`,
  `CFG_TUD_HID_EP_BUFSIZE 64` — must stay 64, see below). **No CDC:**
  USB is the FIDO HID interface only; flash via BOOTSEL uf2; debug
  prints on UART0 (GPIO 0/1). Main loop is single-threaded polling
  (`tud_task(); fido_hid_tick(); sleep_ms(1);`) — every TinyUSB callback
  runs in that context.
- **Report layout (corrects the earlier draft):** NO report IDs — two
  raw 64-byte reports (IN + OUT), usage page **0xF1D0**, usage 0x01
  (IN usage 0x20, OUT usage 0x21). The 34-byte report descriptor is
  TinyUSB's own `TUD_HID_REPORT_DESC_FIDO_U2F(64)` template (static-
  asserted to 34 bytes; byte-identical to Nitrokey's). IN EP 0x81 /
  OUT EP 0x01 interrupt, max packet 64, bInterval 5 (U2FHID spec
  example values). OUT buffer stays 64: the RP2040 DCD arms the OUT
  transfer with that size and only a 64-byte arm sets the hardware
  LAST bit, so one full 64-byte host packet completes the transfer;
  a larger buffer would wait for a second packet that never comes.
- **Framing:** init `CID(4,BE)|CMD(1=0x80|cmd)|BCNT(2,BE)|DATA(57)`;
  continuation `CID(4,BE)|SEQ(1)|DATA(59)` with **0-based SEQ
  (0x00..0x7F)**; max message 7609 = 57 + 128×59 (129 packets).
  Commands: PING/MSG/LOCK/INIT/WINK/CBOR/CANCEL/KEEPALIVE/ERROR; CTAP
  v2.0 §8.1.9 error table. The **INIT response is exactly 17 bytes**
  on the request's CID: nonce(8)|cid(4,BE)|protocol(1)=0x02|version(3)
  |caps(1)=0x0D (WINK|CBOR|NMSG — CTAP2-only). First allocated CID is
  2 (0 and 0xFFFFFFFF reserved); broadcast INIT allocates, specific
  INIT syncs (discards in-flight on that channel only). Unknown CIDs
  are auto-accepted; the 8-slot channel table LRU-evicts (never the
  in-flight channel) so broadcast INIT can never fail. One global
  7609-byte in-flight buffer, one message at a time: a new init on a
  different channel while buffering → ERR_CHANNEL_BUSY; bcnt > 7609 →
  ERR_INVALID_LEN; wrong SEQ or a re-init on the in-flight CID →
  ERR_INVALID_SEQ (in-flight cleared). In-flight idle ≥ 750 ms (clock
  refreshed by every accepted packet) → ERR_MSG_TIMEOUT. CANCEL gets
  NO response (Chromium doesn't wait); MSG/LOCK → ERR_INVALID_CMD on
  a CTAP2-only device. Keep-alive: 1-byte status (1=processing,
  2=UP-needed), 500 ms throttle, on the transaction's CID — the
  mechanism exists but nothing emits one in Phase 1 (the CBOR stub
  returns at once with a status byte).
- **Startup contract (house style, deliberate deviation from the
  examples' auto-provision):** probe the chip; require config zone
  locked + identity key present (`atecc608_get_pubkey` slot 2,
  read-only). If not provisioned, the device still enumerates over
  USB but the state machine is gated off (answers nothing), the LED
  (GP25) slow-blinks, and UART0 says "provision with the console" —
  **never provision**. USB unmount re-inits the CTAPHID state (fresh
  CIDs from 2).
- **Host-verified core:** `fido_ctaphid.c` is pure C (no pico-sdk, no
  TinyUSB); `tests/test_ctaphid.c` drives the whole state machine on
  the host — INIT allocation/sync and the 17-byte response shape, PING
  echo (single-packet shapes and multi-packet up to the 7609 max), the
  error table, busy/timeout rules, keep-alive throttling, LRU
  eviction.
- **Bench (user action):** a generic HID monitor on the PC sees the
  FIDO descriptor (usage page 0xF1D0, two 64-byte raw reports);
  channel init (INIT → nonce echo + allocated CID) works. No browser
  yet.

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
- **authData:** rpIdHash(32) ‖ flags(UP|AT) ‖ counter(4 BE, the CTAP sync counter —
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
- **CTAP sync counter (increment BEFORE building authData):** read the
  current value → **increment** → build authData with the *new* value → chip
  Sign → send. Incrementing first means the first assertion after
  registration reports a value strictly greater than the registration's, so
  a relying party that compares against the stored registration counter (the
  demo's fido2-lib does exactly this) never sees a "rollback". If the
  increment fails, return an error — never send a stale-counter assertion.
  (The littlefs backend enforces monotonicity in software: never write a
  value lower than the one read; the chip backend is hardware-monotonic.)
- **RESET:** wipe the littlefs DB (the on-chip keys remain; the next
  MAKE_CREDENTIAL re-binds the slots). In littlefs-counter mode this also
  resets the counter to 0 (dev convenience); in chip-counter mode the
  counter is on the chip and is NOT reset.
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
2. **Hardware SHA-256 (RESOLVED in Phase 1):** the fork exposes
   `pico_sha256` / `hardware_sha256` (`src/rp2_common/`) — the RP2350
   cryptoaccel is usable on-device from the CTAP phases (it is not
   host-compilable, so host tests needing the digest path stay pure C).
3. **Counter 0 increment on the frozen chip:** expected to work by design
   (the COUNTER command is the one config-zone field writable after the
   lock). Because the dev default is the littlefs counter, this is no longer
   a Phase 0 gate — we confirm it when we flip `FIDO2_COUNTER_CHIP` for the
   chip-counter verification. If it fails, chip-counter mode can't
   increment (a static counter is spec-noncompliant), but the littlefs-counter
   default is unaffected.

## Risks

- **FIDO HID descriptor (RESOLVED in Phase 1):** the fork's TinyUSB
  (v0.21) expresses it natively — `CFG_TUD_HID 1` + the
  `TUD_HID_REPORT_DESC_FIDO_U2F` template, no fork changes. The
  descriptor itself still gets its bench confirmation with a generic
  HID monitor *before* any CTAP work. (Fork quirks found and handled:
  no descriptor-builder macros like `TUD_DESC_TYPE_*`/`LO16`, no
  per-class `tud_hid_mount_cb` — the bus-level `tud_mount_cb`/
  `tud_umount_cb` are the events; `osal_time_millis()` is the clock;
  `tud_hid_get_report_cb` is mandatory and STALLed, as GET_REPORT is
  not part of the FIDO protocol.)
- **Browsers are strict** about the FIDO HID layout — resolved against
  Chromium/libfido2/Linux-kernel behavior in Phase 1: NO report IDs
  (two raw 64-byte reports), the exactly-17-byte INIT response,
  0-based continuation SEQ, 500 ms keep-alive throttle, 750 ms busy
  timeout, no 0x0B to the browser (unknown CIDs auto-accepted).
- **Chip Counter 0 only ever increases** (monotonic) — correct FIDO
  behavior, not a bug; once exercised, the bench chip's counter will not
  return to 0. This is why the dev default is the littlefs counter
  (resettable by RESET), with the chip counter exercised deliberately at the
  end.

## Out of scope (explicit)

CTAP 2.1/2.2, FIDO2.1, cred_prot, large-blob storage, biometrics / real
UV, multiple AAGUIDs, key rotation beyond RESET's re-bind, secure
firmware updates, and any config change (the chip is frozen).

## Planned file layout

```
example/fido2/
  main.c            CTAP app: startup contract, USB init, main loop
  tusb_config.h     TinyUSB config (device mode, CFG_TUD_HID, 64-byte EP)
  fido_hid.c/.h     FIDO HID descriptors + TinyUSB glue (USB device)
  fido_ctaphid.c/.h CTAPHID transport core: pure-C framing/channel state
                    machine (host-tested; the CBOR/WINK callbacks are the
                    seam for the CTAP layer)
  cbor.c/.h         minimal CBOR codec (host + device)
  ctap.c/.h         CTAP2 commands: GET_INFO / MAKE_CREDENTIAL /
                    GET_ASSERTION / RESET
  fido_db.c/.h      littlefs credential store (flat /f2_<n>)
  fido_count.c/.h   CTAP sync-counter provider: littlefs (/f2_cnt) default,
                    chip Counter 0 behind FIDO2_COUNTER_CHIP; read/increment
CMakeLists.txt      + pico-atecc608-fido2 target (FIDO2_COUNTER_CHIP option)
tests/              + test_ctaphid (transport state machine, host);
                    + test_cbor (host KATs); test_crypto has sign/verify;
                    + test_fido_count (littlefs backend host KAT)
```

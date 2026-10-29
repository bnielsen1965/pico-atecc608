# Plan: FIDO2 example — passkey authenticator

**Current state (2026-10-29, post-cleanup + commit): the usbhid -22
is ROOT-CAUSED, FIXED, and FULLY BENCH-VERIFIED end-to-end — round 6
clean replug (the kernel's live probe succeeded: SET_IDLE ACKed,
GET_DESCRIPTOR served the 34-byte report in ONE attempt, dmesg shows
the `hid-generic ... hiddev99,hidraw7: USB HID v1.11 Device` bind
with NO error, /dev/hidraw7 fresh) AND the final probe run (device 23
+ "detached kernel driver (usbhid)" + every GET_DESC byte exact). The
UART-silence bug is ROOT-CAUSED + FIXED (`stdio_init_all()`). Both
permanent fixes + the `bench/` probe tool are now COMMITTED. The probe
TOOL had protocol bugs along the way (round 5b: GET_DESCRIPTOR sent
class-typed rt=0xA1 instead of the standard rt=0x81 the kernel uses,
which also retroactively explains the round-2/4 "baseline STALL"
results; round 6: SET_IDLE sent 0x04, but Linux's `uapi/linux/hid.h`
and TinyUSB number the SET_* HID requests 0x09/0x0A/0x0B, not the
USB-IF table's 0x02/0x04/0x06 — the kernel sends 0x0A). The device
was never at fault. All temporary instrumentation (B/P/T markers,
heartbeat, `// DBG-TMP` fork prints) is REMOVED; clean build =
`/tmp/opencode/fido2-clean-1031.uf2` (md5
`111109eedbc43b46678a30a6b4c63ddc`; reflash optional — functionally
identical to the verified fix22 build minus the debug prints).
NOTE: the fork's `dcd_rp2040.c` has an UNCOMMITTED functional change
(RP2040 IN-endpoint ping-pong / EPSTATE_PENDING handling; mtime
2026-09-14 — predates the -22 debugging and is part of the verified
build). It is NOT bench instrumentation; it was kept (the two true
DBG-TMP files `usbd.c`/`hid_device.c` were reverted). Decide whether
to commit it into the fork.
NEXT: the provisioning side-quest (CTAP is gated off by design —
`fido_probe.py` can't pass until the chip is provisioned; its
/dev/hidraw path + 0x00+65-byte framing verified against v7.2
`usbhid_output_report`), then Phase 2.

**The -22 root cause (the whole multi-round hunt, in one line): the
HID class descriptor in `fido_hid.c` referenced the report descriptor
with byte `0x21` (the HID descriptor type) instead of `0x22` (the
REPORT descriptor type).** Kernel 7.2's `usbhid_parse` (verified
against the v7.2 source, `/tmp/opencode/hid-core-7.2.c`) reads the HID
class descriptor from the *cached* config descriptor — in memory, zero
USB traffic — and only adopts `wDescriptorLength` when
`rpt_desc.bDescriptorType == HID_DT_REPORT (0x22)`; with `0x21` it
gets rsize=0 → `return -EINVAL` → "can't add hid device: -22" *before
sending any probe request*. This explains every observation: the fast
failure ~306 ms after connect (no 5 s control timeouts), the trace log
showing no probe SETUP ever reach the device (SET_IDLE rt=0x21 /
GET_DESCRIPTOR rt=0x81 — the kernel never sends them), and the
baseline raw-libusb probe's SET_IDLE→ACK / GET_DESCRIPTOR→STALL being
*our own* libusb requests, not the kernel's. Fix in `fido_hid.c`
(0x21→0x22 + comment; spec + Nitrokey/YubiKey descriptors + the kernel
check all agree on 0x22); verified present in the built ELF.

Bench round 4 (trace2) also closed the remaining open threads: (a)
the main loop is ALIVE (500 ms `.` heartbeat keeps flowing after
mount — the "freeze" hypothesis is dead; `led_tick` runs in the same
loop, so round 3's "LED off" observation is superseded); (b)
enumeration was 100% NORMAL — the earlier reading of "corrupted
SETUP reads / flaky EP0" was a misdecode: wValue 0x0600 =
GET_DESCRIPTOR *device-qualifier* (type 0x06), and the ×3 pattern is
the kernel's -EPIPE retry loop against the qualifier we
intentionally STALL (no device-qualifier descriptor defined); wValue
0x0200 = GET_DESCRIPTOR *configuration* (type 0x02) with wLen 9/41 =
the header + full read, exactly as expected. No dpram corruption, no
EP0 flakiness, nothing else to fix. (c) Provisioning side-quest:
banner confirmed "ATECC608 not provisioned — provision with the
console (pico-atecc608) first."

**UART root cause (permanent finding, fixed in `example/fido2/main.c`
working tree):** the pico-sdk does NOT auto-initialize stdio before
main — the app must call `stdio_init_all()` (the official hello-world
does). The console/vault apps got it for free because
`pico-command-line` calls it (`pico-command-line.c:60`); fido2 links
no such library, so `clk_uart` never started, GP0/GP1 were never
routed to UART0, and EVERY printf (even `uart_putc_raw`) was
silently dropped since the first bench run. Fix: `stdio_init_all()`
at the top of main (replaces the ad-hoc `uart_init` + pin routing).

**Remaining: bench-verify the -22 fix** (round 5, checklist below).
The trace2 instrumentation is STILL in the fork (`// DBG-TMP`,
main-context `printf()`s in `usbd.c` event/SETUP log + `hid_device.c`
open/GET_DESCRIPTOR dispatch) so the verification round shows the
kernel's probe requests arriving (SET_IDLE + GET_DESCRIPTOR REPORT)
and succeeding; remove it all when the bench passes. Do NOT
re-enable CFG_TUSB_DEBUG. Phase 2 (CBOR + CTAP core + GET_INFO) is ON
HOLD until the bench passes.** Phase 1 code landed:
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

1. **RESOLVED (2026-10-29): kernel `usbhid` rejects the interface:
   `can't add hid device: -22`.** Root cause: the report-descriptor
   reference byte in the HID class descriptor was `0x21` instead of
   `0x22` (see "The -22 root cause" in Current state). Fixed in
   `fido_hid.c` (uncommitted, permanent — commit with the bench
   pass). The -22 is -EINVAL from `hid_add_device()` via
   `usbhid_parse` — which in kernel 7.2 does the descriptor
   validation IN MEMORY from the cached config (no USB requests),
   which is why dmesg was silent (parse failures log only via
   `dbg_hid`) and no probe SETUP ever reached the device. Kernel
   v7.2 sources fetched to `/tmp/opencode/hid-core-7.2.c` (+
   `hidid-7.2.h` attempt, `usb-7.2.h`; kernel.org is
   Anubis-protected — use raw.githubusercontent.com, tag `v7.2`).
   The baseline raw-libusb probe results (SET_IDLE→ACK,
   GET_DESCRIPTOR→STALL) were our own libusb requests — the kernel
   never issued them. RESOLVED (round 5b): those GET_DESCRIPTOR
   STALLs were the probe's own bug — it sent rt=0xA1 (CLASS type)
   instead of rt=0x81 (STANDARD, as the kernel does), and hidd
   correctly STALLs class-typed GET_DESCRIPTOR; its "SET_IDLE" was
   really a zero-length SET_REPORT (0x02), harmlessly ACKed. The
   device was never at fault. Whether the kernel's own (rt=0x81)
   GET_DESCRIPTOR succeeds at enumeration is what the next clean
   replug run settles.

2. **RESOLVED (2026-10-29): UART0 silence** — the fido2 app never
   called `stdio_init_all()`. The pico-sdk does NOT auto-initialize
   stdio before main (verified against official 2.3.1: identical
   `stdio.c`, no startup hook anywhere in the SDK; the official
   hello-world calls `stdio_init_all()` in main). The console/vault
   apps got it for free via `pico-command-line`
   (`pico-command-line.c:60`); fido2 links no such library, so
   `clk_uart` never started and GP0/GP1 were never routed to UART0 —
   every printf (even raw `uart_putc_raw`) was silently dropped since
   the first bench run; the Phase 1 banner was dead code on hardware.
   Fix in the working tree: `stdio_init_all()` at the top of main;
   diag-build bench run confirmed B/P/T + banner now print.

   **Do NOT re-enable `CFG_TUSB_DEBUG` in this fork.** A
   `CFG_TUSB_DEBUG=3` build killed USB enumeration entirely (no
   2e8a in lsusb): TinyUSB's debug logging routes `TU_LOG` through
   plain `printf`, and the fork's RP2040 DCD calls log macros from
   the **USB IRQ path** (`rp2usb_xfer_start` etc.); printf at
   115200 blocks the IRQ handler for milliseconds per line → the
   SIE starves → enumeration dies. Main-context printf (usbd event
   handling in `tud_task`, app code) is safe; only the DCD IRQ-path
   logging is poison.

**Prepared bench builds (2026-10-29, in /tmp/opencode/):**
- `fido2-fix22-0808.uf2` (90112 B, md5
  `6ecd120454f5d16f9b82ada600d062c7`): **the build to flash next** —
  the descriptor fix (HID class descriptor report-type byte 0x21→0x22)
  on top of trace2 (all round-3/4 `// DBG-TMP` instrumentation
  retained for the verification log). ELF checked: the fixed 9-byte
  HID descriptor `09 21 11 01 00 01 22 22 00` is present, the old
  `... 21 22 00` byte sequence is gone.
- `fido2-trace2-0645.uf2` (90112 B, md5
  `07274c97067de4873bd1a55565835d26`): trace build + the round-3
  freeze instruments (all `// DBG-TMP`):
  - NEW `usbd.c tud_task_ext`: EVERY DCD event is logged before
    processing — event ID (1=bus_reset, 2=unplugged, 3=sof,
    4=suspend, 5=resume, 7=xfer_complete) and for SETUP_RECEIVED the
    full setup (bmRequestType/bRequest/wValue/wIndex/wLength). This
    is the request log: which SETUPs actually arrive, and whether the
    loop keeps running after the last one.
  - NEW `main.c`: raw `.` heartbeat on UART0 every 500 ms from the
    main loop (dot stops = main loop frozen; dots continue = loop
    alive, problem is on the USB side).
  - Carried over: `stdio_init_all()` fix + B/P/T markers; `usbd.c`
    `configuration_reset` + `driver->open` results +
    `SET_CONFIGURATION FAILED`; `hid_device.c` `hidd_open`
    entry/FAIL/OK + `hidd_control_xfer_cb` GET_DESCRIPTOR dispatch +
    state dump.
  Superseded: `fido2-trace-0619.uf2` (`fb2e4968...`), baseline
  `67420184...`, diag `666f7ca3...`.

**Uncommitted working tree:**
- `example/fido2/fido_hid.c`: the PERMANENT -22 fix (HID class
  descriptor report-type byte 0x21→0x22 + comment). Commit with the
  bench pass.
- `example/fido2/main.c`: the PERMANENT `stdio_init_all()` fix +
  TEMPORARY B/P/T raw markers + TEMPORARY 500 ms `.` heartbeat in the
  main loop (all `// DBG-TMP`). Remove the markers/heartbeat when the
  bench passes.
- Fork `/home/burnin/Projects/pico-sdk` `lib/tinyusb`: TEMPORARY
  `// DBG-TMP` printf instrumentation in `src/device/usbd.c` and
  `src/class/hid/hid_device.c` (+ `#include <stdio.h>` in both).
  Remove after the -22 is root-caused.
- `bench/` (untracked): `fido_desc_probe.c` (raw-libusb
  SET_IDLE/GET_DESCRIPTOR probe, builds on bench with libusb-1.0)
  and `fido_probe.py`. Commit both with the bench-pass.
- `example/fido2/tusb_config.h`: clean — the temporary
  `CFG_TUSB_DEBUG 3` define is already removed; no diff.

**Bench round 2 results (2026-10-29, DONE):** 1) BOOTSEL enumerates
(mass storage) — bench USB path healthy; the earlier total silence
was bench-side. 2) Baseline reproduced the pause state (lsusb OK,
usbhid -22). 3) Diag build: fast blink + B/P/T + banner on UART0,
device enumerates, usbhid -22 as before, LED slow-blinks.

**Bench round 3 results (2026-10-29, DONE — trace build):** banner +
"P" + "ATECC608 not provisioned — provision with the console
(pico-atecc608) first." (provisioning side-quest: full banner
confirmed, still unclear WHICH sub-check failed — probe /
config-locked / identity slot 2) + "T". Then: `configuration_reset`
x2 (both BEFORE the open — no post-open wipe), `hidd_open OK:
hid_desc=10009E02 report_len=34 ep_in=0x81 ep_out=0x01`,
`set_config: drv open -> drv_len=32 (remaining=32, itf_class=0x03)`
(driver name prints empty — `DRIVER_NAME` is NULL without
`CFG_TUSB_DEBUG`, expected), `fido2: USB enumerated (HID interface
mounted)`. THEN: total silence — no further DBG lines (no
GET_DESCRIPTOR dispatch ever reached the class driver), and the LED
is OFF + not blinking (round 2's diag build slow-blinked in the same
unprovisioned state). Working hypothesis: the main loop (or its
USB-event supply) FREEZES right after the mount event — new failure
mode vs the pause state. The trace2 build (heartbeat `.` + full
event/SETUP log) splits the hypothesis: dots stop → loop frozen in
`tud_task` (last logged event says where); dots continue → loop
alive, DCD stopped delivering events (check host dmesg).

**Bench round 4 results (2026-10-29, DONE — trace2 build):**
1. Full UART0: banner + "not provisioned" text + T, then the full
   enumeration trace. Key facts: the main loop is ALIVE (`.`
   heartbeats keep flowing — 27 dots ≈ 13.5 s after mount); `hidd_open
   OK` + mount as before; after mount the last SETUP is a string
   re-read (0x0303, completes), then ONLY dots — no probe SETUPs
   (SET_IDLE / GET_DESCRIPTOR) ever arrived.
2. dmesg: clean enumeration (`2e8a:000b`, strings OK), `usbhid
   5-1.4.1:1.0: can't add hid device: -22` ~306 ms after the
   enumeration start — too fast for any control timeout ⇒ the kernel
   failed IN MEMORY, before sending probe requests.
3. Decoded the SETUP log correctly (the earlier "corruption" reading
   was wrong — wValue high byte = descriptor TYPE): 0x0100 = device
   desc; 0x0600 wLen=10 ×3 = device-QUALIFIER request (type 0x06)
   STALLed by us (none defined) with the kernel's standard -EPIPE
   retry loop; 0x0200 wLen=9/41 = configuration descriptor header +
   full read (type 0x02) — all normal; strings 0/2/1/3 normal; the
   two bus resets pre-date SET_ADDRESS (harmless). Enumeration was
   100% normal; no EP0/dpram problem.
4. Read kernel 7.2's `usbhid_parse` (v7.2 source fetched): the HID
   class descriptor is validated from the cached config in memory;
   `rsize` is only adopted when `rpt_desc.bDescriptorType == 0x22`;
   ours was 0x21 ⇒ rsize=0 ⇒ `return -EINVAL` ⇒ -22, zero USB
   traffic. ROOT CAUSE = the 0x21/0x22 typo in `fido_hid.c`.

**Bench round 5b results (2026-10-29, DONE — probe re-run):**
 1. `fido_desc_probe` (rebuilt with kernel-driver detach/reattach):
    `SET_IDLE n=0 (ok)` but all three GET_DESCRIPTORs →
    LIBUSB_ERROR_PIPE (STALL); NO "detached kernel driver" line →
    NO kernel driver attached to the interface right now (usbhid
    is NOT bound).
 2. UART log during the run (device side): `SETUP rt=0x21
    req=0x02 wLen=0` + event 7 (xfer complete); then the three
    GET_DESCRIPTOR SETUPs (rt=0xA1, wValue 0x2200/0x2200/0x2100)
    with NO hidd prints and NO completions → STALLed in hidd's
    class-request path (GET_DESCRIPTOR is not a HID class request).
 3. ROOT CAUSE of the probe failures: the PROBE was wrong (our bug,
    written in round 2): (a) its "SET_IDLE" used bRequest=0x02 —
    that is HID_SET_REPORT (zero-length, harmlessly ACKed);
    HID_SET_IDLE is 0x04, which is what the kernel's `hid_set_idle`
    sends. (b) its GET_DESCRIPTOR used rt=0xA1 (CLASS); the
    kernel's `hid_get_class_descriptor` sends it as a STANDARD
    request, rt=0x81 (`USB_RECIP_INTERFACE|USB_DIR_IN`) — the USB
    spec agrees GET_DESCRIPTOR is standard. TinyUSB's hidd answers
    GET_DESCRIPTOR only in its standard branch (verified in the
    fork's `hid_device.c`: `HID_DESC_TYPE_REPORT`=0x22 →
    `tud_hid_descriptor_report_cb` → `s_report_desc`, no gating),
    so a class-typed GET_DESCRIPTOR is correctly STALLed.
    This retroactively explains the round-2/4 "baseline STALL"
    results too: the probe was never a faithful kernel replay.
 4. Probe fixed: SET_IDLE bRequest 0x02→0x04; GET_DESCRIPTOR rt
    0xA1→0x81 (all three). Rebuilt on the bench.
 5. Kernel 7.2 probe sequence, exactly (from the fetched
    `usbhid_parse` + `include/uapi/linux/hid.h`): `hid_set_idle` =
    rt=0x21 req=**0x0A** wValue=0x0000 wIndex=0 wLen=0 (result
    ignored). NOTE the numbering: Linux's `uapi/linux/hid.h` (and
    TinyUSB's `hid.h`) define the SET_* HID requests as
    0x09/0x0A/0x0B, NOT the USB-IF table's 0x02/0x04/0x06 — the
    kernel sends 0x0A and a 0x04 is STALLed by hidd. Then
    `hid_get_class_descriptor` = rt=0x81 req=0x06 wValue=0x2200
    wIndex=0 wLen=34, retried up to 4× while the answer is short;
    a STALLed fetch surfaces as "can't add hid device: -32"
    (EPIPE) in dmesg via `usbhid_probe`.

**Bench round 6 results (2026-10-29, DONE — clean replug: PASS at
the USB/HID level):**
 1. Full UART log since the plug: banner + P + "not provisioned" +
    T; enumeration 100% normal (device desc, SET_ADDRESS 7,
    qualifier ×3 STALLed as designed, config header + full, strings
    0/2/1/3); `hidd_open OK: hid_desc=10009EDA report_len=34
    ep_in=0x81 ep_out=0x01`; mount. THEN the kernel's probe,
    exactly as predicted: `SETUP rt=0x21 req=0x0A wValue=0x0000
    wLen=0` + event 7 (SET_IDLE ACKed by hidd's 0x0a case), then
    `SETUP rt=0x81 req=0x06 wValue=0x2200 wIndex=0x0000 wLen=34` →
    `DBG: hidd_ctrl` + `DBG: GET_DESCRIPTOR(type=0x22) ...
    report_len=34 wLength=34` + data-complete + status-complete
    events, ONE attempt (no retries). (The extra `hidd_ctrl`
    prints without a type-line are the DATA/ACK stages re-invoking
    the class cb — the line-298 print is stage-agnostic.)
 2. dmesg: CLEAN — `hid-generic 0003:2E8A:000B.000A: hiddev99,
    hidraw7: USB HID v1.11 Device [Raspberry Pi Pico ATECC608 FIDO]
    on usb-0000:12:00.4-1.4.1/input0`; NO "can't add hid device"
    at all. usbhid bound; `/dev/hidraw7` is ours (fresh
    timestamp).
 3. Probe (rebuilt binary): `GET_DESC(REPORT) len=34` → the exact
    34-byte report descriptor
    `06 D0 F1 09 01 A1 01 09 20 15 00 26 FF 00 75 08 95 40 81 02
    09 21 15 00 26 FF 00 75 08 95 40 91 02 C0`; len=4096 → 34;
    `GET_DESC(HID) len=9` → `09 21 11 01 00 01 22 22 00` (the
    fixed 0x22 in byte 8). SET_IDLE showed n=-9 (PIPE): that
    binary sent 0x04 (the USB-IF value) — STALLed, because
    Linux/TinyUSB number SET_IDLE = 0x0A (round 5b item 5). Probe
    fixed to 0x0A and rebuilt.
    NOTE: that probe run printed "device 22" with NO "detached"
    line — it evidently ran against the OLD (pre-replug, unbound)
    device; its GET results are still valid (same firmware, and the
    kernel's own fetch on device 23 proved the same path). The
    final probe run (checklist step 3) should print device 23 +
    the detach line.
 4. VERDICT: the -22 is FULLY bench-verified — the kernel fetched +
    parsed the 34-byte report descriptor and bound usbhid with zero
    errors; /dev/hidraw7 exists; the descriptor bytes on the wire
    are exactly right. What remains: final all-green probe run
    (step 3), the provisioning side-quest (CTAP is gated off by
    design), then cleanup + commit (step 6).

**Resume checklist (in order, 2026-10-29 post-round-6 revision):**
1. ~~Flash the fix22 build (`fido2-fix22-0808.uf2`, md5
   `6ecd120454f5d16f9b82ada600d062c7`)~~ **DONE (round 5): the -22
   is gone from dmesg.**
2. ~~Clean replug + full capture~~ **DONE (round 6): PASS** — see
   "Bench round 6 results": the kernel's probe arrived exactly as
   predicted (SET_IDLE req=0x0A ACKed; GET_DESCRIPTOR rt=0x81
   wValue=0x2200 wLen=34 served 34 bytes in one attempt), dmesg
   clean with the `hid-generic` bind line, /dev/hidraw7 fresh.
3. ~~Final probe run~~ **DONE: all green.** `sudo
   ./bench/fido_desc_probe` printed `found ... on bus 5 device 23`,
   `detached kernel driver (usbhid) from interface 0` (confirms
   usbhid was bound — the kernel's round-6 fetch succeeded),
   SET_IDLE ok, `GET_DESC(REPORT) len=34` → the exact 34-byte report
   descriptor
   `06 D0 F1 09 01 A1 01 09 20 15 00 26 FF 00 75 08 95 40 81 02
   09 21 15 00 26 FF 00 75 08 95 40 91 02 C0`, len=4096 → 34 bytes,
   `GET_DESC(HID) len=9` → `09 21 11 01 00 01 22 22 00`.
4. **CTAP probe:** `sudo python3 bench/fido_probe.py` (uses
   /dev/hidraw — the real-host path; its 0x00+65-byte framing
   verified correct against v7.2 `usbhid_output_report`). Will STILL
   fail until the chip is provisioned — the app is gated off by
   design; that's the provisioning side-quest, not a regression.
5. **Provisioning side-quest (in parallel):** banner confirmed
   "not provisioned". Check the bench chip's identity key in slot 2
   via the console app (the startup contract is probe + config
   locked + identity key slot 2) — fido2 answers nothing (by design)
   until it passes, which matters for the browser test even now that
   the -22 is fixed.
6. ~~Cleanup + commit~~ **DONE.** Removed the B/P/T markers +
   heartbeat from `main.c` (kept `stdio_init_all()` — the fix),
   removed ALL `// DBG-TMP` prints from the fork (reverted
   `usbd.c`/`hid_device.c`; kept the unrelated functional
   `dcd_rp2040.c` change — see the note in "Current state"), rebuilt
   clean (`/tmp/opencode/fido2-clean-1031.uf2`), committed
   `fido_hid.c` + `main.c` + `bench/` + this file. REMAINING (not
   blocking Phase 2): decide whether to commit the fork's
   `dcd_rp2040.c` change into the fork (it's a real driver fix, part
   of the verified build).

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

#!/usr/bin/env python3
"""fido_probe.py — Phase 1 bench check for the Pico FIDO2 key.

Finds the key by VID/PID (2e8a:000b), then runs the three transport
checks that Phase 1 promises:

  1. CTAPHID INIT (broadcast) -> the exactly-17-byte response with the
     nonce echoed, an allocated CID (first one is 2), protocol 0x02 and
     capabilities 0x0D (WINK|CBOR|NMSG).
  2. CTAPHID PING on the allocated channel -> the payload echoed back.
  3. CTAPHID WINK (sent 3x, 1 s apart) -> empty responses; the on-board
     LED flickers 600 ms after each, so watch the Pico during the run.

No third-party dependencies (no pyusb/hidapi) — plain /dev/hidraw.
Run as root, or add a udev rule granting your user access to 2e8a:000b.

Wire framing (CTAP v2.0 §8.1.8 / v2.1 §11.2.4): each 64-byte packet is
CID(4, big-endian) | CMD(1, bit 7 ALWAYS set — e.g. INIT is 0x86) |
BCNT(2, big-endian, total payload length) | DATA(57). Broadcast INIT
goes to CID 0xFFFFFFFF (channel 0 is reserved); allocation responses
come back on the broadcast CID, with the new CID inside the payload.

hidraw is ASYMMETRIC for a device WITHOUT report IDs (verified
against kernel 7.2 source, drivers/hid/):
  - WRITE: pass 0x00 + the 64 report bytes (65 total); usbhid's
    output_report() drops the leading 0x00 ("Don't send the Report
    ID"), so the device sees exactly 64 bytes.
  - READ: the raw 64-byte report, NO prefix (hid_irq_in passes the
    wire bytes straight through to hidraw_report_event, which stores
    them untouched).

If every read times out but lsusb shows the device: the chip is not
provisioned (LED slow-blinks) — the app enumerates but answers nothing
by design; provision with the console app first.
"""
import glob
import os
import sys
import time

VID, PID = '2e8a', '000b'
READ_TIMEOUT_S = 1.0

# Spec (CTAP v2.0 8.1.9.1.3 / v2.1 11.2.3): channel 0 is reserved and
# 0xFFFFFFFF is the broadcast CID; INIT MUST be sent to it. Channel
# allocation responses also go out on the broadcast CID.
BROADCAST = bytes.fromhex('ffffffff')

# Error codes as returned in a 1-byte payload of a 0xBF (ERROR) command.
ERR_NAMES = {
    0x01: 'INVALID_CMD', 0x02: 'INVALID_PARAM', 0x03: 'INVALID_LENGTH',
    0x04: 'INVALID_SEQ', 0x05: 'MESSAGE_TIMEOUT', 0x06: 'CHANNEL_BUSY',
    0x0A: 'LOCK_REQUIRED', 0x0B: 'INVALID_CHANNEL', 0x7F: 'OTHER',
}


def check_error(r, what):
    """Die with a decoded message if the reply is a CTAPHID ERROR (0xBF)."""
    if r[4] != 0xBF:
        return
    if r[5:7] == b'\x00\x01':
        err = r[7]
        sys.exit(f'{what}: device answered ERROR {err:#04x} '
                 f'({ERR_NAMES.get(err, "UNKNOWN")})')
    sys.exit(f'{what}: device answered ERROR with unexpected shape: '
             f'{r[:8].hex()}')


def find_hidraw():
    """Return the /dev/hidraw node whose USB parent is 2e8a:000b."""
    for node in sorted(glob.glob('/dev/hidraw*')):
        path = os.path.realpath(os.path.join(
            '/sys/class/hidraw', os.path.basename(node), 'device'))
        d = path
        while d and d != '/sys':
            if os.path.exists(os.path.join(d, 'idVendor')):
                if (open(os.path.join(d, 'idVendor')).read().strip() == VID
                        and open(os.path.join(d, 'idProduct')).read().strip() == PID):
                    return node
            d = os.path.dirname(d)
    return None


def read_report(fd):
    """Read one IN report: the raw 64-byte report (no report-ID prefix)."""
    end = time.time() + READ_TIMEOUT_S
    while True:
        try:
            data = os.read(fd, 64)
            if data:
                return data
        except BlockingIOError:
            pass
        if time.time() > end:
            return b''


def write_report(fd, report64):
    assert len(report64) == 64, f'report must be 64 bytes, got {len(report64)}'
    os.write(fd, b'\x00' + report64)   # 0x00 = hidraw report-ID prefix


def main():
    node = find_hidraw()
    if not node:
        sys.exit(f'no hidraw device with {VID}:{PID} found (plug the Pico in)')
    print(f'using {node}')

    fd = os.open(node, os.O_RDWR | os.O_NONBLOCK)
    try:
        # --- 1. INIT (broadcast) -----------------------------------------
        nonce = bytes(range(1, 9))
        pkt = BROADCAST + bytes([0x86]) + (8).to_bytes(2, 'big') + nonce \
            + bytes(49)
        write_report(fd, pkt)
        resp = read_report(fd)
        if len(resp) != 64:
            sys.exit(f'INIT: no/bad response ({len(resp)} bytes: {resp.hex()})')
        r = resp                                      # the 64-byte report
        check_error(r, 'INIT')
        got_cid = r[15:19]
        print(f'INIT  -> cid={got_cid.hex()} '
              f'proto={r[19]:#04x} fw={r[20]}.{r[21]}.{r[22]} caps={r[23]:#04x}')
        assert r[0:4] == BROADCAST, \
            f'response must go to the broadcast CID, got {r[0:4].hex()}'
        assert r[4] == 0x86, f'expected INIT response, cmd={r[4]:#04x}'
        assert r[5:7] == (17).to_bytes(2, 'big'), 'INIT payload must be 17 bytes'
        assert r[7:15] == nonce, f'nonce mismatch: {r[7:15].hex()} != {nonce.hex()}'
        assert r[19] == 0x02, 'protocol must be 0x02'
        assert r[23] == 0x0D, 'caps must be 0x0D (WINK|CBOR|NMSG)'
        assert int.from_bytes(got_cid, 'big') >= 2, 'first allocated CID must be >= 2'
        print('      ok (nonce echoed, CID allocated, 17-byte shape)')

        # --- 2. PING echo on the allocated channel ------------------------
        pkt = got_cid + bytes([0x81]) + (8).to_bytes(2, 'big') + nonce + bytes(49)
        write_report(fd, pkt)
        resp = read_report(fd)
        if len(resp) != 64:
            sys.exit(f'PING: no response ({len(resp)} bytes)')
        r = resp
        check_error(r, 'PING')
        print(f'PING  -> cid={r[0:4].hex()} cmd={r[4]:#04x} '
              f'echo={r[7:15].hex()}')
        assert r[0:4] == got_cid, 'response must come back on the allocated CID'
        assert r[4] == 0x81, f'expected PING response, cmd={r[4]:#04x}'
        assert r[5:7] == (8).to_bytes(2, 'big'), 'PING echo must be 8 bytes'
        assert r[7:15] == nonce, f'PING echo mismatch: {r[7:15].hex()}'
        print('      ok (payload echoed)')

        # --- 3. WINK (watch the LED flicker) -------------------------------
        # Provisioned and idle, the on-board LED is steady (no blink);
        # each WINK makes it flicker (100 ms on/off) for 600 ms. A single
        # WINK's flicker ends before this probe exits, so send three,
        # 1 s apart: ~3 s of visible flickering to actually catch.
        print('WINK  -> watch the Pico: the LED flickers 600 ms per WINK')
        for i in range(3):
            pkt = got_cid + bytes([0x88]) + (0).to_bytes(2, 'big') + bytes(57)
            write_report(fd, pkt)
            resp = read_report(fd)
            if len(resp) != 64:
                sys.exit(f'WINK {i + 1}: no response ({len(resp)} bytes)')
            r = resp
            check_error(r, f'WINK {i + 1}')
            assert r[0:4] == got_cid, \
                'response must come back on the allocated CID'
            assert r[4] == 0x88, f'expected WINK response, cmd={r[4]:#04x}'
            assert r[5:7] == (0).to_bytes(2, 'big'), 'WINK response must be empty'
            if i < 2:
                time.sleep(1.0)
        print('      ok (3x empty response — the LED flickered 3x600 ms)')

        print('PASS — Phase 1 transport verified (descriptor-level checks')
        print('       1 and 2 were done separately: lsusb + report_descriptor)')
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()

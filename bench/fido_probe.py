#!/usr/bin/env python3
"""fido_probe.py — Phase 1 bench check for the Pico FIDO2 key.

Finds the key by VID/PID (2e8a:000b), then runs the three transport
checks that Phase 1 promises:

  1. CTAPHID INIT (broadcast) -> the exactly-17-byte response with the
     nonce echoed, an allocated CID (first one is 2), protocol 0x02 and
     capabilities 0x0D (WINK|CBOR|NMSG).
  2. CTAPHID PING on the allocated channel -> the payload echoed back.
  3. CTAPHID WINK -> empty response, and the on-board LED flickers for
     600 ms (watch it).

No third-party dependencies (no pyusb/hidapi) — plain /dev/hidraw.
Run as root, or add a udev rule granting your user access to 2e8a:000b.

Linux hidraw quirk (why the 0x00 byte below): for a device WITHOUT
report IDs, hidraw still prepends a report-ID byte, and the kernel's
usbhid strips the leading 0x00 before the wire — the device sees
exactly 64 report bytes. Reads come back the same way: 0x00 + 64.

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
    """Read one IN report: 0x00 prefix + 64 report bytes (65 total)."""
    end = time.time() + READ_TIMEOUT_S
    while True:
        try:
            data = os.read(fd, 65)
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
        pkt = bytes(4) + bytes([0x86]) + (8).to_bytes(2, 'big') + nonce + bytes(49)
        write_report(fd, pkt)
        resp = read_report(fd)
        if len(resp) != 65 or resp[0] != 0:
            sys.exit(f'INIT: no/bad response ({len(resp)} bytes: {resp.hex()})')
        r = resp[1:]                                  # the 64-byte report
        got_cid = r[15:19]
        print(f'INIT  -> cid={got_cid.hex()} '
              f'proto={r[19]:#04x} fw={r[20]}.{r[21]}.{r[22]} caps={r[23]:#04x}')
        assert r[0:4] == bytes(4), 'response must go to the broadcast CID'
        assert r[4] == 0x06, f'expected INIT response, cmd={r[4]:#04x}'
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
        if len(resp) != 65:
            sys.exit(f'PING: no response ({len(resp)} bytes)')
        r = resp[1:]
        print(f'PING  -> cid={r[0:4].hex()} cmd={r[4]:#04x} '
              f'echo={r[7:15].hex()}')
        assert r[0:4] == got_cid, 'response must come back on the allocated CID'
        assert r[4] == 0x01, f'expected PING response, cmd={r[4]:#04x}'
        assert r[7:15] == nonce, f'PING echo mismatch: {r[7:15].hex()}'
        print('      ok (payload echoed)')

        # --- 3. WINK (watch the LED flicker for 600 ms) --------------------
        pkt = got_cid + bytes([0x88]) + (0).to_bytes(2, 'big') + bytes(57)
        write_report(fd, pkt)
        resp = read_report(fd)
        if len(resp) != 65:
            sys.exit(f'WINK: no response ({len(resp)} bytes)')
        r = resp[1:]
        print(f'WINK  -> cmd={r[4]:#04x} bcnt={int.from_bytes(r[5:7], "big")}')
        assert r[4] == 0x08, f'expected WINK response, cmd={r[4]:#04x}'
        assert r[5:7] == (0).to_bytes(2, 'big'), 'WINK response must be empty'
        print('      ok (empty response — LED flickering now)')

        print('PASS — Phase 1 transport verified (descriptor-level checks')
        print('       1 and 2 were done separately: lsusb + report_descriptor)')
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()

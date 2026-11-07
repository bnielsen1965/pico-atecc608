#!/usr/bin/env python3
"""fido_watch.py — passive CTAPHID wire watcher for the Pico FIDO2 key.

Finds the key by VID/PID (2e8a:000b, same as fido_probe.py) and prints
every IN report (device -> host) with a relative timestamp and a
decoded one-line description. It is READ-ONLY: it never writes to the
device, so a browser (or the probe) can drive the key while it runs.

Why it exists: when a browser says "insert your security key and touch
it" forever, the open question is whether the browser is TALKING to the
key at all. While this watcher runs, any browser request (INIT,
GET_INFO, MAKE_CREDENTIAL, ...) still reaches the device, and the
device's answers show up here — so:

  - reports appear  -> the browser talks to the key; read the decoded
                       lines to see where the exchange stops.
  - nothing appears -> the browser never touches the key; that is a
                       detection problem (permissions, udev, Chrome),
                       not a protocol problem.

Caveat: hidraw hands each IN report to ONE reader. If the browser
holds the device open at the same time, reports are split between the
readers; starting the watcher first wins most of them, and seeing even
one report answers the question above.

Usage: python3 bench/fido_watch.py [seconds]     (default 90)
Run as root, or with the udev/ACL grant for 2e8a:000b (see fido_probe).
"""
import glob
import os
import sys
import time

VID, PID = '2e8a', '000b'
BROADCAST = bytes.fromhex('ffffffff')

# CTAP2 status codes (CTAP v2.1 §8.2) for annotating 1-byte responses.
CTAP2_ERRS = {
    0x00: 'OK', 0x01: 'INVALID_COMMAND', 0x02: 'INVALID_PARAMETER',
    0x03: 'INVALID_LENGTH', 0x04: 'INVALID_SEQ', 0x05: 'TIMEOUT',
    0x06: 'CHANNEL_BUSY', 0x0A: 'LOCK_REQUIRED', 0x0B: 'INVALID_CHANNEL',
    0x11: 'CBOR_UNEXPECTED_TYPE', 0x12: 'INVALID_CBOR',
    0x14: 'MISSING_PARAMETER', 0x15: 'LIMIT_EXCEEDED',
    0x19: 'CREDENTIAL_EXCLUDED', 0x21: 'PROCESSING',
    0x22: 'INVALID_CREDENTIAL', 0x26: 'UNSUPPORTED_ALGORITHM',
    0x27: 'OPERATION_DENIED', 0x28: 'KEY_STORE_FULL',
    0x2E: 'NO_CREDENTIALS', 0x3A: 'ACTION_TIMEOUT',
    0x3B: 'UP_REQUIRED', 0x7F: 'OTHER',
}


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


def decode(r):
    """One decoded line for a 64-byte IN report (see fido_probe.py for
    the framing: CID(4 BE) | CMD(1) | BCNT(2 BE, first packet) | DATA)."""
    cid = r[0:4]
    cmd = r[4]
    if cmd == 0x86 and cid == BROADCAST:
        return (f'INIT response: new cid={r[15:19].hex()} '
                f'proto={r[19]:#04x} fw={r[20]}.{r[21]}.{r[22]} '
                f'caps={r[23]:#04x}')
    if cmd == 0x81:
        return f'PING response cid={cid.hex()} echo={r[7:15].hex()}'
    if cmd == 0x88:
        return f'WINK response cid={cid.hex()}'
    if cmd == 0xBF:
        if r[5:7] == b'\x00\x01':
            return f'ERROR cid={cid.hex()} code={r[7]:#04x}'
        return f'ERROR cid={cid.hex()} (unexpected shape: {r[5:8].hex()})'
    if cmd == 0x3B:
        return f'KEEPALIVE cid={cid.hex()} msg={r[7:15].hex()}'
    if cmd == 0x90:
        bcnt = int.from_bytes(r[5:7], 'big')
        data = r[7:64]
        if 0 < bcnt <= 57:
            extra = ''
            if bcnt == 1:
                extra = (' (status-only: '
                         + CTAP2_ERRS.get(data[0], f'0x{data[0]:02x}') + ')')
            return (f'CBOR response cid={cid.hex()} bcnt={bcnt} '
                    f'payload={data[:bcnt].hex()}{extra}')
        return (f'CBOR response (part 1) cid={cid.hex()} bcnt={bcnt} '
                f'payload={data[:12].hex()}...')
    if cmd == 0x00:
        return f'CBOR continuation cid={cid.hex()} data={r[5:17].hex()}'
    return f'cmd={cmd:#04x} cid={cid.hex()} raw={r[:13].hex()}'


def main():
    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 90.0
    node = find_hidraw()
    if not node:
        sys.exit(f'no hidraw device with {VID}:{PID} found (plug the Pico in)')

    fd = os.open(node, os.O_RDONLY | os.O_NONBLOCK)
    t0 = time.time()
    n = 0
    print(f'watching {node} for {seconds:.0f}s — '
          f'trigger the browser operation now', flush=True)
    try:
        while True:
            left = t0 + seconds - time.time()
            if left <= 0:
                break
            try:
                r = os.read(fd, 64)
            except BlockingIOError:
                r = b''
            if r:
                n += 1
                t = time.time() - t0
                print(f'[{t:8.3f}] IN  {r[:13].hex(" ")} | {decode(r)}',
                      flush=True)
            else:
                time.sleep(min(0.05, left))
    finally:
        os.close(fd)
    print(f'done: {n} report(s) seen in {seconds:.0f}s', flush=True)
    if n == 0:
        print('=> no traffic at all: whatever drove the operation never '
              'talked to the key (a detection problem, not a protocol '
              'problem)', flush=True)


if __name__ == '__main__':
    main()

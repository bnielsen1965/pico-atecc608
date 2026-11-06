#!/usr/bin/env python3
"""fido_mc.py — E2E makeCredential rehearsal over the wire.

The pre-browser validation for the FIDO2 key. libfido2 1.16 (fido2-cred /
fido2-token) CANNOT be used for this: it is a CTAP 2.3 client (2.3 caps
bits, 2.3 GET_INFO key numbers, no legacy fallback — src/info.c
parse_reply_element in the 1.16.0 source) and our device deliberately
emits the CTAP 2.1+ wire encoding that the shipping browsers require
(the CTAP 2.0 spec's key table was never used by shipping hardware —
dual keys are impossible, every GET_INFO key 0x01-0x0A collides between
the two numberings; round C13 root cause, see PLAN.md). So this script
speaks the same protocol directly over /dev/hidraw and drives user
presence through the UART console, exactly like a browser round:

  1. CTAPHID INIT (broadcast) -> CID; expect fw 1.0.8, caps 0x07.
  2. CTAP2 GET_INFO -> the 81-byte response (0x00 status + 80-byte
     CBOR map, CTAP 2.1+ key numbers), 2 packets (57+24).
  3. CTAP2 makeCredential with the EXACT 190-byte request Firefox sent
     in bench round C1 (pinned in tests/test_ctap.c, s_firefox_c1_req):
     rp "xorengineering.com", ES256, the 2.2 `extensions` slot,
     options {rk:false}. 4 OUT packets (57+59+59+15).
  4. `up` via the UART console ~2 s in (the agent is the operator for
     this round — the user is not at the console).
  5. Keep-alives (0xBB, BCNT 1, status 0x01 = UP_NEEDED) at ~500 ms
     until the touch; then the 258-262-byte success response (0x00
     status + CBOR attestation object) over 5 packets (57+59+59+59+
     24..28 — the ES256 DER sig is 68-72 bytes).
  6. Validate the response: attestation type "packed", authData
     (rpIdHash = SHA-256("xorengineering.com"), flags 0x41, counter,
     AAGUID, 32-byte credId, 77-byte COSE_Key), attStmt {alg:-7,
     sig: a 70-72-byte ASN.1 DER Ecdsa-Sig-Value (WebAuthn L3 6.5.5)}.
  7. `wipe` via the console so the browser round starts from an empty
     store.

No third-party dependencies — plain /dev/hidraw + /dev/ttyUSB0.
Console protocol (ground rules 7 + 11): plain byte I/O, CR line
endings, no termios rewrites — the port state is enforced with the
rule-11 stty recipe (ALWAYS 115200 8N1, no echo) before every open,
because the CP210x bridge re-enumerates after unplugs/reflashes and
comes back at the kernel default (9600 + cooked + echo), where the
exchange is dead in both directions. This script is the ONLY console
reader while it runs.
"""
import hashlib
import os
import secrets
import select
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fido_probe import (  # noqa: E402
    BROADCAST,
    check_error,
    find_hidraw,
    read_report,
    write_report,
)

# --- P-256 raw-digest ECDSA verify (pure Python; no third-party deps) -------
# The ATECC608 Sign (external-digest mode) signs the 32-byte Message Digest
# Buffer AS-IS -- it does not hash it. The packed attestation signature is over
# SHA-256(authData || clientDataHash), so we verify that 32-byte digest
# directly: e = int(digest) mod n. Do NOT re-hash the digest: the `cryptography`
# lib's verify(sig, data, ECDSA(SHA256)) hashes `data` first, which would
# verify SHA-256(digest) -- the wrong value. That double-hash was the C15 false
# alarm (a valid chip signature read as "invalid").
_P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_P256_A = _P256_P - 3
_P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_P256_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
           0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P256_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    return (x3, (lam * (x1 - x3) - y1) % _P256_P)


def _ec_mul(k, pt):
    r = None
    a = pt
    while k:
        if k & 1:
            r = _ec_add(r, a)
        a = _ec_add(a, a)
        k >>= 1
    return r


def _ecdsa_verify_raw(x, y, r, s, digest):
    """Verify a P-256 ECDSA signature over a pre-hashed 32-byte digest."""
    if not (1 <= r < _P256_N and 1 <= s < _P256_N):
        return False
    e = int.from_bytes(digest, "big") % _P256_N
    w = pow(s, -1, _P256_N)
    pt = _ec_add(_ec_mul((e * w) % _P256_N, _P256_G),
                 _ec_mul((r * w) % _P256_N, (x, y)))
    return pt is not None and pt[0] % _P256_N == r


def _ecdsa_selftest():
    # Round-trip: pick a private key, sign a digest, verify it, and confirm a
    # wrong digest is rejected. Catches any regression in the curve arithmetic
    # before it is trusted to judge a real device signature.
    d = secrets.randbelow(_P256_N - 1) + 1
    Q = _ec_mul(d, _P256_G)
    digest = bytes(range(32))
    e = int.from_bytes(digest, "big") % _P256_N
    while True:
        k = secrets.randbelow(_P256_N - 1) + 1
        R = _ec_mul(k, _P256_G)
        rr = R[0] % _P256_N
        if rr == 0:
            continue
        ss = pow(k, -1, _P256_N) * (e + rr * d) % _P256_N
        if ss == 0:
            continue
        break
    return (_ecdsa_verify_raw(Q[0], Q[1], rr, ss, digest)
            and not _ecdsa_verify_raw(Q[0], Q[1], rr, ss, bytes(range(1, 33))))


def parse_ecdsa_der(sig):
    """Parse an ASN.1 DER Ecdsa-Sig-Value (RFC 3279 2.2.3) -> (r, s).

    WebAuthn L3 section 6.5.5 MANDATES this encoding for ES256 "sig"
    values (assertion AND packed-attestation signatures) — the raw
    R||S form is the COSE_Sign encoding (RFC 9052), NOT a WebAuthn
    signature. Each INTEGER is minimally encoded: no leading zero
    octets, except a single 0x00 sign pad when the next octet's high
    bit is set. Raises ValueError on malformed input."""
    if len(sig) < 8 or sig[0] != 0x30 or sig[1] != len(sig) - 2:
        raise ValueError(f'not a DER SEQUENCE of the right length: '
                         f'{sig.hex()}')
    off = 2
    vals = []
    for _ in range(2):
        if sig[off] != 0x02:
            raise ValueError(f'expected INTEGER tag at {off}, '
                             f'got {sig[off]:#04x}')
        ln = sig[off + 1]
        off += 2
        v = sig[off:off + ln]
        if ln != len(v):
            raise ValueError('truncated INTEGER')
        if v[0] == 0x00 and (ln < 2 or v[1] < 0x80):
            raise ValueError('non-minimal INTEGER (spurious 0x00)')
        vals.append(int.from_bytes(v, 'big'))
        off += ln
    if off != len(sig):
        raise ValueError('trailing bytes after the second INTEGER')
    return vals[0], vals[1]


CONSOLE = '/dev/ttyUSB0'
READ_TIMEOUT_S = 1.0

# The EXACT makeCredential request Firefox sent in bench round C1 (the
# first real browser request; pinned in tests/test_ctap.c as
# s_firefox_c1_req). 190 bytes, command byte first: rp
# "xorengineering.com", user nobody@mail.com, ES256 + RS256 params,
# the CTAP 2.2 `extensions` slot ({"hmac-secret": false}), options
# {rk:false}.
MC_REQ = bytes.fromhex(
    '01a6015820e0f0eacdd7dfc590e61423fb722a1c4938d6bbf9cb167cc8230aef9db71be38602a162'
    '696472786f72656e67696e656572696e672e636f6d03a26269645820bf0bf55987471f8ed5490b1d'
    '744ca5711b603b4f9e79af6176c50d9c4186c5a2646e616d656f6e6f626f6479406d61696c2e636f'
    '6d0482a263616c672664747970656a7075626c69632d6b6579a263616c6739010064747970656a70'
    '75626c69632d6b657906a16b686d61632d736563726574f407a162726bf4'
)

# AAGUID the firmware claims (must stay in sync with fido_ctap.c).
AAGUID = bytes.fromhex('65f5107f31a6478593016788e10ec776')

# The 81-byte GET_INFO KAT (0x00 status + 80-byte map, CTAP 2.1+ key
# numbers — the same bytes fido_probe.py pins).
GETINFO_KAT = bytes.fromhex(
    '00a80181684649444f5f325f30035065f5107f31a6478593016788e10ec776'
    '04a262726bf5627570f505190100071880081840098163757362'
    '0a81a263616c672664747970656a7075626c69632d6b6579')

RP_ID_HASH = hashlib.sha256(b'xorengineering.com').digest()


def _console_ready():
    """Enforce ground rule 11 on the console port: ALWAYS 115200 8N1,
    no echo, no output post-processing — the exact stty recipe from
    the rule. The CP210x bridge re-enumerates on every reflash/replug
    (and hub power events) and comes back at the kernel default
    (9600 + cooked + local ECHO); at 9600 the exchange is dead in both
    directions, and a live-ECHO port makes it worse (the device chews
    its own console output forever). Never assume the port's current
    speed; never toggle DTR/RTS (a CP210x DTR de-assert can
    re-initialize the chip's line config).
    """
    subprocess.run(
        ['stty', '-F', CONSOLE, '115200', 'cs8', '-cstopb', '-parenb',
         '-echo', '-opost'],
        check=True, capture_output=True)


def console_cmd(cmd, timeout=4.0):
    """Send one console command and return the device's reply text."""
    _console_ready()  # ground rule 11: always 115200 8N1 no-echo
    with open(CONSOLE, 'r+b', 0) as c:
        c.write(cmd.encode() + b'\r')
        c.flush()
        out = b''
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([c], [], [], 0.5)
            if r:
                chunk = os.read(c.fileno(), 256)
                if not chunk:
                    break
                out += chunk
                if b'\r\n' in out[-8:]:
                    break
        return out.decode(errors='replace')


def read_until(fd, want_cmd, want_bcnt=None, timeout=35.0):
    """Read IN reports until the response to `want_cmd` arrives.

    `want_bcnt` may be an int (exact length) or a (min, max) tuple —
    the ES256 DER sig is 68-72 bytes, so the MC response is 258-262.
    Keeps a tally of 0xBB keep-alives (expected at ~500 ms while the
    device waits for the touch). Returns (payload, n_keepalives).
    """
    keepalives = 0
    end = time.time() + timeout
    while time.time() < end:
        r = read_report(fd)
        if not r:
            continue
        check_error(r, f'poll cmd={want_cmd:#04x}')
        if r[4] == 0xBB:
            keepalives += 1
            continue
        if r[4] != want_cmd:
            sys.exit(f'unexpected IN report cmd={r[4]:#04x}: {r[:8].hex()}')
        bcnt = int.from_bytes(r[5:7], 'big')
        if isinstance(want_bcnt, tuple):
            if not want_bcnt[0] <= bcnt <= want_bcnt[1]:
                sys.exit(f'response BCNT {bcnt} outside expected '
                         f'{want_bcnt[0]}..{want_bcnt[1]}')
        elif want_bcnt is not None and bcnt != want_bcnt:
            sys.exit(f'response BCNT {bcnt} != expected {want_bcnt}')
        payload = bytearray(r[7:64])
        seq = 0
        while len(payload) < bcnt:
            r2 = read_report(fd)
            if len(r2) != 64:
                sys.exit('no continuation packet')
            check_error(r2, 'continuation')
            if r2[4] != seq:
                sys.exit(f'continuation SEQ {r2[4]} != {seq}')
            take = min(59, bcnt - len(payload))
            payload += r2[5:5 + take]
            seq += 1
        return bytes(payload), keepalives
    sys.exit(f'timeout waiting for the {want_cmd:#04x} response '
             f'({keepalives} keep-alives seen)')


def main():
    node = find_hidraw()
    if not node:
        sys.exit(f'no hidraw device with 2e8a:000b found (plug the Pico in)')
    print(f'using {node}')
    fd = os.open(node, os.O_RDWR | os.O_NONBLOCK)
    try:
        # --- 1. INIT ---------------------------------------------------
        nonce = bytes(range(1, 9))
        pkt = BROADCAST + bytes([0x86]) + (8).to_bytes(2, 'big') + nonce \
            + bytes(49)
        write_report(fd, pkt)
        r = read_report(fd)
        if len(r) != 64:
            sys.exit(f'INIT: no response ({len(r)} bytes)')
        check_error(r, 'INIT')
        cid = r[15:19]
        print(f'INIT  -> cid={cid.hex()} fw={r[20]}.{r[21]}.{r[22]} '
              f'caps={r[23]:#04x}')
        assert r[20:23] == bytes([1, 0, 8]), \
            f'firmware must be 1.0.8, got {r[20]}.{r[21]}.{r[22]}'
        assert r[23] == 0x07, f'caps must be 0x07, got {r[23]:#04x}'

        # --- 2. GET_INFO -------------------------------------------------
        pkt = cid + bytes([0x90]) + (1).to_bytes(2, 'big') + b'\x04' \
            + bytes(56)
        write_report(fd, pkt)
        gi, _ = read_until(fd, 0x90, 81)
        assert gi == GETINFO_KAT, \
            f'GET_INFO != KAT:\n  got      {gi.hex()}\n  expected ' \
            f'{GETINFO_KAT.hex()}'
        print('GET_INFO  -> 81 bytes (0x00 status + 80-B map), KAT match')

        # --- 3. makeCredential (the exact Firefox C1 request) ------------
        assert len(MC_REQ) == 190
        chunks = [MC_REQ[0:57], MC_REQ[57:116], MC_REQ[116:175],
                  MC_REQ[175:190]]
        pkt = cid + bytes([0x90]) + (190).to_bytes(2, 'big') + chunks[0]
        write_report(fd, pkt)
        for i, ch in enumerate(chunks[1:], start=0):
            pkt = cid + bytes([i]) + ch + bytes(59 - len(ch))
            write_report(fd, pkt)
        print(f'MC_REQ  -> 190 bytes in 4 OUT packets '
              f'(rp xorengineering.com, ES256, ext hmac-secret)')

        # --- 4. `up` via the console ~2 s in ------------------------------
        time.sleep(2.0)
        reply = console_cmd('up')
        print(f'console -> up: {reply.strip()!r}')

        # --- 5. the 258-262-byte response ---------------------------------
        resp, ka = read_until(fd, 0x90, (258, 262))
        print(f'MC_RESP -> {len(resp)} bytes over 5 packets, '
              f'{ka} keep-alive(s) before the touch')

        # --- 6. validate the attestation object ---------------------------
        assert resp[0] == 0x00, f'status byte must be 0x00, got {resp[0]:#04x}'
        assert resp[1] == 0xA3, 'top level must be map(3)'
        assert resp[2] == 0x01 and resp[3] == 0x66 \
            and resp[4:10] == b'packed', 'attestation type must be "packed"'
        assert resp[10] == 0x02 and resp[11] == 0x58 and resp[12] == 0xA4, \
            'authData must be bytes(164)'
        authdata = resp[13:13 + 164]
        assert authdata[:32] == RP_ID_HASH, \
            'authData rpIdHash != SHA-256("xorengineering.com")'
        flags = authdata[32]
        assert flags == 0x41, f'authData flags must be 0x41 (UP|AT), ' \
            f'got {flags:#04x}'
        counter = int.from_bytes(authdata[33:37], 'big')
        assert authdata[37:53] == AAGUID, 'authData AAGUID mismatch'
        cred_id_len = int.from_bytes(authdata[53:55], 'big')
        assert cred_id_len == 32, f'credIdLen must be 32, got {cred_id_len}'
        cose = authdata[55 + 32:]
        assert len(cose) == 77 and cose[0] == 0xA5, \
            f'COSE_Key must be 77-byte map(5), got {len(cose)} bytes'
        # CTAP2 layout: {1:kty=2, 3:alg=-7, -1:crv=1, -2:x, -3:y}
        assert cose[1:7] == bytes([0x01, 0x02, 0x03, 0x26, 0x20, 0x01]), \
            'COSE_Key must be kty EC2 / alg ES256 / crv P-256 (CTAP2 layout)'
        # attStmt: 03 | A2 | 63 "alg" | 26 | 63 "sig" | 58 <len> | <DER>.
        # The ES256 sig is an ASN.1 DER Ecdsa-Sig-Value (WebAuthn L3
        # section 6.5.5, RFC 3279 section 2.2.3): 68-72 bytes — 70 in
        # the common case, 72 when r and/or s need the 0x00 sign pad.
        rest = resp[13 + 164:]
        assert rest[0] == 0x03 and rest[1] == 0xA2, 'attStmt must be map(2)'
        assert rest[2:6] == b'\x63alg' and rest[6] == 0x26, \
            'attStmt alg must be -7'
        assert rest[7:11] == b'\x63sig' and rest[11] == 0x58, \
            'attStmt sig must be a byte string'
        sig_len = rest[12]
        assert 0x44 <= sig_len <= 0x48, \
            f'attStmt DER sig length {sig_len} out of range 68..72'
        assert len(rest) == 13 + sig_len, f'attStmt size off: {len(rest)}'
        r, s = parse_ecdsa_der(rest[13:13 + sig_len])
        print(f'attestation  -> packed, flags 0x41, counter {counter}, '
              f'AAGUID ok, credId 32 B, COSE_Key ok, sig DER {sig_len} B')

        # --- 6b. cryptographically verify the packed signature -------------
        # The checks above only looked at lengths. Now verify the signature
        # for real: it is over SHA-256(authData || clientDataHash), and the
        # ATECC608 signs that 32-byte digest AS-IS (raw-digest verify; do NOT
        # re-hash it -- see the note above _ecdsa_verify_raw / the C15 note).
        assert _ecdsa_selftest(), 'ECDSA self-test failed (verifier broken)'
        print('ecdsa      -> self-test ok (sign/verify round-trip)')
        cdh = MC_REQ[5:37]   # clientDataHash: first map entry of the request
        digest = hashlib.sha256(authdata + cdh).digest()
        # r and s were parsed from the DER in step 6.
        px = int.from_bytes(cose[10:42], 'big')
        py = int.from_bytes(cose[45:77], 'big')
        assert _ecdsa_verify_raw(px, py, r, s, digest), \
            'packed signature INVALID over SHA-256(authData||clientDataHash)'
        print(f'signature  -> VALID over SHA256(authData||cdh)  '
              f'(digest {digest.hex()[:16]}..., r {format(r, "064x")[:16]}...)')

        # --- 7. wipe the store for the browser round ----------------------
        reply = console_cmd('wipe')
        print(f'console -> wipe: {reply.strip()!r}')

        print('PASS — E2E makeCredential rehearsal verified (CTAP 2.1+ '
              'GET_INFO keys, 0x00 status framing)')
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()

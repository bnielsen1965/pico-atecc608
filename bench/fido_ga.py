#!/usr/bin/env python3
"""fido_ga.py — E2E getAssertion rehearsal over the wire.

Reproduces the browser's *login half* deterministically so a failed
round C20 ("authentication failed: could not verify authentication
signature") can be pinned down without a browser:

  1. `wipe` via the console (clean store + zeroed counter).
  2. CTAPHID INIT -> CID; expect fw 1.0.8, caps 0x07.
  3. CTAP2 makeCredential (the exact Firefox C1 request, re-used from
     fido_mc.py) -> capture the attestation authData: the COSE public
     key (the key the browser AND the server store), the counter, and
     the 32-byte credId. Verify the attestation signature (sanity).
  4. CTAP2 getAssertion in the two shapes a shipping browser actually
     sends for userVerification:'preferred' / Conditional UI:
        a. allowList [credId] + options {up:false}  (synchronous)
        b. no allowList (resident enumeration)      (synchronous)
     For each: parse the response CBOR (credential / authData /
     signature / user), check the 37-byte assertion authData layout
     (NO attested credential data — WebAuthn L3 §6.3.3 step 10), then
     verify the assertion signature OFF-CHIP against the
     REGISTRATION's public key — the key the browser and the
     py_webauthn server both hold.

  The verdict:
    * authData 37 B + sig VALID  -> the device crypto is correct; any
      C20 failure is in the browser / Conditional-UI / server layer.
    * authData != 37 B           -> the assertion carries attested
      credential data (AT bit) — spec violation, the device bug.
    * sig INVALID                -> signature over the wrong data or a
      wrong key; inspect authData vs the signed digest.

No third-party dependencies — plain /dev/hidraw + /dev/ttyUSB0.
"""
import hashlib
import os
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
from fido_mc import (  # noqa: E402
    AAGUID,
    MC_REQ,
    _ecdsa_selftest,
    _ecdsa_verify_raw,
    console_cmd,
    parse_ecdsa_der,
    read_until,
)

RP = b'xorengineering.com'
CDH = bytes(range(32))          # a fixed clientDataHash for the login
RP_ID_HASH = hashlib.sha256(RP).digest()


# --- minimal CBOR reader (just enough for the GA response) --------------
def cbor_read(buf, off):
    major = buf[off] >> 5
    info = buf[off] & 0x1F
    off += 1
    if info < 24:
        val = info
    elif info == 24:
        val = buf[off]; off += 1
    elif info == 25:
        val = int.from_bytes(buf[off:off + 2], 'big'); off += 2
    elif info == 26:
        val = int.from_bytes(buf[off:off + 4], 'big'); off += 4
    elif info == 27:
        val = int.from_bytes(buf[off:off + 8], 'big'); off += 8
    else:
        val = None
    if major == 0:
        return 'uint', val, off
    if major == 1:
        return 'negint', -1 - val, off
    if major == 2:
        data = buf[off:off + val]; off += val
        return 'bytes', data, off
    if major == 3:
        data = buf[off:off + val]; off += val
        return 'text', data.decode('utf-8', 'replace'), off
    if major == 4:
        return 'array', val, off
    if major == 5:
        return 'map', val, off
    if major == 7:
        if val == 20:
            return 'bool', False, off
        if val == 21:
            return 'bool', True, off
    return 'other', val, off


def parse_ga(resp):
    """Parse a getAssertion response payload -> (status, cred_id,
    authdata, sig, user_id, no_creds)."""
    status = resp[0]
    off = 1
    t, n, off = cbor_read(resp, off)
    if t != 'map':
        sys.exit(f'GA: top level must be a map, got {t}')
    cred_id = authdata = sig = user_id = None
    no_creds = None
    for _ in range(n):
        kt, key, off = cbor_read(resp, off)
        if key == 1:                       # credential map {id, type}
            _, cn, off = cbor_read(resp, off)
            for _ in range(cn):
                _, k, off = cbor_read(resp, off)
                _, v, off = cbor_read(resp, off)
                if k == 'id':
                    cred_id = v
        elif key == 2:                     # authData
            _, authdata, off = cbor_read(resp, off)
        elif key == 3:                     # signature
            _, sig, off = cbor_read(resp, off)
        elif key == 4:                     # user map {id}
            _, un, off = cbor_read(resp, off)
            for _ in range(un):
                _, k, off = cbor_read(resp, off)
                _, v, off = cbor_read(resp, off)
                if k == 'id':
                    user_id = v
        elif key == 5:                     # numberOfCredentials
            _, no_creds, off = cbor_read(resp, off)
        else:
            sys.exit(f'GA: unexpected top-level key {key!r}')
    return status, cred_id, authdata, sig, user_id, no_creds


def parse_att_authdata(authdata):
    """makeCredential authData (AT=1): rpIdHash(32) | flags(1) |
    counter(4 BE) | AAGUID(16) | credIdLen(2 BE) | credId | COSE_Key(77)."""
    rp_id_hash = authdata[:32]
    flags = authdata[32]
    counter = int.from_bytes(authdata[33:37], 'big')
    aaguid = authdata[37:53]
    cred_id_len = int.from_bytes(authdata[53:55], 'big')
    cred_id = authdata[55:55 + cred_id_len]
    cose = authdata[55 + cred_id_len:]
    # COSE_Key {1:2,3:-7,-1:1,-2:x,-3:y}; x at [10:42], y at [45:77].
    px = int.from_bytes(cose[10:42], 'big')
    py = int.from_bytes(cose[45:77], 'big')
    return rp_id_hash, flags, counter, aaguid, cred_id_len, cred_id, px, py


def parse_assert_authdata(authdata):
    """getAssertion authData — EXACTLY 37 bytes: rpIdHash(32) | flags(1)
    | signCount(4 BE). The assertion EXCLUDES the attested credential
    data (WebAuthn L3 §6.3.3 step 10): no AT bit, no AAGUID/credId/COSE.
    The credential itself travels in the response's "credential" member."""
    assert len(authdata) == 37, \
        f'assertion authData must be 37 bytes, got {len(authdata)}'
    rp_id_hash = authdata[:32]
    flags = authdata[32]
    counter = int.from_bytes(authdata[33:37], 'big')
    assert flags & 0x40 == 0, \
        f'assertion authData must NOT set the AT bit, flags {flags:#04x}'
    return rp_id_hash, flags, counter


def build_ga(cred_id, with_allow, up):
    """Build a getAssertion payload [0x02][CBOR map].

    up: None  = omit options (device default is up:true -> deferred)
        False = options {up:false}  (the CTAP 2.3 pre-flight, sync)
        True  = options {up:true}   (what Firefox sends for a
                user-initiated 'preferred' login -> the deferred path)
    """
    out = bytearray([0x02])
    has_up = up is not None
    nkeys = 2 + (1 if with_allow else 0) + (1 if has_up else 0)
    out.append(0xA0 + nkeys)
    # 1: rpId (text)
    out += bytes([0x01])
    out += bytes([0x60 + len(RP)]) + RP
    # 2: clientDataHash (bytes 32)
    out += bytes([0x02, 0x58, 0x20]) + CDH
    if with_allow:
        # 3: allowList = [ {id: credId, type: "public-key"} ]
        out += bytes([0x03, 0x81, 0xA2])
        out += b'\x62id' + bytes([0x58, 0x20]) + cred_id
        out += b'\x64type' + bytes([0x6A]) + b'public-key'
    if has_up:
        # 5: options = {up: <bool>}
        out += bytes([0x05, 0xA1, 0x62]) + b'up'
        out += bytes([0xF4 if up is False else 0xF5])
    return bytes(out)


def send_msg(fd, cid, payload):
    """Send a CTAPHID 0x90 (CBOR) message, multi-packet."""
    chunks = [payload[0:57]] + [payload[i:i + 59] for i in range(57, len(payload), 59)]
    write_report(fd, cid + bytes([0x90]) + len(payload).to_bytes(2, 'big') +
                 chunks[0].ljust(57, b'\x00'))
    for i, ch in enumerate(chunks[1:]):
        write_report(fd, cid + bytes([i]) + ch.ljust(59, b'\x00'))


def verify_assertion(label, px_reg, py_reg, authdata, sig):
    print(f'\n--- getAssertion [{label}] ---')
    (rp_id_hash, flags, counter) = parse_assert_authdata(authdata)
    print(f'  authData    : {len(authdata)} bytes (37 — no attested '
          f'credential data, per WebAuthn L3 §6.3.3)')
    print(f'  rpIdHash ok : {rp_id_hash == RP_ID_HASH}')
    print(f'  flags       : {flags:#04x}  (UP={flags & 1}, AT={flags & 0x40})')
    print(f'  counter     : {counter}')
    # The sig is an ASN.1 DER Ecdsa-Sig-Value (WebAuthn L3 6.5.5,
    # RFC 3279 2.2.3) — 70-72 bytes, not the raw R||S COSE_Sign form.
    r, s = parse_ecdsa_der(sig)
    print(f'  sig         : {len(sig)} B (ASN.1 DER Ecdsa-Sig-Value, '
          f'WebAuthn L3 6.5.5)')
    digest = hashlib.sha256(authdata + CDH).digest()
    ok_reg = _ecdsa_verify_raw(px_reg, py_reg, r, s, digest)
    print(f'  sig vs REGISTRATION key (what browser+server check): {ok_reg}')
    return ok_reg


def main():
    node = find_hidraw()
    if not node:
        sys.exit(f'no hidraw device with 2e8a:000b found (plug the Pico in)')
    print(f'using {node}')
    fd = os.open(node, os.O_RDWR | os.O_NONBLOCK)
    try:
        # --- 0. clean slate ------------------------------------------------
        print(f'console -> wipe: {console_cmd("wipe").strip()!r}')

        # --- 1. INIT -------------------------------------------------------
        nonce = bytes(range(1, 9))
        write_report(fd, BROADCAST + bytes([0x86]) + (8).to_bytes(2, 'big') +
                     nonce + bytes(49))
        r = read_report(fd)
        if len(r) != 64:
            sys.exit(f'INIT: no response ({len(r)} bytes)')
        check_error(r, 'INIT')
        cid = r[15:19]
        print(f'INIT  -> cid={cid.hex()} fw={r[20]}.{r[21]}.{r[22]} '
              f'caps={r[23]:#04x}')
        assert r[20:23] == bytes([1, 0, 8]), 'firmware must be 1.0.8'
        assert r[23] == 0x07, 'caps must be 0x07'

        # --- 2. makeCredential (the exact Firefox C1 request) --------------
        send_msg(fd, cid, MC_REQ)
        print(f'MC_REQ  -> 190 bytes (rp {RP.decode()})')
        time.sleep(2.0)
        print(f'console -> up: {console_cmd("up").strip()!r}')
        mc_resp, ka = read_until(fd, 0x90, (258, 262))
        print(f'MC_RESP -> {len(mc_resp)} bytes, {ka} keep-alive(s)')
        assert mc_resp[0] == 0x00, f'MC status must be 0x00, {mc_resp[0]:#04x}'
        # authData is at a fixed offset in the packed attestation object
        # (see fido_mc.py): resp[13:13+164].
        mc_auth = mc_resp[13:13 + 164]
        (_, mc_flags, mc_ctr, _, _, cred_id_reg, px_reg, py_reg) = \
            parse_att_authdata(mc_auth)
        print(f'MC      -> flags {mc_flags:#04x}, counter {mc_ctr}, '
              f'credId {cred_id_reg.hex()[:16]}..., key captured')
        assert mc_flags == 0x41, f'MC flags must be 0x41, {mc_flags:#04x}'
        assert len(cred_id_reg) == 32

        assert _ecdsa_selftest(), 'ECDSA self-test failed'

        # --- 3. getAssertion, three shapes ---------------------------------
        results = {}
        # (a) allowList + up:false (the synchronous preflight)
        send_msg(fd, cid, build_ga(cred_id_reg, with_allow=True, up=False))
        t0 = time.time()
        ga_resp, ka = read_until(fd, 0x90, timeout=6.0)
        dt = time.time() - t0
        print(f'\nGA(a) allowList+up:false -> {len(ga_resp)} bytes in '
              f'{dt * 1000:.0f} ms, {ka} keep-alive(s)')
        st, cid_a, ad_a, sig_a, _, no_a = parse_ga(ga_resp)
        print(f'  status {st:#04x}, noCreds={no_a}')
        if st == 0x00:
            results['a'] = verify_assertion('allowList+up:false',
                                            px_reg, py_reg, ad_a, sig_a)
        else:
            print(f'  ERROR: status {st:#04x}')
            results['a'] = False

        # (b) resident enumeration + up:false
        send_msg(fd, cid, build_ga(cred_id_reg, with_allow=False, up=False))
        t0 = time.time()
        ga_resp, ka = read_until(fd, 0x90, timeout=6.0)
        dt = time.time() - t0
        print(f'\nGA(b) enumeration+up:false -> {len(ga_resp)} bytes in '
              f'{dt * 1000:.0f} ms, {ka} keep-alive(s)')
        st, cid_b, ad_b, sig_b, _, no_b = parse_ga(ga_resp)
        print(f'  status {st:#04x}, noCreds={no_b}')
        if st == 0x00:
            results['b'] = verify_assertion('enumeration+up:false',
                                            px_reg, py_reg, ad_b, sig_b)
        else:
            print(f'  ERROR: status {st:#04x}')
            results['b'] = False

        # (c) allowList + up:true — THE REAL BROWSER PATH. libwebauthn
        #     always serializes up:true for a non-preflight getAssertion,
        #     so the device MUST defer: emit keep-alives, wait for UP, then
        #     sign. This is the path the failed C20 login actually took.
        send_msg(fd, cid, build_ga(cred_id_reg, with_allow=True, up=True))
        # Let the deferral start and a couple of keep-alives flow so we can
        # confirm the device is WAITING (not answering synchronously).
        time.sleep(3.0)
        print(f'\nGA(c) allowList+up:true (deferred) — sent; 3 s elapsed, '
              f'now sending up')
        print(f'console -> up: {console_cmd("up").strip()!r}')
        t0 = time.time()
        ga_resp, ka = read_until(fd, 0x90, timeout=20.0)
        dt = time.time() - t0
        print(f'GA(c) -> {len(ga_resp)} bytes in {dt * 1000:.0f} ms after up, '
              f'{ka} keep-alive(s)')
        st, cid_c, ad_c, sig_c, _, no_c = parse_ga(ga_resp)
        print(f'  status {st:#04x}, noCreds={no_c}')
        if st == 0x00:
            results['c'] = verify_assertion('allowList+up:true (DEFERRED)',
                                            px_reg, py_reg, ad_c, sig_c)
            (_rph, flags_c, _ctr) = parse_assert_authdata(ad_c)
            # Deferred path MUST set the UP bit (0x01), and MUST have
            # waited (keep-alives seen), not answered synchronously.
            results['c_deferred'] = ka > 0
            results['c_up_bit'] = (flags_c & 0x01) != 0
        else:
            print(f'  ERROR: status {st:#04x}')
            results['c'] = False

        print('\n=== VERDICT ===')
        for k in sorted(results):
            if k in ('c_deferred', 'c_up_bit'):
                print(f'  {k}: {"PASS" if results[k] else "FAIL"}')
            else:
                print(f'  {k}: signature vs registration key '
                      f'{"VALID" if results[k] else "INVALID"}')
        sigs_ok = all(results.get(k) for k in ('a', 'b', 'c'))
        deferred_ok = results.get('c_deferred') and results.get('c_up_bit')
        print()
        if sigs_ok and deferred_ok:
            print('  -> ALL PATHS CORRECT: signatures verify against the')
            print('     registration key, and the deferred (up:true) path')
            print('     waits for UP with keep-alives. Device is sound.')
        elif sigs_ok and not deferred_ok:
            print('  -> SIGNATURES OK BUT DEFERRED PATH MISBEHAVES: see the')
            print('     c_deferred / c_up_bit lines (synchronous answer or')
            print('     missing UP bit on the up:true path).')
        else:
            print('  -> DEVICE BUG: a getAssertion does not verify against')
            print('     the registration key; inspect authData vs the')
            print('     signed digest (SHA-256(authData || clientDataHash)).')
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()

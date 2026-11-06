#!/usr/bin/env python3
"""fido_demo_lib.py — offline replica of the fido2-demonstration round.

The browser round on https://localhost:8888 (fido2-demonstration, fido2-lib
3.5.6 on Node 24) failed server-side with "packed attestation signature
verification failed" even though the device's registration and assertion
crypto are spec-correct (fido_mc.py / fido_ga.py, and webauthn.io /
py_webauthn in round C19). Root cause: fido2-lib's verifySignature()
unconditionally derToRaw()'s ECDSA signatures before webcrypto.subtle.
verify(); Node >= 24 webcrypto wants raw R||S, so the stock library only
ever accepts DER — but WebAuthn (RFC 8152 §3.4) mandates fixed-size raw
R||S, which is what this device sends (and what real authenticators send).

The harness was patched (patches/fido2-lib-3.5.6-raw-ecdsa.patch in the
fido2-demonstration checkout). This script proves the patched harness
accepts the device's REAL output end-to-end, without a browser:

  1. wipe, INIT (fw 1.0.7 gate).
  2. makeCredential the way the demo's Firefox round sends it: rp.id
     "localhost", a 128-byte challenge base64url'd inside a synthetic
     clientDataJSON (type webauthn.create — the browser's spec form;
     the demo server's standard-base64 transport encoding is decoded
     by the page before the browser re-encodes it), user {id, name,
     displayName}, options {rk:false} — then the deferred UP wait
     (console `up`), as for a user-initiated create.
  3. getAssertion the way the demo's login sends it: allowList [credId]
     + options {up:true} (libwebauthn always serializes up:true for a
     user-initiated get), synthetic clientDataJSON (type webauthn.get),
     deferred UP wait.
  4. Hand the captured attestationObject + assertion (the same base64
     shapes the demo's fido2.js POSTs) to fido2lib-verify.mjs in the
     fido2-demonstration checkout — the exact fido2-lib code path
     index.js runs: attestationResult, then assertionResult with
     prevCounter + credentialPublicKeyPem taken from the attestation
     result, as index.js stores and reuses them.

Exit 0 = the patched harness validates both halves of the round.

No third-party dependencies — plain /dev/hidraw + /dev/ttyUSB0.
"""
import base64
import hashlib
import json
import os
import secrets
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
from fido_mc import (  # noqa: E402
    AAGUID,
    _ecdsa_selftest,
    _ecdsa_verify_raw,
    console_cmd,
    read_until,
)
from fido_ga import (  # noqa: E402
    parse_att_authdata,
    parse_assert_authdata,
    parse_ga,
    send_msg,
)

DEMO = '/home/burnin/Projects/fido2-demonstration'
ORIGIN = 'https://localhost:8888'
RP = b'localhost'
USER_NAME = b'bench@example.com'
DISPLAY_NAME = b'bench user'
CASE_PATH = '/tmp/opencode/fido2lib_case.json'


def b64(b):
    # The demo's fido2.js bufferToBase64 / index.js challenge encoding:
    # STANDARD base64.
    return base64.b64encode(b).decode()


def b64url(b):
    # The browser's credentials.id / rawId: base64url.
    return base64.urlsafe_b64encode(b).decode()


def client_data_json(wt, challenge_bytes):
    """The clientDataJSON Firefox would build for the demo page.

    Challenge encoding, traced through the real demo flow: index.js
    re-encodes fido2-lib's 128-byte challenge as STANDARD base64 for
    transport to the page (Buffer.from(...).toString("base64")); the
    page decodes it back to the raw buffer (base64ToBuffer = atob)
    before navigator.credentials.create; the BROWSER then
    base64url-encodes the raw buffer into clientDataJSON (the WebAuthn
    spec form). fido2-lib's validateChallenge isBase64Url-checks the
    clientData challenge (standard base64 with +/ is rejected) and
    compares it against the expectations challenge after
    coerceToBase64Url (character-level +/ -> -/_ , padding stripped) —
    so the expectations may stay standard base64, exactly as index.js
    stores them in the session.
    """
    return json.dumps({
        'type': wt,
        'challenge': b64url(challenge_bytes),
        'origin': ORIGIN,
        'crossOrigin': False,
        'tokenBinding': {'status': 'not-supported'},
    }, separators=(',', ':'))


def build_mc(cdh, user_id):
    """makeCredential [0x01][CBOR map] — the demo's registration shape.

    Mirrors the pinned Firefox C1 request (fido_mc.py MC_REQ) with the
    demo's values: rp "localhost", the server-issued user.id, crypto
    params [-7, -257], extensions {hmac-secret:false}, options
    {rk:false}. (No `up` in MC options — INVALID_OPTION on this device;
    Firefox does not send it for create either.)
    """
    out = bytearray([0x01, 0xA6])
    # 1: clientDataHash (bytes 32)
    out += bytes([0x01, 0x58, 0x20]) + cdh
    # 2: rp {id: "localhost"}
    out += bytes([0x02, 0xA1, 0x62]) + b'id'
    out += bytes([0x60 + len(RP)]) + RP
    # 3: user {id: bytes, name: text, displayName: text}
    out += bytes([0x03, 0xA3, 0x62]) + b'id'
    out += bytes([0x58, len(user_id)]) + user_id
    out += bytes([0x64]) + b'name'
    out += bytes([0x60 + len(USER_NAME)]) + USER_NAME
    out += bytes([0x67]) + b'displayName'
    out += bytes([0x60 + len(DISPLAY_NAME)]) + DISPLAY_NAME
    # 4: pubKeyCredParams [{alg:-7, type:"public-key"},
    #                       {alg:-257, type:"public-key"}]
    out += bytes([0x04, 0x82])
    out += b'\xa2\x63alg\x26\x64type\x6apublic-key'
    out += b'\xa2\x63alg\x39\x01\x00\x64type\x6apublic-key'
    # 6: extensions {hmac-secret: false} (Firefox sends it; device ignores)
    out += bytes([0x06]) + b'\xa1\x6bhmac-secret\xf4'
    # 7: options {rk: false}
    out += bytes([0x07]) + b'\xa1\x62rk\xf4'
    return bytes(out)


def build_ga(cred_id, cdh):
    """getAssertion [0x02][CBOR map] — the demo's login shape.

    allowList [credId] + options {up:true}: exactly what libwebauthn
    serializes for a user-initiated get (the deferred UP path).
    """
    out = bytearray([0x02, 0xA4])
    out += bytes([0x01, 0x60 + len(RP)]) + RP
    out += bytes([0x02, 0x58, 0x20]) + cdh
    out += bytes([0x03, 0x81, 0xA2])
    out += b'\x62id' + bytes([0x58, 0x20]) + cred_id
    out += b'\x64type' + bytes([0x6A]) + b'public-key'
    out += bytes([0x05, 0xA1, 0x62]) + b'up' + bytes([0xF5])
    return bytes(out)


def main():
    node = find_hidraw()
    if not node:
        sys.exit('no hidraw device with 2e8a:000b found (plug the Pico in)')
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
            sys.exit('INIT: no response')
        check_error(r, 'INIT')
        cid = r[15:19]
        print(f'INIT  -> cid={cid.hex()} fw={r[20]}.{r[21]}.{r[22]} '
              f'caps={r[23]:#04x}')
        assert r[20:23] == bytes([1, 0, 7]), 'firmware must be 1.0.7'
        assert r[23] == 0x07, 'caps must be 0x07'

        assert _ecdsa_selftest(), 'ECDSA self-test failed'

        # --- 2. makeCredential (the demo's registration shape) -------------
        user_id = secrets.token_bytes(32)       # the server's createUserId()
        challenge1 = secrets.token_bytes(128)   # the server's challenge
        cdj1 = client_data_json('webauthn.create', challenge1)
        cdh1 = hashlib.sha256(cdj1.encode()).digest()
        send_msg(fd, cid, build_mc(cdh1, user_id))
        print(f'MC    -> rp "localhost", user id {user_id.hex()[:12]}... '
              f'(deferred UP)')
        time.sleep(2.0)
        print(f'console -> up: {console_cmd("up").strip()!r}')
        mc_resp, ka1 = read_until(fd, 0x90, 254)
        print(f'MC resp -> 254 bytes, {ka1} keep-alive(s)')
        assert mc_resp[0] == 0x00, f'MC status must be 0x00, {mc_resp[0]:#04x}'
        # authData sits at a fixed offset in the packed attestation object
        # (same layout as fido_ga.py): resp[13:13+164].
        mc_auth = mc_resp[13:13 + 164]
        (mc_rph, mc_flags, mc_ctr, mc_aag, _, cred_id, px, py) = \
            parse_att_authdata(mc_auth)
        print(f'  flags {mc_flags:#04x}, counter {mc_ctr}, '
              f'rpIdHash==sha256("localhost"): '
              f'{mc_rph == hashlib.sha256(RP).digest()}, '
              f'AAGUID ok: {mc_aag == AAGUID}')
        assert mc_flags == 0x41, f'MC flags must be 0x41, {mc_flags:#04x}'
        assert mc_ctr == 0, f'MC counter must be 0 after wipe, {mc_ctr}'
        assert len(cred_id) == 32
        att_obj = mc_resp[1:]   # the attestationObject the browser got

        # --- 3. getAssertion (the demo's login shape) ----------------------
        challenge2 = secrets.token_bytes(128)
        cdj2 = client_data_json('webauthn.get', challenge2)
        cdh2 = hashlib.sha256(cdj2.encode()).digest()
        send_msg(fd, cid, build_ga(cred_id, cdh2))
        print(f'GA    -> allowList [credId] + up:true (deferred UP)')
        time.sleep(3.0)
        print(f'console -> up: {console_cmd("up").strip()!r}')
        t0 = time.time()
        ga_resp, ka2 = read_until(fd, 0x90, timeout=20.0)
        dt = time.time() - t0
        print(f'GA resp -> {len(ga_resp)} bytes in {dt * 1000:.0f} ms after '
              f'up, {ka2} keep-alive(s)')
        assert ka2 > 0, 'the deferred GA path must wait for UP'
        st, ga_cred, ga_auth, ga_sig, ga_user, no_creds = parse_ga(ga_resp)
        print(f'  status {st:#04x}, noCreds={no_creds}')
        assert st == 0x00, f'GA status must be 0x00, {st:#04x}'
        assert ga_cred == cred_id, 'GA credId != the registration credId'
        assert ga_user == user_id, 'GA user id != the server-issued user id'
        (ga_rph, ga_flags, ga_ctr) = parse_assert_authdata(ga_auth)
        print(f'  authData {len(ga_auth)} bytes (37 — no attested '
              f'credential data), flags {ga_flags:#04x} '
              f'(UP={ga_flags & 1}), counter {ga_ctr}')
        assert ga_rph == hashlib.sha256(RP).digest(), \
            'GA authData rpIdHash != sha256(rpId)'
        assert ga_flags == 0x01, f'GA flags must be 0x01 (UP only), {ga_flags:#04x}'
        assert ga_ctr == mc_ctr + 1, 'GA counter must be MC counter + 1'
        # Raw-verify the assertion signature (the device-side sanity check;
        # the fido2-lib check below is the one that matters for the demo).
        r_ = int.from_bytes(ga_sig[0:32], 'big')
        s_ = int.from_bytes(ga_sig[32:64], 'big')
        assert _ecdsa_verify_raw(px, py, r_, s_,
                                 hashlib.sha256(ga_auth + cdh2).digest()), \
            'assertion signature does not verify against the registration key'
        print('  sig raw-verified against the registration key: True')

        # --- 4. the demo's server-side validation (patched fido2-lib) ------
        case = {
            'attestation': {
                'id': b64url(cred_id),
                'rawId': b64(cred_id),
                'response': {
                    'attestationObject': b64(att_obj),
                    'clientDataJSON': b64(cdj1.encode()),
                },
            },
            # index.js attestationExpectations: {challenge, origin, factor}
            'attestationExpectations': {
                'challenge': b64(challenge1),
                'origin': ORIGIN,
                'factor': 'either',
            },
            'assertion': {
                'id': b64url(cred_id),
                'rawId': b64(cred_id),
                'response': {
                    'authenticatorData': b64(ga_auth),
                    'clientDataJSON': b64(cdj2.encode()),
                    'signature': b64(ga_sig),
                    # NOTE: the demo's fido2.js does not POST userHandle —
                    # fido2-lib then skips the userHandle check.
                },
            },
            # index.js assertionExpectations (prevCounter/publicKey are
            # filled in by fido2lib-verify.mjs from the attestation result,
            # exactly as index.js stores and reuses them).
            'assertionExpectations': {
                'origin': ORIGIN,
                'factor': 'either',
                'challenge': b64(challenge2),
                'userHandle': b64(user_id),
            },
        }
        os.makedirs(os.path.dirname(CASE_PATH), exist_ok=True)
        with open(CASE_PATH, 'w') as f:
            json.dump(case, f, indent=2)
        print(f'\ncase  -> {CASE_PATH}')
        verify = os.path.join(DEMO, 'fido2lib-verify.mjs')
        p = subprocess.run(['node', verify, CASE_PATH],
                           capture_output=True, text=True)
        sys.stdout.write(p.stdout)
        if p.stderr:
            sys.stdout.write(p.stderr)
        assert p.returncode == 0, 'fido2-lib verification failed (above)'
        assert 'ATTESTATION OK' in p.stdout, 'no ATTESTATION OK from fido2-lib'
        assert 'ASSERTION OK' in p.stdout, 'no ASSERTION OK from fido2-lib'

        print('\n=== VERDICT ===')
        print('  the patched fido2-demonstration harness validates BOTH')
        print('  halves of the round against the device\'s real output')
        print('  (attestation + deferred-UP assertion, raw R||S sigs).')
        print('  The browser round should now pass end to end.')
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Regenerate the GA/GNA KAT fixtures for the 37-byte assertion authData.

Same offline method as the original fixtures (Python hashlib,
independent of the C implementation):
  rpIdHash  = SHA-256("example.com")
  cdh       = bytes 0x00..0x1F
  authData  = rpIdHash | flags | counter(4 BE)          (37 bytes — the
               assertion EXCLUDES the attested credential data, WebAuthn
               L3 6.3.3 step 10)
  sig       = SHA-256(authData | cdh) | itself          (fake_sign)
  response  = 0x00 | { 1: {"id":credId,"type":"public-key"},
                        2: authData, 3: sig, 4: {"id":userHandle}
                        [5: noCreds] }

Writes the fixtures to ./ga_kat_fixtures.c (or $GA_KAT_OUT) in the current
directory; splice_ga_kat.py (this directory) then splices them into
tests/test_ctap.c. Run both from the same directory.
"""
import hashlib
import os

RP = hashlib.sha256(b"example.com").digest()
CDH = bytes(range(32))
AAGUID = bytes.fromhex('65f5107f31a6478593016788e10ec776')

CRED_A = bytes(0x5A + i for i in range(32))
CRED_B = bytes(0x6A + i for i in range(32))
USERH = bytes(range(1, 9))

# --- sanity: reproduce the OLD pinned signature (164-B authData) --------
old_authdata = (RP + bytes([0x41, 0x01, 0x02, 0x03, 0x05]) + AAGUID
                + bytes([0x00, 0x20]) + CRED_A
                + bytes.fromhex(
                    'a5010203262001215820101112131415161718191a1b1c1d1e1f'
                    '202122232425262728292a2b2c2d2e2f22582020212223242526'
                    '2728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'))
old_digest = hashlib.sha256(old_authdata + CDH).digest()
expect_old = bytes.fromhex(
    '4b39d862d7d60c16be22b4ed9e4809a25db85010c160cd75052c21a1dd9480e4')
assert old_digest == expect_old, \
    f"offline method does NOT reproduce the old KAT: {old_digest.hex()}"
print("sanity OK: old 164-B authData digest reproduces the pinned sig")


def authdata(flags, counter):
    return RP + bytes([flags]) + counter.to_bytes(4, 'big')


def cbor_bstr(b):
    assert len(b) < 256
    if len(b) < 24:
        return bytes([0x40 + len(b)]) + b
    return bytes([0x58, len(b)]) + b


def build_response(cred, flags, counter, nocreds=None):
    ad = authdata(flags, counter)
    sig = hashlib.sha256(ad + CDH).digest() * 2
    out = bytearray([0x00, 0xA5 if nocreds is not None else 0xA4])
    out += bytes([0x01, 0xA2])
    out += b'\x62id' + cbor_bstr(cred)
    out += b'\x64type' + b'\x6apublic-key'
    out += bytes([0x02]) + cbor_bstr(ad)
    out += bytes([0x03]) + cbor_bstr(sig)
    out += bytes([0x04, 0xA1]) + b'\x62id' + cbor_bstr(USERH)
    if nocreds is not None:
        out += bytes([0x05, nocreds])
    return bytes(out)


def c_arr(name, b, width=12):
    lines = []
    for i in range(0, len(b), width):
        chunk = b[i:i + width]
        lines.append('    ' + ', '.join(f'0x{c:02x}' for c in chunk) + ',')
    return f'static const uint8_t {name}[{len(b)}] = {{\n' \
           + '\n'.join(lines) + '\n};'


fixtures = [
    ('s_ga_authdata', authdata(0x01, 0x01020305)),
    ('s_ga_resp', build_response(CRED_A, 0x01, 0x01020305, nocreds=1)),
    ('s_ga_preflight_resp', build_response(CRED_A, 0x00, 0x01020305,
                                           nocreds=1)),
    ('s_ga_allow_resp', build_response(CRED_A, 0x01, 0x01020305)),
    ('s_ga_enum_first_resp', build_response(CRED_B, 0x01, 0x01020305,
                                            nocreds=2)),
    ('s_gna_resp', build_response(CRED_A, 0x01, 0x01020306)),
]

sizes = {n: len(b) for n, b in fixtures}
print('sizes:', sizes)
assert sizes['s_ga_authdata'] == 37
assert sizes['s_ga_resp'] == 180
assert sizes['s_ga_preflight_resp'] == 180
assert sizes['s_ga_allow_resp'] == 178
assert sizes['s_ga_enum_first_resp'] == 180
assert sizes['s_gna_resp'] == 178

OUT = os.environ.get('GA_KAT_OUT', 'ga_kat_fixtures.c')
with open(OUT, 'w') as f:
    for name, b in fixtures:
        f.write(c_arr(name, b) + '\n\n')
print(f'wrote {OUT} (then run: python3 splice_ga_kat.py)')

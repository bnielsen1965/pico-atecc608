#!/usr/bin/env python3
"""Splice the new 37-byte-authData GA/GNA KAT fixtures into tests/test_ctap.c.

Reads ./ga_kat_fixtures.c (or $GA_KAT_FIXTURES) from the current directory —
the output of gen_ga_kat.py — and replaces the GET_ASSERTION fixture block in
tests/test_ctap.c (located relative to this script, so it works from any
checkout). Run after gen_ga_kat.py, from the same directory.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# tools/ -> fido2/ -> example/ -> repo root
ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
PATH = os.path.join(ROOT, 'tests', 'test_ctap.c')
FIX = os.environ.get('GA_KAT_FIXTURES', 'ga_kat_fixtures.c')

src = open(PATH).read()
fix = open(FIX).read()

start_marker = ('// --- GET_ASSERTION '
                '---------------------------------------------------------------')
i = src.index(start_marker)

# end: the '};' closing s_gna_resp
j = src.index('static const uint8_t s_gna_resp[')
k = src.index('};', j) + len('};')

fix_lines = fix.rstrip('\n').split('\n')
arrays = {}
cur = None
for line in fix_lines:
    m = re.match(r'static const uint8_t (s_\w+)\[\d+\] = \{$', line)
    if m:
        cur = m.group(1)
        arrays[cur] = [line]
    elif cur is not None:
        arrays[cur].append(line)
assert set(arrays) == {'s_ga_authdata', 's_ga_resp', 's_ga_preflight_resp',
                       's_ga_allow_resp', 's_ga_enum_first_resp', 's_gna_resp'}, \
    f"unexpected fixture arrays: {sorted(arrays)}"

comments = {
    's_ga_authdata': (
        '// The canonical 37-byte assertion authData: flags 0x01 (UP),\n'
        '// counter 0x01020305 (the first increment).\n'),
    's_ga_resp': (
        '// Resident enumeration of ONE credential: flags 0x01 (UP),\n'
        '// counter 0x01020305 (the first increment),\n'
        '// numberOfCredentials = 1.\n'),
    's_ga_preflight_resp': (
        '// "up": false (preflight): the flags carry no bits (0x00),\n'
        '// served synchronously with no presence wait.\n'),
    's_ga_allow_resp': (
        '// allowList assertion: 4-entry map (no numberOfCredentials).\n'),
    's_ga_enum_first_resp': (
        '// Two-credential enumeration, FIRST response: the newer\n'
        '// credential (reverse slot order), numberOfCredentials = 2.\n'),
    's_gna_resp': (
        '// get_next_assertion: the older credential, counter\n'
        '// 0x01020306 (the second increment), no numberOfCredentials.\n'),
}

order = ['s_ga_authdata', 's_ga_resp', 's_ga_preflight_resp',
         's_ga_allow_resp', 's_ga_enum_first_resp', 's_gna_resp']

parts = [start_marker,
         '//',
         '// KAT fixtures (computed OFFLINE — Python hashlib — independently of',
         '// the C implementation; the same method as the makeCredential KATs):',
         '//   rpIdHash  = SHA-256("example.com")',
         '//   counter   = 0x01020304 + N (N assertions in the test; the',
         '//               increment happens BEFORE the authData is built)',
         '//   authData  = rpIdHash | flags | counter(4 BE)  (37 bytes — the',
         '//               assertion EXCLUDES the attested credential data:',
         '//               WebAuthn L3 §6.3.3 step 10; no AT bit, no AAGUID/',
         '//               credId/COSE)',
         '//   sig       = SHA-256(authData ‖ clientDataHash) ‖ itself',
         '//   response  = 0x00 | { 1: {"id": credId, "type": "public-key"},',
         '//                          2: authData, 3: sig, 4: {"id": userHandle}',
         '//                          [5: numberOfCredentials] }',
         '//               (INTEGER top-level keys, TEXT keys in the nested',
         "//               maps — Firefox's deserializer rejects unknown fields,",
         '//               so exactly these fields and no others)',
         'static uint8_t s_cred_a[32];   // 0x5A+i — the "older" credential',
         'static uint8_t s_cred_b[32];   // 0x6A+i — the "newer" credential',
         'static uint8_t s_cred_c[32];   // 0x7A+i — a third credential (3-cred tests)',
         '']
for name in order:
    parts.append(comments[name])
    parts.extend(arrays[name])
    parts.append('')
new_block = '\n'.join(parts).rstrip('\n') + '\n'

src = src[:i] + new_block + src[k:]
open(PATH, 'w').write(src)
print(f"spliced {len(new_block)} chars into {PATH} "
      f"(replaced {k - i} old chars)")

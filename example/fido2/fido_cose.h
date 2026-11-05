// fido_cose.h
//
// COSE_Key encoding for this device's one algorithm (ES256 on P-256):
// the ATECC608's 64-byte X‖Y public key becomes the canonical CBOR
// COSE map a MakeCredential response carries in its
// attestedCredentialData (WebAuthn §6.2). Pure C on the CTAP CBOR
// codec; host-tested with a byte-pinned KAT in tests/test_ctap.c.

#pragma once

#include <stdint.h>

// The encoded length of the ES256 COSE_Key: 1 (map(5)) + 2 + 2 + 2 +
// (1 + 2 + 32) + (1 + 2 + 32) = 77.
#define FIDO_COSE_ES256_LEN 77

// Encode pub = X(32) ‖ Y(32) as the CTAP2 COSE_Key
//
//   { 1: 2, 3: -7, -1: 1, -2: X, -3: Y }
//
// (kty EC2, alg ES256, crv P-256 = 1) in the CTAP 2.3 spec's label
// layout (getPublicKey: 1=kty, 3=alg, -1=crv, -2=x, -3=y) — the form
// Yubico's python-fido2 and Firefox's authenticator-rs both require.
// Keys are in ascending encoded-byte order (0x01, 0x03, 0x20, 0x21,
// 0x22 — the RFC 8949 canonical sort). Returns the encoded length
// (FIDO_COSE_ES256_LEN), or 0 when out is too small.
uint32_t fido_cose_encode_es256(const uint8_t pub[64], uint8_t *out,
                                uint32_t out_max);

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

// The maximum encoded length of a P-256 ECDSA signature as an ASN.1 DER
// Ecdsa-Sig-Value: SEQUENCE(2) + two INTEGERs, each at most 2 (tag +
// length) + 1 (sign pad) + 32 (value) = 72.
#define FIDO_ECDSA_DER_SIG_MAX 72

// Encode a raw P-256 ECDSA signature (R(32) || S(32), the ATECC608 Sign
// output) as the ASN.1 DER Ecdsa-Sig-Value that WebAuthn L3 section 6.5.5
// MANDATES for ES256 assertion and packed-attestation signatures (RFC 3279
// section 2.2.3):
//
//   SEQUENCE { r INTEGER, s INTEGER }
//
// Each INTEGER is minimally encoded (leading zero octets stripped, a 0x00
// sign-pad octet added when the high bit is set) — byte-identical to what
// OpenSSL and the browsers emit. (The raw R||S form is the COSE_Sign
// encoding, RFC 9052 — NOT what a WebAuthn "sig" value carries.) Returns
// the encoded length (10..FIDO_ECDSA_DER_SIG_MAX), or 0 when out is too
// small.
uint32_t fido_ecdsa_der_encode(const uint8_t raw[64], uint8_t *out,
                               uint32_t out_max);

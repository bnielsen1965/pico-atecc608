// fido_cose.c — COSE_Key for ES256 (see fido_cose.h).

#include "fido_cose.h"

#include "fido_cbor.h"

#include <stddef.h>
#include <string.h>

uint32_t fido_cose_encode_es256(const uint8_t pub[64], uint8_t *out,
                                uint32_t out_max)
{
    if ((NULL == pub) || (NULL == out) || (out_max < FIDO_COSE_ES256_LEN)) {
        return 0;
    }

    fido_cbor_enc_t e;
    fido_cbor_enc_init(&e, out, out_max);
    // FIVE pairs follow — the CTAP2 COSE_Key layout for EC2/ES256, as
    // mandated by the CTAP 2.3 spec (getPublicKey: "1 (kty)=2, 3 (alg),
    // -1 (crv)=1, -2 (x), -3 (y)"), used by Yubico's python-fido2, and
    // required by Firefox's authenticator-rs COSEKeyVisitor (which reads
    // 3 as alg, -1 as curve/i64, -2 as x, -3 as y). This is NOT the bare
    // RFC 8152 §13.1 label set (kty=1, crv=3, x=-1, y=-2): that 4-entry
    // form is what Firefox rejects with "invalid type: byte array,
    // expected i64" (it reads our -1/x byte string where it wants the
    // curve int). (An earlier "5-entry was rejected by Chromium" note
    // referred to a MALFORMED 5-entry key with crv/x/y on the wrong
    // labels, not this one.)
    fido_cbor_enc_map(&e, 5);
    // Keys in ascending encoded-byte order (RFC 8949 canonical form):
    // 1 (0x01), 3 (0x03), -1 (0x20), -2 (0x21), -3 (0x22).
    fido_cbor_enc_uint(&e, 1);      // kty
    fido_cbor_enc_uint(&e, 2);      //   EC2
    fido_cbor_enc_uint(&e, 3);      // alg
    fido_cbor_enc_negint(&e, -7);   //   ES256
    fido_cbor_enc_negint(&e, -1);   // crv
    fido_cbor_enc_uint(&e, 1);      //   P-256
    fido_cbor_enc_negint(&e, -2);   // x
    fido_cbor_enc_bytes(&e, pub, 32);
    fido_cbor_enc_negint(&e, -3);   // y
    fido_cbor_enc_bytes(&e, &pub[32], 32);

    if (e.overflow) {
        return 0;   // cannot happen (out_max was checked); be safe
    }
    return e.len;   // FIDO_COSE_ES256_LEN
}

// --- ECDSA signature DER encoding (WebAuthn L3 section 6.5.5) ------------

// Minimal DER INTEGER source for one 32-byte big-endian field: strip
// leading zero octets (DER requires the shortest encoding of the value)
// and report whether a 0x00 sign-pad octet is needed (high bit set).
static const uint8_t *der_field(const uint8_t v[32], uint32_t *len,
                                uint8_t *pad)
{
    uint32_t i = 0;
    while (i < 31 && 0x00 == v[i]) {
        i++;
    }
    *len = 32 - i;
    *pad = (v[i] & 0x80) ? 1 : 0;
    return &v[i];
}

uint32_t fido_ecdsa_der_encode(const uint8_t raw[64], uint8_t *out,
                               uint32_t out_max)
{
    if ((NULL == raw) || (NULL == out)) {
        return 0;
    }
    uint32_t len_r, len_s;
    uint8_t pad_r, pad_s;
    const uint8_t *r = der_field(raw, &len_r, &pad_r);
    const uint8_t *s = der_field(&raw[32], &len_s, &pad_s);
    const uint32_t body = (2 + pad_r + len_r) + (2 + pad_s + len_s);
    if (out_max < 2 + body) {
        return 0;
    }

    uint32_t o = 0;
    out[o++] = 0x30;                       // SEQUENCE
    out[o++] = (uint8_t)body;              // short form: body <= 70
    out[o++] = 0x02;                       // INTEGER (r)
    out[o++] = (uint8_t)(pad_r + len_r);
    if (pad_r) {
        out[o++] = 0x00;
    }
    memcpy(&out[o], r, len_r);
    o += len_r;
    out[o++] = 0x02;                       // INTEGER (s)
    out[o++] = (uint8_t)(pad_s + len_s);
    if (pad_s) {
        out[o++] = 0x00;
    }
    memcpy(&out[o], s, len_s);
    o += len_s;
    return o;
}

// fido_cose.c — COSE_Key for ES256 (see fido_cose.h).

#include "fido_cose.h"

#include "fido_cbor.h"

#include <stddef.h>

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
    // curve int) — round C16. (The C6 "5-entry was rejected by Chromium"
    // note referred to a MALFORMED 5-entry key with crv/x/y on the wrong
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

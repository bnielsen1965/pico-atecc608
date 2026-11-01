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
    fido_cbor_enc_map(&e, 5);
    // Keys in ascending byte order (canonical form).
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

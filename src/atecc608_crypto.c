// ATECC608 crypto pass-through API (Phase 5): KDF (PRF mode) over the
// real cryptoauthlib atcab_* / atcah_* layers. HAL-agnostic — see
// include/atecc608/atecc608_crypto.h for the contract.

#include "atecc608/atecc608_crypto.h"

#include <string.h>

#include "atecc608_int.h"
#include "atca_host.h"      // atcah_io_decrypt (I/O-protection decrypt)
#include "cryptoauthlib.h"

atecc608_status_t atecc608_kdf_prf(uint8_t slot,
                                   const uint8_t nonce[ATECC608_KDF_NONCE_LEN],
                                   const uint8_t *msg, uint8_t msg_len,
                                   const uint8_t io_key[ATECC608_DATA_SLOT_LEN],
                                   uint8_t out[ATECC608_KDF_OUT_LEN])
{
    static const uint8_t zero_nonce[ATECC608_KDF_NONCE_LEN] = { 0 };
    // Zeroed: the library fills it ONLY if the response carried a nonce
    // (enforced I/O protection); it must start all-zero for that to be a
    // reliable marker.
    uint8_t resp_nonce[ATECC608_KDF_NONCE_LEN] = { 0 };
    ATCA_STATUS atca;

    if ((out == NULL) || (msg == NULL)
        || (0u == msg_len) || (msg_len > ATECC608_KDF_MSG_MAX_LEN)
        || (slot > ATECC608_MAX_DATA_SLOT)) {
        return ATECC608_ERR_BAD_PARAM;
    }

    // Load the TempKey nonce (pass-through: the buffer's CONTENTS become
    // the chip's TempKey — bench-verified 2026-10-25). NULL = a fixed
    // zero nonce, for a deterministic output.
    atca = atcab_nonce((NULL != nonce) ? nonce : zero_nonce);
    if (ATCA_SUCCESS != atca) {
        return atecc608_map_status(atca);
    }

    // PRF, 32-byte source key, 32-byte target, no AEAD processing; the
    // message length lives in the top byte of the details word. Source =
    // the slot (low byte of key_id; the high byte is the target slot,
    // unused for target=output).
    const uint32_t details = KDF_DETAILS_PRF_KEY_LEN_32
                           | KDF_DETAILS_PRF_TARGET_LEN_32
                           | KDF_DETAILS_PRF_AEAD_MODE0
                           | ((uint32_t)msg_len << 24);
    atca = atcab_kdf(KDF_MODE_ALG_PRF | KDF_MODE_SOURCE_SLOT | KDF_MODE_TARGET_OUTPUT,
                     (uint16_t)slot, details, msg, out, resp_nonce);
    if (ATCA_SUCCESS != atca) {
        return atecc608_map_status(atca);
    }

    // Enforced I/O protection (kdf_prot=1, bench-verified 2026-10-25):
    // the response carries a 32-byte nonce and out is ENCRYPTED. The
    // library leaves resp_nonce untouched when the response carried no
    // nonce, so any non-zero byte marks the encrypted case (a random
    // 32-byte nonce is all-zero with probability 2^-256).
    bool encrypted = false;
    for (size_t i = 0; i < sizeof(resp_nonce); i++) {
        encrypted = encrypted || (0u != resp_nonce[i]);
    }
    if (encrypted) {
        if (io_key == NULL) {
            return ATECC608_ERR_BAD_PARAM; // cannot decrypt without the I/O key
        }
        atca_io_decrypt_in_out_t dec = {
            .io_key    = io_key,
            .out_nonce = resp_nonce,
            .data      = out,
            .data_size = ATECC608_KDF_OUT_LEN,
        };
        atca = atcah_io_decrypt(&dec);
        if (ATCA_SUCCESS != atca) {
            return atecc608_map_status(atca);
        }
    }
    return ATECC608_OK;
}

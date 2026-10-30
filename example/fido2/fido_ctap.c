// fido_ctap.c — implementation of the CTAP2 command dispatch (see
// fido_ctap.h for the wire format and the phase scope).

#include "fido_ctap.h"

#include <string.h>

#include "fido_cbor.h"

// The claimed AAGUID — fixed per firmware (recorded in PLAN.md; a
// demo value, not FIDO-registered). 16 bytes, as transmitted in
// MakeCredential AuthenticatorData.
static const uint8_t s_aaguid[16] = {
    0x65, 0xF5, 0x10, 0x7F, 0x31, 0xA6, 0x47, 0x85,
    0x93, 0x01, 0x67, 0x88, 0xE1, 0x0E, 0xC7, 0x76,
};

void fido_ctap_ctx_init(fido_ctap_ctx_t *ctx)
{
    memcpy(ctx->aaguid, s_aaguid, sizeof s_aaguid);
}

// GET_INFO (CTAP v2.0 §5.4 / v2.1 §6.2). The response map carries the
// members a real client needs to treat this as a resident-capable
// CTAP2.0 authenticator; keys are numeric and emitted in ascending
// order (the CTAP2 canonical form requires sorted map keys). The
// member set is the v2.1 key space (a superset of v2.0's — v2.0
// clients MUST ignore keys they do not understand, CTAP v2.0 §6),
// which is what modern clients (Chromium, libfido2) parse:
//
//   1  versions        ["FIDO_2_0"]            (required)
//   3  aaguid          <16 bytes>              (required)
//   4  options         {"rk": true, "up": true}
//   5  maxMsgSize      256
//   7  maxCredentialCountInList  128
//   8  maxCredentialIdLength     64
//   9  transports      ["usb"]
//   10 algorithms      [-7]  (COSE_ES256)
//   14 firmwareVersion 1
//   20 remainingDiscoverableCredentials  4
//
// No "clientPin"/"uv" option: this device has no PIN and no built-in
// biometrics — user presence is the touch of the board (Phase 4
// wires the button).
static void handle_get_info(const fido_ctap_ctx_t *ctx,
                            uint8_t *resp, uint32_t resp_max,
                            uint32_t *resp_len)
{
    fido_cbor_enc_t e;

    *resp_len = 1;
    if (resp_max < 2) {
        resp[0] = FIDO_CTAP2_ERR_OTHER;   // cannot fit even a stub
        return;
    }

    fido_cbor_enc_init(&e, resp + 1, resp_max - 1);
    fido_cbor_enc_map(&e, 10);

    fido_cbor_enc_uint(&e, 1);            // versions
    fido_cbor_enc_array(&e, 1);
    fido_cbor_enc_text(&e, "FIDO_2_0");

    fido_cbor_enc_uint(&e, 3);            // aaguid
    fido_cbor_enc_bytes(&e, ctx->aaguid, sizeof ctx->aaguid);

    fido_cbor_enc_uint(&e, 4);            // options
    fido_cbor_enc_map(&e, 2);
    fido_cbor_enc_text(&e, "rk");
    fido_cbor_enc_bool(&e, true);
    fido_cbor_enc_text(&e, "up");
    fido_cbor_enc_bool(&e, true);

    fido_cbor_enc_uint(&e, 5);            // maxMsgSize
    fido_cbor_enc_uint(&e, FIDO_CTAP_MAX_MSG_SIZE);

    fido_cbor_enc_uint(&e, 7);            // maxCredentialCountInList
    fido_cbor_enc_uint(&e, FIDO_CTAP_MAX_CRED_LIST);

    fido_cbor_enc_uint(&e, 8);            // maxCredentialIdLength
    fido_cbor_enc_uint(&e, FIDO_CTAP_MAX_CRED_ID_LEN);

    fido_cbor_enc_uint(&e, 9);            // transports
    fido_cbor_enc_array(&e, 1);
    fido_cbor_enc_text(&e, "usb");

    fido_cbor_enc_uint(&e, 10);           // algorithms
    fido_cbor_enc_array(&e, 1);
    fido_cbor_enc_negint(&e, FIDO_CTAP_ALG_ES256);

    fido_cbor_enc_uint(&e, 14);           // firmwareVersion
    fido_cbor_enc_uint(&e, FIDO_CTAP_FW_VERSION);

    fido_cbor_enc_uint(&e, 20);           // remainingDiscoverableCredentials
    fido_cbor_enc_uint(&e, FIDO_CTAP_MAX_CREDENTIALS);

    if (e.overflow) {
        // Cannot happen with the transport's 7609-byte response
        // buffer (the map is 63 bytes); a hostile resp_max degrades
        // to a status-only answer instead of a partial CBOR.
        resp[0] = FIDO_CTAP2_ERR_OTHER;
        return;
    }

    resp[0]   = FIDO_CTAP2_OK;
    *resp_len = 1u + e.len;
}

void fido_ctap_dispatch(void *vctx, const uint8_t *req, uint32_t req_len,
                        uint8_t *resp, uint32_t resp_max, uint32_t *resp_len)
{
    const fido_ctap_ctx_t *ctx = vctx;

    *resp_len = 1;
    if (resp_max < 1) {
        *resp_len = 0;
        return;
    }

    // --- message validation ----------------------------------------------
    // The first byte is the command itself (CTAP v2.1 §8.1); the
    // CTAPHID framing mandates BCNT >= 1 for a CBOR message
    // (§11.2.9.1.2), so an empty payload is not a command.
    if (req_len < 1) {
        resp[0] = FIDO_CTAP2_ERR_INVALID_LENGTH;
        return;
    }

    // --- dispatch -----------------------------------------------------------
    switch (req[0]) {
    case FIDO_CTAP_INS_GET_INFO: {
        // GET_INFO takes no parameters (CTAP v2.1 §6.4); a conforming
        // client sends the bare command byte. Stray parameter bytes, when
        // present, must form exactly one well-formed CBOR item and are
        // then ignored (unknown content is ignored, CTAP v2.1 §8);
        // malformed CBOR earns CTAP2_ERR_INVALID_CBOR.
        if (req_len > 1) {
            fido_cbor_dec_t d;
            fido_cbor_dec_init(&d, req + 1, req_len - 1);
            if (!fido_cbor_dec_skip(&d) || d.p != d.end) {
                resp[0] = FIDO_CTAP2_ERR_INVALID_CBOR;
                return;
            }
        }
        handle_get_info(ctx, resp, resp_max, resp_len);
        return;
    }
    default:
        // CTAP v2.1 §8.1: "If an authenticator receives a command code
        // it does not implement, it MUST return
        // CTAP1_ERR_INVALID_COMMAND." (Unimplemented today:
        // MAKE_CREDENTIAL, GET_ASSERTION, RESET — later phases.)
        resp[0] = FIDO_CTAP2_ERR_INVALID_COMMAND;
        return;
    }
}

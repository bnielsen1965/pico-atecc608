// Host unit tests for the fido2 example's CTAP2 command dispatch
// (example/fido2/fido_ctap.c + fido_cbor.c) — pure C, no Pico.
//
// Covers: the message framing (an empty payload is
// CTAP1_ERR_INVALID_LENGTH; stray parameter bytes must be one
// well-formed CBOR item or the answer is CTAP2_ERR_INVALID_CBOR),
// GET_INFO (the full response map decoded field by field with the codec
// itself, plus a hand-computed 64-byte KAT; stray parameter maps are
// ignored), and the unimplemented-command answer
// (CTAP1_ERR_INVALID_COMMAND, the spec's MUST for a command code the
// device does not implement).

#include <stdio.h>
#include <string.h>

#include "fido_cbor.h"
#include "fido_ctap.h"

// --- tiny harness ---------------------------------------------------------------

static int s_checks = 0;
static int s_failures = 0;

#define CHECK(cond) do { \
    s_checks++; \
    if (!(cond)) { \
        s_failures++; \
        printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
    } \
} while (0)

// The AAGUID the firmware claims (must stay in sync with fido_ctap.c).
static const uint8_t s_aaguid[16] = {
    0x65, 0xF5, 0x10, 0x7F, 0x31, 0xA6, 0x47, 0x85,
    0x93, 0x01, 0x67, 0x88, 0xE1, 0x0E, 0xC7, 0x76,
};

// Build a CTAP2 message: command byte + optional parameters.
// Returns the total length.
static uint32_t msg(uint8_t *buf, uint8_t ins,
                    const uint8_t *params, uint16_t plen)
{
    buf[0] = ins;
    if (plen > 0) {
        memcpy(&buf[1], params, plen);
    }
    return (uint32_t)(1 + plen);
}

static fido_ctap_ctx_t s_ctx;

// Dispatch into a big-enough buffer and return the response.
static uint32_t dispatch(const uint8_t *req, uint32_t req_len,
                         uint8_t *resp, uint32_t resp_max)
{
    uint32_t resp_len = 0;
    fido_ctap_dispatch(&s_ctx, req, req_len, resp, resp_max, &resp_len);
    return resp_len;
}

// --- GET_INFO ------------------------------------------------------------------

// The whole response map, field by field, decoded with the codec itself
// (independent of the encoder's layout choices).
static void t_get_info_fields(void)
{
    uint8_t req[64];
    uint8_t resp[512];
    uint32_t len = dispatch(req, msg(req, FIDO_CTAP_INS_GET_INFO, NULL, 0),
                            resp, sizeof resp);

    fido_cbor_dec_t d;
    fido_cbor_type_t t;
    uint64_t         u;
    const uint8_t   *data = NULL;
    uint32_t         dlen = 0;

    CHECK(resp[0] == FIDO_CTAP2_OK);

    fido_cbor_dec_init(&d, resp + 1, (uint32_t)(len - 1));
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_MAP && u == 10);

    // 1: versions ["FIDO_2_0"]
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 1);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_ARRAY && u == 1);
    CHECK(fido_cbor_dec_item(&d, &t, &u, &data, &dlen));
    CHECK(t == FIDO_CBOR_TEXT && dlen == 8 && 0 == memcmp(data, "FIDO_2_0", 8));

    // 3: aaguid
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 3);
    CHECK(fido_cbor_dec_item(&d, &t, &u, &data, &dlen));
    CHECK(t == FIDO_CBOR_BYTES && dlen == 16);
    CHECK(0 == memcmp(data, s_aaguid, 16));

    // 4: options {"rk": true, "up": true}
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 4);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_MAP && u == 2);
    CHECK(fido_cbor_dec_item(&d, &t, &u, &data, &dlen));
    CHECK(t == FIDO_CBOR_TEXT && dlen == 2 && 0 == memcmp(data, "rk", 2));
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_BOOL && u == 1);
    CHECK(fido_cbor_dec_item(&d, &t, &u, &data, &dlen));
    CHECK(t == FIDO_CBOR_TEXT && dlen == 2 && 0 == memcmp(data, "up", 2));
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_BOOL && u == 1);

    // 5: maxMsgSize 256
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 5);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 256);

    // 7: maxCredentialCountInList 128
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 7);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 128);

    // 8: maxCredentialIdLength 64
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 8);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 64);

    // 9: transports ["usb"]
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 9);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_ARRAY && u == 1);
    CHECK(fido_cbor_dec_item(&d, &t, &u, &data, &dlen));
    CHECK(t == FIDO_CBOR_TEXT && dlen == 3 && 0 == memcmp(data, "usb", 3));

    // 10: algorithms [-7] (COSE_ES256)
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 10);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_ARRAY && u == 1);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_NEGINT && u == 6);   // -(6 + 1) = -7

    // 14: firmwareVersion 1
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 14);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 1);

    // 20: remainingDiscoverableCredentials 4
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 20);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 4);

    // exactly consumed — no trailing bytes
    CHECK(d.p == d.end);
}

// The full response pinned byte for byte (hand-computed, cross-checked
// against an independent CBOR walk). Status + 63 payload bytes.
static void t_get_info_bytes(void)
{
    uint8_t req[64];
    uint8_t resp[512];
    uint32_t len = dispatch(req, msg(req, FIDO_CTAP_INS_GET_INFO, NULL, 0),
                            resp, sizeof resp);

    static const uint8_t expected[] = {
        0x00,                         // status OK
        0xAA,                         // map(10)
        0x01,                         //   1: versions
            0x81, 0x68,
            0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30,   // "FIDO_2_0"
        0x03,                         //   3: aaguid
            0x50,
            0x65, 0xF5, 0x10, 0x7F, 0x31, 0xA6, 0x47, 0x85,
            0x93, 0x01, 0x67, 0x88, 0xE1, 0x0E, 0xC7, 0x76,
        0x04,                         //   4: options
            0xA2,
            0x62, 0x72, 0x6B, 0xF5,   //   "rk": true
            0x62, 0x75, 0x70, 0xF5,   //   "up": true
        0x05,                         //   5: maxMsgSize
            0x19, 0x01, 0x00,         //   256
        0x07,                         //   7: maxCredentialCountInList
            0x18, 0x80,               //   128
        0x08,                         //   8: maxCredentialIdLength
            0x18, 0x40,               //   64
        0x09,                         //   9: transports
            0x81, 0x63, 0x75, 0x73, 0x62,   // ["usb"]
        0x0A,                         //   10: algorithms
            0x81, 0x26,               //   [-7]
        0x0E,                         //   14: firmwareVersion
            0x01,
        0x14,                         //   20: remainingDiscoverableCredentials
            0x04,
    };

    CHECK(len == sizeof expected);
    CHECK(0 == memcmp(resp, expected, sizeof expected));
}

// GET_INFO takes no inputs — stray parameter maps are ignored (unknown
// content is ignored, CTAP v2.1 §8), so an empty or non-empty map gets
// the same answer as the bare command byte.
static void t_get_info_with_params(void)
{
    uint8_t req[64];
    uint8_t ref[64];
    uint8_t resp[512];
    uint8_t refresp[512];
    const uint8_t empty_map[1] = { 0xA0 };
    const uint8_t junk_map[3]  = { 0xA1, 0x01, 0x01 };
    uint32_t rlen = dispatch(ref,
                             msg(ref, FIDO_CTAP_INS_GET_INFO, NULL, 0),
                             refresp, sizeof refresp);

    uint32_t len = dispatch(req,
                            msg(req, FIDO_CTAP_INS_GET_INFO, empty_map, 1),
                            resp, sizeof resp);
    CHECK(resp[0] == FIDO_CTAP2_OK);
    CHECK(len == rlen);
    CHECK(0 == memcmp(resp, refresp, len));

    len = dispatch(req,
                   msg(req, FIDO_CTAP_INS_GET_INFO, junk_map, 3),
                   resp, sizeof resp);
    CHECK(resp[0] == FIDO_CTAP2_OK);
    CHECK(len == rlen);
    CHECK(0 == memcmp(resp, refresp, len));
}

// A response buffer too small for the map degrades to a status-only
// answer (never a partial CBOR).
static void t_get_info_tiny_buffer(void)
{
    uint8_t req[64];
    uint8_t resp[2];
    uint32_t len = dispatch(req, msg(req, FIDO_CTAP_INS_GET_INFO, NULL, 0),
                            resp, sizeof resp);
    CHECK(resp[0] == FIDO_CTAP2_ERR_OTHER);
    CHECK(len == 1);
}

// --- header validation ------------------------------------------------------------

static void t_header(void)
{
    uint8_t req[64];
    uint8_t resp[8];
    uint32_t len;

    {   // no command byte at all
        len = dispatch(NULL, 0, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_INVALID_LENGTH && len == 1);
    }
    {   // a bare command byte is well-formed
        uint8_t m[1] = { FIDO_CTAP_INS_GET_INFO };
        uint8_t big[128];   // the response map needs 64 bytes
        len = dispatch(m, sizeof m, big, sizeof big);
        CHECK(big[0] == FIDO_CTAP2_OK && len > 1);
    }
    {   // parameters must be ONE complete CBOR item: a valid map plus a
        // stray byte is not
        const uint8_t p[3] = { 0xA0, 0x01, 0x02 };
        uint32_t n = msg(req, FIDO_CTAP_INS_GET_INFO, p, sizeof p);
        len = dispatch(req, n, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_INVALID_CBOR && len == 1);
    }
    {   // truncated CBOR: an array header promising two elements, one present
        const uint8_t p[2] = { 0x82, 0x01 };
        uint32_t n = msg(req, FIDO_CTAP_INS_GET_INFO, p, sizeof p);
        len = dispatch(req, n, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_INVALID_CBOR && len == 1);
    }
    {   // indefinite length (0x9F) is not CTAP2 canonical CBOR
        const uint8_t p[1] = { 0x9F };
        uint32_t n = msg(req, FIDO_CTAP_INS_GET_INFO, p, sizeof p);
        len = dispatch(req, n, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_INVALID_CBOR && len == 1);
    }
    {   // zero response capacity: nothing to write
        uint32_t n = msg(req, FIDO_CTAP_INS_GET_INFO, NULL, 0);
        uint32_t rlen = 99;
        fido_ctap_dispatch(&s_ctx, req, n, NULL, 0, &rlen);
        CHECK(rlen == 0);
    }
}

// --- unimplemented commands ------------------------------------------------------------

static void t_unimplemented(void)
{
    uint8_t req[128];
    uint8_t resp[8];
    uint32_t len;
    const uint8_t dummy[2] = { 0x01, 0x02 };

    // Every command code the device does not implement yet — including
    // the reserved gaps and the vendor range — answers
    // CTAP1_ERR_INVALID_COMMAND (the spec's MUST).
    const uint8_t inss[] = {
        0x00,   // not a command code at all
        FIDO_CTAP_INS_MAKE_CREDENTIAL,      // Phase 3
        FIDO_CTAP_INS_GET_ASSERTION,        // Phase 3
        0x03,   // (reserved gap)
        FIDO_CTAP_INS_CLIENT_PIN,           // never — no PIN
        FIDO_CTAP_INS_RESET,                // Phase 5
        0x05,   // (reserved gap)
        FIDO_CTAP_INS_GET_NEXT_ASSERTION,   // never — 2.0 only
        0x40,   // vendor range start
        0xBF,   // vendor range end
        0xC0,   // past the vendor range (reserved)
        0xFF,
    };
    for (size_t i = 0; i < sizeof inss; i++) {
        uint32_t n = msg(req, inss[i], dummy, 2);
        len = dispatch(req, n, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_INVALID_COMMAND);
        CHECK(len == 1);
    }
}

int main(void)
{
    fido_ctap_ctx_init(&s_ctx);
    // The context must carry the AAGUID the KATs expect.
    CHECK(0 == memcmp(s_ctx.aaguid, s_aaguid, 16));

    t_get_info_fields();
    t_get_info_bytes();
    t_get_info_with_params();
    t_get_info_tiny_buffer();
    t_header();
    t_unimplemented();

    printf("%s: %d checks, %d failures\n",
           (s_failures == 0) ? "PASS" : "FAIL", s_checks, s_failures);
    return (s_failures == 0) ? 0 : 1;
}

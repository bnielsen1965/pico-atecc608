// Host unit tests for the fido2 example's CTAP2 command dispatch
// (example/fido2/fido_ctap.c + fido_cbor.c + fido_cred.c + fido_cose.c
// + fido_sha256.c) — pure C, no Pico.
//
// Covers: the message framing (an empty payload is
// CTAP1_ERR_INVALID_LENGTH; stray parameter bytes must be one
// well-formed CBOR item or the answer is CTAP2_ERR_INVALID_CBOR),
// GET_INFO (the full response map decoded field by field with the codec
// itself, plus a hand-computed 85-byte KAT; stray parameter maps are
// ignored), MakeCredential (the full request parse and the CTAP2 error
// table, the error-ordering rules, the deferred user-presence state
// machine — cancel, timeout, a stale touch, the second-while-pending
// guard, the umount abort — the excludeList hit, the rk overwrite, the
// store-full and key-backend failure paths, and the response: the
// v2.1 layout byte-pinned against a deterministic key-backend fake),
// and the unimplemented-command answer
// (CTAP1_ERR_INVALID_COMMAND, the spec's MUST for a command code the
// device does not implement).

#include <stdio.h>
#include <string.h>

#include "fido_cbor.h"
#include "fido_cose.h"
#include "fido_ctap.h"
#include "fido_sha256.h"

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

    // 10: algorithms [{"alg": -7, "type": "public-key"}] (COSE_ES256)
    // — WebAuthn PublicKeyCredentialParameters objects (Chromium's
    // GetInfo parser rejects a bare integer entry).
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 10);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_ARRAY && u == 1);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_MAP && u == 2);
    CHECK(fido_cbor_dec_item(&d, &t, &u, &data, &dlen));
    CHECK(t == FIDO_CBOR_TEXT && dlen == 3 && 0 == memcmp(data, "alg", 3));
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_NEGINT && u == 6);   // -(6 + 1) = -7
    CHECK(fido_cbor_dec_item(&d, &t, &u, &data, &dlen));
    CHECK(t == FIDO_CBOR_TEXT && dlen == 4 && 0 == memcmp(data, "type", 4));
    CHECK(fido_cbor_dec_item(&d, &t, &u, &data, &dlen));
    CHECK(t == FIDO_CBOR_TEXT && dlen == 10
          && 0 == memcmp(data, "public-key", 10));

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
// against an independent CBOR walk). Status + 84 payload bytes.
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
            0x81,                     //   array(1)
            0xA2,                     //   map(2)  (PublicKeyCredentialParameters)
            0x63, 0x61, 0x6C, 0x67,   //   "alg"
            0x26,                     //   -7 (COSE_ES256)
            0x64, 0x74, 0x79, 0x70, 0x65,   // "type"
            0x6A,                     //   "public-key"
            0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,
            0x2D, 0x6B, 0x65, 0x79,
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
        FIDO_CTAP_INS_GET_ASSERTION,        // Phase 4
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

// --- MAKE_CREDENTIAL ---------------------------------------------------------------

// The deterministic key backend: genkey -> X = 0x10+i / Y = 0x20+i
// (i = byte index); sign -> digest ‖ digest; rand -> 0xA5+i; the counter
// and the clock are test-steered globals. Every KAT below follows from
// these.
static uint32_t s_now_ms   = 1000000;
static uint32_t s_counter  = 0x01020304;
static int s_fail_genkey = 0;
static int s_fail_sign   = 0;
static int s_fail_rand   = 0;
static int s_genkey_calls = 0;
static int s_sign_calls   = 0;
static uint8_t s_last_keyslot  = 0;
static uint8_t s_last_signslot = 0;

static int fake_genkey(void *dev, uint8_t slot, uint8_t pub[64])
{
    (void)dev;
    s_genkey_calls++;
    s_last_keyslot = slot;
    if (s_fail_genkey) {
        return -1;
    }
    for (int i = 0; i < 32; i++) {
        pub[i]       = (uint8_t)(0x10 + i);
        pub[32 + i]  = (uint8_t)(0x20 + i);
    }
    return 0;
}

static int fake_sign(void *dev, uint8_t slot, const uint8_t digest[32],
                     uint8_t sig[64])
{
    (void)dev;
    s_sign_calls++;
    s_last_signslot = slot;
    if (s_fail_sign) {
        return -1;
    }
    memcpy(sig, digest, 32);
    memcpy(sig + 32, digest, 32);
    return 0;
}

static uint32_t fake_counter(void *dev)
{
    (void)dev;
    return s_counter;
}

static int fake_rand(void *dev, uint8_t *buf, uint32_t len)
{
    (void)dev;
    if (s_fail_rand) {
        return -1;
    }
    for (uint32_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(0xA5 + i);
    }
    return 0;
}

static uint32_t fake_clock(void *dev)
{
    (void)dev;
    return s_now_ms;
}

// The request fixtures (the KAT inputs).
static const char MC_RP[] = "example.com";
static uint8_t s_cdh[32];       // 0..31
static uint8_t s_user_id[8];    // 1..8
static uint8_t s_excl_id[32];   // the excludeList entry (0xE0+i)

// Wire the deterministic key backend into a freshly initialized context
// (the credential store is RAM-only — no persistence hooks).
static void mc_install(fido_ctap_ctx_t *ctx)
{
    fido_ctap_ctx_init(ctx);
    ctx->keys.genkey   = fake_genkey;
    ctx->keys.sign     = fake_sign;
    ctx->keys.counter  = fake_counter;
    ctx->keys.rand     = fake_rand;
    ctx->keys.clock    = fake_clock;
    ctx->keys.dev      = NULL;
}

// Reset the backend's failure flags and call counters.
static void mc_reset(void)
{
    s_fail_genkey  = 0;
    s_fail_sign    = 0;
    s_fail_rand    = 0;
    s_genkey_calls = 0;
    s_sign_calls   = 0;
    s_now_ms       = 1000000;
    s_counter      = 0x01020304;
}

// The request builder: a makeCredential map with any field omitted,
// mistyped or oversize (all-zero opts = the canonical valid request).
// Returns the total length, command byte first.
typedef struct {
    int no_cdh;      // omit clientDataHash (key 1)
    int cdh_len;     // its length (0 = the valid 32)
    int cdh_text;    // encode it as a text string (a type error)
    int no_rp;       // omit rp (key 2)
    int rp_no_id;    // the rp map without its "id"
    int rp_id_len;   // length of rp.id (0 = the valid "example.com")
    int no_user;     // omit user (key 3)
    int user_no_id, user_no_name, user_no_disp;
    int user_id_len; // (0 = the valid 8 bytes)
    int name_len;    // (0 = the valid "user")
    int no_pkcp;     // omit pubKeyCredParams (key 4)
    int alg;         // (0 = the supported -7)
    int pkcp_type;   // 0 = no "type"; 1 = "public-key"; 2 = "opaque"
    int opt_up;      // options "up": true (not a CTAP2.0 option)
    int opt_uv;      // options "uv": true
    int opt_rk;      // options "rk": true
    int pin;         // pinUvAuthToken (key 6)
    int ent;         // enterpriseAttestation (key 10) = 1
    int excl;        // an excludeList (key 5) with one entry: s_excl_id
    int trailing;    // one stray byte after the map
} mc_opts_t;

static uint32_t build_mc(uint8_t *buf, uint32_t cap, const mc_opts_t *o)
{
    const int nkeys = (!o->no_cdh) + (!o->no_rp) + (!o->no_user) +
                      (!o->no_pkcp) + o->excl + o->pin +
                      (o->opt_up || o->opt_uv || o->opt_rk) + o->ent;

    buf[0] = FIDO_CTAP_INS_MAKE_CREDENTIAL;
    fido_cbor_enc_t e;
    fido_cbor_enc_init(&e, buf + 1, cap - 1);
    fido_cbor_enc_map(&e, (uint32_t)nkeys);

    if (!o->no_cdh) {
        fido_cbor_enc_uint(&e, 1);
        if (o->cdh_text) {
            fido_cbor_enc_text(&e,
                "abcdefghijklmnopqrstuvwxyz0123456789");
        } else {
            fido_cbor_enc_bytes(&e, s_cdh,
                                (uint32_t)(o->cdh_len ? o->cdh_len : 32));
        }
    }
    if (!o->no_rp) {
        fido_cbor_enc_uint(&e, 2);
        fido_cbor_enc_map(&e, 1);
        if (o->rp_no_id) {
            fido_cbor_enc_text(&e, "name");
            fido_cbor_enc_text(&e, "Example");
        } else {
            fido_cbor_enc_text(&e, "id");
            char big[300];
            const char *id = MC_RP;
            if (o->rp_id_len && o->rp_id_len != (int)strlen(MC_RP)) {
                memset(big, 'x', (size_t)o->rp_id_len);
                big[o->rp_id_len] = '\0';
                id = big;
            }
            fido_cbor_enc_text(&e, id);
        }
    }
    if (!o->no_user) {
        fido_cbor_enc_uint(&e, 3);
        const int un = 3 - o->user_no_id - o->user_no_name - o->user_no_disp;
        fido_cbor_enc_map(&e, (uint32_t)un);
        if (!o->user_no_id) {
            fido_cbor_enc_text(&e, "id");
            uint8_t uid[70];
            const int ulen = o->user_id_len ? o->user_id_len : 8;
            for (int i = 0; i < ulen; i++) {
                uid[i] = (uint8_t)(i + 1);
            }
            fido_cbor_enc_bytes(&e, uid, (uint32_t)ulen);
        }
        if (!o->user_no_name) {
            fido_cbor_enc_text(&e, "name");
            char nm[64];
            if (!o->name_len) {
                fido_cbor_enc_text(&e, "user");
            } else {
                memset(nm, 'n', (size_t)o->name_len);
                nm[o->name_len] = '\0';
                fido_cbor_enc_text(&e, nm);
            }
        }
        if (!o->user_no_disp) {
            fido_cbor_enc_text(&e, "displayName");
            fido_cbor_enc_text(&e, "User");
        }
    }
    if (!o->no_pkcp) {
        fido_cbor_enc_uint(&e, 4);
        fido_cbor_enc_array(&e, 1);
        fido_cbor_enc_map(&e, 1u + (o->pkcp_type != 0));
        fido_cbor_enc_text(&e, "alg");
        fido_cbor_enc_negint(&e, (int64_t)(o->alg ? o->alg : -7));
        if (o->pkcp_type != 0) {
            fido_cbor_enc_text(&e, "type");
            fido_cbor_enc_text(&e, (o->pkcp_type == 1) ? "public-key"
                                                       : "opaque");
        }
    }
    if (o->excl) {
        fido_cbor_enc_uint(&e, 5);
        fido_cbor_enc_array(&e, 1);
        fido_cbor_enc_map(&e, 1);
        fido_cbor_enc_text(&e, "id");
        fido_cbor_enc_bytes(&e, s_excl_id, sizeof s_excl_id);
    }
    if (o->pin) {
        fido_cbor_enc_uint(&e, 6);
        fido_cbor_enc_bytes(&e, s_cdh, 16);
    }
    if (o->opt_up || o->opt_uv || o->opt_rk) {
        fido_cbor_enc_uint(&e, 7);
        fido_cbor_enc_map(&e, (uint32_t)(o->opt_up + o->opt_uv + o->opt_rk));
        if (o->opt_rk) {
            fido_cbor_enc_text(&e, "rk");
            fido_cbor_enc_bool(&e, true);
        }
        if (o->opt_uv) {
            fido_cbor_enc_text(&e, "uv");
            fido_cbor_enc_bool(&e, true);
        }
        if (o->opt_up) {
            fido_cbor_enc_text(&e, "up");
            fido_cbor_enc_bool(&e, true);
        }
    }
    if (o->ent) {
        fido_cbor_enc_uint(&e, 0x0A);
        fido_cbor_enc_uint(&e, 1);
    }
    CHECK(!e.overflow);
    if (o->trailing) {
        buf[1 + e.len] = 0x00;
        return 2 + e.len;
    }
    return 1 + e.len;
}

// Dispatch into a caller context and return the response length (0 =
// deferred).
static uint32_t mc_dispatch(fido_ctap_ctx_t *ctx, const uint8_t *req,
                            uint32_t req_len, uint8_t *resp,
                            uint32_t resp_max)
{
    uint32_t resp_len = 0;
    fido_ctap_dispatch(ctx, req, req_len, resp, resp_max, &resp_len);
    return resp_len;
}

// Install one credential for (MC_RP, s_user_id) at store index idx,
// chip slot idx+3, with the given 32-byte credential ID.
static void seed_credential(fido_ctap_ctx_t *ctx, int idx,
                            const uint8_t cred_id[32])
{
    fido_cred_record_t rec;
    memset(&rec, 0, sizeof rec);
    rec.slot = (uint8_t)(idx + FIDO_CRED_SLOT_MIN);
    fido_sha256((const uint8_t *)MC_RP, strlen(MC_RP), rec.rp_id_hash);
    rec.cred_id_len = 32;
    memcpy(rec.cred_id, cred_id, 32);
    rec.user_handle_len = sizeof s_user_id;
    memcpy(rec.user_handle, s_user_id, sizeof s_user_id);
    memcpy(rec.name, "user", 4);
    rec.name_len = 4;
    memcpy(rec.display_name, "User", 4);
    rec.display_name_len = 4;
    CHECK(0 == fido_cred_store_insert(&ctx->creds, idx, &rec));
}

// The byte-pinned KATs — computed OFFLINE (Python hashlib) from the
// fixtures above, independently of the C implementation:
//   rpIdHash  = SHA-256("example.com")
//   authData  = rpIdHash | 0x41 | 01 02 03 04 (counter) | aaguid |
//               00 20 | credId (0xA5+i) | COSE_Key (77)
//   sig       = SHA-256(authData ‖ clientDataHash) ‖ itself
//   response  = 0x00 | {1: "packed", 2: authData, 3: {1: -7, 2: sig}}
static const uint8_t s_mc_authdata[164] = {
    0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11,
    0x80, 0x34, 0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB,
    0x13, 0xD2, 0x12, 0x55, 0x86, 0xCE, 0x19, 0x47, 0x41, 0x01, 0x02, 0x03,
    0x04, 0x65, 0xF5, 0x10, 0x7F, 0x31, 0xA6, 0x47, 0x85, 0x93, 0x01, 0x67,
    0x88, 0xE1, 0x0E, 0xC7, 0x76, 0x00, 0x20, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9,
    0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
    0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1,
    0xC2, 0xC3, 0xC4, 0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58,
    0x20, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
    0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
    0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x22, 0x58, 0x20,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
    0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
};

// The full 248-byte response (status + the v2.1 response map).
static const uint8_t s_mc_resp[248] = {
    0x00, 0xA3, 0x01, 0x66, 0x70, 0x61, 0x63, 0x6B, 0x65, 0x64, 0x02, 0x58,
    0xA4, 0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C,
    0x11, 0x80, 0x34, 0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30,
    0xAB, 0x13, 0xD2, 0x12, 0x55, 0x86, 0xCE, 0x19, 0x47, 0x41, 0x01, 0x02,
    0x03, 0x04, 0x65, 0xF5, 0x10, 0x7F, 0x31, 0xA6, 0x47, 0x85, 0x93, 0x01,
    0x67, 0x88, 0xE1, 0x0E, 0xC7, 0x76, 0x00, 0x20, 0xA5, 0xA6, 0xA7, 0xA8,
    0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4,
    0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
    0xC1, 0xC2, 0xC3, 0xC4, 0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21,
    0x58, 0x20, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
    0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x22, 0x58,
    0x20, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
    0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x03, 0xA2, 0x01,
    0x26, 0x02, 0x58, 0x40, 0x78, 0x82, 0xB2, 0xB7, 0x37, 0x22, 0x21, 0x14,
    0x43, 0xA2, 0x0B, 0x9F, 0x91, 0x63, 0x4F, 0xA2, 0x7C, 0x93, 0x74, 0xE4,
    0x55, 0xCD, 0x49, 0x83, 0x6D, 0xEE, 0xFE, 0xF9, 0x0A, 0x77, 0x71, 0xA3,
    0x78, 0x82, 0xB2, 0xB7, 0x37, 0x22, 0x21, 0x14, 0x43, 0xA2, 0x0B, 0x9F,
    0x91, 0x63, 0x4F, 0xA2, 0x7C, 0x93, 0x74, 0xE4, 0x55, 0xCD, 0x49, 0x83,
    0x6D, 0xEE, 0xFE, 0xF9, 0x0A, 0x77, 0x71, 0xA3,
};

// The COSE_Key encoding (77 bytes), pinned on its own.
static void t_mc_cose(void)
{
    uint8_t pub[64];
    for (int i = 0; i < 32; i++) {
        pub[i]       = (uint8_t)(0x10 + i);
        pub[32 + i]  = (uint8_t)(0x20 + i);
    }
    uint8_t out[FIDO_COSE_ES256_LEN];
    CHECK(FIDO_COSE_ES256_LEN == fido_cose_encode_es256(pub, out,
                                                        sizeof out));
    CHECK(0 == memcmp(out, &s_mc_authdata[164 - FIDO_COSE_ES256_LEN],
                      FIDO_COSE_ES256_LEN));   // the same 77 bytes the
                                                // KAT embeds in authData
    // A too-small buffer is refused outright, never truncated.
    CHECK(0 == fido_cose_encode_es256(pub, out, sizeof out - 1));
    CHECK(0 == fido_cose_encode_es256(pub, NULL, sizeof out));
}

// The parse error table: each malformed request is answered at once
// (len 1, no deferred transaction).
static void t_mc_error_table(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t req[512];
    uint8_t resp[8];

    struct { const char *what; mc_opts_t o; uint8_t want; } cases[] = {
        { "missing clientDataHash",     { .no_cdh = 1 },
          FIDO_CTAP2_ERR_MISSING_PARAMETER },
        { "clientDataHash wrong type",  { .cdh_text = 1 },
          FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE },
        { "clientDataHash 31 bytes",    { .cdh_len = 31 },
          FIDO_CTAP2_ERR_LIMIT_EXCEEDED },
        { "clientDataHash 33 bytes",    { .cdh_len = 33 },
          FIDO_CTAP2_ERR_LIMIT_EXCEEDED },
        { "missing rp",                 { .no_rp = 1 },
          FIDO_CTAP2_ERR_MISSING_PARAMETER },
        { "rp without id",              { .rp_no_id = 1 },
          FIDO_CTAP2_ERR_MISSING_PARAMETER },
        { "rp.id 256 bytes",            { .rp_id_len = 256 },
          FIDO_CTAP2_ERR_LIMIT_EXCEEDED },
        { "missing user",               { .no_user = 1 },
          FIDO_CTAP2_ERR_MISSING_PARAMETER },
        { "user.id 65 bytes",           { .user_id_len = 65 },
          FIDO_CTAP2_ERR_LIMIT_EXCEEDED },
        { "user.name 33 bytes",         { .name_len = 33 },
          FIDO_CTAP2_ERR_LIMIT_EXCEEDED },
        { "missing pubKeyCredParams",   { .no_pkcp = 1 },
          FIDO_CTAP2_ERR_MISSING_PARAMETER },
        { "unsupported algorithm",      { .alg = -257 },
          FIDO_CTAP2_ERR_UNSUPPORTED_ALGORITHM },
        { "alg -7, type opaque",        { .pkcp_type = 2 },
          FIDO_CTAP2_ERR_UNSUPPORTED_ALGORITHM },
        { "options up",                 { .opt_up = 1 },
          FIDO_CTAP2_ERR_INVALID_OPTION },
        { "options uv",                 { .opt_uv = 1 },
          FIDO_CTAP2_ERR_UNSUPPORTED_OPTION },
        { "pinUvAuthToken",             { .pin = 1 },
          FIDO_CTAP2_ERR_PIN_AUTH_INVALID },
        { "enterpriseAttestation",      { .ent = 1 },
          FIDO_CTAP2_ERR_UNSUPPORTED_OPTION },
        { "trailing bytes",             { .trailing = 1 },
          FIDO_CTAP2_ERR_INVALID_CBOR },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        const uint32_t n = build_mc(req, sizeof req, &cases[i].o);
        const uint32_t len =
            mc_dispatch(&ctx, req, n, resp, sizeof resp);
        CHECK(resp[0] == cases[i].want);
        CHECK(len == 1);
        CHECK(!fido_ctap_pending(&ctx));
    }

    {   // the top level must be a map (a plain integer is not)
        const uint8_t notmap[2] = { FIDO_CTAP_INS_MAKE_CREDENTIAL, 0x01 };
        const uint32_t len =
            mc_dispatch(&ctx, notmap, sizeof notmap, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE && len == 1);
    }
    {   // no parameters at all: clientDataHash is missing
        const uint8_t bare[1] = { FIDO_CTAP_INS_MAKE_CREDENTIAL };
        const uint32_t len =
            mc_dispatch(&ctx, bare, sizeof bare, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_MISSING_PARAMETER && len == 1);
    }
}

// The v2.0 §5.1 error ordering: the excludeList hit is checked before
// the algorithm (a match with an unsupported alg defers to 0x19), and
// the algorithm is checked before the options (an unsupported alg with
// "up" earns 0x26, not 0x2C).
static void t_mc_error_order(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t req[512];
    uint8_t resp[8];
    uint32_t tlen = 0;

    // A stored credential the excludeList will match.
    seed_credential(&ctx, 0, s_excl_id);

    {   // excluded + unsupported alg -> deferred (0x19 after the touch)
        mc_opts_t o = { .alg = -257, .excl = 1 };
        const uint32_t n = build_mc(req, sizeof req, &o);
        CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
        CHECK(fido_ctap_pending(&ctx));
        ctx.user_present = true;
        CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
        CHECK(resp[0] == FIDO_CTAP2_ERR_CREDENTIAL_EXCLUDED && tlen == 1);
    }

    {   // unsupported alg + "up" -> 0x26 (the alg step comes first)
        mc_install(&ctx);
        mc_reset();
        mc_opts_t o = { .alg = -257, .opt_up = 1 };
        const uint32_t n = build_mc(req, sizeof req, &o);
        const uint32_t len = mc_dispatch(&ctx, req, n, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_UNSUPPORTED_ALGORITHM && len == 1);
    }
}

// The happy path, end to end: the deferred parse, the presence wait,
// the completion — pinned against the offline-computed 248-byte
// response — and the resulting store state.
static void t_mc_happy(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_MC_RESP_MAX];
    const mc_opts_t o = {0};
    const uint32_t n = build_mc(req, sizeof req, &o);

    // A valid request is DEFERRED: no response, a pending transaction.
    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    CHECK(fido_ctap_pending(&ctx));

    // No touch yet: tick reports "still waiting" (resp_len 0).
    uint32_t tlen = 99;
    CHECK(0 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(tlen == 0);

    // The touch: the transaction completes with the full response.
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(!fido_ctap_pending(&ctx));
    CHECK(!ctx.user_present);        // the touch is consumed
    CHECK(tlen == sizeof s_mc_resp);
    CHECK(0 == memcmp(resp, s_mc_resp, sizeof s_mc_resp));

    // The key backend saw the right chip slot (store index 0 -> slot 3).
    CHECK(1 == s_genkey_calls && 3 == s_last_keyslot);
    CHECK(1 == s_sign_calls && 3 == s_last_signslot);

    // The credential is stored with the minted ID and the request data.
    CHECK(ctx.creds.present[0]);
    const fido_cred_record_t *r = &ctx.creds.rec[0];
    CHECK(r->slot == FIDO_CRED_SLOT_MIN);
    CHECK(r->cred_id_len == FIDO_MC_CRED_ID_LEN);
    for (int i = 0; i < FIDO_MC_CRED_ID_LEN; i++) {
        CHECK(r->cred_id[i] == (uint8_t)(0xA5 + i));
    }
    // The stored rpIdHash is the KAT's (authData begins with it).
    CHECK(0 == memcmp(r->rp_id_hash, s_mc_authdata, 32));
    CHECK(r->user_handle_len == sizeof s_user_id);
    CHECK(0 == memcmp(r->user_handle, s_user_id, sizeof s_user_id));
    CHECK(0 == memcmp(r->name, "user", 4));
    CHECK(0 == memcmp(r->display_name, "User", 4));
    // insert() computed a valid CRC over the stored record.
    CHECK(r->crc32 == fido_cred_crc32((const uint8_t *)r,
                                      FIDO_CRED_FILE_SIZE - 4));
}

// The lenient user sub-fields (bench round 1 fix): the
// fido2-demonstration harness sends user = {"name": …} — no user.id,
// no displayName (and pkcp entries WITH "type": "public-key"). The
// sub-fields are optional on this device; a missing user.id is
// synthesized as a 32-byte handle from the TRNG (the fake: 0xA5+i).
// The user handle never appears in the response, so with the same
// cdh/RP the 248-byte KAT is unchanged (s_mc_resp).
static void t_mc_lenient_user(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_MC_RESP_MAX];
    uint32_t tlen = 0;

    // Case 1: the harness shape — user with only "name", pkcp with
    // "type": "public-key". Deferred, then the full KAT response; the
    // stored handle is the synthesized one.
    {
        mc_opts_t o = { .user_no_id = 1, .user_no_disp = 1, .pkcp_type = 1 };
        const uint32_t n = build_mc(req, sizeof req, &o);
        CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
        CHECK(fido_ctap_pending(&ctx));
        ctx.user_present = true;
        CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
        CHECK(tlen == sizeof s_mc_resp);
        CHECK(0 == memcmp(resp, s_mc_resp, sizeof s_mc_resp));
        CHECK(ctx.creds.present[0]);
        const fido_cred_record_t *r = &ctx.creds.rec[0];
        CHECK(r->user_handle_len == FIDO_MC_CRED_ID_LEN);
        for (int i = 0; i < FIDO_MC_CRED_ID_LEN; i++) {
            CHECK(r->user_handle[i] == (uint8_t)(0xA5 + i));
        }
        CHECK(0 == memcmp(r->name, "user", 4));
        CHECK(r->name_len == 4);
        CHECK(r->display_name_len == 0);
    }

    // Case 2: user = {} (an empty map) — also accepted.
    {
        mc_opts_t o = { .user_no_id = 1, .user_no_name = 1, .user_no_disp = 1 };
        const uint32_t n = build_mc(req, sizeof req, &o);
        CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
        CHECK(fido_ctap_pending(&ctx));
        ctx.user_present = true;
        CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
        CHECK(tlen == sizeof s_mc_resp);
        CHECK(0 == memcmp(resp, s_mc_resp, sizeof s_mc_resp));
        CHECK(ctx.creds.present[1]);
        const fido_cred_record_t *r = &ctx.creds.rec[1];
        CHECK(r->user_handle_len == FIDO_MC_CRED_ID_LEN);
        CHECK(r->name_len == 0 && r->display_name_len == 0);
    }

    // Case 3: user with only "id" — the request handle is used as-is
    // (no synthesis), name/displayName stay empty.
    {
        mc_opts_t o = { .user_no_name = 1, .user_no_disp = 1 };
        const uint32_t n = build_mc(req, sizeof req, &o);
        CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
        CHECK(fido_ctap_pending(&ctx));
        ctx.user_present = true;
        CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
        CHECK(tlen == sizeof s_mc_resp);
        CHECK(ctx.creds.present[2]);
        const fido_cred_record_t *r = &ctx.creds.rec[2];
        CHECK(r->user_handle_len == sizeof s_user_id);
        CHECK(0 == memcmp(r->user_handle, s_user_id, sizeof s_user_id));
        CHECK(r->name_len == 0 && r->display_name_len == 0);
    }
}

// The rk option: a (rp, user) credential is overwritten IN PLACE — the
// same slot, the same store footprint, a fresh credential ID.
static void t_mc_rk_overwrite(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_MC_RESP_MAX];

    uint8_t old_id[32];
    for (int i = 0; i < 32; i++) {
        old_id[i] = (uint8_t)(0x10 + i);
    }
    seed_credential(&ctx, 0, old_id);

    mc_opts_t o = { .opt_rk = 1 };
    const uint32_t n = build_mc(req, sizeof req, &o);
    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    ctx.user_present = true;
    uint32_t tlen = 0;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_OK && tlen == sizeof s_mc_resp);

    // Overwritten in place: one record, still slot 3, a new credential
    // ID, and the rest of the store untouched.
    CHECK(ctx.creds.present[0]);
    CHECK(!ctx.creds.present[1]);
    CHECK(ctx.creds.rec[0].slot == FIDO_CRED_SLOT_MIN);
    CHECK(0 != memcmp(ctx.creds.rec[0].cred_id, old_id, 32));
    CHECK(ctx.creds.rec[0].cred_id[0] == 0xA5);
    CHECK(1 == s_genkey_calls && 3 == s_last_keyslot);
    // The store is not corrupted: allocation offers the next index.
    CHECK(1 == fido_cred_store_alloc(&ctx.creds));
}

// The excludeList: a hit is DEFERRED (the presence wait still happens,
// to behave like a U2F key) and answered CREDENTIAL_EXCLUDED after the
// touch; a miss is a normal registration.
static void t_mc_excluded(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_MC_RESP_MAX];
    uint32_t tlen = 0;

    // A stored credential whose ID the excludeList carries.
    seed_credential(&ctx, 1, s_excl_id);

    mc_opts_t o = { .excl = 1 };
    const uint32_t n = build_mc(req, sizeof req, &o);
    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    CHECK(fido_ctap_pending(&ctx));
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_ERR_CREDENTIAL_EXCLUDED && tlen == 1);
    CHECK(!fido_ctap_pending(&ctx));
    CHECK(0 == s_genkey_calls);       // no key was generated
    CHECK(!ctx.creds.present[0] && !ctx.creds.present[2]);

    // A non-matching excludeList: a normal registration.
    fido_ctap_ctx_init(&ctx);
    mc_install(&ctx);
    mc_reset();
    uint8_t other_id[32];
    for (int i = 0; i < 32; i++) {
        other_id[i] = (uint8_t)(0x10 + i);
    }
    seed_credential(&ctx, 0, other_id);
    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_OK);
    CHECK(ctx.creds.present[1]);      // the new credential, index 1
}

// The store is full (four records) and the request is not an rk
// overwrite: KEY_STORE_FULL after the touch.
static void t_mc_store_full(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_MC_RESP_MAX];
    uint32_t tlen = 0;

    for (int i = 0; i < FIDO_CRED_MAX; i++) {
        uint8_t id[32];
        for (int j = 0; j < 32; j++) {
            id[j] = (uint8_t)(0x10 * (i + 1) + j);
        }
        seed_credential(&ctx, i, id);
    }
    CHECK(-1 == fido_cred_store_alloc(&ctx.creds));

    const mc_opts_t o = {0};
    const uint32_t n = build_mc(req, sizeof req, &o);
    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_ERR_KEY_STORE_FULL && tlen == 1);
    CHECK(0 == s_genkey_calls);       // the slot check comes first
}

// The key backend failures: a rand failure is at PARSE time (the
// credential ID is minted there — no deferral); genkey and sign fail
// after the touch; a persistence failure (the store's save hook) leaves
// the store unchanged. All answer CTAP2_ERR_OTHER.
static int always_fail(void *priv, uint8_t slot,
                       const fido_cred_record_t *rec)
{
    (void)priv;
    (void)slot;
    (void)rec;
    return -1;
}

static void t_mc_backend_fail(void)
{
    fido_ctap_ctx_t ctx;
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_MC_RESP_MAX];
    uint32_t tlen = 0;
    const mc_opts_t o = {0};
    const uint32_t n = build_mc(req, sizeof req, &o);

    {   // rand fails BEFORE the presence wait
        mc_install(&ctx);
        mc_reset();
        s_fail_rand = 1;
        const uint32_t len = mc_dispatch(&ctx, req, n, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_OTHER && len == 1);
        CHECK(!fido_ctap_pending(&ctx));
    }
    {   // genkey fails after the touch
        mc_install(&ctx);
        mc_reset();
        s_fail_genkey = 1;
        CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
        ctx.user_present = true;
        CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
        CHECK(resp[0] == FIDO_CTAP2_ERR_OTHER && tlen == 1);
        CHECK(0 == s_sign_calls);     // the sign step was never reached
    }
    {   // sign fails after the touch
        mc_install(&ctx);
        mc_reset();
        s_fail_sign = 1;
        CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
        ctx.user_present = true;
        CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
        CHECK(resp[0] == FIDO_CTAP2_ERR_OTHER && tlen == 1);
    }
    {   // persistence fails: the store stays unchanged
        mc_install(&ctx);
        mc_reset();
        ctx.creds.save = always_fail;
        CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
        ctx.user_present = true;
        CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
        CHECK(resp[0] == FIDO_CTAP2_ERR_OTHER && tlen == 1);
        CHECK(0 == s_genkey_calls || 1 == s_genkey_calls);
        CHECK(!ctx.creds.present[0]); // persist-first: RAM untouched
        CHECK(1 == s_genkey_calls);   // the chip slot was (re)generable
    }
}

// The user-presence wait expires: USER_ACTION_TIMEOUT (>= 10 s per
// spec; 30 s here), and the timeout wins over a touch that arrives on
// the same tick.
static void t_mc_timeout(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_MC_RESP_MAX];
    uint32_t tlen = 99;
    const mc_opts_t o = {0};
    const uint32_t n = build_mc(req, sizeof req, &o);

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    // deadline = s_now_ms + FIDO_CTAP_UP_TIMEOUT_MS = 1030000
    s_now_ms = 1000000 + FIDO_CTAP_UP_TIMEOUT_MS - 1;
    CHECK(0 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(tlen == 0);
    s_now_ms = 1000000 + FIDO_CTAP_UP_TIMEOUT_MS;   // exactly the deadline
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_ERR_USER_ACTION_TIMEOUT && tlen == 1);
    CHECK(!fido_ctap_pending(&ctx));
    CHECK(!ctx.user_present);   // the (too-late) touch is cleared
}

// Without a clock hook the wait never times out.
static void t_mc_no_clock(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    ctx.keys.clock = NULL;
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_MC_RESP_MAX];
    uint32_t tlen = 99;
    const mc_opts_t o = {0};
    const uint32_t n = build_mc(req, sizeof req, &o);

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    s_now_ms += 10 * 60 * 1000;   // an hour passes
    CHECK(0 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_OK);
}

// A recorded CTAPHID_CANCEL finishes the transaction with
// KEEPALIVE_CANCEL — with or without a touch in flight — and clears the
// touch.
static void t_mc_cancel(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_MC_RESP_MAX];
    uint32_t tlen = 0;
    const mc_opts_t o = {0};
    const uint32_t n = build_mc(req, sizeof req, &o);

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    CHECK(1 == fido_ctap_tick(&ctx, true, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_ERR_KEEPALIVE_CANCEL && tlen == 1);
    CHECK(!fido_ctap_pending(&ctx));

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    ctx.user_present = true;      // a touch, then the cancel
    CHECK(1 == fido_ctap_tick(&ctx, true, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_ERR_KEEPALIVE_CANCEL && tlen == 1);
    CHECK(!ctx.user_present);
}

// A touch recorded BEFORE the request (a stale one) completes the
// transaction on the first tick — no second touch is needed.
static void t_mc_stale_up(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_MC_RESP_MAX];
    uint32_t tlen = 0;
    const mc_opts_t o = {0};
    const uint32_t n = build_mc(req, sizeof req, &o);

    ctx.user_present = true;      // stale
    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_OK && tlen == sizeof s_mc_resp);
    CHECK(!ctx.user_present);
}

// A second makeCredential while one waits: OPERATION_PENDING (the
// transport serializes, so this is defensive). fido_ctap_abort() drops
// the transaction without a response (the USB unmount path).
static void t_mc_pending_lifecycle(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t req[512];
    uint8_t resp[8];
    uint32_t tlen = 99;
    const mc_opts_t o = {0};
    const uint32_t n = build_mc(req, sizeof req, &o);

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    {
        const uint32_t len = mc_dispatch(&ctx, req, n, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_OPERATION_PENDING && len == 1);
    }
    fido_ctap_abort(&ctx);
    CHECK(!fido_ctap_pending(&ctx));
    CHECK(0 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(tlen == 0);

    // tick() on an idle context is a no-op with resp_len 0.
    fido_ctap_ctx_init(&ctx);
    CHECK(0 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(tlen == 0);
}

// A response buffer that cannot hold the map degrades to a status-only
// answer (never a partial CBOR).
static void t_mc_tiny_buffer(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t req[512];
    uint8_t resp[1];
    uint32_t tlen = 99;
    const mc_opts_t o = {0};
    const uint32_t n = build_mc(req, sizeof req, &o);

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_ERR_OTHER && tlen == 1);
    CHECK(!fido_ctap_pending(&ctx));
}

// --- context ---------------------------------------------------------------------

// The user-presence flag (Phase 3) is app-written, handler-consumed
// state: a fresh context must start with no touch pending, and re-init
// must clear a stale one.
static void t_ctx_init(void)
{
    fido_ctap_ctx_t ctx;

    fido_ctap_ctx_init(&ctx);
    CHECK(0 == memcmp(ctx.aaguid, s_aaguid, 16));
    CHECK(!ctx.user_present);

    ctx.user_present = true;
    fido_ctap_ctx_init(&ctx);
    CHECK(!ctx.user_present);
}

int main(void)
{
    fido_ctap_ctx_init(&s_ctx);
    // The context must carry the AAGUID the KATs expect.
    CHECK(0 == memcmp(s_ctx.aaguid, s_aaguid, 16));

    t_ctx_init();
    t_get_info_fields();
    t_get_info_bytes();
    t_get_info_with_params();
    t_get_info_tiny_buffer();
    t_header();
    t_unimplemented();

    // The MakeCredential fixtures (the KAT inputs).
    for (int i = 0; i < 32; i++) {
        s_cdh[i]     = (uint8_t)i;
        s_excl_id[i] = (uint8_t)(0xE0 + i);
    }
    for (int i = 0; i < 8; i++) {
        s_user_id[i] = (uint8_t)(i + 1);
    }

    t_mc_cose();
    t_mc_error_table();
    t_mc_error_order();
    t_mc_happy();
    t_mc_lenient_user();
    t_mc_rk_overwrite();
    t_mc_excluded();
    t_mc_store_full();
    t_mc_backend_fail();
    t_mc_timeout();
    t_mc_no_clock();
    t_mc_cancel();
    t_mc_stale_up();
    t_mc_pending_lifecycle();
    t_mc_tiny_buffer();

    printf("%s: %d checks, %d failures\n",
           (s_failures == 0) ? "PASS" : "FAIL", s_checks, s_failures);
    return (s_failures == 0) ? 0 : 1;
}

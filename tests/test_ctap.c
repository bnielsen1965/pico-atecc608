// Host unit tests for the fido2 example's CTAP2 command dispatch
// (example/fido2/fido_ctap.c + fido_cbor.c + fido_cred.c + fido_cose.c
// + fido_sha256.c) — pure C, no Pico.
//
// Covers: the message framing (an empty payload is
// CTAP1_ERR_INVALID_LENGTH; stray parameter bytes must be one
// well-formed CBOR item or the answer is CTAP2_ERR_INVALID_CBOR),
// GET_INFO (the full response — 0x00 status byte + map — decoded field
// by field with the codec itself, plus a hand-computed 81-byte KAT;
// stray parameter maps are ignored), MakeCredential (the full request parse and the CTAP2 error
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

    // A CTAPHID_CBOR success response is [0x00 status][CBOR map]
    // (CTAP 2.3 PS §11.2.9.1.2).
    CHECK(resp[0] == FIDO_CTAP2_OK);
    fido_cbor_dec_init(&d, resp + 1, (uint32_t)len - 1);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_MAP && u == 8);

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
    // — WebAuthn PublicKeyCredentialParameters objects (Firefox's and
    // Chromium's GetInfo parsers reject a bare integer entry).
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

    // exactly consumed — no trailing bytes
    CHECK(d.p == d.end);
}

// The full response pinned byte for byte (hand-computed, cross-checked
// against an independent CBOR walk). 81 payload bytes — the 0x00 CTAP
// status byte (CTAP 2.3 PS §11.2.9.1.2) followed by the 80-byte CBOR
// map with the CTAP 2.1+ GET_INFO key numbers (see handle_get_info for
// the key-numbering rationale — this is the table Firefox's
// AuthenticatorInfo deserializer and every shipping device parse).
static void t_get_info_bytes(void)
{
    uint8_t req[64];
    uint8_t resp[512];
    uint32_t len = dispatch(req, msg(req, FIDO_CTAP_INS_GET_INFO, NULL, 0),
                            resp, sizeof resp);

    static const uint8_t expected[] = {
        0x00,                         // CTAP status (success)
        0xA8,                         // map(8)
        0x01,                         //   1: versions
            0x81, 0x68,
            0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30,   // "FIDO_2_0"
        0x03,                         //   3: aaguid
            0x50,                     //   bytes(16)
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
    CHECK(len == rlen);
    CHECK(0 == memcmp(resp, refresp, len));

    len = dispatch(req,
                   msg(req, FIDO_CTAP_INS_GET_INFO, junk_map, 3),
                   resp, sizeof resp);
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
        uint8_t big[128];   // the response needs 81 bytes (status + map)
        len = dispatch(m, sizeof m, big, sizeof big);
        CHECK(big[0] == 0x00 && big[1] == 0xA8 && len > 1);
        // 0x00 status + CBOR map(8)
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

    // Every command code the device does not implement — CLIENT_PIN
    // (no PIN support is advertised), the reserved gaps and the vendor
    // range — answers CTAP1_ERR_INVALID_COMMAND (the spec's MUST).
    const uint8_t inss[] = {
        0x00,   // not a command code at all
        0x03,   // (reserved gap)
        FIDO_CTAP_INS_CLIENT_PIN,           // never — no PIN
        0x05,   // (reserved gap)
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
static int s_fail_genkey      = 0;
static int s_fail_sign        = 0;
static int s_fail_rand        = 0;
static int s_fail_getpubkey   = 0;
static int s_fail_counter_inc = 0;
static int s_fail_counter_zero = 0;
static int s_genkey_calls     = 0;
static int s_sign_calls       = 0;
static int s_getpubkey_calls  = 0;
static int s_counter_inc_calls = 0;
static int s_counter_zero_calls = 0;
static uint8_t s_last_keyslot    = 0;
static uint8_t s_last_signslot   = 0;
static uint8_t s_last_getpubslot = 0;

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

// The public key: X = 0x10+i / Y = 0x20+i — byte-identical to
// fake_genkey, so the makeCredential COSE_Key is the 77 bytes the
// KATs pin. (The getAssertion path never calls it — the assertion
// authData carries no COSE key.)
static int fake_get_pubkey(void *dev, uint8_t slot, uint8_t pub[64])
{
    (void)dev;
    s_getpubkey_calls++;
    s_last_getpubslot = slot;
    if (s_fail_getpubkey) {
        return -1;
    }
    for (int i = 0; i < 32; i++) {
        pub[i]      = (uint8_t)(0x10 + i);
        pub[32 + i] = (uint8_t)(0x20 + i);
    }
    return 0;
}

// The sync counter increment: s_counter++ and report the new value.
static int fake_counter_inc(void *dev, uint32_t *new_value)
{
    (void)dev;
    s_counter_inc_calls++;
    if (s_fail_counter_inc) {
        return -1;
    }
    s_counter++;
    *new_value = s_counter;
    return 0;
}

// The sync counter reset (the littlefs backend's hook; the chip's is
// NULL in firmware).
static int fake_counter_zero(void *dev)
{
    (void)dev;
    s_counter_zero_calls++;
    if (s_fail_counter_zero) {
        return -1;
    }
    s_counter = 0;
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
    ctx->keys.genkey       = fake_genkey;
    ctx->keys.get_pubkey   = fake_get_pubkey;
    ctx->keys.sign         = fake_sign;
    ctx->keys.counter      = fake_counter;
    ctx->keys.counter_inc  = fake_counter_inc;
    ctx->keys.counter_zero = fake_counter_zero;
    ctx->keys.rand         = fake_rand;
    ctx->keys.clock        = fake_clock;
    ctx->keys.dev          = NULL;
}

// Reset the backend's failure flags and call counters.
static void mc_reset(void)
{
    s_fail_genkey       = 0;
    s_fail_sign         = 0;
    s_fail_rand         = 0;
    s_fail_getpubkey    = 0;
    s_fail_counter_inc  = 0;
    s_fail_counter_zero = 0;
    s_genkey_calls      = 0;
    s_sign_calls        = 0;
    s_getpubkey_calls   = 0;
    s_counter_inc_calls = 0;
    s_counter_zero_calls = 0;
    s_now_ms            = 1000000;
    s_counter           = 0x01020304;
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
//   authData  = rpIdHash | 0x41 (UP|AT) | 01 02 03 04 (counter) | aaguid
//               | 00 20 (credIdLen, 2 B) | credId (0xA5+i) |
//               COSE_Key (77, map(5): kty/alg/crv/x/y — CTAP2 layout)
//   sig       = SHA-256(authData ‖ clientDataHash) ‖ itself
//   response  = 0x00 | {1: "packed", 2: authData, 3: {"alg": -7, "sig": sig}}
//               (the 0x00 CTAP status byte precedes the CBOR map,
//               CTAP 2.3 PS §11.2.9.1.2)
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

// The full 260-byte response: the 0x00 CTAP status byte followed by the
// v2.1 response map (CTAP 2.3 PS §11.2.9.1.2).
static const uint8_t s_mc_resp[260] = {
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
    0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x03, 0xA2, 0x63,
    0x61, 0x6C, 0x67, 0x26, 0x63, 0x73, 0x69, 0x67, 0x58, 0x46, 0x30, 0x44, 0x02, 0x20, 0x78, 0x82, 0xB2, 0xB7, 0x37, 0x22,
    0x21, 0x14, 0x43, 0xA2, 0x0B, 0x9F, 0x91, 0x63, 0x4F, 0xA2, 0x7C, 0x93,
    0x74, 0xE4, 0x55, 0xCD, 0x49, 0x83, 0x6D, 0xEE, 0xFE, 0xF9, 0x0A, 0x77,
    0x71, 0xA3, 0x02, 0x20, 0x78, 0x82, 0xB2, 0xB7, 0x37, 0x22, 0x21, 0x14,
    0x43, 0xA2, 0x0B, 0x9F, 0x91, 0x63, 0x4F, 0xA2, 0x7C, 0x93, 0x74, 0xE4,
    0x55, 0xCD, 0x49, 0x83, 0x6D, 0xEE, 0xFE, 0xF9, 0x0A, 0x77, 0x71, 0xA3,
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
    CHECK(0 == memcmp(out,
                      &s_mc_authdata[sizeof s_mc_authdata -
                                     FIDO_COSE_ES256_LEN],
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
// the completion — pinned against the offline-computed 260-byte
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
// cdh/RP the 260-byte KAT is unchanged (s_mc_resp).
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

// Bench round C1: the EXACT makeCredential Firefox 2026 sent (the
// console DBG MSG capture; 190 bytes — the first real browser request,
// reassembled from four CTAPHID packets). It uses the renumbered CTAP
// v2.2 parameter table: key 6 is the `extensions` map
// ({"hmac-secret": false}), NOT the v2.0 pinUvAuthToken byte string —
// the pre-fix code answered PIN_AUTH_INVALID (0x2A) to it, which
// Firefox surfaces to the page as NotAllowedError. Expected: the
// extensions map is ignored, the request defers for UP, and the
// completed response carries rpIdHash = SHA-256("xorengineering.com")
// with the request's user entity stored.
static const uint8_t s_firefox_c1_req[190] = {
    0x01, 0xA6, 0x01, 0x58, 0x20, 0xE0, 0xF0, 0xEA, 0xCD, 0xD7, 0xDF, 0xC5,
    0x90, 0xE6, 0x14, 0x23, 0xFB, 0x72, 0x2A, 0x1C, 0x49, 0x38, 0xD6, 0xBB,
    0xF9, 0xCB, 0x16, 0x7C, 0xC8, 0x23, 0x0A, 0xEF, 0x9D, 0xB7, 0x1B, 0xE3,
    0x86, 0x02, 0xA1, 0x62, 0x69, 0x64, 0x72, 0x78, 0x6F, 0x72, 0x65, 0x6E,
    0x67, 0x69, 0x6E, 0x65, 0x65, 0x72, 0x69, 0x6E, 0x67, 0x2E, 0x63, 0x6F,
    0x6D, 0x03, 0xA2, 0x62, 0x69, 0x64, 0x58, 0x20, 0xBF, 0x0B, 0xF5, 0x59,
    0x87, 0x47, 0x1F, 0x8E, 0xD5, 0x49, 0x0B, 0x1D, 0x74, 0x4C, 0xA5, 0x71,
    0x1B, 0x60, 0x3B, 0x4F, 0x9E, 0x79, 0xAF, 0x61, 0x76, 0xC5, 0x0D, 0x9C,
    0x41, 0x86, 0xC5, 0xA2, 0x64, 0x6E, 0x61, 0x6D, 0x65, 0x6F, 0x6E, 0x6F,
    0x62, 0x6F, 0x64, 0x79, 0x40, 0x6D, 0x61, 0x69, 0x6C, 0x2E, 0x63, 0x6F,
    0x6D, 0x04, 0x82, 0xA2, 0x63, 0x61, 0x6C, 0x67, 0x26, 0x64, 0x74, 0x79,
    0x70, 0x65, 0x6A, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65,
    0x79, 0xA2, 0x63, 0x61, 0x6C, 0x67, 0x39, 0x01, 0x00, 0x64, 0x74, 0x79,
    0x70, 0x65, 0x6A, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65,
    0x79, 0x06, 0xA1, 0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63,
    0x72, 0x65, 0x74, 0xF4, 0x07, 0xA1, 0x62, 0x72, 0x6B, 0xF4,
};

static void t_mc_firefox_c1(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t resp[FIDO_CTAP_MC_RESP_MAX];
    uint32_t tlen = 0;

    // The pre-fix behavior was an immediate 0x2A (resp_len 1, no
    // pending transaction).
    CHECK(0 == mc_dispatch(&ctx, s_firefox_c1_req,
                           sizeof s_firefox_c1_req, resp, sizeof resp));
    CHECK(fido_ctap_pending(&ctx));

    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(resp[0] == 0x00 && resp[1] == 0xA3 && tlen == sizeof s_mc_resp);

    // authData begins at resp+13 (00 | A3 | 01 "packed" | 02 58 A2 |
    // rpIdHash...): rpIdHash = SHA-256("xorengineering.com") — the
    // first 16 bytes pinned offline (Python hashlib), the rest
    // re-derived with the same SHA-256 the firmware uses.
    static const uint8_t xor_rph[16] = {
        0x08, 0x79, 0xFF, 0x55, 0x64, 0x78, 0x90, 0x97,
        0x09, 0xCB, 0x39, 0x12, 0xE1, 0x5E, 0xBF, 0xCC,
    };
    uint8_t rph[32];
    fido_sha256((const uint8_t *)"xorengineering.com", 18, rph);
    CHECK(0 == memcmp(resp + 13, xor_rph, 16));
    CHECK(0 == memcmp(resp + 13, rph, 32));

    // The stored record kept the request's user entity (user.id at
    // request offset 68).
    CHECK(ctx.creds.present[0]);
    const fido_cred_record_t *r = &ctx.creds.rec[0];
    CHECK(r->user_handle_len == 32);
    CHECK(0 == memcmp(r->user_handle, &s_firefox_c1_req[68], 32));
    CHECK(r->name_len == 15
          && 0 == memcmp(r->name, "nobody@mail.com", 15));
    CHECK(r->display_name_len == 0);
}

// The v2.2 `extensions` slot with NESTED content: the whole subtree
// must be skipped cleanly (a request with nothing else in it then
// fails MISSING_PARAMETER — never INVALID_CBOR), and a byte string in
// the slot is still the v2.0 pinUvAuthToken (PIN_AUTH_INVALID, pinned
// by the error table's "pinUvAuthToken" case).
static void t_mc_extensions_nested(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    uint8_t req[128];
    uint8_t resp[8];

    uint8_t params[96];
    fido_cbor_enc_t e;
    fido_cbor_enc_init(&e, params, sizeof params);
    fido_cbor_enc_map(&e, 1);
    fido_cbor_enc_uint(&e, 6);
    fido_cbor_enc_map(&e, 1);
    fido_cbor_enc_text(&e, "hmac-secret");
    fido_cbor_enc_map(&e, 1);          // nested one level deeper
    fido_cbor_enc_text(&e, "key");
    fido_cbor_enc_bytes(&e, s_cdh, 32);
    CHECK(!e.overflow);
    const uint32_t n = msg(req, FIDO_CTAP_INS_MAKE_CREDENTIAL,
                           params, (uint16_t)e.len);
    const uint32_t len = mc_dispatch(&ctx, req, n, resp, sizeof resp);
    CHECK(resp[0] == FIDO_CTAP2_ERR_MISSING_PARAMETER && len == 1);
    CHECK(!fido_ctap_pending(&ctx));
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
    CHECK(resp[0] == 0x00 && resp[1] == 0xA3 && tlen == sizeof s_mc_resp);

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
    CHECK(resp[0] == 0x00);
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
    CHECK(resp[0] == 0x00);
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
    CHECK(resp[0] == 0x00 && resp[1] == 0xA3 && tlen == sizeof s_mc_resp);
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

// --- GET_ASSERTION ---------------------------------------------------------------
//
// KAT fixtures (computed OFFLINE — Python hashlib — independently of
// the C implementation; the same method as the makeCredential KATs):
//   rpIdHash  = SHA-256("example.com")
//   counter   = 0x01020304 + N (N assertions in the test; the
//               increment happens BEFORE the authData is built)
//   authData  = rpIdHash | flags | counter(4 BE)  (37 bytes — the
//               assertion EXCLUDES the attested credential data:
//               WebAuthn L3 §6.3.3 step 10; no AT bit, no AAGUID/
//               credId/COSE)
//   sig       = SHA-256(authData ‖ clientDataHash) ‖ itself
//   response  = 0x00 | { 1: {"id": credId, "type": "public-key"},
//                          2: authData, 3: sig, 4: {"id": userHandle}
//                          [5: numberOfCredentials] }
//               (SD-6: INTEGER top-level keys, TEXT keys in the nested
//               maps — Firefox's deserializer rejects unknown fields,
//               so exactly these fields and no others)
static uint8_t s_cred_a[32];   // 0x5A+i — the "older" credential
static uint8_t s_cred_b[32];   // 0x6A+i — the "newer" credential
static uint8_t s_cred_c[32];   // 0x7A+i — a third credential (3-cred tests)

// The canonical 37-byte assertion authData: flags 0x01 (UP),
// counter 0x01020305 (the first increment).

static const uint8_t s_ga_authdata[37] = {
    0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11,
    0x80, 0x34, 0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab,
    0x13, 0xd2, 0x12, 0x55, 0x86, 0xce, 0x19, 0x47, 0x01, 0x01, 0x02, 0x03,
    0x05,
};


// Resident enumeration of ONE credential: flags 0x01 (UP),
// counter 0x01020305 (the first increment),
// numberOfCredentials = 1.

static const uint8_t s_ga_resp[186] = {
    0x00, 0xa5, 0x01, 0xa2, 0x62, 0x69, 0x64, 0x58, 0x20, 0x5a, 0x5b, 0x5c,
    0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70,
    0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x02, 0x58, 0x25,
    0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11,
    0x80, 0x34, 0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab,
    0x13, 0xd2, 0x12, 0x55, 0x86, 0xce, 0x19, 0x47, 0x01, 0x01, 0x02, 0x03,
    0x05, 0x03, 0x58, 0x46, 0x30, 0x44, 0x02, 0x20, 0x6d, 0x62, 0x07, 0xcc, 0x07, 0x1f,
    0x40, 0x06, 0xd3, 0x34, 0x97, 0xd7, 0xb8, 0xe6, 0x3d, 0x69, 0xe9, 0x2f,
    0xe0, 0xde, 0xce, 0x6b, 0x27, 0x53, 0xc2, 0x3d, 0x5d, 0x4e, 0xf1, 0xe8,
    0x2e, 0xa3, 0x02, 0x20, 0x6d, 0x62, 0x07, 0xcc, 0x07, 0x1f, 0x40, 0x06,
    0xd3, 0x34, 0x97, 0xd7, 0xb8, 0xe6, 0x3d, 0x69, 0xe9, 0x2f, 0xe0, 0xde,
    0xce, 0x6b, 0x27, 0x53, 0xc2, 0x3d, 0x5d, 0x4e, 0xf1, 0xe8, 0x2e, 0xa3, 0x04, 0xa1, 0x62, 0x69,
    0x64, 0x48, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x05, 0x01,
};


// "up": false (preflight): the flags carry no bits (0x00),
// served synchronously with no presence wait.

static const uint8_t s_ga_preflight_resp[186] = {
    0x00, 0xa5, 0x01, 0xa2, 0x62, 0x69, 0x64, 0x58, 0x20, 0x5a, 0x5b, 0x5c,
    0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70,
    0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x02, 0x58, 0x25,
    0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11,
    0x80, 0x34, 0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab,
    0x13, 0xd2, 0x12, 0x55, 0x86, 0xce, 0x19, 0x47, 0x00, 0x01, 0x02, 0x03,
    0x05, 0x03, 0x58, 0x46, 0x30, 0x44, 0x02, 0x20, 0x47, 0x43, 0xf6, 0x4c, 0x83, 0xcc,
    0x89, 0x2f, 0x9e, 0x91, 0x1e, 0x40, 0x21, 0xe7, 0x9e, 0xd8, 0xa3, 0x53,
    0x78, 0x64, 0x35, 0x3f, 0x27, 0xf5, 0xe9, 0x4c, 0x4f, 0x91, 0x0a, 0xbb,
    0x11, 0xbb, 0x02, 0x20, 0x47, 0x43, 0xf6, 0x4c, 0x83, 0xcc, 0x89, 0x2f,
    0x9e, 0x91, 0x1e, 0x40, 0x21, 0xe7, 0x9e, 0xd8, 0xa3, 0x53, 0x78, 0x64,
    0x35, 0x3f, 0x27, 0xf5, 0xe9, 0x4c, 0x4f, 0x91, 0x0a, 0xbb, 0x11, 0xbb, 0x04, 0xa1, 0x62, 0x69,
    0x64, 0x48, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x05, 0x01,
};


// allowList assertion: 4-entry map (no numberOfCredentials).

static const uint8_t s_ga_allow_resp[184] = {
    0x00, 0xa4, 0x01, 0xa2, 0x62, 0x69, 0x64, 0x58, 0x20, 0x5a, 0x5b, 0x5c,
    0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70,
    0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x02, 0x58, 0x25,
    0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11,
    0x80, 0x34, 0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab,
    0x13, 0xd2, 0x12, 0x55, 0x86, 0xce, 0x19, 0x47, 0x01, 0x01, 0x02, 0x03,
    0x05, 0x03, 0x58, 0x46, 0x30, 0x44, 0x02, 0x20, 0x6d, 0x62, 0x07, 0xcc, 0x07, 0x1f,
    0x40, 0x06, 0xd3, 0x34, 0x97, 0xd7, 0xb8, 0xe6, 0x3d, 0x69, 0xe9, 0x2f,
    0xe0, 0xde, 0xce, 0x6b, 0x27, 0x53, 0xc2, 0x3d, 0x5d, 0x4e, 0xf1, 0xe8,
    0x2e, 0xa3, 0x02, 0x20, 0x6d, 0x62, 0x07, 0xcc, 0x07, 0x1f, 0x40, 0x06,
    0xd3, 0x34, 0x97, 0xd7, 0xb8, 0xe6, 0x3d, 0x69, 0xe9, 0x2f, 0xe0, 0xde,
    0xce, 0x6b, 0x27, 0x53, 0xc2, 0x3d, 0x5d, 0x4e, 0xf1, 0xe8, 0x2e, 0xa3, 0x04, 0xa1, 0x62, 0x69,
    0x64, 0x48, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};


// Two-credential enumeration, FIRST response: the newer
// credential (reverse slot order), numberOfCredentials = 2.

static const uint8_t s_ga_enum_first_resp[186] = {
    0x00, 0xa5, 0x01, 0xa2, 0x62, 0x69, 0x64, 0x58, 0x20, 0x6a, 0x6b, 0x6c,
    0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84,
    0x85, 0x86, 0x87, 0x88, 0x89, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70,
    0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x02, 0x58, 0x25,
    0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11,
    0x80, 0x34, 0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab,
    0x13, 0xd2, 0x12, 0x55, 0x86, 0xce, 0x19, 0x47, 0x01, 0x01, 0x02, 0x03,
    0x05, 0x03, 0x58, 0x46, 0x30, 0x44, 0x02, 0x20, 0x6d, 0x62, 0x07, 0xcc, 0x07, 0x1f,
    0x40, 0x06, 0xd3, 0x34, 0x97, 0xd7, 0xb8, 0xe6, 0x3d, 0x69, 0xe9, 0x2f,
    0xe0, 0xde, 0xce, 0x6b, 0x27, 0x53, 0xc2, 0x3d, 0x5d, 0x4e, 0xf1, 0xe8,
    0x2e, 0xa3, 0x02, 0x20, 0x6d, 0x62, 0x07, 0xcc, 0x07, 0x1f, 0x40, 0x06,
    0xd3, 0x34, 0x97, 0xd7, 0xb8, 0xe6, 0x3d, 0x69, 0xe9, 0x2f, 0xe0, 0xde,
    0xce, 0x6b, 0x27, 0x53, 0xc2, 0x3d, 0x5d, 0x4e, 0xf1, 0xe8, 0x2e, 0xa3, 0x04, 0xa1, 0x62, 0x69,
    0x64, 0x48, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x05, 0x02,
};


// get_next_assertion: the older credential, counter
// 0x01020306 (the second increment), no numberOfCredentials.

static const uint8_t s_gna_resp[184] = {
    0x00, 0xa4, 0x01, 0xa2, 0x62, 0x69, 0x64, 0x58, 0x20, 0x5a, 0x5b, 0x5c,
    0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70,
    0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x02, 0x58, 0x25,
    0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11,
    0x80, 0x34, 0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab,
    0x13, 0xd2, 0x12, 0x55, 0x86, 0xce, 0x19, 0x47, 0x01, 0x01, 0x02, 0x03,
    0x06, 0x03, 0x58, 0x46, 0x30, 0x44, 0x02, 0x20, 0x7c, 0x2e, 0xd3, 0x86, 0x69, 0x33,
    0x6e, 0xff, 0xfc, 0xea, 0x5b, 0x3b, 0x27, 0x61, 0xaf, 0xeb, 0x65, 0x2c,
    0x31, 0x2e, 0xd0, 0x45, 0x6e, 0xc8, 0xf7, 0x2a, 0x75, 0xdf, 0x25, 0x50,
    0x12, 0xac, 0x02, 0x20, 0x7c, 0x2e, 0xd3, 0x86, 0x69, 0x33, 0x6e, 0xff,
    0xfc, 0xea, 0x5b, 0x3b, 0x27, 0x61, 0xaf, 0xeb, 0x65, 0x2c, 0x31, 0x2e,
    0xd0, 0x45, 0x6e, 0xc8, 0xf7, 0x2a, 0x75, 0xdf, 0x25, 0x50, 0x12, 0xac, 0x04, 0xa1, 0x62, 0x69,
    0x64, 0x48, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};


// The request builder: a getAssertion map with any field omitted,
// mistyped or oversize (all-zero opts = the canonical valid request).
// Returns the total length, command byte first.
typedef struct {
    int no_rp;         // omit rpId (key 1)
    int no_cdh;        // omit clientDataHash (key 2)
    int cdh_len;       // its length (0 = the valid 32)
    int cdh_text;      // encode it as a text string (a type error)
    int rp_other;      // rpId = "other.com" (no residents)
    int rp_long;       // rpId = 256 'x' (oversize)
    int allow;         // an allowList naming s_cred_a
    int allow_foreign; // an allowList naming s_cred_b (not seeded)
    int allow_no_array; // the allowList is a map (a type error)
    int allow_text_id;  // the entry's "id" is text (a type error)
    int opt_uv;        // options "uv": true
    int opt_rk;        // options "rk": true
    int opt_up_false;  // options "up": false
    int opt_unknown;   // options "foo": true (must be ignored)
    int pin;           // pinUvAuthParam (key 6), no protocol
    int pin_map;       // pinUvAuthParam as a map (a type error)
    int pin_proto;     // pinUvAuthProtocol (key 7)
    int extra;         // key 9 (a 2.1+ extra) = 1 (must be ignored)
    int trailing;      // one stray byte after the map
    int not_map;       // the top level is an array, not a map
} ga_opts_t;

static uint32_t build_ga(uint8_t *buf, uint32_t cap, const ga_opts_t *o)
{
    const int nkeys = (!o->no_rp) + (!o->no_cdh) +
                      (o->allow || o->allow_foreign || o->allow_no_array ||
                       o->allow_text_id) +
                      (o->opt_uv || o->opt_rk || o->opt_up_false ||
                       o->opt_unknown) +
                      (o->pin || o->pin_map) + o->pin_proto + o->extra;

    buf[0] = FIDO_CTAP_INS_GET_ASSERTION;
    fido_cbor_enc_t e;
    fido_cbor_enc_init(&e, buf + 1, cap - 1);
    if (o->not_map) {
        fido_cbor_enc_array(&e, 0);
    } else {
        fido_cbor_enc_map(&e, (uint32_t)nkeys);
        if (!o->no_rp) {
            fido_cbor_enc_uint(&e, 1);
            if (o->rp_long) {
                char big[300];
                memset(big, 'x', 256);
                big[256] = '\0';
                fido_cbor_enc_text(&e, big);
            } else {
                fido_cbor_enc_text(&e,
                                   o->rp_other ? "other.com" : MC_RP);
            }
        }
        if (!o->no_cdh) {
            fido_cbor_enc_uint(&e, 2);
            if (o->cdh_text) {
                fido_cbor_enc_text(&e,
                    "abcdefghijklmnopqrstuvwxyz0123456789");
            } else {
                fido_cbor_enc_bytes(&e, s_cdh,
                                    (uint32_t)(o->cdh_len ? o->cdh_len :
                                                 32));
            }
        }
        if (o->allow || o->allow_foreign || o->allow_no_array ||
            o->allow_text_id) {
            fido_cbor_enc_uint(&e, 3);
            if (o->allow_no_array) {
                fido_cbor_enc_map(&e, 0);
            } else {
                fido_cbor_enc_array(&e, 1);
                fido_cbor_enc_map(&e, 2);
                fido_cbor_enc_text(&e, "id");
                if (o->allow_text_id) {
                    fido_cbor_enc_text(&e, "not-bytes");
                } else {
                    fido_cbor_enc_bytes(&e,
                                        o->allow_foreign ? s_cred_b
                                                         : s_cred_a,
                                        32);
                }
                fido_cbor_enc_text(&e, "type");
                fido_cbor_enc_text(&e, "public-key");
            }
        }
        if (o->opt_uv || o->opt_rk || o->opt_up_false || o->opt_unknown) {
            fido_cbor_enc_uint(&e, 5);
            fido_cbor_enc_map(&e,
                              (uint32_t)(o->opt_uv + o->opt_rk +
                                         o->opt_up_false + o->opt_unknown));
            // Canonical (ascending) key order: foo, rk, up, uv.
            if (o->opt_unknown) {
                fido_cbor_enc_text(&e, "foo");
                fido_cbor_enc_bool(&e, true);
            }
            if (o->opt_rk) {
                fido_cbor_enc_text(&e, "rk");
                fido_cbor_enc_bool(&e, true);
            }
            if (o->opt_up_false) {
                fido_cbor_enc_text(&e, "up");
                fido_cbor_enc_bool(&e, false);
            }
            if (o->opt_uv) {
                fido_cbor_enc_text(&e, "uv");
                fido_cbor_enc_bool(&e, true);
            }
        }
        if (o->pin || o->pin_map) {
            fido_cbor_enc_uint(&e, 6);
            if (o->pin_map) {
                fido_cbor_enc_map(&e, 0);
            } else {
                fido_cbor_enc_bytes(&e, s_cdh, 16);
            }
        }
        if (o->pin_proto) {
            fido_cbor_enc_uint(&e, 7);
            fido_cbor_enc_uint(&e, 1);
        }
        if (o->extra) {
            fido_cbor_enc_uint(&e, 9);
            fido_cbor_enc_uint(&e, 1);
        }
    }
    CHECK(!e.overflow);
    if (o->trailing) {
        buf[1 + e.len] = 0x00;
        return 2 + e.len;
    }
    return 1 + e.len;
}

// A bare get_next_assertion / RESET command, optionally followed by a
// stray CBOR item: 0 = none, 1 = one well-formed item, 2 = a truncated
// array (not one well-formed item).
static uint32_t build_bare(uint8_t *buf, uint8_t ins, int param_kind)
{
    buf[0] = ins;
    if (param_kind == 1) {
        buf[1] = 0x00;
        return 2;
    }
    if (param_kind == 2) {
        buf[1] = 0x82;   // array(2)
        buf[2] = 0x00;   // one element: truncated
        return 3;
    }
    return 1;
}

// The login: resident enumeration of one credential, deferred until the
// touch, then the byte-pinned response. The counter moves ONCE and the
// authData carries the NEW value.
static void t_ga_happy(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    seed_credential(&ctx, 0, s_cred_a);   // slot 3

    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
    uint32_t tlen = 0;
    const ga_opts_t o = {0};
    const uint32_t n = build_ga(req, sizeof req, &o);

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    CHECK(fido_ctap_pending(&ctx));
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(tlen == sizeof s_ga_resp);
    CHECK(0 == memcmp(resp, s_ga_resp, sizeof s_ga_resp));
    CHECK(1 == s_counter_inc_calls);
    CHECK(0x01020305 == s_counter);
    CHECK(0 == s_genkey_calls);           // no keygen on login
    CHECK(0 == s_getpubkey_calls);        // no pubkey on login either:
                                          // the assertion authData carries
                                          // no COSE key (WebAuthn L3
                                          // §6.3.3 step 10)
    CHECK(1 == s_sign_calls);
    CHECK(3 == s_last_signslot);          // the credential's slot
    CHECK(!fido_ctap_pending(&ctx));
    CHECK(!ctx.user_present);
    // The authData embedded in the response: status(1) + map(5)(1) +
    // key1(1) + map(2)(1) + "id"(3) + credId(34) + "type"(5) +
    // "public-key"(11) + key2(1) + bytes(37) header(2) = offset 60.
    CHECK(0 == memcmp(resp + 60, s_ga_authdata, sizeof s_ga_authdata));
}

// "up": false (preflight): a synchronous full assertion, the flags' UP
// bit clear, and no presence wait (the touch is never consumed).
static void t_ga_preflight(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    seed_credential(&ctx, 0, s_cred_a);

    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
    const ga_opts_t o = { .opt_up_false = 1 };
    const uint32_t n = build_ga(req, sizeof req, &o);

    const uint32_t len = mc_dispatch(&ctx, req, n, resp, sizeof resp);
    CHECK(len == sizeof s_ga_preflight_resp);
    CHECK(0 == memcmp(resp, s_ga_preflight_resp,
                      sizeof s_ga_preflight_resp));
    CHECK(1 == s_counter_inc_calls);
    CHECK(!fido_ctap_pending(&ctx));
    CHECK(!ctx.user_present);
}

// allowList assertion: the named credential, a 4-entry response (no
// numberOfCredentials), and no enumeration state.
static void t_ga_allowlist(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    seed_credential(&ctx, 0, s_cred_a);
    seed_credential(&ctx, 1, s_cred_b);   // present, NOT in the allowList

    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
    uint32_t tlen = 0;
    const ga_opts_t o = { .allow = 1 };
    const uint32_t n = build_ga(req, sizeof req, &o);

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(tlen == sizeof s_ga_allow_resp);
    CHECK(0 == memcmp(resp, s_ga_allow_resp, sizeof s_ga_allow_resp));
    // No enumeration state: get_next_assertion is not allowed.
    uint8_t g[4];
    const uint32_t gn =
        build_bare(g, FIDO_CTAP_INS_GET_NEXT_ASSERTION, 0);
    const uint32_t gl = mc_dispatch(&ctx, g, gn, resp, sizeof resp);
    CHECK(resp[0] == FIDO_CTAP2_ERR_NOT_ALLOWED && gl == 1);
}

// Two-credential resident enumeration: first the newer credential with
// numberOfCredentials = 2, then get_next_assertion serves the older one
// (counter +1 again), then the list is exhausted.
static void t_ga_enum(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    seed_credential(&ctx, 0, s_cred_a);   // slot 3 — the older
    seed_credential(&ctx, 3, s_cred_b);   // slot 6 — the newer

    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
    uint32_t tlen = 0;
    const ga_opts_t o = {0};
    const uint32_t n = build_ga(req, sizeof req, &o);

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(tlen == sizeof s_ga_enum_first_resp);
    CHECK(0 == memcmp(resp, s_ga_enum_first_resp,
                      sizeof s_ga_enum_first_resp));
    CHECK(1 == s_counter_inc_calls);

    uint8_t g[4];
    const uint32_t gn =
        build_bare(g, FIDO_CTAP_INS_GET_NEXT_ASSERTION, 0);
    {
        const uint32_t gl = mc_dispatch(&ctx, g, gn, resp, sizeof resp);
        CHECK(gl == sizeof s_gna_resp);
        CHECK(0 == memcmp(resp, s_gna_resp, sizeof s_gna_resp));
    }
    CHECK(2 == s_counter_inc_calls);
    CHECK(0x01020306 == s_counter);

    const uint32_t gl2 = mc_dispatch(&ctx, g, gn, resp, sizeof resp);
    CHECK(resp[0] == FIDO_CTAP2_ERR_NOT_ALLOWED && gl2 == 1);
}

// get_next_assertion on its own: no remembered state, malformed
// parameters (checked before the state), a well-formed single-item
// parameter (accepted), and the 30-s window expiring between calls
// (the state is discarded).
static void t_gna_standalone(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    seed_credential(&ctx, 0, s_cred_a);   // slot 3
    seed_credential(&ctx, 1, s_cred_c);   // slot 4
    seed_credential(&ctx, 3, s_cred_b);   // slot 6

    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
    uint32_t tlen = 0;
    const ga_opts_t o = {0};
    const uint32_t n = build_ga(req, sizeof req, &o);
    uint8_t g[4];
    const uint32_t gn =
        build_bare(g, FIDO_CTAP_INS_GET_NEXT_ASSERTION, 0);

    {   // no remembered state: NOT_ALLOWED (before any getAssertion)
        const uint32_t len = mc_dispatch(&ctx, g, gn, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_NOT_ALLOWED && len == 1);
    }
    {   // a malformed parameter: INVALID_CBOR, checked before the state
        uint8_t g2[4];
        const uint32_t n2 =
            build_bare(g2, FIDO_CTAP_INS_GET_NEXT_ASSERTION, 2);
        const uint32_t len = mc_dispatch(&ctx, g2, n2, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_INVALID_CBOR && len == 1);
    }
    // Arm the state with a 3-credential enumeration (serves B)...
    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    {   // ...a well-formed single-item parameter is accepted (serves C)
        uint8_t g2[4];
        const uint32_t n2 =
            build_bare(g2, FIDO_CTAP_INS_GET_NEXT_ASSERTION, 1);
        const uint32_t len = mc_dispatch(&ctx, g2, n2, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_OK && len > 1);
        CHECK(2 == s_counter_inc_calls);
    }
    // ...and the 30-s window expires between get_next calls.
    s_now_ms += FIDO_CTAP_GA_ENUM_TIMEOUT_MS + 1;
    {
        const uint32_t len = mc_dispatch(&ctx, g, gn, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_NOT_ALLOWED && len == 1);
    }
    CHECK(!ctx.ga_enum.active);
}

// The parse error table (every case: a one-byte error, no pending
// transaction).
static void t_ga_parse_errors(void)
{
    struct {
        ga_opts_t o;
        uint8_t expect;
    } cases[] = {
        { { .no_rp = 1 },           FIDO_CTAP2_ERR_MISSING_PARAMETER },
        { { .no_cdh = 1 },          FIDO_CTAP2_ERR_MISSING_PARAMETER },
        { { .cdh_len = 16 },        FIDO_CTAP2_ERR_LIMIT_EXCEEDED },
        { { .cdh_text = 1 },        FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE },
        { { .rp_long = 1 },         FIDO_CTAP2_ERR_LIMIT_EXCEEDED },
        { { .allow_no_array = 1 },  FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE },
        { { .allow_text_id = 1 },   FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE },
        { { .pin_map = 1 },         FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE },
        { { .trailing = 1 },        FIDO_CTAP2_ERR_INVALID_CBOR },
        { { .not_map = 1 },         FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE },
        { { .pin = 1 },             FIDO_CTAP2_ERR_MISSING_PARAMETER },
        { { .pin = 1, .pin_proto = 1 },
                                   FIDO_CTAP2_ERR_INVALID_PARAMETER },
        { { .opt_uv = 1 },          FIDO_CTAP2_ERR_UNSUPPORTED_OPTION },
        { { .opt_rk = 1 },          FIDO_CTAP2_ERR_UNSUPPORTED_OPTION },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        fido_ctap_ctx_t ctx;
        mc_install(&ctx);
        mc_reset();
        seed_credential(&ctx, 0, s_cred_a);
        uint8_t req[512];
        uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
        const uint32_t n = build_ga(req, sizeof req, &cases[i].o);
        const uint32_t len = mc_dispatch(&ctx, req, n, resp, sizeof resp);
        CHECK(resp[0] == cases[i].expect);
        CHECK(len == 1);
        CHECK(!fido_ctap_pending(&ctx));
    }
    // A bare command byte (no parameters at all): missing parameters.
    {
        fido_ctap_ctx_t ctx;
        mc_install(&ctx);
        mc_reset();
        uint8_t req = FIDO_CTAP_INS_GET_ASSERTION;
        uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
        const uint32_t len = mc_dispatch(&ctx, &req, 1, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_MISSING_PARAMETER && len == 1);
    }
}

// Unknown options and 2.1+ request keys are ignored, not errors — the
// assertion is still served (byte-pinned, same as the happy path).
static void t_ga_ignored_extras(void)
{
    struct {
        ga_opts_t o;
    } cases[] = {
        { { .opt_unknown = 1 } },
        { { .extra = 1 } },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        fido_ctap_ctx_t ctx;
        mc_install(&ctx);
        mc_reset();
        seed_credential(&ctx, 0, s_cred_a);
        uint8_t req[512];
        uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
        uint32_t tlen = 0;
        const uint32_t n = build_ga(req, sizeof req, &cases[i].o);
        CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
        ctx.user_present = true;
        CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
        CHECK(resp[0] == 0x00 && tlen == sizeof s_ga_resp);
        CHECK(0 == memcmp(resp, s_ga_resp, sizeof s_ga_resp));
    }
}

// No match: NO_CREDENTIALS (before any presence wait), for an RP with
// no residents (enumeration), the same with an allowList, and the right
// RP with a foreign allowList entry.
static void t_ga_no_credentials(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    seed_credential(&ctx, 0, s_cred_a);   // for "example.com"

    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
    {   // an RP with no residents (enumeration)
        const ga_opts_t o = { .rp_other = 1 };
        const uint32_t n = build_ga(req, sizeof req, &o);
        const uint32_t len = mc_dispatch(&ctx, req, n, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_NO_CREDENTIALS && len == 1);
    }
    {   // an RP with no residents + an allowList
        const ga_opts_t o = { .rp_other = 1, .allow = 1 };
        const uint32_t n = build_ga(req, sizeof req, &o);
        const uint32_t len = mc_dispatch(&ctx, req, n, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_NO_CREDENTIALS && len == 1);
    }
    {   // the right RP, a foreign allowList entry
        const ga_opts_t o = { .allow_foreign = 1 };
        const uint32_t n = build_ga(req, sizeof req, &o);
        const uint32_t len = mc_dispatch(&ctx, req, n, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_NO_CREDENTIALS && len == 1);
    }
    CHECK(0 == s_counter_inc_calls);   // nothing was served
    CHECK(!fido_ctap_pending(&ctx));
}

// A backend failure AFTER the presence wait: a one-byte OTHER, never a
// partial response; the steps that did not run leave no side effects.
static void t_ga_backend_fail(void)
{
    fido_ctap_ctx_t ctx;
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
    uint32_t tlen = 0;
    const ga_opts_t o = {0};
    const uint32_t n = build_ga(req, sizeof req, &o);

    {   // counter_inc fails: the sign step was never reached, the
        // counter stands
        mc_install(&ctx);
        mc_reset();
        seed_credential(&ctx, 0, s_cred_a);
        s_fail_counter_inc = 1;
        CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
        ctx.user_present = true;
        CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
        CHECK(resp[0] == FIDO_CTAP2_ERR_OTHER && tlen == 1);
        CHECK(0 == s_sign_calls);
        CHECK(0x01020304 == s_counter);
    }
    {   // sign fails: the increment stood (a failed assertion still
        // consumed a counter value — the next one must read higher)
        mc_install(&ctx);
        mc_reset();
        seed_credential(&ctx, 0, s_cred_a);
        s_fail_sign = 1;
        CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
        ctx.user_present = true;
        CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
        CHECK(resp[0] == FIDO_CTAP2_ERR_OTHER && tlen == 1);
        CHECK(1 == s_counter_inc_calls);
        CHECK(0x01020305 == s_counter);
    }
}

// The presence wait times out like any other transaction (nothing was
// served, the counter stands).
static void t_ga_timeout(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    seed_credential(&ctx, 0, s_cred_a);
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
    uint32_t tlen = 0;
    const ga_opts_t o = {0};
    const uint32_t n = build_ga(req, sizeof req, &o);

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    s_now_ms += FIDO_CTAP_UP_TIMEOUT_MS + 1;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_ERR_USER_ACTION_TIMEOUT && tlen == 1);
    CHECK(!fido_ctap_pending(&ctx));
    CHECK(0 == s_counter_inc_calls);
}

// CTAPHID_CANCEL while waiting: KEEPALIVE_CANCEL, the touch is
// consumed, nothing was served.
static void t_ga_cancel(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    seed_credential(&ctx, 0, s_cred_a);
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
    uint32_t tlen = 0;
    const ga_opts_t o = {0};
    const uint32_t n = build_ga(req, sizeof req, &o);

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, true, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_ERR_KEEPALIVE_CANCEL && tlen == 1);
    CHECK(!fido_ctap_pending(&ctx));
    CHECK(!ctx.user_present);
    CHECK(0 == s_counter_inc_calls);
}

// While an assertion waits: a second getAssertion, get_next_assertion
// and RESET all answer OPERATION_PENDING (defensive — the transport
// serializes). The touch still completes the ORIGINAL transaction.
static void t_ga_pending_guard(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    seed_credential(&ctx, 0, s_cred_a);
    uint8_t req[512];
    uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
    uint32_t tlen = 0;
    const ga_opts_t o = {0};
    const uint32_t n = build_ga(req, sizeof req, &o);

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    {
        uint8_t r2[512];
        const uint32_t n2 = build_ga(r2, sizeof r2, &o);
        const uint32_t len = mc_dispatch(&ctx, r2, n2, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_OPERATION_PENDING && len == 1);
    }
    {
        uint8_t g[4];
        const uint32_t gn =
            build_bare(g, FIDO_CTAP_INS_GET_NEXT_ASSERTION, 0);
        const uint32_t len = mc_dispatch(&ctx, g, gn, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_OPERATION_PENDING && len == 1);
    }
    {
        uint8_t r[4];
        const uint32_t nr = build_bare(r, FIDO_CTAP_INS_RESET, 0);
        const uint32_t len = mc_dispatch(&ctx, r, nr, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_OPERATION_PENDING && len == 1);
    }
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(resp[0] == 0x00 && tlen == sizeof s_ga_resp);
    CHECK(0 == memcmp(resp, s_ga_resp, sizeof s_ga_resp));
}

// A response buffer that cannot hold the map degrades to a status-only
// answer (never a partial CBOR) — on the deferred and the synchronous
// (preflight) paths alike.
static void t_ga_tiny_buffer(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    seed_credential(&ctx, 0, s_cred_a);
    uint8_t req[512];
    uint8_t resp[1];
    uint32_t tlen = 99;
    const ga_opts_t o = {0};
    const uint32_t n = build_ga(req, sizeof req, &o);

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_ERR_OTHER && tlen == 1);
    CHECK(!fido_ctap_pending(&ctx));

    {   // the synchronous preflight path degrades the same way
        mc_install(&ctx);
        mc_reset();
        seed_credential(&ctx, 0, s_cred_a);
        const ga_opts_t p = { .opt_up_false = 1 };
        const uint32_t n2 = build_ga(req, sizeof req, &p);
        const uint32_t len = mc_dispatch(&ctx, req, n2, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_OTHER && len == 1);
    }
}

// --- RESET ---------------------------------------------------------------

// Inside the 10-s power-on window: deferred (the presence wait), then
// the bare 0x00 status byte (no CBOR); the store is wiped and the sync
// counter zeroed.
static void t_reset_happy(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();
    s_now_ms = 5000;   // inside the window
    seed_credential(&ctx, 0, s_cred_a);
    seed_credential(&ctx, 2, s_cred_b);
    CHECK(0x01020304 == s_counter);

    uint8_t req[4];
    uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
    uint32_t tlen = 99;
    const uint32_t n = build_bare(req, FIDO_CTAP_INS_RESET, 0);

    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    CHECK(fido_ctap_pending(&ctx));
    ctx.user_present = true;
    CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
    CHECK(resp[0] == FIDO_CTAP2_OK && tlen == 1);
    for (int i = 0; i < FIDO_CRED_MAX; i++) {
        CHECK(!ctx.creds.present[i]);
    }
    CHECK(0 == s_counter);
    CHECK(1 == s_counter_zero_calls);
    CHECK(!fido_ctap_pending(&ctx));
}

// Late (past the window): NOT_ALLOWED, nothing wiped; the boundary
// (exactly 10 s) is still inside the window.
static void t_reset_late(void)
{
    fido_ctap_ctx_t ctx;
    mc_install(&ctx);
    mc_reset();   // s_now_ms = 1000000 — well past the window
    seed_credential(&ctx, 0, s_cred_a);

    uint8_t req[4];
    uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
    const uint32_t n = build_bare(req, FIDO_CTAP_INS_RESET, 0);
    const uint32_t len = mc_dispatch(&ctx, req, n, resp, sizeof resp);
    CHECK(resp[0] == FIDO_CTAP2_ERR_NOT_ALLOWED && len == 1);
    CHECK(!fido_ctap_pending(&ctx));
    CHECK(ctx.creds.present[0]);   // nothing was wiped

    s_now_ms = FIDO_CTAP_RESET_WINDOW_MS;   // the boundary: inside
    CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
    fido_ctap_abort(&ctx);
    CHECK(!fido_ctap_pending(&ctx));
}

// RESET's error paths: a malformed parameter (checked first), a failed
// counter zero (the records were erased, the counter stands), and the
// presence wait timing out.
static void t_reset_errors(void)
{
    fido_ctap_ctx_t ctx;
    uint8_t req[8];
    uint8_t resp[FIDO_CTAP_GA_RESP_MAX];
    uint32_t tlen = 0;

    {   // a malformed parameter: INVALID_CBOR, before the window check
        mc_install(&ctx);
        mc_reset();
        s_now_ms = 5000;
        const uint32_t n = build_bare(req, FIDO_CTAP_INS_RESET, 2);
        const uint32_t len = mc_dispatch(&ctx, req, n, resp, sizeof resp);
        CHECK(resp[0] == FIDO_CTAP2_ERR_INVALID_CBOR && len == 1);
    }
    {   // counter_zero fails: the wipe did not complete -> OTHER
        mc_install(&ctx);
        mc_reset();
        s_now_ms = 5000;
        seed_credential(&ctx, 0, s_cred_a);
        s_fail_counter_zero = 1;
        const uint32_t n = build_bare(req, FIDO_CTAP_INS_RESET, 0);
        CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
        ctx.user_present = true;
        CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
        CHECK(resp[0] == FIDO_CTAP2_ERR_OTHER && tlen == 1);
        CHECK(!ctx.creds.present[0]);   // the erase ran first
        CHECK(0x01020304 == s_counter); // the counter stands
    }
    {   // the presence wait times out like any other transaction
        mc_install(&ctx);
        mc_reset();
        s_now_ms = 5000;
        const uint32_t n = build_bare(req, FIDO_CTAP_INS_RESET, 0);
        CHECK(0 == mc_dispatch(&ctx, req, n, resp, sizeof resp));
        s_now_ms += FIDO_CTAP_UP_TIMEOUT_MS + 1;
        CHECK(1 == fido_ctap_tick(&ctx, false, resp, sizeof resp, &tlen));
        CHECK(resp[0] == FIDO_CTAP2_ERR_USER_ACTION_TIMEOUT && tlen == 1);
        CHECK(!fido_ctap_pending(&ctx));
    }
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

// --- ECDSA DER encoding (WebAuthn L3 section 6.5.5) ------------------------
//
// fido_ecdsa_der_encode(): the minimal-INTEGER corners the KATs pin —
// no pad, sign pad (high bit), leading-zero strip, strip-then-pad, and
// the undersized-output failure.

static void t_ecdsa_der(void)
{
    uint8_t raw[64];
    uint8_t der[FIDO_ECDSA_DER_SIG_MAX];
    uint32_t n;

    // V1: no sign pad, no leading zeros: 30 44 02 20 r 02 20 s (70 B).
    for (int i = 0; i < 32; i++) {
        raw[i]      = (uint8_t)(i + 1);      // 0x01..0x20
        raw[32 + i] = (uint8_t)(i + 0x41);   // 0x41..0x60
    }
    n = fido_ecdsa_der_encode(raw, der, sizeof der);
    CHECK(70 == n);
    CHECK(0x30 == der[0] && 0x44 == der[1]);
    CHECK(0x02 == der[2] && 0x20 == der[3]);
    CHECK(0 == memcmp(&der[4], raw, 32));
    CHECK(0x02 == der[36] && 0x20 == der[37]);
    CHECK(0 == memcmp(&der[38], &raw[32], 32));

    // V2: both high bits set: a 0x00 sign pad on each (72 B, the max).
    for (int i = 0; i < 32; i++) {
        raw[i]      = (uint8_t)((i == 0) ? 0x80 : i);
        raw[32 + i] = (uint8_t)((i == 0) ? 0xFF : (i + 1));
    }
    n = fido_ecdsa_der_encode(raw, der, sizeof der);
    CHECK(72 == n);
    CHECK(0x30 == der[0] && 0x46 == der[1]);
    CHECK(0x02 == der[2] && 0x21 == der[3] && 0x00 == der[4]);
    CHECK(0 == memcmp(&der[5], raw, 32));
    CHECK(0x02 == der[37] && 0x21 == der[38] && 0x00 == der[39]);
    CHECK(0 == memcmp(&der[40], &raw[32], 32));

    // V3: r carries a leading zero byte (stripped to 31; the next byte
    // 0x11 keeps the high bit clear, so no pad); s plain: 30 43 02 1F
    // r31 02 20 s (69 B).
    memset(raw, 0x22, 64);
    raw[0] = 0x00;
    raw[1] = 0x11;
    raw[32] = 0x33;
    n = fido_ecdsa_der_encode(raw, der, sizeof der);
    CHECK(69 == n);
    CHECK(0x30 == der[0] && 0x43 == der[1]);
    CHECK(0x02 == der[2] && 0x1F == der[3] && 0x11 == der[4]);
    for (int i = 1; i < 31; i++) {
        CHECK(0x22 == der[4 + i]);
    }
    CHECK(0x02 == der[35] && 0x20 == der[36]);
    CHECK(0 == memcmp(&der[37], &raw[32], 32));

    // V4: r = 00 80 .. (strip the zero, then the high bit forces the
    // pad back: a 32-byte integer); s = 00 00 01 .. (stripped to 30):
    // 30 42 02 20 00 80 r30 02 1E s30 (68 B).
    memset(raw, 0x00, 64);
    raw[1] = 0x80;
    raw[34] = 0x01;
    n = fido_ecdsa_der_encode(raw, der, sizeof der);
    CHECK(68 == n);
    CHECK(0x30 == der[0] && 0x42 == der[1]);
    CHECK(0x02 == der[2] && 0x20 == der[3] && 0x00 == der[4]
          && 0x80 == der[5]);
    for (int i = 0; i < 30; i++) {
        CHECK(0x00 == der[6 + i]);
    }
    CHECK(0x02 == der[36] && 0x1E == der[37] && 0x01 == der[38]);
    for (int i = 0; i < 29; i++) {
        CHECK(0x00 == der[39 + i]);
    }

    // V5: an output buffer one byte short of the 70-byte V1 encoding.
    for (int i = 0; i < 32; i++) {
        raw[i]      = (uint8_t)(i + 1);
        raw[32 + i] = (uint8_t)(i + 0x41);
    }
    CHECK(0 == fido_ecdsa_der_encode(raw, der, 69));
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
    t_ecdsa_der();
    t_mc_error_table();
    t_mc_error_order();
    t_mc_happy();
    t_mc_lenient_user();
    t_mc_firefox_c1();
    t_mc_extensions_nested();
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

    // The getAssertion fixtures (the KAT inputs).
    for (int i = 0; i < 32; i++) {
        s_cred_a[i] = (uint8_t)(0x5A + i);
        s_cred_b[i] = (uint8_t)(0x6A + i);
        s_cred_c[i] = (uint8_t)(0x7A + i);
    }

    t_ga_happy();
    t_ga_preflight();
    t_ga_allowlist();
    t_ga_enum();
    t_gna_standalone();
    t_ga_parse_errors();
    t_ga_ignored_extras();
    t_ga_no_credentials();
    t_ga_backend_fail();
    t_ga_timeout();
    t_ga_cancel();
    t_ga_pending_guard();
    t_ga_tiny_buffer();
    t_reset_happy();
    t_reset_late();
    t_reset_errors();

    printf("%s: %d checks, %d failures\n",
           (s_failures == 0) ? "PASS" : "FAIL", s_checks, s_failures);
    return (s_failures == 0) ? 0 : 1;
}

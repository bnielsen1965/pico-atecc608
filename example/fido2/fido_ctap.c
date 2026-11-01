// fido_ctap.c — implementation of the CTAP2 command dispatch (see
// fido_ctap.h for the wire format and the phase scope).

#include "fido_ctap.h"

#include <string.h>

#include "fido_cbor.h"
#include "fido_cose.h"
#include "fido_sha256.h"

// The claimed AAGUID — fixed per firmware (recorded in PLAN.md; a
// demo value, not FIDO-registered). 16 bytes, as transmitted in
// MakeCredential AuthenticatorData.
static const uint8_t s_aaguid[16] = {
    0x65, 0xF5, 0x10, 0x7F, 0x31, 0xA6, 0x47, 0x85,
    0x93, 0x01, 0x67, 0x88, 0xE1, 0x0E, 0xC7, 0x76,
};

void fido_ctap_ctx_init(fido_ctap_ctx_t *ctx)
{
    memset(ctx, 0, sizeof *ctx);   // user_present starts false
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
//   10 algorithms      [{"alg": -7, "type": "public-key"}]
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
    // WebAuthn PublicKeyCredentialParameters objects, not bare
    // integers — Chromium's GetInfo parser rejects a non-map entry
    // (and falls back to U2F for the whole device). Map keys in
    // canonical sorted order ("alg" < "type").
    fido_cbor_enc_map(&e, 2);
    fido_cbor_enc_text(&e, "alg");
    fido_cbor_enc_negint(&e, FIDO_CTAP_ALG_ES256);
    fido_cbor_enc_text(&e, "type");
    fido_cbor_enc_text(&e, "public-key");

    fido_cbor_enc_uint(&e, 14);           // firmwareVersion
    fido_cbor_enc_uint(&e, FIDO_CTAP_FW_VERSION);

    fido_cbor_enc_uint(&e, 20);           // remainingDiscoverableCredentials
    fido_cbor_enc_uint(&e, FIDO_CTAP_MAX_CREDENTIALS);

    if (e.overflow) {
        // Cannot happen with the transport's 7609-byte response
        // buffer (the map is 84 bytes); a hostile resp_max degrades
        // to a status-only answer instead of a partial CBOR.
        resp[0] = FIDO_CTAP2_ERR_OTHER;
        return;
    }

    resp[0]   = FIDO_CTAP2_OK;
    *resp_len = 1u + e.len;
}

// --- MAKE_CREDENTIAL (CTAP v2.0 §5.1 / v2.1 §6.1) ------------------------------
//
// Request: a CBOR map with top-level INTEGER keys; the nested WebAuthn
// entities (rp, user, the pubKeyCredParams entries, the excludeList
// entries, options) use STRING keys (the v2.0 spec's own sample:
// 2: {"id": "example.com", ...}):
//
//   1   clientDataHash        bytes(32)   required
//   2   rp                    map {"id": text (required), "name": text}
//   3   user                  map {"id": bytes (required), "name": text
//                               (required), "displayName": text (required),
//                               "icon": ...}
//   4   pubKeyCredParams      array of map {"type": "public-key", "alg": int}
//   5   excludeList           array of map {"id": bytes, ...}  (optional)
//   6   pinUvAuthToken        bytes       present -> PIN_AUTH_INVALID
//                                           (this device has no clientPin)
//   7   options               map text -> bool
//   8   largeBlobKey          bytes       ignored (no "lbk" support)
//   9   pinUvAuthProtocol     uint        ignored
//   0x0A enterpriseAttestation value     nonzero/true -> UNSUPPORTED_OPTION
//
// The v2.0 algorithm order (spec §5.1, "When an authenticatorMakeCredential
// request is received...") — parse errors answer at once, then:
//   1. excludeList match        -> wait for UP, then 0x19 (deferred)
//   2. pubKeyCredParams has no  -> 0x26
//                                  supported algorithm
//   3. options: "up" present    -> 0x2C (not a valid CTAP2.0 option —
//                                  user presence is always checked);
//                                  "uv": true -> 0x2B (no UV support);
//                                  "rk" is honored, unknown options
//                                  ignored
//   4. otherwise                -> deferred: wait for UP, then genkey +
//                                  attestation + store + respond.
//
// Response — the v2.1 layout:
//
//   1: "packed"        (string)
//   2: authData        (bytestring)
//   3: { 1: -7, 2: sig } (map — attStmt)
//
// NOTE: the v2.0 spec's table has authData under 0x01 and fmt under
// 0x02 (attStmt a bytestring), but current Chromium parses ONLY the
// v2.1 shape unconditionally (device_response_converter.cc
// ReadCTAPMakeCredentialResponse: 0x01 must be a string, 0x02 a
// bytestring, 0x03 a map — a v2.0-layout answer fails is_string() and
// the whole registration), and python-fido2's AttestationResponse uses
// the v2.1 shape too. So the v2.1 layout is emitted even while
// advertising versions=["FIDO_2_0"]. attStmt carries no x5c —
// self-attestation (WebAuthn §8.2), which is what the
// fido2-demonstration harness verifies (its fido2-lib "packed" handler
// re-checks the signature with the attested key).
//
// authData (WebAuthn §6.1):
//
//   rpIdHash(32) | flags(1) | signCount(4, BE) |
//   aaguid(16) | credIdLen(2, BE) | credId | COSE_Key
//
// flags = 0x41 (UP bit 0 | AT bit 6; no UV — this device cannot do
// user verification). rpIdHash = SHA-256(rp.id). signCount = the
// ATECC608's counter 0, READ (Phase 4 increments it per signature).
// The "packed" signature is over SHA-256(authData ‖ clientDataHash),
// made by the freshly generated credential key.

// ExcludeList entries tracked during the parse (pointers into the
// request; the request buffer outlives the parse — nothing else runs
// between dec_item calls, and the transport blocks a new message while
// the parse holds the channel).
#define FIDO_MC_EXCLUDE_MAX 32

typedef struct {
    fido_mc_pending_t p;
    bool has_cdh;
    bool has_rp_id;
    bool has_user;
    bool has_pkcp;
    uint8_t  rp_id[255];      // max hostname length + margin
    uint16_t rp_id_len;
    bool alg_supported;
    uint8_t opt_err;          // first options error (0 = none)
    const uint8_t *excl[FIDO_MC_EXCLUDE_MAX];
    uint16_t excl_len[FIDO_MC_EXCLUDE_MAX];
    uint8_t n_excl;
} mc_parse_t;

static void mc_begin(fido_ctap_ctx_t *ctx, const fido_mc_pending_t *p)
{
    ctx->pending        = *p;
    ctx->pending_active = true;
    ctx->pending.deadline_ms =
        ctx->keys.clock ?
        ctx->keys.clock(ctx->keys.dev) + FIDO_CTAP_UP_TIMEOUT_MS :
        0;   // no clock hook: the wait never times out
}

// Wrap-safe deadline test for a 32-bit ms clock: timed out when now has
// reached the deadline (valid across the 2^31 ms reach of the diff).
static bool mc_timed_out(uint32_t now_ms, uint32_t deadline_ms)
{
    return (int32_t)(now_ms - deadline_ms) >= 0;
}

// The full parse: 0 with ctx->pending committed (deferred), or a CTAP2
// error code (the caller answers it immediately).
static uint8_t parse_make_credential(fido_ctap_ctx_t *ctx,
                                     const uint8_t *params,
                                     uint32_t params_len)
{
    mc_parse_t m;
    fido_cbor_dec_t d;
    fido_cbor_type_t t;
    uint64_t u;
    const uint8_t *data = NULL;
    uint32_t dlen = 0;

    memset(&m, 0, sizeof m);

    fido_cbor_dec_init(&d, params, params_len);
    if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL) || FIDO_CBOR_MAP != t) {
        return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }

    // Nested headers (map/array counts, booleans) are decoded into `u`,
    // so every loop bound must be captured separately — otherwise a
    // container read clobbers the count its loop iterates over and the
    // remaining keys are seen as trailing bytes.
    const uint64_t n_top = u;
    for (uint64_t i = 0; i < n_top; i++) {
        // Top-level keys are integers (CTAP v2.1 §8).
        if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL) ||
            FIDO_CBOR_UINT != t) {
            return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        switch (u) {
        case 1: {   // clientDataHash
            if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen) ||
                FIDO_CBOR_BYTES != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            if (32 != dlen) {
                return FIDO_CTAP2_ERR_LIMIT_EXCEEDED;
            }
            memcpy(m.p.client_data_hash, data, 32);
            m.has_cdh = true;
            break;
        }
        case 2: {   // rp
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL) ||
                FIDO_CBOR_MAP != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            const uint64_t n_rp = u;
            for (uint64_t j = 0; j < n_rp; j++) {
                if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen) ||
                    FIDO_CBOR_TEXT != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                if (2 == dlen && 0 == memcmp(data, "id", 2)) {
                    if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen) ||
                        FIDO_CBOR_TEXT != t) {
                        return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                    }
                    if (0 == dlen || dlen > sizeof m.rp_id) {
                        return FIDO_CTAP2_ERR_LIMIT_EXCEEDED;
                    }
                    memcpy(m.rp_id, data, dlen);
                    m.rp_id_len = (uint16_t)dlen;
                    m.has_rp_id = true;
                } else {   // "name" (and anything else): not needed
                    if (!fido_cbor_dec_skip(&d)) {
                        return FIDO_CTAP2_ERR_INVALID_CBOR;
                    }
                }
            }
            break;
        }
        case 3: {   // user
            // The sub-fields are OPTIONAL on this device: the
            // fido2-demonstration harness (the FIDO Alliance's own demo
            // tool) sends user = {"name": "dummy"} — no user.id, no
            // displayName — and the spec-strict
            // CTAP2_ERR_MISSING_PARAMETER failed Chrome registration
            // there (bench round 1). This device has no UV, so the user
            // entity is storage metadata only: a request without user.id
            // gets a synthesized 32-byte handle (below, with the credId
            // mint); absent name/displayName stay empty.
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL) ||
                FIDO_CBOR_MAP != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            const uint64_t n_user = u;
            for (uint64_t j = 0; j < n_user; j++) {
                if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen) ||
                    FIDO_CBOR_TEXT != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                if (2 == dlen && 0 == memcmp(data, "id", 2)) {
                    if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen) ||
                        FIDO_CBOR_BYTES != t) {
                        return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                    }
                    if (0 == dlen || dlen > FIDO_CRED_USER_HANDLE_MAX) {
                        return FIDO_CTAP2_ERR_LIMIT_EXCEEDED;
                    }
                    m.p.user_handle_len = (uint8_t)dlen;
                    memcpy(m.p.user_handle, data, dlen);
                } else if (4 == dlen && 0 == memcmp(data, "name", 4)) {
                    if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen) ||
                        FIDO_CBOR_TEXT != t) {
                        return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                    }
                    if (0 == dlen || dlen > FIDO_CRED_NAME_MAX) {
                        return FIDO_CTAP2_ERR_LIMIT_EXCEEDED;
                    }
                    m.p.name_len = (uint8_t)dlen;
                    memcpy(m.p.name, data, dlen);
                } else if (11 == dlen &&
                           0 == memcmp(data, "displayName", 11)) {
                    if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen) ||
                        FIDO_CBOR_TEXT != t) {
                        return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                    }
                    if (0 == dlen || dlen > FIDO_CRED_DISPLAY_NAME_MAX) {
                        return FIDO_CTAP2_ERR_LIMIT_EXCEEDED;
                    }
                    m.p.display_name_len = (uint8_t)dlen;
                    memcpy(m.p.display_name, data, dlen);
                } else {   // "icon" and friends: not needed
                    if (!fido_cbor_dec_skip(&d)) {
                        return FIDO_CTAP2_ERR_INVALID_CBOR;
                    }
                }
            }
            m.has_user = true;
            break;
        }
        case 4: {   // pubKeyCredParams
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL) ||
                FIDO_CBOR_ARRAY != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            m.has_pkcp = true;
            const uint64_t n_pkcp = u;
            for (uint64_t j = 0; j < n_pkcp; j++) {
                bool have_alg = false;
                int64_t alg = 0;
                bool have_type = false;
                bool type_pk = false;
                if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL) ||
                    FIDO_CBOR_MAP != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                const uint64_t n_pk = u;
                for (uint64_t k = 0; k < n_pk; k++) {
                    if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen) ||
                        FIDO_CBOR_TEXT != t) {
                        return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                    }
                    if (3 == dlen && 0 == memcmp(data, "alg", 3)) {
                        if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                            return FIDO_CTAP2_ERR_INVALID_CBOR;
                        }
                        if (FIDO_CBOR_UINT == t) {
                            alg = (int64_t)u;
                        } else if (FIDO_CBOR_NEGINT == t) {
                            alg = -(int64_t)u - 1;
                        } else {
                            return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                        }
                        have_alg = true;
                    } else if (4 == dlen &&
                               0 == memcmp(data, "type", 4)) {
                        if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen) ||
                            FIDO_CBOR_TEXT != t) {
                            return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                        }
                        type_pk = (10 == dlen &&
                                   0 == memcmp(data, "public-key", 10));
                        have_type = true;
                    } else {
                        if (!fido_cbor_dec_skip(&d)) {
                            return FIDO_CTAP2_ERR_INVALID_CBOR;
                        }
                    }
                }
                if (have_alg && FIDO_CTAP_ALG_ES256 == alg &&
                    (!have_type || type_pk)) {
                    m.alg_supported = true;
                }
            }
            break;
        }
        case 5: {   // excludeList
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL) ||
                FIDO_CBOR_ARRAY != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            const uint64_t n_excl = u;
            for (uint64_t j = 0; j < n_excl; j++) {
                if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL) ||
                    FIDO_CBOR_MAP != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                const uint64_t n_ex = u;
                for (uint64_t k = 0; k < n_ex; k++) {
                    if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen) ||
                        FIDO_CBOR_TEXT != t) {
                        return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                    }
                    if (2 == dlen && 0 == memcmp(data, "id", 2)) {
                        if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen) ||
                            FIDO_CBOR_BYTES != t) {
                            return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                        }
                        if (m.n_excl < FIDO_MC_EXCLUDE_MAX) {
                            m.excl[m.n_excl]     = data;
                            m.excl_len[m.n_excl] = (uint16_t)dlen;
                            m.n_excl++;
                        }
                        // past the cap: the entry is skipped (it cannot
                        // match — the stored IDs are <= 64 bytes and a
                        // 256-byte request holds at most a handful)
                    } else {
                        if (!fido_cbor_dec_skip(&d)) {
                            return FIDO_CTAP2_ERR_INVALID_CBOR;
                        }
                    }
                }
            }
            break;
        }
        case 6:
            // pinUvAuthToken: this device advertises no clientPin, so a
            // token cannot be verified (v2.0 §5.1 step 5: pinAuth
            // present with an unsupported pinProtocol -> PIN_AUTH_INVALID).
            return FIDO_CTAP2_ERR_PIN_AUTH_INVALID;
        case 7: {   // options
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL) ||
                FIDO_CBOR_MAP != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            const uint64_t n_opts = u;
            for (uint64_t j = 0; j < n_opts; j++) {
                bool v;
                uint64_t bv;
                if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen) ||
                    FIDO_CBOR_TEXT != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                if (!fido_cbor_dec_item(&d, &t, &bv, NULL, NULL) ||
                    FIDO_CBOR_BOOL != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                v = (1 == bv);
                if (2 == dlen && 0 == memcmp(data, "up", 2)) {
                    // "up" is not a valid makeCredential option for a
                    // CTAP2.0 authenticator (v2.0 §5.1: user presence is
                    // ALWAYS checked; the "up" option belongs to v2.1)
                    // -> INVALID_OPTION, regardless of the value.
                    if (0 == m.opt_err) {
                        m.opt_err = FIDO_CTAP2_ERR_INVALID_OPTION;
                    }
                } else if (2 == dlen && 0 == memcmp(data, "uv", 2)) {
                    // No user verification on this device: uv=true is
                    // known-but-unsupported, uv=false is the default.
                    if (v && 0 == m.opt_err) {
                        m.opt_err = FIDO_CTAP2_ERR_UNSUPPORTED_OPTION;
                    }
                } else {
                    // "rk" is honored (the credential is stored either
                    // way — the demo is resident-capable); unknown
                    // options are ignored (CTAP v2.1 §8).
                    if (2 == dlen && 0 == memcmp(data, "rk", 2)) {
                        m.p.rk = v;
                    }
                }
            }
            break;
        }
        case 8:   // largeBlobKey
        case 9:   // pinUvAuthProtocol
            if (!fido_cbor_dec_skip(&d)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            break;
        case 0x0A: {   // enterpriseAttestation (v2.1; no "ep" advertised)
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            bool requested;
            if (FIDO_CBOR_BOOL == t) {
                requested = (1 == u);
            } else if (FIDO_CBOR_UINT == t) {
                requested = (0 != u);
            } else if (FIDO_CBOR_NEGINT == t) {
                requested = true;
            } else {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            if (requested && 0 == m.opt_err) {
                // Enterprise attestation is not supported on this
                // device.
                m.opt_err = FIDO_CTAP2_ERR_UNSUPPORTED_OPTION;
            }
            break;
        }
        default:   // unknown top-level key: ignored (CTAP v2.1 §8)
            if (!fido_cbor_dec_skip(&d)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            break;
        }
    }

    if (d.p != d.end) {
        return FIDO_CTAP2_ERR_INVALID_CBOR;   // trailing bytes
    }

    // Required parameters (checked after the full parse: an early error
    // would mask a type error in a later key).
    if (!m.has_cdh || !m.has_rp_id || !m.has_user || !m.has_pkcp) {
        return FIDO_CTAP2_ERR_MISSING_PARAMETER;
    }

    // rp.id -> rpIdHash (WebAuthn §6.1: SHA-256 of the rp.id string).
    fido_sha256(m.rp_id, m.rp_id_len, m.p.rp_id_hash);

    // Algorithm step 1 (v2.0 §5.1): an excludeList hit is answered
    // CREDENTIAL_EXCLUDED — but AFTER a user-presence wait, "to behave
    // similarly to CTAP1/U2F authenticators" (deferred below).
    m.p.excluded = false;
    for (uint8_t i = 0; i < m.n_excl; i++) {
        if (fido_cred_store_find_by_cred_id(&ctx->creds, m.p.rp_id_hash,
                                            m.excl[i],
                                            (uint8_t)m.excl_len[i]) >= 0) {
            m.p.excluded = true;
            break;
        }
    }
    if (m.p.excluded) {
        mc_begin(ctx, &m.p);
        return 0;
    }

    // Algorithm step 2.
    if (!m.alg_supported) {
        return FIDO_CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    }

    // Algorithm step 3 (options).
    if (0 != m.opt_err) {
        return m.opt_err;
    }

    // The credential ID: 32 random bytes from the chip's TRNG.
    if (NULL == ctx->keys.rand ||
        0 != ctx->keys.rand(ctx->keys.dev, m.p.cred_id, FIDO_MC_CRED_ID_LEN)) {
        return FIDO_CTAP2_ERR_OTHER;
    }

    // The user handle: the request's user.id when present; a request
    // without it (the fido2-demonstration harness) gets a synthesized
    // 32-byte handle from the same TRNG, so the credential record stays
    // self-consistent and rk overwrites keep working.
    if (0 == m.p.user_handle_len) {
        m.p.user_handle_len = FIDO_MC_CRED_ID_LEN;
        if (0 != ctx->keys.rand(ctx->keys.dev, m.p.user_handle,
                                FIDO_MC_CRED_ID_LEN)) {
            return FIDO_CTAP2_ERR_OTHER;
        }
    }

    mc_begin(ctx, &m.p);
    return 0;
}

// The user-presence-satisfied path: slot allocation, key generation,
// authData + attestation, credential store, response. Returns 1 (the
// transaction is over, resp/*resp_len filled).
static int mc_create(fido_ctap_ctx_t *ctx, uint8_t *resp, uint32_t resp_max,
                     uint32_t *resp_len)
{
    const fido_mc_pending_t *p = &ctx->pending;

    // Slot allocation: an rk request reuses the (rp, user) credential's
    // slot (v2.0 §5.1 step 7: overwrite in place); otherwise the first
    // free record.
    int idx = (p->rk) ?
              fido_cred_store_find_by_user(&ctx->creds, p->rp_id_hash,
                                           p->user_handle, p->user_handle_len)
              : -1;
    if (idx < 0) {
        idx = fido_cred_store_alloc(&ctx->creds);
    }
    if (idx < 0) {
        ctx->pending_active = false;
        resp[0]   = FIDO_CTAP2_ERR_KEY_STORE_FULL;
        *resp_len = 1;
        return 1;
    }
    const uint8_t slot = (uint8_t)(idx + FIDO_CRED_SLOT_MIN);

    // The on-chip key pair (the private key never leaves the ATECC608).
    uint8_t pub[64];
    if (NULL == ctx->keys.genkey ||
        0 != ctx->keys.genkey(ctx->keys.dev, slot, pub)) {
        ctx->pending_active = false;
        resp[0]   = FIDO_CTAP2_ERR_OTHER;
        *resp_len = 1;
        return 1;
    }

    // authData = rpIdHash(32) | flags(1) | signCount(4, BE) |
    //            aaguid(16) | credIdLen(2, BE) | credId | COSE_Key.
    uint8_t authdata[32 + 1 + 4 + 16 + 2 + FIDO_MC_CRED_ID_LEN +
                      FIDO_COSE_ES256_LEN];
    uint32_t n = 0;
    memcpy(&authdata[n], p->rp_id_hash, 32);
    n += 32;
    authdata[n++] = 0x41;   // UP (bit 0) | AT (bit 6); no UV (no UV here)
    const uint32_t ctr =
        ctx->keys.counter ? ctx->keys.counter(ctx->keys.dev) : 0;
    authdata[n++] = (uint8_t)(ctr >> 24);
    authdata[n++] = (uint8_t)(ctr >> 16);
    authdata[n++] = (uint8_t)(ctr >> 8);
    authdata[n++] = (uint8_t)ctr;
    memcpy(&authdata[n], ctx->aaguid, 16);
    n += 16;
    authdata[n++] = 0;
    authdata[n++] = FIDO_MC_CRED_ID_LEN;
    memcpy(&authdata[n], p->cred_id, FIDO_MC_CRED_ID_LEN);
    n += FIDO_MC_CRED_ID_LEN;
    const uint32_t cose = fido_cose_encode_es256(pub, &authdata[n],
                                                 sizeof authdata - n);
    n += cose;   // always FIDO_COSE_ES256_LEN (the buffer is sized for it)

    // Attestation: "packed" self-attestation (no x5c) — the credential
    // key signs SHA-256(authData ‖ clientDataHash).
    uint8_t digest[FIDO_SHA256_DIGEST_LEN];
    fido_sha256_ctx_t sh;
    fido_sha256_init(&sh);
    fido_sha256_update(&sh, authdata, n);
    fido_sha256_update(&sh, p->client_data_hash, 32);
    fido_sha256_final(&sh, digest);

    uint8_t sig[64];
    if (NULL == ctx->keys.sign ||
        0 != ctx->keys.sign(ctx->keys.dev, slot, digest, sig)) {
        ctx->pending_active = false;
        resp[0]   = FIDO_CTAP2_ERR_OTHER;
        *resp_len = 1;
        return 1;
    }

    // Record the credential (the store persists through its save hook
    // FIRST — a failed persistence leaves the store unchanged and the
    // registration fails; the chip slot is re-generable, so the next
    // request self-heals).
    fido_cred_record_t rec;
    memset(&rec, 0, sizeof rec);
    rec.slot = slot;
    memcpy(rec.rp_id_hash, p->rp_id_hash, 32);
    rec.cred_id_len = FIDO_MC_CRED_ID_LEN;
    memcpy(rec.cred_id, p->cred_id, FIDO_MC_CRED_ID_LEN);
    rec.user_handle_len = p->user_handle_len;
    memcpy(rec.user_handle, p->user_handle, p->user_handle_len);
    rec.name_len = p->name_len;
    memcpy(rec.name, p->name, p->name_len);
    rec.display_name_len = p->display_name_len;
    memcpy(rec.display_name, p->display_name, p->display_name_len);
    if (0 != fido_cred_store_insert(&ctx->creds, idx, &rec)) {
        ctx->pending_active = false;
        resp[0]   = FIDO_CTAP2_ERR_OTHER;
        *resp_len = 1;
        return 1;
    }

    // Response map (v2.1 layout — see the section note above).
    fido_cbor_enc_t e;
    fido_cbor_enc_init(&e, resp + 1, resp_max - 1);
    fido_cbor_enc_map(&e, 3);
    fido_cbor_enc_uint(&e, 1);
    fido_cbor_enc_text(&e, "packed");
    fido_cbor_enc_uint(&e, 2);
    fido_cbor_enc_bytes(&e, authdata, n);
    fido_cbor_enc_uint(&e, 3);
    fido_cbor_enc_map(&e, 2);
    fido_cbor_enc_uint(&e, 1);
    fido_cbor_enc_negint(&e, FIDO_CTAP_ALG_ES256);
    fido_cbor_enc_uint(&e, 2);
    fido_cbor_enc_bytes(&e, sig, sizeof sig);
    if (e.overflow) {
        // Cannot happen with a resp_max of FIDO_CTAP_MC_RESP_MAX; a
        // hostile caller with a tiny buffer gets a status-only answer.
        ctx->pending_active = false;
        resp[0]   = FIDO_CTAP2_ERR_OTHER;
        *resp_len = 1;
        return 1;
    }

    ctx->pending_active = false;
    resp[0]   = FIDO_CTAP2_OK;
    *resp_len = 1u + e.len;
    return 1;
}

bool fido_ctap_pending(const fido_ctap_ctx_t *ctx)
{
    return ctx->pending_active;
}

void fido_ctap_abort(fido_ctap_ctx_t *ctx)
{
    ctx->pending_active = false;
}

int fido_ctap_tick(fido_ctap_ctx_t *ctx, bool cancelled,
                   uint8_t *resp, uint32_t resp_max, uint32_t *resp_len)
{
    *resp_len = 0;
    if (!ctx->pending_active || NULL == resp || 0 == resp_max) {
        return 0;
    }

    if (cancelled) {
        // CTAPHID_CANCEL on the transaction's channel (CTAP v2.0
        // §8.1.9.1.7): the response is CTAP2_ERR_KEEPALIVE_CANCEL.
        ctx->pending_active = false;
        ctx->user_present   = false;   // the touch was for this transaction
        resp[0]   = FIDO_CTAP2_ERR_KEEPALIVE_CANCEL;
        *resp_len = 1;
        return 1;
    }

    const fido_mc_pending_t *p = &ctx->pending;
    if (0 != p->deadline_ms &&
        mc_timed_out(ctx->keys.clock(ctx->keys.dev), p->deadline_ms)) {
        // User-presence wait expired (CTAP v2.1 §8.2
        // USER_ACTION_TIMEOUT; the spec requires >= 10 s).
        ctx->pending_active = false;
        ctx->user_present   = false;
        resp[0]   = FIDO_CTAP2_ERR_USER_ACTION_TIMEOUT;
        *resp_len = 1;
        return 1;
    }

    if (!ctx->user_present) {
        return 0;   // still waiting for the touch
    }
    ctx->user_present = false;   // consume the touch

    if (p->excluded) {
        // excludeList hit: the presence wait happened (v2.0 §5.1 step
        // 1), now the exclusion error.
        ctx->pending_active = false;
        resp[0]   = FIDO_CTAP2_ERR_CREDENTIAL_EXCLUDED;
        *resp_len = 1;
        return 1;
    }

    return mc_create(ctx, resp, resp_max, resp_len);
}

void fido_ctap_dispatch(void *vctx, const uint8_t *req, uint32_t req_len,
                        uint8_t *resp, uint32_t resp_max, uint32_t *resp_len)
{
    fido_ctap_ctx_t *ctx = vctx;

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
    case FIDO_CTAP_INS_MAKE_CREDENTIAL: {
        if (ctx->pending_active) {
            // The transport serializes channels (a deferred transaction
            // keeps its channel busy), so this is defensive only.
            resp[0] = FIDO_CTAP2_ERR_OPERATION_PENDING;
            return;
        }
        if (req_len < 2) {
            // No parameters at all: clientDataHash is missing.
            resp[0] = FIDO_CTAP2_ERR_MISSING_PARAMETER;
            return;
        }
        const uint8_t err = parse_make_credential(ctx, req + 1, req_len - 1);
        if (0 != err) {
            resp[0] = err;
            return;
        }
        // Deferred: the response follows fido_ctap_tick() (the
        // user-presence wait); the transport keeps the channel active
        // on *resp_len == 0 (fido2_ctaphid.h).
        *resp_len = 0;
        return;
    }
    default:
        // CTAP v2.1 §8.1: "If an authenticator receives a command code
        // it does not implement, it MUST return
        // CTAP1_ERR_INVALID_COMMAND." (Unimplemented: GET_ASSERTION,
        // RESET — later phases.)
        resp[0] = FIDO_CTAP2_ERR_INVALID_COMMAND;
        return;
    }
}

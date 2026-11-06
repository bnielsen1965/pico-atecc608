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

// GET_INFO. The response map carries the members a real client needs
// to treat this as a resident-capable CTAP2 authenticator; keys are
// numeric and emitted in ascending order (the CTAP2 canonical form
// requires sorted map keys).
//
// KEY NUMBERING — the compatibility-critical detail (rounds C12/C13,
// 2026-11-03/04): the CTAP 2.0 spec's table (aaguid 0x01, versions
// 0x02, options 0x03, ...) was NEVER used by shipping hardware. CTAP
// 2.1 renumbered the table (versions 0x01, extensions 0x02, aaguid
// 0x03, options 0x04, maxMsgSize 0x05, pinUvAuthProtocols 0x06,
// maxCredentialCountInList 0x07, maxCredentialIdLength 0x08,
// transports 0x09, algorithms 0x0A); 2.2 and 2.3 kept it, and every
// real device (the YubiKey vector in Firefox's own test suite) and
// every shipping client parse THAT numbering. Verified 2026-11-04
// against Firefox's AuthenticatorInfo deserializer (dom/webauthn/
// authenticator/src/ctap2/commands/get_info.rs): 0x01 => versions
// (array of text), 0x03 => aaguid (bytes(16)), ...; unknown keys are
// warned and skipped. The 1.0.2-1.0.3 2.0-numbered map put the AAGUID
// bytes under 0x01, which Firefox tried to parse as `versions` ->
// type error -> the whole GetInfo rejected -> U2F fallback (version
// check -> 69 86) -> no makeCredential — the C13 dialog timeout. We
// therefore emit the 2.1+ keys. firmwareVersion is a 2.1+ UINT key
// (0x0E), not an array, so it stays OUT of this map — the firmware
// version is carried by the INIT response instead:
//
//   1   versions        ["FIDO_2_0"]            (required)
//   3   aaguid          <16 bytes>              (required)
//   4   options         {"rk": true, "up": true}
//   5   maxMsgSize      256
//   7   maxCredentialCountInList  128
//   8   maxCredentialIdLength     64
//   9   transports      ["usb"]
//   10  algorithms      [{"alg": -7, "type": "public-key"}]
//
// No "clientPin"/"uv" option and no pinUvAuthProtocols (key 6): this
// device has no PIN and no built-in biometrics — user presence is the
// touch of the board (Phase 4 wires the button).
static void handle_get_info(const fido_ctap_ctx_t *ctx,
                            uint8_t *resp, uint32_t resp_max,
                            uint32_t *resp_len)
{
    fido_cbor_enc_t e;

    if (resp_max < 2) {
        resp[0] = FIDO_CTAP2_ERR_OTHER;   // cannot fit even a stub
        *resp_len = 1;
        return;
    }

    // A CTAPHID_CBOR success response is [CTAP status code][CBOR data]
    // (CTAP 2.3 PS §11.2.9.1.2: DATA = status, DATA+1 = n bytes of CBOR;
    // 0x00 = CTAP2_OK). libfido2's cbor_parse_reply() and the browser
    // stacks both require the 0x00 prefix — a bare CBOR map is read as
    // an unknown error code (0xA9) and the device is rejected.
    resp[0] = FIDO_CTAP2_OK;
    fido_cbor_enc_init(&e, resp + 1, resp_max - 1);
    fido_cbor_enc_map(&e, 8);

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
    // integers — Firefox's (and Chromium's) GetInfo parser rejects a
    // non-map entry. Map keys in canonical sorted order ("alg" < "type").
    fido_cbor_enc_map(&e, 2);
    fido_cbor_enc_text(&e, "alg");
    fido_cbor_enc_negint(&e, FIDO_CTAP_ALG_ES256);
    fido_cbor_enc_text(&e, "type");
    fido_cbor_enc_text(&e, "public-key");

    if (e.overflow) {
        // Cannot happen with the transport's response buffer (the
        // status byte + map is 81 bytes); a hostile resp_max degrades
        // to a status-only answer instead of a partial CBOR.
        resp[0] = FIDO_CTAP2_ERR_OTHER;
        *resp_len = 1;
        return;
    }

    *resp_len = 1 + e.len;   // the 0x00 status byte + the CBOR map
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
//                                           (this device has no
//                                           clientPin); a MAP here is
//                                           the CTAP v2.2 `extensions`
//                                           parameter (v2.2 renumbers
//                                           the table: pinUvAuthToken
//                                           moves to 0x08) — ignored,
//                                           no extensions supported
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
//   3: { "alg": -7, "sig": sig } (map — attStmt, TEXT keys per L3)
//
// NOTE: the v2.0 spec's table has authData under 0x01 and fmt under
// 0x02 (attStmt a bytestring), but current browsers parse ONLY the
// v2.1 shape unconditionally. Verified 2026-11-04 against Firefox's
// `MakeCredentialsResult` deserializer (make_credentials.rs: 0x01 must
// be a string, 0x02 a bytestring = authData, 0x03 a map = attStmt) and
// its own test vector MAKE_CREDENTIALS_SAMPLE_RESPONSE_CTAP2, which is
// exactly this layout — round C14 proved the framing is NOT what
// Firefox rejects (the C14 defect was the COSE_Key crv value, see
// fido_cose.c). So the v2.1 layout is emitted even while advertising
// versions=["FIDO_2_0"]. attStmt carries no x5c — self-attestation
// (WebAuthn §8.2; Firefox's Packed statement takes x5c as
// #[serde(default)]), which is what the fido2-demonstration harness
// verifies (its fido2-lib "packed" handler re-checks the signature
// with the attested key).
//
// authData (WebAuthn L3 §6.5.1):
//
//   rpIdHash(32) | flags(1) | signCount(4, BE) |
//   aaguid(16) | credIdLen(2, BE) | credId | COSE_Key
//
// flags = 0x41 (UP bit 0 | AT bit 6; no UV — this device cannot do
// user verification). The AT bit marks the attested credential data
// that always follows; L3 layout is UP=0x01 UV=0x04 BE=0x08 BS=0x10
// AT=0x40 ED=0x80 (matching the FIDO-certified pico-fido2 reference).
// rpIdHash = SHA-256(rp.id). signCount = the
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

// Open a deferred (UP-waiting) transaction of kind `op`. The caller
// commits the operation's payload (ctx->mc / ctx->ga) first.
static void begin_pending(fido_ctap_ctx_t *ctx, fido_ctap_op_t op)
{
    ctx->pending_op          = op;
    ctx->pending_active      = true;
    ctx->pending_deadline_ms =
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
    if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
        return FIDO_CTAP2_ERR_INVALID_CBOR;
    }
    if (FIDO_CBOR_MAP != t) {
        return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }

    // Nested headers (map/array counts, booleans) are decoded into `u`,
    // so every loop bound must be captured separately — otherwise a
    // container read clobbers the count its loop iterates over and the
    // remaining keys are seen as trailing bytes.
    const uint64_t n_top = u;
    for (uint64_t i = 0; i < n_top; i++) {
        // Top-level keys are integers (CTAP v2.1 §8).
        if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
            return FIDO_CTAP2_ERR_INVALID_CBOR;
        }
        if (FIDO_CBOR_UINT != t) {
            return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        switch (u) {
        case 1: {   // clientDataHash
            if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            if (FIDO_CBOR_BYTES != t) {
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
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            if (FIDO_CBOR_MAP != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            const uint64_t n_rp = u;
            for (uint64_t j = 0; j < n_rp; j++) {
                if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                    return FIDO_CTAP2_ERR_INVALID_CBOR;
                }
                if (FIDO_CBOR_TEXT != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                if (2 == dlen && 0 == memcmp(data, "id", 2)) {
                    if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                        return FIDO_CTAP2_ERR_INVALID_CBOR;
                    }
                    if (FIDO_CBOR_TEXT != t) {
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
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            if (FIDO_CBOR_MAP != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            const uint64_t n_user = u;
            for (uint64_t j = 0; j < n_user; j++) {
                if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                    return FIDO_CTAP2_ERR_INVALID_CBOR;
                }
                if (FIDO_CBOR_TEXT != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                if (2 == dlen && 0 == memcmp(data, "id", 2)) {
                    if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                        return FIDO_CTAP2_ERR_INVALID_CBOR;
                    }
                    if (FIDO_CBOR_BYTES != t) {
                        return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                    }
                    if (0 == dlen || dlen > FIDO_CRED_USER_HANDLE_MAX) {
                        return FIDO_CTAP2_ERR_LIMIT_EXCEEDED;
                    }
                    m.p.user_handle_len = (uint8_t)dlen;
                    memcpy(m.p.user_handle, data, dlen);
                } else if (4 == dlen && 0 == memcmp(data, "name", 4)) {
                    if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                        return FIDO_CTAP2_ERR_INVALID_CBOR;
                    }
                    if (FIDO_CBOR_TEXT != t) {
                        return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                    }
                    if (0 == dlen || dlen > FIDO_CRED_NAME_MAX) {
                        return FIDO_CTAP2_ERR_LIMIT_EXCEEDED;
                    }
                    m.p.name_len = (uint8_t)dlen;
                    memcpy(m.p.name, data, dlen);
                } else if (11 == dlen &&
                           0 == memcmp(data, "displayName", 11)) {
                    if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                        return FIDO_CTAP2_ERR_INVALID_CBOR;
                    }
                    if (FIDO_CBOR_TEXT != t) {
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
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            if (FIDO_CBOR_ARRAY != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            m.has_pkcp = true;
            const uint64_t n_pkcp = u;
            for (uint64_t j = 0; j < n_pkcp; j++) {
                bool have_alg = false;
                int64_t alg = 0;
                bool have_type = false;
                bool type_pk = false;
                if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                    return FIDO_CTAP2_ERR_INVALID_CBOR;
                }
                if (FIDO_CBOR_MAP != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                const uint64_t n_pk = u;
                for (uint64_t k = 0; k < n_pk; k++) {
                    if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                        return FIDO_CTAP2_ERR_INVALID_CBOR;
                    }
                    if (FIDO_CBOR_TEXT != t) {
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
                        if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                            return FIDO_CTAP2_ERR_INVALID_CBOR;
                        }
                        if (FIDO_CBOR_TEXT != t) {
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
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            if (FIDO_CBOR_ARRAY != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            const uint64_t n_excl = u;
            for (uint64_t j = 0; j < n_excl; j++) {
                if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                    return FIDO_CTAP2_ERR_INVALID_CBOR;
                }
                if (FIDO_CBOR_MAP != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                const uint64_t n_ex = u;
                for (uint64_t k = 0; k < n_ex; k++) {
                    if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                        return FIDO_CTAP2_ERR_INVALID_CBOR;
                    }
                    if (FIDO_CBOR_TEXT != t) {
                        return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                    }
                    if (2 == dlen && 0 == memcmp(data, "id", 2)) {
                        if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                            return FIDO_CTAP2_ERR_INVALID_CBOR;
                        }
                        if (FIDO_CBOR_BYTES != t) {
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
        case 6: {   // pinUvAuthToken (v2.0/v2.1) / extensions (v2.2)
            // The VALUE'S TYPE decides which parameter this is: in
            // CTAP v2.0/v2.1, 0x06 is pinUvAuthToken (a byte string);
            // in CTAP v2.2 the table is renumbered and 0x06 is
            // `extensions` (a map of extension id -> input), which
            // modern browsers send unconditionally (bench round C1:
            // Firefox 2026 sent {"hmac-secret": false} to this FIDO_2_0
            // device, and the blanket PIN_AUTH_INVALID failed the
            // registration — Firefox surfaces any CTAP error there as
            // NotAllowedError). A v2.0 authenticator ignores
            // parameters it does not understand (v2.0 §8), so the map
            // is skipped whole; a byte string is a real PIN token this
            // device cannot verify (no clientPin).
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            if (FIDO_CBOR_BYTES == t) {
                return FIDO_CTAP2_ERR_PIN_AUTH_INVALID;
            }
            if (FIDO_CBOR_MAP == t) {
                // The v2.2 `extensions` parameter: no extension is
                // supported on this device — ignore it. The header was
                // consumed above, so skip its `u` key/value pairs.
                for (uint64_t j = 0; j < u; j++) {
                    if (!fido_cbor_dec_skip(&d) ||
                        !fido_cbor_dec_skip(&d)) {
                        return FIDO_CTAP2_ERR_INVALID_CBOR;
                    }
                }
            } else {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            break;
        }
        case 7: {   // options
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            if (FIDO_CBOR_MAP != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            const uint64_t n_opts = u;
            for (uint64_t j = 0; j < n_opts; j++) {
                bool v;
                uint64_t bv;
                if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                    return FIDO_CTAP2_ERR_INVALID_CBOR;
                }
                if (FIDO_CBOR_TEXT != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                if (!fido_cbor_dec_item(&d, &t, &bv, NULL, NULL)) {
                    return FIDO_CTAP2_ERR_INVALID_CBOR;
                }
                if (FIDO_CBOR_BOOL != t) {
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
        ctx->mc = m.p;
        begin_pending(ctx, FIDO_CTAP_OP_MAKING_CREDENTIAL);
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

    ctx->mc = m.p;
    begin_pending(ctx, FIDO_CTAP_OP_MAKING_CREDENTIAL);
    return 0;
}

// --- GET_ASSERTION (CTAP v2.0 §5.2 / v2.3 §6.2) ------------------------------
//
// Request (the table is STABLE across CTAP 2.0 -> 2.3 — unlike
// makeCredential it was never renumbered; verified against the 2.0 PS
// §5.2, the 2.3 spec of record §6.2, Chrome's
// ctap_get_assertion_request.cc and Firefox's GetAssertion::serialize —
// SD-6):
//
//   1   rpId              text          required
//   2   clientDataHash    bytes(32)     required
//   3   allowList         array of map {"id": bytes, "type": text}
//                           (OMITTED when empty — the RP's residents are
//                           enumerated instead)
//   4   extensions        map           ignored (none supported)
//   5   options           map text -> bool
//   6   pinUvAuthParam    bytes         present -> MISSING_PARAMETER
//                           (no pinUvAuthProtocol) or
//                           CTAP1_ERR_INVALID_PARAMETER (an unsupported
//                           protocol — none is supported)
//   7   pinUvAuthProtocol uint          (see 6)
//   8, 9 (2.1+ extras)    ...           ignored
//
// The allowList descriptors use TEXT keys ("id"/"type") — the CTAP 2.0
// PS's own EXAMPLE 5 and Firefox's PublicKeyCredentialDescriptor
// serializer (SD-6).
//
// Options (spec order, 2.3 §6.2.2 step 4): "uv": true ->
// UNSUPPORTED_OPTION (no built-in UV; this device advertises FIDO_2_0,
// and 0x2B is what its clients expect for that case); "rk" present ->
// UNSUPPORTED_OPTION (2.3 step 4.4 — it is not a getAssertion option);
// "up": false -> preflight (served synchronously, the flags' UP bit
// clear); unknown options ignored.
//
// Locate (step 7, BEFORE the UP wait): allowList -> the matching (rp,
// credId) records; no allowList -> every record of the RP (all of ours
// are discoverable). No match -> NO_CREDENTIALS. Serve order: most
// recent first = reverse slot order (a documented approximation — the
// record carries no creation timestamp).
//
// Response (stable 2.0 -> 2.3; SD-6 — INTEGER top-level keys, TEXT keys
// in the nested credential and user maps):
//
//   1: credential { "id": bytes, "type": "public-key" }
//   2: authData
//   3: signature
//   4: user { "id": bytes }   (no name/displayName — user-identifying
//                              data is never returned without UV, 2.3
//                              step 12.3)
//   5: numberOfCredentials    (first getAssertion of a resident
//                              enumeration only; deleted when the
//                              allowList is present, 2.3 step 11)
//
// authData (W3C §6.5.1 — byte-identical layout to makeCredential's,
// verified against both browsers' attested-credential-data parsers):
//
//   rpIdHash(32) | flags(1) | signCount(4 BE) | aaguid(16) |
//   credIdLen(2 BE) | credId | COSE_Key
//
// flags = 0x41 (UP|AT) after a presence wait, 0x40 (AT only) for a
// preflight. The sign counter is INCREMENTED BEFORE the authData is
// built (a failed increment is an error, never a stale-counter
// assertion — the first assertion after a registration must read
// strictly higher than the registration's counter). The signature is
// the credential key's ECDSA over SHA-256(authData ‖ clientDataHash).

// allowList entries beyond this cap are skipped (a 256-byte request
// holds a handful at most; a skipped entry degrades to NO_CREDENTIALS
// at worst — the same convention as makeCredential's excludeList cap).
#define FIDO_GA_ALLOW_MAX   32

typedef struct {
    bool     has_rp_id;
    bool     has_cdh;
    uint8_t  rp_id[255];
    uint16_t rp_id_len;
    uint8_t  cdh[32];
    bool     has_allow;
    const uint8_t *allow[FIDO_GA_ALLOW_MAX];
    uint16_t allow_len[FIDO_GA_ALLOW_MAX];
    uint8_t  n_allow;
    bool     has_pin;        // key 6 present
    bool     has_pin_proto;  // key 7 present
    bool     uv_requested;   // an "uv": true option (spec step 4.1)
    bool     rk_seen;        // an "rk" option (spec step 4.4)
    uint8_t  opt_err;        // the options error (0 = none)
    bool     up;             // false only for an explicit "up": false
} ga_parse_t;

// The full parse: 0 when the request is valid (*out filled), else the
// CTAP2 error code.
static uint8_t ga_parse(const uint8_t *params, uint32_t params_len,
                        ga_parse_t *out)
{
    memset(out, 0, sizeof *out);
    out->up = true;

    fido_cbor_dec_t d;
    fido_cbor_type_t t;
    uint64_t u;
    const uint8_t *data = NULL;
    uint32_t dlen = 0;

    fido_cbor_dec_init(&d, params, params_len);
    if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
        return FIDO_CTAP2_ERR_INVALID_CBOR;
    }
    if (FIDO_CBOR_MAP != t) {
        return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }

    const uint64_t n_top = u;
    for (uint64_t i = 0; i < n_top; i++) {
        if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
            return FIDO_CTAP2_ERR_INVALID_CBOR;
        }
        if (FIDO_CBOR_UINT != t) {
            return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        switch (u) {
        case 1: {   // rpId (text)
            if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            if (FIDO_CBOR_TEXT != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            if (0 == dlen || dlen > sizeof out->rp_id) {
                return FIDO_CTAP2_ERR_LIMIT_EXCEEDED;
            }
            memcpy(out->rp_id, data, dlen);
            out->rp_id_len = (uint16_t)dlen;
            out->has_rp_id = true;
            break;
        }
        case 2: {   // clientDataHash (bytes(32))
            if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            if (FIDO_CBOR_BYTES != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            if (32 != dlen) {
                return FIDO_CTAP2_ERR_LIMIT_EXCEEDED;
            }
            memcpy(out->cdh, data, 32);
            out->has_cdh = true;
            break;
        }
        case 3: {   // allowList (array of descriptor maps)
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            if (FIDO_CBOR_ARRAY != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            out->has_allow = true;
            const uint64_t n_allow = u;
            for (uint64_t j = 0; j < n_allow; j++) {
                if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                    return FIDO_CTAP2_ERR_INVALID_CBOR;
                }
                if (FIDO_CBOR_MAP != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                const uint64_t n_ad = u;
                for (uint64_t k = 0; k < n_ad; k++) {
                    // The descriptor's keys are TEXT ("id", "type").
                    if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                        return FIDO_CTAP2_ERR_INVALID_CBOR;
                    }
                    if (FIDO_CBOR_TEXT != t) {
                        return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                    }
                    if (2 == dlen && 0 == memcmp(data, "id", 2)) {
                        if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                            return FIDO_CTAP2_ERR_INVALID_CBOR;
                        }
                        if (FIDO_CBOR_BYTES != t) {
                            return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                        }
                        if (0 == dlen ||
                            dlen > FIDO_CRED_CRED_ID_MAX) {
                            return FIDO_CTAP2_ERR_LIMIT_EXCEEDED;
                        }
                        if (out->n_allow < FIDO_GA_ALLOW_MAX) {
                            out->allow[out->n_allow] = data;
                            out->allow_len[out->n_allow] = (uint16_t)dlen;
                            out->n_allow++;
                        }
                        // beyond the cap: the entry is skipped
                    } else {
                        // "type" or unknown: the value is ignored.
                        if (!fido_cbor_dec_skip(&d)) {
                            return FIDO_CTAP2_ERR_INVALID_CBOR;
                        }
                    }
                }
            }
            break;
        }
        case 4:   // extensions — none supported; the value is ignored
            // (2.3: an authenticator MUST ignore extensions it does
            // not understand).
            if (!fido_cbor_dec_skip(&d)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            break;
        case 5: {   // options (map text -> bool)
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            if (FIDO_CBOR_MAP != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            const uint64_t n_opt = u;
            for (uint64_t j = 0; j < n_opt; j++) {
                if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                    return FIDO_CTAP2_ERR_INVALID_CBOR;
                }
                if (FIDO_CBOR_TEXT != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                bool v = false;
                if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                    return FIDO_CTAP2_ERR_INVALID_CBOR;
                }
                if (FIDO_CBOR_BOOL != t) {
                    return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                }
                v = (0 != u);
                if (2 == dlen && 0 == memcmp(data, "uv", 2)) {
                    if (v) {
                        out->uv_requested = true;
                    }
                } else if (2 == dlen && 0 == memcmp(data, "rk", 2)) {
                    // 2.3 step 4.4: rk is not a getAssertion option.
                    out->rk_seen = true;
                } else if (2 == dlen && 0 == memcmp(data, "up", 2)) {
                    out->up = v;
                }
                // Unknown option: ignored (treated as absent).
            }
            break;
        }
        case 6: {   // pinUvAuthParam (bytes)
            if (!fido_cbor_dec_item(&d, &t, &u, &data, &dlen)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            if (FIDO_CBOR_BYTES != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            (void)dlen;
            out->has_pin = true;
            break;
        }
        case 7:   // pinUvAuthProtocol (uint) — meaningful only with key
            // 6 (checked after the map, in spec order).
            if (!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            if (FIDO_CBOR_UINT != t) {
                return FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            out->has_pin_proto = true;
            break;
        default:   // 8, 9 (2.1+ extras) and anything else: unknown,
            // ignored (CTAP v2.0 §8).
            if (!fido_cbor_dec_skip(&d)) {
                return FIDO_CTAP2_ERR_INVALID_CBOR;
            }
            break;
        }
    }
    if (d.p != d.end) {
        return FIDO_CTAP2_ERR_INVALID_CBOR;   // trailing bytes
    }

    // The required parameters.
    if (!out->has_rp_id || !out->has_cdh) {
        return FIDO_CTAP2_ERR_MISSING_PARAMETER;
    }

    // pinUvAuthParam without clientPin (2.3 §6.2.2 step 2 — step 1 does
    // not apply, the device supports neither pinUvAuthToken nor
    // clientPin): a missing protocol is MISSING_PARAMETER, a
    // present-but-unsupported protocol CTAP1_ERR_INVALID_PARAMETER.
    if (out->has_pin) {
        return out->has_pin_proto ? FIDO_CTAP2_ERR_INVALID_PARAMETER
                                  : FIDO_CTAP2_ERR_MISSING_PARAMETER;
    }

    // The options, resolved in spec order (2.3 step 4): uv first, then
    // rk — the first error in THAT order wins, regardless of the
    // options' positions in the map. Both are UNSUPPORTED_OPTION 0x2B
    // (not 2.3's INVALID_OPTION 0x2C): this device advertises FIDO_2_0,
    // and 0x2B is the code its clients expect for "no UV available".
    if (out->uv_requested || out->rk_seen) {
        out->opt_err = FIDO_CTAP2_ERR_UNSUPPORTED_OPTION;
    }
    return 0;
}

// Arm the get_next_assertion enumeration state from the located match
// list (the 30-s timer starts now). The state is armed only when a
// "next" exists.
static void ga_enum_begin(fido_ctap_ctx_t *ctx, const fido_ga_pending_t *ga,
                          bool up)
{
    fido_ga_enum_t *en = &ctx->ga_enum;
    // The state is ALWAYS filled — the first assertion is served from
    // it even when no get_next_assertion follows (count == 1, or an
    // allowList match). Only the "there is a next" flag is gated on
    // count.
    memcpy(en->rp_id_hash, ga->rp_id_hash, 32);
    memcpy(en->client_data_hash, ga->client_data_hash, 32);
    en->up        = up;
    en->count     = ga->count;
    memcpy(en->order, ga->order, sizeof en->order);
    en->next_idx  = 1;
    en->deadline_ms =
        ctx->keys.clock ?
        ctx->keys.clock(ctx->keys.dev) + FIDO_CTAP_GA_ENUM_TIMEOUT_MS :
        0;   // no clock hook: no timer
    en->active = (ga->count > 1);   // a get_next_assertion may follow
}

// Build and sign one assertion for the store record at `idx` under the
// enumeration `en`, and emit the response map into resp. Returns 1
// (resp/*resp_len filled; a backend failure fills the status byte).
static int ga_assert(fido_ctap_ctx_t *ctx, const fido_ga_enum_t *en, int idx,
                     bool include_no, uint8_t *resp, uint32_t resp_max,
                     uint32_t *resp_len)
{
    const fido_cred_record_t *rec = &ctx->creds.rec[idx];

    // The sign counter: INCREMENTED BEFORE the authData is built — the
    // first assertion after a registration must read strictly higher
    // than the registration's counter; a failed increment is an error,
    // never a stale-counter assertion.
    uint32_t ctr = 0;
    if (NULL == ctx->keys.counter_inc ||
        0 != ctx->keys.counter_inc(ctx->keys.dev, &ctr)) {
        resp[0]   = FIDO_CTAP2_ERR_OTHER;
        *resp_len = 1;
        return 1;
    }

    // authData (WebAuthn L3 §6.3.3, step 10: the assertion's
    // authenticatorData EXCLUDES the attested credential data — no AT
    // bit, no AAGUID/credId/COSE; the credential travels in the
    // response's "credential" member instead).
    // rpIdHash(32) | flags(1) | signCount(4 BE).
    uint8_t authdata[32 + 1 + 4];
    uint32_t n = 0;
    memcpy(&authdata[n], en->rp_id_hash, 32);
    n += 32;
    authdata[n++] = (uint8_t)(en->up ? 0x01 : 0x00);   // UP only
    authdata[n++] = (uint8_t)(ctr >> 24);
    authdata[n++] = (uint8_t)(ctr >> 16);
    authdata[n++] = (uint8_t)(ctr >> 8);
    authdata[n++] = (uint8_t)ctr;

    // The assertion signature: the credential key over
    // SHA-256(authData ‖ clientDataHash) (WebAuthn L3 §6.1).
    uint8_t digest[FIDO_SHA256_DIGEST_LEN];
    fido_sha256_ctx_t sh;
    fido_sha256_init(&sh);
    fido_sha256_update(&sh, authdata, n);
    fido_sha256_update(&sh, en->client_data_hash, 32);
    fido_sha256_final(&sh, digest);

    uint8_t sig[64];
    if (NULL == ctx->keys.sign ||
        0 != ctx->keys.sign(ctx->keys.dev, rec->slot, digest, sig)) {
        resp[0]   = FIDO_CTAP2_ERR_OTHER;
        *resp_len = 1;
        return 1;
    }
    // WebAuthn L3 section 6.5.5: the ES256 "sig" value MUST be an ASN.1
    // DER Ecdsa-Sig-Value (RFC 3279 section 2.2.3) — not the raw R||S
    // the key backend produces (that is the COSE_Sign form, RFC 9052).
    // The raw form broke every py_webauthn RP (webauthn.io round C20+).
    uint8_t sig_der[FIDO_ECDSA_DER_SIG_MAX];
    const uint32_t sig_der_len =
        fido_ecdsa_der_encode(sig, sig_der, sizeof sig_der);
    if (0 == sig_der_len) {
        resp[0]   = FIDO_CTAP2_ERR_OTHER;   // cannot happen: sized for max
        *resp_len = 1;
        return 1;
    }

    // Response (SD-6): INTEGER top-level keys; TEXT keys in the nested
    // credential and user maps. numberOfCredentials is present on the
    // first response of a resident enumeration only — deleted for an
    // allowList assertion and for every get_next_assertion.
    resp[0] = FIDO_CTAP2_OK;
    fido_cbor_enc_t e;
    fido_cbor_enc_init(&e, resp + 1, resp_max - 1);
    fido_cbor_enc_map(&e, include_no ? 5 : 4);
    fido_cbor_enc_uint(&e, 1);
    fido_cbor_enc_map(&e, 2);
    fido_cbor_enc_text(&e, "id");
    fido_cbor_enc_bytes(&e, rec->cred_id, rec->cred_id_len);
    fido_cbor_enc_text(&e, "type");
    fido_cbor_enc_text(&e, "public-key");
    fido_cbor_enc_uint(&e, 2);
    fido_cbor_enc_bytes(&e, authdata, n);
    fido_cbor_enc_uint(&e, 3);
    fido_cbor_enc_bytes(&e, sig_der, sig_der_len);
    fido_cbor_enc_uint(&e, 4);
    fido_cbor_enc_map(&e, 1);
    fido_cbor_enc_text(&e, "id");
    fido_cbor_enc_bytes(&e, rec->user_handle, rec->user_handle_len);
    if (include_no) {
        fido_cbor_enc_uint(&e, 5);
        fido_cbor_enc_uint(&e, en->count);
    }
    if (e.overflow) {
        // Cannot happen with a resp_max of FIDO_CTAP_GA_RESP_MAX; a
        // hostile caller with a tiny buffer gets a status-only answer.
        resp[0]   = FIDO_CTAP2_ERR_OTHER;
        *resp_len = 1;
        return 1;
    }
    *resp_len = 1 + e.len;   // the 0x00 status byte + the CBOR map
    return 1;
}

// The user-presence-satisfied path: slot allocation, key generation,
// authData + attestation, credential store, response. Returns 1 (the
// transaction is over, resp/*resp_len filled).
static int mc_create(fido_ctap_ctx_t *ctx, uint8_t *resp, uint32_t resp_max,
                     uint32_t *resp_len)
{
    const fido_mc_pending_t *p = &ctx->mc;

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

    // authData (WebAuthn L3 §6.5.1) = rpIdHash(32) | flags(1) |
    //   signCount(4, BE) | aaguid(16) | credIdLen(2, BE) | credId |
    //   COSE_Key.
    //
    // flags = 0x41 = UP (bit 0) | AT (bit 6). The AT (attested-credential
    // data) bit is REQUIRED whenever attested credential data follows the
    // sign count — it always does here — and the L3 flag layout is
    // UP=0x01 UV=0x04 BE=0x08 BS=0x10 AT=0x40 ED=0x80. A client that sees
    // AT=0 with 126 trailing authData bytes rejects the whole response
    // (NotAllowedError). This matches the FIDO-certified pico-fido2
    // reference (FIDO2_AUT_FLAG_AT = 0x40) and the current W3C REC.
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
    authdata[n++] = 0;                        // credIdLen (2 octets, BE)
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
    // WebAuthn L3 section 6.5.5: the packed attestation "sig" MUST be
    // an ASN.1 DER Ecdsa-Sig-Value (RFC 3279 section 2.2.3) — not the
    // raw R||S the key backend produces (the COSE_Sign form, RFC 9052).
    uint8_t sig_der[FIDO_ECDSA_DER_SIG_MAX];
    const uint32_t sig_der_len =
        fido_ecdsa_der_encode(sig, sig_der, sizeof sig_der);
    if (0 == sig_der_len) {
        ctx->pending_active = false;
        resp[0]   = FIDO_CTAP2_ERR_OTHER;   // cannot happen: sized for max
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

    // Response map (v2.1 layout — see the section note above). As with
    // GET_INFO, the CTAPHID_CBOR success framing is [0x00 status][CBOR]
    // (CTAP 2.3 PS §11.2.9.1.2).
    resp[0] = FIDO_CTAP2_OK;
    fido_cbor_enc_t e;
    fido_cbor_enc_init(&e, resp + 1, resp_max - 1);
    fido_cbor_enc_map(&e, 3);
    fido_cbor_enc_uint(&e, 1);
    fido_cbor_enc_text(&e, "packed");
    fido_cbor_enc_uint(&e, 2);
    fido_cbor_enc_bytes(&e, authdata, n);
    fido_cbor_enc_uint(&e, 3);
    // attStmt: WebAuthn L3 defines the "packed" attestation statement with
    // TEXT member names "alg" and "sig" (not the integers 1/2). Browsers
    // validate the statement against those names; integer keys are rejected.
    fido_cbor_enc_map(&e, 2);
    fido_cbor_enc_text(&e, "alg");
    fido_cbor_enc_negint(&e, FIDO_CTAP_ALG_ES256);
    fido_cbor_enc_text(&e, "sig");
    fido_cbor_enc_bytes(&e, sig_der, sig_der_len);
    if (e.overflow) {
        // Cannot happen with a resp_max of FIDO_CTAP_MC_RESP_MAX; a
        // hostile caller with a tiny buffer gets a status-only answer.
        ctx->pending_active = false;
        resp[0]   = FIDO_CTAP2_ERR_OTHER;
        *resp_len = 1;
        return 1;
    }

    ctx->pending_active = false;
    *resp_len = 1 + e.len;   // the 0x00 status byte + the CBOR map
    return 1;
}

bool fido_ctap_pending(const fido_ctap_ctx_t *ctx)
{
    return ctx->pending_active;
}

void fido_ctap_abort(fido_ctap_ctx_t *ctx)
{
    ctx->pending_active = false;
    ctx->pending_op = FIDO_CTAP_OP_NONE;
    // The enumeration state belongs to this connection's browser: a
    // stale 30-s window must not answer a fresh connection's
    // get_next_assertion.
    ctx->ga_enum.active = false;
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

    // The deadline is non-zero only when a clock hook was installed at
    // begin_pending (the hooks are fixed for the context's lifetime).
    if (0 != ctx->pending_deadline_ms &&
        mc_timed_out(ctx->keys.clock(ctx->keys.dev),
                     ctx->pending_deadline_ms)) {
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

    switch (ctx->pending_op) {
    case FIDO_CTAP_OP_MAKING_CREDENTIAL:
        if (ctx->mc.excluded) {
            // excludeList hit: the presence wait happened (v2.0 §5.1
            // step 1), now the exclusion error.
            ctx->pending_active = false;
            resp[0]   = FIDO_CTAP2_ERR_CREDENTIAL_EXCLUDED;
            *resp_len = 1;
            return 1;
        }
        return mc_create(ctx, resp, resp_max, resp_len);
    case FIDO_CTAP_OP_GETTING_ASSERTION: {
        // The presence wait is over: arm the enumeration state (the
        // 30-s window for get_next_assertion) and serve the first
        // located credential.
        ctx->pending_active = false;
        const fido_ga_pending_t *ga = &ctx->ga;
        ga_enum_begin(ctx, ga, true);
        return ga_assert(ctx, &ctx->ga_enum, ga->order[0], !ga->allow,
                         resp, resp_max, resp_len);
    }
    case FIDO_CTAP_OP_RESETTING: {
        // Wipe the credential DB (persisted first, per record) and —
        // in the littlefs-counter build — zero the counter (the chip's
        // monotonic counter never resets; its hook is NULL there). The
        // on-chip key pairs remain; the next makeCredential rebinds the
        // slots (GenKey regenerates them).
        ctx->pending_active = false;
        ctx->ga_enum.active = false;
        int err = 0;
        for (int i = 0; i < FIDO_CRED_MAX && 0 == err; i++) {
            if (ctx->creds.present[i]) {
                err = fido_cred_store_erase(&ctx->creds, i);
            }
        }
        if (0 == err && NULL != ctx->keys.counter_zero) {
            err = ctx->keys.counter_zero(ctx->keys.dev);
        }
        if (0 != err) {
            resp[0] = FIDO_CTAP2_ERR_OTHER;   // a failed reset is not a success
        } else {
            resp[0] = FIDO_CTAP2_OK;          // bare status byte, no CBOR
        }
        *resp_len = 1;
        return 1;
    }
    default:
        // Corrupted state: abort with an error.
        ctx->pending_active = false;
        resp[0]   = FIDO_CTAP2_ERR_OTHER;
        *resp_len = 1;
        return 1;
    }
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
    case FIDO_CTAP_INS_GET_ASSERTION: {
        if (ctx->pending_active) {
            // The transport serializes channels (a deferred transaction
            // keeps its channel busy), so this is defensive only.
            resp[0] = FIDO_CTAP2_ERR_OPERATION_PENDING;
            return;
        }
        if (req_len < 2) {
            // No parameters at all: rpId and clientDataHash are missing.
            resp[0] = FIDO_CTAP2_ERR_MISSING_PARAMETER;
            return;
        }
        ga_parse_t m;
        const uint8_t err = ga_parse(req + 1, req_len - 1, &m);
        if (0 != err) {
            resp[0] = err;
            return;
        }
        if (0 != m.opt_err) {
            resp[0] = m.opt_err;
            return;
        }

        // rpId -> its hash (WebAuthn: SHA-256 of the rpId string).
        uint8_t rp_id_hash[32];
        fido_sha256(m.rp_id, m.rp_id_len, rp_id_hash);

        // Locate (2.3 step 7 — BEFORE the UP wait): the allowList's
        // matches, or — when absent — every record of the RP (all of
        // ours are discoverable). Serve order: reverse slot order (the
        // most-recent-first proxy).
        fido_ga_pending_t *ga = &ctx->ga;
        memset(ga, 0, sizeof *ga);
        memcpy(ga->rp_id_hash, rp_id_hash, 32);
        memcpy(ga->client_data_hash, m.cdh, 32);
        ga->allow = (m.has_allow && 0 < m.n_allow);
        if (ga->allow) {
            uint8_t found = 0;
            for (uint8_t j = 0; j < m.n_allow; j++) {
                const int idx =
                    fido_cred_store_find_by_cred_id(&ctx->creds, rp_id_hash,
                                                    m.allow[j],
                                                    m.allow_len[j]);
                if (idx >= 0) {
                    found |= (uint8_t)(1u << idx);
                }
            }
            for (int i = FIDO_CRED_MAX - 1; 0 <= i; i--) {
                if (found & (uint8_t)(1u << i)) {
                    ga->order[ga->count++] = (uint8_t)i;
                }
            }
        } else {
            for (int i = FIDO_CRED_MAX - 1; 0 <= i; i--) {
                if (ctx->creds.present[i] &&
                    0 == memcmp(ctx->creds.rec[i].rp_id_hash, rp_id_hash,
                                32)) {
                    ga->order[ga->count++] = (uint8_t)i;
                }
            }
        }
        if (0 == ga->count) {
            resp[0] = FIDO_CTAP2_ERR_NO_CREDENTIALS;
            return;
        }

        // "up": false (preflight, 2.3 step 12.2): a synchronous full
        // assertion, the flags' UP bit clear.
        if (!m.up) {
            ga_enum_begin(ctx, ga, false);
            ga_assert(ctx, &ctx->ga_enum, ga->order[0], !ga->allow,
                      resp, resp_max, resp_len);
            return;
        }

        // Deferred: the first assertion follows fido_ctap_tick() after
        // the user-presence wait.
        begin_pending(ctx, FIDO_CTAP_OP_GETTING_ASSERTION);
        *resp_len = 0;
        return;
    }
    case FIDO_CTAP_INS_RESET: {
        // No parameters (2.3 §6.6).
        if (ctx->pending_active) {
            resp[0] = FIDO_CTAP2_ERR_OPERATION_PENDING;
            return;
        }
        if (req_len > 1) {
            fido_cbor_dec_t d;
            fido_cbor_dec_init(&d, req + 1, req_len - 1);
            if (!fido_cbor_dec_skip(&d) || d.p != d.end) {
                resp[0] = FIDO_CTAP2_ERR_INVALID_CBOR;
                return;
            }
        }
        // Displayless authenticator: the request must have arrived
        // within 10 s of power-on (2.3 §6.6). The clock is
        // uptime-based, so the window is clock() <= 10 s; without a
        // clock hook it cannot be measured and is not enforced.
        if (NULL != ctx->keys.clock &&
            ctx->keys.clock(ctx->keys.dev) > FIDO_CTAP_RESET_WINDOW_MS) {
            resp[0] = FIDO_CTAP2_ERR_NOT_ALLOWED;
            return;
        }
        // User presence is required (deferred; the 30-s timeout is
        // USER_ACTION_TIMEOUT, the tick's business).
        begin_pending(ctx, FIDO_CTAP_OP_RESETTING);
        *resp_len = 0;
        return;
    }
    case FIDO_CTAP_INS_GET_NEXT_ASSERTION: {
        // No parameters (2.3 §6.3: "It takes no arguments").
        if (ctx->pending_active) {
            resp[0] = FIDO_CTAP2_ERR_OPERATION_PENDING;
            return;
        }
        if (req_len > 1) {
            fido_cbor_dec_t d;
            fido_cbor_dec_init(&d, req + 1, req_len - 1);
            if (!fido_cbor_dec_skip(&d) || d.p != d.end) {
                resp[0] = FIDO_CTAP2_ERR_INVALID_CBOR;
                return;
            }
        }
        // Spec order (§6.3 steps 1-3): no remembered state, then
        // exhausted, then the 30-s timer (expired -> discard the state).
        fido_ga_enum_t *en = &ctx->ga_enum;
        if (!en->active || en->next_idx >= en->count) {
            resp[0] = FIDO_CTAP2_ERR_NOT_ALLOWED;
            return;
        }
        if (0 != en->deadline_ms &&
            mc_timed_out(ctx->keys.clock(ctx->keys.dev), en->deadline_ms)) {
            en->active = false;
            resp[0] = FIDO_CTAP2_ERR_NOT_ALLOWED;
            return;
        }
        const int idx = en->order[en->next_idx];
        en->next_idx++;
        en->deadline_ms = ctx->keys.clock ?
            ctx->keys.clock(ctx->keys.dev) + FIDO_CTAP_GA_ENUM_TIMEOUT_MS :
            0;   // the timer restarts with every get_next_assertion
        ga_assert(ctx, en, idx, false, resp, resp_max, resp_len);
        return;
    }
    default:
        // CTAP v2.1 §8.1: "If an authenticator receives a command code
        // it does not implement, it MUST return
        // CTAP1_ERR_INVALID_COMMAND." (Unimplemented: CLIENT_PIN — the
        // device advertises no PIN support — and the vendor range.)
        resp[0] = FIDO_CTAP2_ERR_INVALID_COMMAND;
        return;
    }
}

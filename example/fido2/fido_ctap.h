// fido_ctap.h
//
// CTAP2 (FIDO2) command dispatch — the message layer above the CTAPHID
// transport (fido_ctaphid.c), per the CTAP v2.1 spec (errata 2022-06-21)
// and its v2.0 predecessor. Pure C, no USB or Pico dependency, so the
// protocol logic is host-tested in tests/test_ctap.c.
//
// A CTAPHID_CBOR message payload is a command byte followed by the
// parameters (CTAP v2.1 §8.1 and §11.2.9.1.2; v2.0 §6.1):
//
//     ins (1) | parameters
//
// The parameters are a CBOR map in the CTAP2 canonical form (CTAP v2.1
// §8), or absent for commands that take no inputs. Neither the channel
// nor the length appears in the message: the channel is the CTAPHID CID
// and the length is the CTAPHID BCNT field. The response on success is
// the CTAP status byte 0x00 (CTAP2_OK) followed by the CBOR payload
// (CTAP 2.3 PS §11.2.9.1.2: DATA = status, DATA+1 = CBOR — the
// libfido2 and browser stacks both require the 0x00 prefix); on failure
// it is a single status byte (a CTAP2 error code, 0x01-0xff) — exactly
// the fido2_cbor_cb_t contract the transport hands the handler (see
// fido_ctaphid.h).
//
// The dispatch implements GET_INFO (0x04), MAKE_CREDENTIAL (0x01),
// GET_ASSERTION (0x02), GET_NEXT_ASSERTION (0x08) and RESET (0x07).
// A request whose answer needs user presence is
// parsed synchronously (errors answered at once), then the handler
// returns with *resp_len == 0 and the transport keeps the channel
// active (keep-alives with status UP_NEEDED, CANCEL recorded) until
// user presence is recorded and fido_ctap_tick() completes the
// transaction — key generation, attestation, credential storage and
// the final response (makeCredential); signing the assertion
// (getAssertion); or wiping the store (RESET). A getAssertion with
// options "up": false (preflight) is served synchronously instead.
// CLIENT_PIN (0x06) and the vendor range remain unimplemented and
// answer CTAP1_ERR_INVALID_COMMAND.

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "fido_cred.h"     // the credential store (the record type)
#include "fido_ctaphid.h"  // fido2_cbor_cb_t (the handler contract)

// Command codes (CTAP v2.0 §6.1 / v2.1 §8.1).
enum {
    FIDO_CTAP_INS_MAKE_CREDENTIAL    = 0x01,
    FIDO_CTAP_INS_GET_ASSERTION      = 0x02,
    FIDO_CTAP_INS_GET_INFO           = 0x04,
    FIDO_CTAP_INS_CLIENT_PIN         = 0x06,
    FIDO_CTAP_INS_RESET              = 0x07,
    FIDO_CTAP_INS_GET_NEXT_ASSERTION = 0x08,
    // 0x40-0xBF is the vendor range — unimplemented here, so it takes
    // the same INVALID_COMMAND answer as anything else.
};

// Status codes (CTAP v2.1 §8.2; the v2.0 table is a subset). 0x01-0x0B
// are shared with U2FHID; the rest are CTAP2-specific. NOT_ALLOWED
// (0x30) is 2.1+; every other code used here exists in both tables.
enum {
    FIDO_CTAP2_OK                         = 0x00,
    FIDO_CTAP2_ERR_INVALID_COMMAND        = 0x01,  // CTAP1_ERR_INVALID_COMMAND
    FIDO_CTAP2_ERR_INVALID_PARAMETER      = 0x02,
    FIDO_CTAP2_ERR_INVALID_LENGTH         = 0x03,
    FIDO_CTAP2_ERR_INVALID_SEQ            = 0x04,
    FIDO_CTAP2_ERR_TIMEOUT                = 0x05,
    FIDO_CTAP2_ERR_CHANNEL_BUSY           = 0x06,
    FIDO_CTAP2_ERR_LOCK_REQUIRED          = 0x0A,
    FIDO_CTAP2_ERR_INVALID_CHANNEL        = 0x0B,
    FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE   = 0x11,
    FIDO_CTAP2_ERR_INVALID_CBOR           = 0x12,
    FIDO_CTAP2_ERR_MISSING_PARAMETER      = 0x14,
    FIDO_CTAP2_ERR_LIMIT_EXCEEDED         = 0x15,
    FIDO_CTAP2_ERR_CREDENTIAL_EXCLUDED    = 0x19,
    FIDO_CTAP2_ERR_PROCESSING             = 0x21,
    FIDO_CTAP2_ERR_INVALID_CREDENTIAL     = 0x22,
    FIDO_CTAP2_ERR_OPERATION_PENDING      = 0x24,
    FIDO_CTAP2_ERR_UNSUPPORTED_ALGORITHM  = 0x26,
    FIDO_CTAP2_ERR_OPERATION_DENIED       = 0x27,
    FIDO_CTAP2_ERR_KEY_STORE_FULL         = 0x28,
    FIDO_CTAP2_ERR_PIN_AUTH_INVALID        = 0x2A,
    FIDO_CTAP2_ERR_UNSUPPORTED_OPTION      = 0x2B,
    FIDO_CTAP2_ERR_INVALID_OPTION          = 0x2C,
    FIDO_CTAP2_ERR_KEEPALIVE_CANCEL       = 0x2D,
    FIDO_CTAP2_ERR_NO_CREDENTIALS         = 0x2E,
    FIDO_CTAP2_ERR_USER_ACTION_TIMEOUT    = 0x2F,
    FIDO_CTAP2_ERR_NOT_ALLOWED            = 0x30,  // CTAP 2.1+ (get_next_assertion, the RESET 10-s window)
    FIDO_CTAP2_ERR_REQUEST_TOO_LARGE      = 0x39,
    FIDO_CTAP2_ERR_ACTION_TIMEOUT         = 0x3A,
    FIDO_CTAP2_ERR_UP_REQUIRED            = 0x3B,
    FIDO_CTAP2_ERR_OTHER                  = 0x7F,  // CTAP1_ERR_OTHER
};

// GET_INFO values — the device's CTAP2 identity (CTAP v2.0 §5.4).
//
// maxMsgSize 256: the transport's message buffer is 7609 bytes, but the
// declared value bounds what clients may send; 256 is the common
// real-world value (SoloKey) and covers every request shape
// (a makeCredential with a 64-byte credential ID is well under).
#define FIDO_CTAP_MAX_MSG_SIZE      256
// allow-list cap for GET_ASSERTION (spec: > 0 if present). 128 entries
// will never fit a 256-byte message anyway; the field is a cap, not a
// promise.
#define FIDO_CTAP_MAX_CRED_LIST     128
// Longest credential ID we accept (spec: > 0 if present). Browsers
// mint 32-64 byte IDs.
#define FIDO_CTAP_MAX_CRED_ID_LEN   64
// Resident-key capacity — the credential DB holds four records (see
// FIDO_CRED_MAX); also the GET_INFO
// remainingDiscoverableCredentials value.
#define FIDO_CTAP_MAX_CREDENTIALS   4

// COSE algorithm identifier for ES256 (P-256, SHA-256) — the only
// algorithm this device supports (the ATECC608 is ECC-only).
#define FIDO_CTAP_ALG_ES256 (-7)

// The user-presence wait of a MakeCredential: the spec requires >= 10 s
// (user action timeout); 30 s matches real keys.
#define FIDO_CTAP_UP_TIMEOUT_MS     30000
// The credential ID length we mint (32 random bytes from the chip's
// TRNG — browsers accept 32-64).
#define FIDO_MC_CRED_ID_LEN         32
// Largest MakeCredential response this firmware builds: map(3)
// with a 64-byte credential ID, the 77-byte COSE key and the 72-byte
// DER attestation signature = 294 bytes (the device mints 32-byte IDs,
// so real responses are 260).
#define FIDO_CTAP_MC_RESP_MAX       296
// Largest getAssertion / get_next_assertion response this firmware
// builds: the 5-entry map with a 64-byte credential ID, the 37-byte
// assertion authData (32+1+4 — no attested credential data, WebAuthn
// L3 6.3.3) and the 72-byte DER signature = 278 bytes (246 with the
// 32-byte IDs the device stores).
#define FIDO_CTAP_GA_RESP_MAX       424
// The RESET 10-second power-on window (CTAP v2.3 §6.6, displayless
// authenticators): a RESET arriving later answers NOT_ALLOWED.
#define FIDO_CTAP_RESET_WINDOW_MS   10000
// The get_next_assertion 30-second enumeration timer (CTAP v2.3 §6.3):
// a gap longer than this discards the enumeration state.
#define FIDO_CTAP_GA_ENUM_TIMEOUT_MS 30000

// The key backend the CTAP layer signs with (the ATECC608 on the Pico;
// deterministic fakes in the host tests). Every hook is
// optional (NULL = the operation is impossible, which the command
// answers CTAP2_ERR_OTHER), but a working registration needs
// genkey/sign/rand/clock and a working login needs get_pubkey and
// counter_inc on top. All return 0 on success, non-zero on failure;
// `dev` is the app's chip handle.
typedef struct {
    // Fresh P-256 key pair in chip `slot`; pub = X(32) ‖ Y(32).
    int  (*genkey)(void *dev, uint8_t slot, uint8_t pub[64]);
    // The P-256 public key of the key pair in `slot`; pub = X(32) ‖
    // Y(32). READ-ONLY on the chip (it recomputes from the private
    // key), so it works even with the data zone locked — the credential
    // record stores no key material, and the assertion authData's
    // COSE_Key comes from here.
    int  (*get_pubkey)(void *dev, uint8_t slot, uint8_t pub[64]);
    // Sign a 32-byte digest with the key in `slot`; sig = 64-byte r‖s.
    int  (*sign)(void *dev, uint8_t slot, const uint8_t digest[32],
                 uint8_t sig[64]);
    // The CTAP sync counter, read (MakeCredential's authData signCount).
    uint32_t (*counter)(void *dev);
    // Increment the CTAP sync counter and report the new value in
    // *new_value. GetAssertion calls this BEFORE building its authData
    // (the first assertion after a registration must read strictly
    // higher than the registration's counter); a failure is an error —
    // never a stale-counter assertion.
    int  (*counter_inc)(void *dev, uint32_t *new_value);
    // Reset the CTAP sync counter to 0 (RESET / console wipe). NULL
    // when the counter cannot be reset (the chip's monotonic counter).
    int  (*counter_zero)(void *dev);
    // Random bytes (the chip's TRNG).
    int  (*rand)(void *dev, uint8_t *buf, uint32_t len);
    // Current time in ms — the UP-wait deadline and the RESET window
    // are measured against it (NULL = the wait never times out and the
    // RESET window is not enforced).
    uint32_t (*clock)(void *dev);
    void *dev;
} fido_ctap_key_ops_t;

// A deferred (UP-waiting) MakeCredential transaction.
typedef struct {
    uint8_t  client_data_hash[32];
    uint8_t  rp_id_hash[32];   // SHA-256(rp.id)
    uint8_t  cred_id[FIDO_MC_CRED_ID_LEN];
    uint8_t  user_handle_len;
    uint8_t  user_handle[FIDO_CRED_USER_HANDLE_MAX];
    uint8_t  name_len;
    char     name[FIDO_CRED_NAME_MAX];
    uint8_t  display_name_len;
    char     display_name[FIDO_CRED_DISPLAY_NAME_MAX];
    bool     rk;        // resident key requested (overwrite semantics)
    bool     excluded;  // excludeList matched: CREDENTIAL_EXCLUDED after UP
} fido_mc_pending_t;

// A deferred (UP-waiting) getAssertion: the request hashes plus the
// located credentials in serve order (store indices; most recent first
// — the reverse slot order, the documented proxy for "reverse creation
// order", the record has no timestamp).
typedef struct {
    uint8_t rp_id_hash[32];
    uint8_t client_data_hash[32];
    bool    allow;     // an effective allowList was present: the response
                       // carries no numberOfCredentials, and no
                       // get_next_assertion follows
    uint8_t count;
    uint8_t order[FIDO_CRED_MAX];
} fido_ga_pending_t;

// The get_next_assertion enumeration state — separate from the pending
// transaction (no channel is held: the browser drives it, one call per
// credential, each within the 30-s window).
typedef struct {
    bool     active;
    uint8_t  rp_id_hash[32];
    uint8_t  client_data_hash[32];
    bool     up;               // the UP bit of the served authData flags
    uint8_t  count;
    uint8_t  next_idx;         // index into order[] of the next credential
    uint8_t  order[FIDO_CRED_MAX];
    uint32_t deadline_ms;      // 0 = no timer (no clock hook installed)
} fido_ga_enum_t;

// The kind of deferred transaction the context is waiting out (at most
// one at a time; fido_ctap_pending / fido_ctap_tick).
typedef enum {
    FIDO_CTAP_OP_NONE = 0,
    FIDO_CTAP_OP_MAKING_CREDENTIAL,
    FIDO_CTAP_OP_GETTING_ASSERTION,
    FIDO_CTAP_OP_RESETTING,
} fido_ctap_op_t;

// The dispatch context: the identity (AAGUID), the key backend, the
// credential store, the pending transaction (the three UP-waiting
// operations) and the get_next_assertion state.
typedef struct {
    uint8_t aaguid[16];   // the claimed AAGUID (fixed per firmware)
    // User presence: the app records a "touch" here — today the UART0
    // console's 'up' command, later a physical button on a free GPIO.
    // fido_ctap_tick() consumes the flag when a deferred transaction
    // completes on it.
    volatile bool user_present;

    fido_ctap_key_ops_t keys;    // the ATECC608 (app-installed)
    fido_cred_store_t   creds;   // the resident-credential DB

    // The deferred transaction (at most one at a time).
    fido_ctap_op_t      pending_op;
    bool                pending_active;
    uint32_t            pending_deadline_ms;  // 0 = no timeout (no clock)
    fido_mc_pending_t   mc;     // valid while pending_op == MAKING_CREDENTIAL
    fido_ga_pending_t   ga;     // valid while pending_op == GETTING_ASSERTION
    fido_ga_enum_t      ga_enum; // get_next_assertion state (no channel)
} fido_ctap_ctx_t;

// Fill the context with this firmware's identity (the fixed AAGUID) and
// zero the rest (the app installs the key ops and the credential
// persistence hooks afterwards).
void fido_ctap_ctx_init(fido_ctap_ctx_t *ctx);

// The CTAP2 dispatch — implements fido2_cbor_cb_t, so it installs
// directly with fido2_ctaphid_set_cbor(). ctx must be a
// fido_ctap_ctx_t initialized with fido_ctap_ctx_init(). A request
// whose answer waits for user presence (MakeCredential; getAssertion
// with "up" true or absent; RESET) returns with *resp_len == 0
// (deferred — see the file header); every other outcome fills
// resp/*resp_len at once.
void fido_ctap_dispatch(void *ctx, const uint8_t *req, uint32_t req_len,
                        uint8_t *resp, uint32_t resp_max, uint32_t *resp_len);

// True while a deferred (UP-waiting) MakeCredential is in progress.
bool fido_ctap_pending(const fido_ctap_ctx_t *ctx);

// Drive a pending transaction from the main loop. Returns 1 and fills
// resp/*resp_len (the 0x00 status byte + CBOR payload on success, a
// single status byte on error — as the transport expects) when the
// transaction finished; 0
// (with *resp_len == 0) while it still waits.
// `cancelled` is the transport's fido2_ctaphid_cancelled() — a recorded
// CTAPHID_CANCEL finishes the transaction with CTAP2 0x2D. A completed
// transaction consumes the recorded user presence (when it used one).
int fido_ctap_tick(fido_ctap_ctx_t *ctx, bool cancelled,
                   uint8_t *resp, uint32_t resp_max, uint32_t *resp_len);

// Abort a pending transaction WITHOUT a response (the USB connection
// died — the host's channels are gone). Call on unmount.
void fido_ctap_abort(fido_ctap_ctx_t *ctx);

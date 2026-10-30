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
// and the length is the CTAPHID BCNT field. The response is a status
// byte (0x00 on success, a CTAP2 error code otherwise) followed by the
// CBOR payload on success — exactly the fido2_cbor_cb_t contract the
// transport hands the handler (see fido_ctaphid.h).
//
// Phase 2 implements GET_INFO (0x04) only. Every other command code
// answers CTAP1_ERR_INVALID_COMMAND (0x01) — the spec's MUST for an
// unimplemented command; MAKE_CREDENTIAL / GET_ASSERTION / RESET land
// in later phases and are added to the dispatch table as they arrive.

#pragma once

#include <stdint.h>

#include "fido_ctaphid.h"   // fido2_cbor_cb_t (the handler contract)

// Command codes (CTAP v2.0 §6.1 / v2.1 §8.1).
enum {
    FIDO_CTAP_INS_MAKE_CREDENTIAL   = 0x01,
    FIDO_CTAP_INS_GET_ASSERTION     = 0x02,
    FIDO_CTAP_INS_GET_INFO          = 0x04,
    FIDO_CTAP_INS_CLIENT_PIN        = 0x06,
    FIDO_CTAP_INS_RESET             = 0x07,
    FIDO_CTAP_INS_GET_NEXT_ASSERTION = 0x08,
    // 0x40-0xBF is the vendor range — unimplemented here, so it takes
    // the same INVALID_COMMAND answer as anything else.
};

// Status codes (CTAP v2.1 §8.2). 0x01-0x0B are shared with U2FHID; the
// rest are CTAP2-specific.
enum {
    FIDO_CTAP2_OK                        = 0x00,
    FIDO_CTAP2_ERR_INVALID_COMMAND       = 0x01,  // CTAP1_ERR_INVALID_COMMAND
    FIDO_CTAP2_ERR_INVALID_PARAMETER     = 0x02,
    FIDO_CTAP2_ERR_INVALID_LENGTH        = 0x03,
    FIDO_CTAP2_ERR_INVALID_SEQ           = 0x04,
    FIDO_CTAP2_ERR_TIMEOUT               = 0x05,
    FIDO_CTAP2_ERR_CHANNEL_BUSY          = 0x06,
    FIDO_CTAP2_ERR_LOCK_REQUIRED         = 0x0A,
    FIDO_CTAP2_ERR_INVALID_CHANNEL       = 0x0B,
    FIDO_CTAP2_ERR_CBOR_UNEXPECTED_TYPE  = 0x11,
    FIDO_CTAP2_ERR_INVALID_CBOR          = 0x12,
    FIDO_CTAP2_ERR_MISSING_PARAMETER     = 0x14,
    FIDO_CTAP2_ERR_LIMIT_EXCEEDED        = 0x15,
    FIDO_CTAP2_ERR_CREDENTIAL_EXCLUDED   = 0x19,
    FIDO_CTAP2_ERR_PROCESSING            = 0x21,
    FIDO_CTAP2_ERR_INVALID_CREDENTIAL    = 0x22,
    FIDO_CTAP2_ERR_OPERATION_PENDING     = 0x24,
    FIDO_CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26,
    FIDO_CTAP2_ERR_OPERATION_DENIED      = 0x27,
    FIDO_CTAP2_ERR_KEY_STORE_FULL        = 0x28,
    FIDO_CTAP2_ERR_UNSUPPORTED_OPTION    = 0x2B,
    FIDO_CTAP2_ERR_INVALID_OPTION        = 0x2C,
    FIDO_CTAP2_ERR_NO_CREDENTIALS        = 0x2E,
    FIDO_CTAP2_ERR_REQUEST_TOO_LARGE     = 0x39,
    FIDO_CTAP2_ERR_ACTION_TIMEOUT        = 0x3A,
    FIDO_CTAP2_ERR_UP_REQUIRED           = 0x3B,
    FIDO_CTAP2_ERR_OTHER                 = 0x7F,  // CTAP1_ERR_OTHER
};

// GET_INFO values — the device's CTAP2 identity (CTAP v2.0 §5.4).
//
// maxMsgSize 256: the transport's message buffer is 7609 bytes, but the
// declared value bounds what clients may send; 256 is the common
// real-world value (SoloKey) and covers every Phase 2-4 request shape
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
// PLAN.md Phase 3 layout); also the GET_INFO
// remainingDiscoverableCredentials value.
#define FIDO_CTAP_MAX_CREDENTIALS   4
// CTAP v2.1 §6.2: "Whenever releasing any code change to the
// authenticator firmware, the authenticator MUST increase the
// version." Start at 1.
#define FIDO_CTAP_FW_VERSION        1

// COSE algorithm identifier for ES256 (P-256, SHA-256) — the only
// algorithm this device supports (the ATECC608 is ECC-only).
#define FIDO_CTAP_ALG_ES256 (-7)

// The dispatch context: Phase 2 is read-only identity data. Later
// phases extend this (credential store, ATECC handles).
typedef struct {
    uint8_t aaguid[16];   // the claimed AAGUID (fixed per firmware)
} fido_ctap_ctx_t;

// Fill the context with this firmware's identity (the fixed AAGUID).
void fido_ctap_ctx_init(fido_ctap_ctx_t *ctx);

// The CTAP2 dispatch — implements fido2_cbor_cb_t, so it installs
// directly with fido2_ctaphid_set_cbor(). ctx must be a
// fido_ctap_ctx_t initialized with fido_ctap_ctx_init().
void fido_ctap_dispatch(void *ctx, const uint8_t *req, uint32_t req_len,
                        uint8_t *resp, uint32_t resp_max, uint32_t *resp_len);

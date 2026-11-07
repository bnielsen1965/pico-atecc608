// fido_ctaphid.h
//
// CTAPHID (CTAP over USB HID) transport state machine — the framing and
// channel layer of the FIDO2 app, per the CTAP v2.0 spec (§8.1.8/8.1.9)
// and the U2FHID spec (§2.4-2.5). Pure C, no USB or Pico dependency, so
// the protocol logic is host-tested in tests/test_ctaphid.c.
//
// The wire protocol in a paragraph: the device exposes two raw 64-byte
// HID reports (IN and OUT, NO report IDs) under FIDO usage page 0xF1D0.
// A message is a sequence of 64-byte packets: the first is
// CID(4, BE) | CMD(1, = 0x80|cmd) | BCNT(2, BE) | DATA(57);
// continuations are CID(4, BE) | SEQ(1) | DATA(59) with SEQ starting at
// 0 and running 0x00..0x7F (bit 7 always clear) — up to 128 of them.
// BCNT is the total message length (max 7609 = 57 + 128*59); a message
// with BCNT <= 57 fits the first packet alone. Responses use the same
// framing with the response command and the total response length.
//
// Only one message may be in flight at a time (the device is
// single-threaded); CIDs form a small table of known channels —
// allocated by broadcast INIT, auto-accepted leniently on first sight
// (the Nitrokey/SoloKey behavior) — and stay known for the session.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// --- wire geometry (CTAP v2.0 8.1.8.1.2) ----------------------------------

#define FIDO2_REPORT_LEN     64
#define FIDO2_INIT_HDR_LEN   7     // CID(4) CMD(1) BCNT(2)
#define FIDO2_INIT_DATA_LEN  57
#define FIDO2_CONT_HDR_LEN   5     // CID(4) SEQ(1)
#define FIDO2_CONT_DATA_LEN  59
#define FIDO2_MAX_MSG        7609  // 57 + 128*59
#define FIDO2_BROADCAST_CID  0xFFFFFFFFu

// Command values (low 7 bits); the header byte on the wire is 0x80|cmd
// (CTAP v2.0 §8.1.9.1). The U2F (CTAP1) commands 0x00 and 0x02-0x05 are
// recognised so the device can answer them with the U2F status word that
// tells a platform "no U2F here — use CTAP2" (see dispatch()); the earlier
// build mislabeled 0x03/0x04 as MSG/LOCK and answered them with a CTAPHID
// ERROR, which left the platform (Chrome) waiting on a U2F reply that
// never came — the registration hang.
enum {
    FIDO2_CMD_MSG          = 0x00,  // CTAPHID_MSG (U2F tunnel) — not impl.
    FIDO2_CMD_PING         = 0x01,
    FIDO2_CMD_MRK          = 0x02,  // U2F — not implemented
    FIDO2_CMD_ENROLL       = 0x03,  // U2F — not implemented
    FIDO2_CMD_VERIFY       = 0x04,  // U2F — not implemented
    FIDO2_CMD_AUTHENTICATE = 0x05,  // U2F — not implemented
    FIDO2_CMD_INIT         = 0x06,
    FIDO2_CMD_VERSION      = 0x07,  // not implemented
    FIDO2_CMD_WINK         = 0x08,
    FIDO2_CMD_CBOR         = 0x10,
    FIDO2_CMD_CANCEL       = 0x11,
    // CTAPHID_KEEPALIVE (device -> host only), value 0x3B per CTAP 2.3
    // §11.2.9.1.7 (USB HID) — the wire byte is 0x80|0x3B = 0xBB. (The 0x82
    // in CTAP 2.3 §11.4.4.3 is the *Bluetooth LE* keep-alive, a different
    // transport; 0x02/0x82 was the CTAP 2.0–2.2 HID value, superseded.)
    // The message is BCNT-framed: BCNT=1 with a single status byte
    // (PROCESSING 0x01 / UP_NEEDED 0x02). fido2_ctaphid_keepalive() frames
    // it directly (not via resp_send()) because it is not a response to a
    // command and must not disturb the in-flight reassembly.
    FIDO2_CMD_KEEPALIVE    = 0x3B,
    FIDO2_CMD_ERROR        = 0x3F,
};

// CTAP error codes (CTAP v2.0 8.1.9.1.6; same values as U2FHID 2.4).
enum {
    FIDO2_ERR_INVALID_CMD     = 0x01,
    FIDO2_ERR_INVALID_PARAM   = 0x02,
    FIDO2_ERR_INVALID_LENGTH  = 0x03,
    FIDO2_ERR_INVALID_SEQ     = 0x04,
    FIDO2_ERR_MESSAGE_TIMEOUT = 0x05,
    FIDO2_ERR_CHANNEL_BUSY    = 0x06,
    FIDO2_ERR_LOCK_REQUIRED   = 0x0A,
    FIDO2_ERR_INVALID_CHANNEL = 0x0B,
    FIDO2_ERR_OTHER           = 0x7F,
};

// The CTAP2 status codes the transport itself needs (CTAP v2.1 §8.2;
// 0x01 is shared with U2FHID); the CTAP layer (Phase 2) uses the full
// code set in its responses.
enum {
    FIDO2_CTAP_ERR_OK              = 0x00,
    FIDO2_CTAP_ERR_INVALID_COMMAND = 0x01,
};

// U2F (CTAP1) status word, ISO 7816-4 "command not allowed (no current
// EF)". The answer a CTAP2-only authenticator gives to a U2F command, so
// a conformant platform abandons U2F and retries CTAP2 (CTAP v2.0 §7.2
// "registration via U2F": "…the platform SHOULD retry using CTAP2").
enum {
    FIDO2_SW_COMMAND_NOT_ALLOWED = 0x6986,
};

// INIT capability flags, emitted in the CTAP 2.0-2.2 bit positions:
// WINK 0x01, CBOR 0x02, NMSG 0x04.
//
// CTAP 2.3 renumbers these bits (WINK 0x01, CBOR 0x04, NMSG 0x08 —
// spec of record §11.2.9.1.3), which is where the old 0x0D value came
// from. Every shipping client — Firefox, Chrome, libfido2 1.16 (which
// printed "nocbor" for our 0x0D) — still parses the 2.0-2.2 positions,
// where 0x0D reads as WINK|NMSG with CBOR CLEAR: the device was
// classified U2F-only and never received a makeCredential (rounds
// C11/C12, 2026-11-03). Emit 0x07 (WINK|CBOR|NMSG), the value real
// CTAP2 keys such as YubiKey advertise. A future 2.3 client reading
// 0x07 sees WINK|CBOR (2.3 positions) without NMSG and may probe
// CTAPHID_MSG; we answer 0x6986 and it falls back to CTAP2 — harmless.
enum {
    FIDO2_CAP_WINK = 0x01,
    FIDO2_CAP_CBOR = 0x02,
    FIDO2_CAP_NMSG = 0x04,  // set = CTAPHID_MSG is NOT implemented
};
// CTAP2-only authenticator (no CTAP1/U2F): advertise NMSG so conformant
// clients never send CTAPHID_MSG.
#define FIDO2_CAPABILITIES (FIDO2_CAP_WINK | FIDO2_CAP_CBOR | FIDO2_CAP_NMSG)

// Protocol version reported by INIT: CTAPHID protocol 2. The device
// version is vendor-defined (spec 8.1.9.1.3); the history below is the
// changelog.
//
// The build number doubles as the on-wire FINGERPRINT of what is
// actually flashed: read the 3-byte version out of any usbmon INIT
// response to verify a flash before benching. History:
//   1.0.0  pre-C11 build (the C11 capture proved the flashed UF2 was
//          stale — a 1.0.0 INIT with behaviors no current source
//          produces)
//   1.0.1  C10 CBOR status-byte fix (bare CBOR responses)
//   1.0.2  2.0-2.2 wire encoding: INIT caps 0x07 (CBOR bit where
//          shipping clients look) + GET_INFO with the 2.0-2.2 key
//          numbers (rounds C11/C12: Firefox classified the 2.3-encoded
//          device as U2F-only and never sent makeCredential)
//   1.0.3  GET_INFO re-keyed to the CTAP 2.1+ table (Firefox's
//          AuthenticatorInfo deserializer; round C13)
//   1.0.4  = 1.0.3 on the wire (the C13 fix); C14 found the makeCredential
//          response rejected by Firefox
//   1.0.5  COSE_Key crv fixed: P-256 is crv 1 (RFC 8152 13.1), not -1
//          (0x20). Firefox's Curve::try_from(-1) = UnknownKeyType, so the
//          whole makeCredential response was rejected (round C14)
//   1.0.6  Phase 4 (the login half): GET_ASSERTION +
//          GET_NEXT_ASSERTION + RESET, the SD-6 wire format (stable 2.0
//          request table; INTEGER top-level response keys; TEXT-keyed
//          inner maps); the sync counter moves to littlefs (/f2_cnt,
//          RESET zeroes it) with the chip Counter 0 behind
//          FIDO2_COUNTER_CHIP (never reset)
//   1.0.7  The assertion authData dropped the attested credential data
//          (AAGUID/credId/COSE, AT bit): WebAuthn L3 §6.3.3 step 10
//          excludes it from the getAssertion authenticatorData, so the
//          assertion is now rpIdHash(32) | flags(UP only) |
//          signCount(4 BE) = 37 bytes (round C20-prep; the old 164-B
//          layout broke fido2-lib's assertion audit)
//   1.0.8  ES256 signatures are now emitted as ASN.1 DER Ecdsa-Sig-
//          Value (RFC 3279 §2.2.3) — BOTH the assertion
//          (getAssertion/get_next_assertion) and the packed attestation
//          (makeCredential) signatures. WebAuthn L3 §6.5.5 MANDATES DER
//          for ES256 "sig" values; the raw R||S (COSE_Sign, RFC 9052)
//          form was a device bug that broke py_webauthn RPs
//          (webauthn.io: "Could not verify authentication signature")
//   1.0.9  Phase 5 hardening: a structurally truncated / malformed
//          CBOR request (a map with fewer pairs than its header
//          declares, a string cut mid-payload, ...) now answers
//          CTAP2_ERR_INVALID_CBOR (0x12); 0x11
//          CTAP2_ERR_CBOR_UNEXPECTED_TYPE is reserved for a
//          well-formed item of the wrong type (CTAP 2.3 §11.2.9.1.3).
//          Happy-path wire format unchanged.
//   1.0.10 Optional user-presence button (GP10, wired to GND, internal
//          pull-up): a host-tested debounce machine (fido_button.c)
//          feeds the same user_present flag as the console 'up'
//          command; a 'pin' console command reports the raw level. No
//          button wired = unchanged behavior. Wire format unchanged.
enum {
    FIDO2_PROTO_VERSION    = 2,
    FIDO2_FW_VERSION_MAJOR = 1,
    FIDO2_FW_VERSION_MINOR = 0,
    FIDO2_FW_VERSION_BUILD = 10,
};

// Timing, in ms. A busy (in-flight) message is aborted with
// FIDO2_ERR_MESSAGE_TIMEOUT after this much time without the next packet
// (U2FHID 2.5.2: the device backs out a stalled channel; Nitrokey uses
// 750). Keep-alives are throttled to one per period while a CTAP
// transaction is pending (spec: at least every 100 ms SHOULD; browsers
// arm ~3 s; real keys use ~500).
#define FIDO2_BUSY_TIMEOUT_MS      750
#define FIDO2_KEEPALIVE_PERIOD_MS  500

// Keep-alive status byte (CTAP 2.3 §11.2.9.1.7): the USB-HID KEEPALIVE
// (0xBB on the wire) is BCNT=1 and carries a single status byte drawn from
// this small enum — NOT a CTAP2 error code. PROCESSING (0x01) while the
// command is running; UP_NEEDED (0x02) while waiting for the test of user
// presence.
enum {
    FIDO2_KEEPALIVE_PROCESSING = 0x01,
    FIDO2_KEEPALIVE_UP_NEEDED  = 0x02,
};

// Known channels. The table is small on purpose; a broadcast INIT evicts
// the least-recently-used entry when it is full (see fido_ctaphid.c) so
// allocation can never fail.
#define FIDO2_MAX_CHANNELS 8

// One 64-byte IN report, produced by the state machine and delivered
// through the sink (the USB layer on the Pico, a collector in tests).
typedef void (*fido2_sink_t)(void *ctx, const uint8_t report[FIDO2_REPORT_LEN]);

// CTAP2 dispatch hook: process one complete CTAPHID_CBOR message. Fill
// resp with the full response — the CBOR payload directly on success
// (a CTAP2 success response IS the CBOR structure, no status byte,
// CTAP v2.1 §8.2), or a single status byte (a CTAP2 error code) on
// failure — and set *resp_len (<= resp_max). The transport frames and
// sends it verbatim. A handler may instead DEFER
// the response: return with *resp_len == 0 (the CTAP layer's
// MakeCredential does this while it waits for user presence) and finish
// later with fido2_ctaphid_complete(). While the callback runs — and,
// for a deferred response, until complete — the transaction is
// "active": fido2_ctaphid_keepalive() emits keep-alives on its
// channel, a CANCEL on its channel is recorded (the app reads it with
// fido2_ctaphid_cancelled() and completes with CTAP2 0x2D), an INIT on
// its channel is treated as a cancel (channel-sync aborts the pending
// transaction), and no other message is accepted on any channel
// (CHANNEL_BUSY, or INVALID_SEQ on the transaction's own channel).
typedef void (*fido2_cbor_cb_t)(void *ctx,
                                const uint8_t *req, uint32_t req_len,
                                uint8_t *resp, uint32_t resp_max,
                                uint32_t *resp_len);

// WINK hook: the app flashes the user LED.
typedef void (*fido2_wink_cb_t)(void *ctx);

typedef struct {
    uint32_t cid;        // 0 = free
    uint32_t last_tick;  // last packet seen on this channel
} fido2_channel_t;

typedef struct {
    // Known channels (see FIDO2_MAX_CHANNELS).
    fido2_channel_t channels[FIDO2_MAX_CHANNELS];
    uint32_t next_cid;   // allocation cursor; first allocation is 2

    // The single in-flight message being received.
    bool     inflight;
    uint32_t inflight_cid;
    uint8_t  inflight_cmd;
    uint8_t  inflight_seq;    // next expected continuation SEQ (starts 0)
    uint32_t inflight_len;    // bytes buffered so far
    uint32_t inflight_total;  // BCNT from the initial packet
    uint32_t inflight_tick;   // last packet of the message (busy timeout)

    // The transaction the CTAP layer is processing (set around the cbor
    // callback; left set for a DEFERRED response until
    // fido2_ctaphid_complete). Keep-alives go to this channel.
    uint32_t tx_cid;
    uint32_t last_keepalive;
    // A CANCEL (or a channel-sync INIT) arrived for the active
    // transaction; the app answers it by completing with CTAP2
    // CTAP2_ERR_KEEPALIVE_CANCEL (0x2D).
    bool cancelled;

    // Message buffer (received) and response scratch (CBOR response).
    uint8_t msgbuf[FIDO2_MAX_MSG];
    uint8_t respbuf[FIDO2_MAX_MSG];

    fido2_cbor_cb_t cbor_cb;
    void          *cbor_ctx;
    fido2_wink_cb_t wink_cb;
    void          *wink_ctx;
} fido2_ctaphid_t;

// First boot: full zero, including the handler hooks (set them with the
// set_* functions afterwards).
void fido2_ctaphid_init(fido2_ctaphid_t *s);

// Re-plug / USB unmount: the host's channels die with the connection, so
// the protocol state (channels, in-flight message, CID cursor) starts
// fresh and allocation restarts at 2 — but the registered cbor/wink
// handlers survive. Use this, not init, after boot.
void fido2_ctaphid_reset(fido2_ctaphid_t *s);

void fido2_ctaphid_set_cbor(fido2_ctaphid_t *s, fido2_cbor_cb_t cb, void *ctx);
void fido2_ctaphid_set_wink(fido2_ctaphid_t *s, fido2_wink_cb_t cb, void *ctx);

// Process one 64-byte OUT report (the transport delivers exactly 64; see
// fido_hid.c). Any response is emitted synchronously through the sink.
void fido2_ctaphid_input(fido2_ctaphid_t *s, uint32_t now_ms,
                         const uint8_t packet[FIDO2_REPORT_LEN],
                         fido2_sink_t sink, void *sink_ctx);

// Periodic housekeeping: aborts a stalled in-flight message with
// FIDO2_ERR_MESSAGE_TIMEOUT. Call from the main loop.
void fido2_ctaphid_tick(fido2_ctaphid_t *s, uint32_t now_ms,
                        fido2_sink_t sink, void *sink_ctx);

// Emit a keep-alive on the current transaction's channel, throttled to
// one per FIDO2_KEEPALIVE_PERIOD_MS; a no-op when no transaction is
// active (synchronous or deferred). The app's main loop calls this
// while a deferred transaction waits (Phase 3: status
// FIDO2_KEEPALIVE_UP_NEEDED during the user-presence wait).
void fido2_ctaphid_keepalive(fido2_ctaphid_t *s, uint32_t now_ms,
                             uint8_t status,
                             fido2_sink_t sink, void *sink_ctx);

// True when a CANCEL (or a channel-sync INIT) arrived for the active
// (deferred) transaction — the app finishes it with CTAP2
// CTAP2_ERR_KEEPALIVE_CANCEL (0x2D).
bool fido2_ctaphid_cancelled(const fido2_ctaphid_t *s);

// Complete a deferred transaction: frame and send resp (the CBOR payload
// on success, a single status byte on error) as the CBOR response on the
// transaction's channel and release the channel (a new message may start
// again). No-op when no deferred transaction is active; resp_len is
// clamped to FIDO2_MAX_MSG.
void fido2_ctaphid_complete(fido2_ctaphid_t *s, const uint8_t *resp,
                            uint32_t resp_len,
                            fido2_sink_t sink, void *sink_ctx);

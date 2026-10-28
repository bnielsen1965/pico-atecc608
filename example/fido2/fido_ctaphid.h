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

// Command values (low 7 bits); the header byte on the wire is 0x80|cmd.
enum {
    FIDO2_CMD_PING      = 0x01,
    FIDO2_CMD_MSG       = 0x03,   // U2F tunneling — not implemented
    FIDO2_CMD_LOCK      = 0x04,   // U2F feature — not implemented
    FIDO2_CMD_INIT      = 0x06,
    FIDO2_CMD_WINK      = 0x08,
    FIDO2_CMD_CBOR      = 0x10,
    FIDO2_CMD_CANCEL    = 0x11,
    FIDO2_CMD_KEEPALIVE = 0x3B,
    FIDO2_CMD_ERROR     = 0x3F,
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

// The one CTAP2 status code the transport itself needs (CTAP v2.0 9.1.1);
// the CTAP layer (Phase 2) uses the full code set in its responses.
enum {
    FIDO2_CTAP_ERR_OK              = 0x00,
    FIDO2_CTAP_ERR_INVALID_COMMAND = 0x11,
};

// INIT capability flags (CTAP v2.0 8.1.9.1.3).
enum {
    FIDO2_CAP_WINK = 0x01,
    FIDO2_CAP_CBOR = 0x04,
    FIDO2_CAP_NMSG = 0x08,  // set = CTAPHID_MSG is NOT implemented
};
// CTAP2-only authenticator (no CTAP1/U2F): advertise NMSG so conformant
// clients never send CTAPHID_MSG. (YubiKey advertises the same 0x0D;
// Nitrokey's 0x05 is for its dual CTAP2+U2F firmware.)
#define FIDO2_CAPABILITIES (FIDO2_CAP_WINK | FIDO2_CAP_CBOR | FIDO2_CAP_NMSG)

// Protocol version reported by INIT: CTAPHID protocol 2. The device
// version is vendor-defined (spec 8.1.9.1.3); report 1.0.0.
enum {
    FIDO2_PROTO_VERSION    = 2,
    FIDO2_FW_VERSION_MAJOR = 1,
    FIDO2_FW_VERSION_MINOR = 0,
    FIDO2_FW_VERSION_BUILD = 0,
};

// Timing, in ms. A busy (in-flight) message is aborted with
// FIDO2_ERR_MESSAGE_TIMEOUT after this much time without the next packet
// (U2FHID 2.5.2: the device backs out a stalled channel; Nitrokey uses
// 750). Keep-alives are throttled to one per period while a CTAP
// transaction is pending (spec: at least every 100 ms SHOULD; browsers
// arm ~3 s; real keys use ~500).
#define FIDO2_BUSY_TIMEOUT_MS      750
#define FIDO2_KEEPALIVE_PERIOD_MS  500

// Keep-alive status byte (CTAP v2.0 8.1.9.1.5).
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
// resp with the full response — status byte first, then payload (just
// the status byte on error) — and set *resp_len (<= resp_max). The
// transport frames and sends it verbatim. While the callback runs the
// transaction is "active": fido2_ctaphid_keepalive() emits keep-alives
// on its channel, and CANCEL clears it. Phase 1 installs a stub that
// answers FIDO2_CTAP_ERR_INVALID_COMMAND; Phase 2 installs the CTAP
// dispatch.
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
    // callback); keep-alives go to this channel.
    uint32_t tx_cid;
    uint32_t last_keepalive;

    // Message buffer (received) and response scratch (CBOR response).
    uint8_t msgbuf[FIDO2_MAX_MSG];
    uint8_t respbuf[FIDO2_MAX_MSG];

    fido2_cbor_cb_t cbor_cb;
    void          *cbor_ctx;
    fido2_wink_cb_t wink_cb;
    void          *wink_ctx;
} fido2_ctaphid_t;

void fido2_ctaphid_init(fido2_ctaphid_t *s);
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
// active. The CTAP layer calls this from its handlers while processing
// (nothing calls it in Phase 1 — the stub CBOR handler returns at once).
void fido2_ctaphid_keepalive(fido2_ctaphid_t *s, uint32_t now_ms,
                             uint8_t status,
                             fido2_sink_t sink, void *sink_ctx);

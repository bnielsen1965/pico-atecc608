// fido_ctaphid.c — CTAPHID framing and channel state machine (see the
// header for the protocol summary and the spec references).
//
// Behavior notes (deviations from the Nitrokey/SoloKey reference are
// deliberate and documented here):
//  - A channel table entry, once seen, is never dropped except by LRU
//    eviction when the table is full (the reference keeps stale entries
//    until a slot is reused). Eviction never touches the in-flight
//    channel, so broadcast INIT can never fail — the reference's
//    CHANNEL_BUSY-on-INIT path is effectively unreachable in a
//    single-in-flight design and is not replicated.
//  - INIT discards an in-flight message only on the channel it is sent
//    to (spec 8.1.9.1.3 channel-sync semantics); the reference resets
//    the buffer on every INIT.
//  - A new initial packet on a channel that already has one in flight
//    answers INVALID_SEQ (reference behavior); the client must re-INIT
//    to re-synchronize.

#include "fido_ctaphid.h"

#include <string.h>

// --- big-endian helpers ----------------------------------------------------

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put16be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

// --- response writer (frames one message into 64-byte reports) -------------

typedef struct {
    fido2_sink_t sink;
    void        *ctx;
    uint32_t     cid;
    uint8_t      cmd;   // wire header byte (0x80 | cmd)
    uint16_t     bcnt;  // total message length (BCNT)
    uint8_t      seq;   // next continuation SEQ (starts at 0)
} fido2_resp_t;

static void resp_init(fido2_resp_t *r, fido2_sink_t sink, void *ctx,
                      uint32_t cid, uint8_t cmd, uint32_t bcnt)
{
    r->sink = sink;
    r->ctx  = ctx;
    r->cid  = cid;
    r->cmd  = (uint8_t)(0x80u | cmd);
    r->bcnt = (uint16_t)bcnt;   // max message is 7609, fits
    r->seq  = 0;
}

// Frame and send a response of `len` payload bytes (BCNT = len). A
// zero-length response is still one packet (header only).
static void resp_send(fido2_resp_t *r, const uint8_t *data, uint32_t len)
{
    if (0 == len) {
        uint8_t pkt[FIDO2_REPORT_LEN];
        memset(pkt, 0, sizeof pkt);
        put32be(pkt, r->cid);
        pkt[4] = r->cmd;
        put16be(&pkt[5], r->bcnt);
        r->sink(r->ctx, pkt);
        return;
    }

    bool first = true;
    while (len > 0) {
        uint8_t pkt[FIDO2_REPORT_LEN];
        const uint32_t hdr  = first ? FIDO2_INIT_HDR_LEN : FIDO2_CONT_HDR_LEN;
        const uint32_t room = FIDO2_REPORT_LEN - hdr;
        const uint32_t n    = (len < room) ? len : room;

        memset(pkt, 0, sizeof pkt);
        put32be(pkt, r->cid);
        if (first) {
            pkt[4] = r->cmd;
            put16be(&pkt[5], r->bcnt);
        } else {
            pkt[4] = r->seq++;
        }
        memcpy(&pkt[hdr], data, n);

        r->sink(r->ctx, pkt);
        first = false;
        data += n;
        len  -= n;
    }
}

static void send_error(fido2_sink_t sink, void *sink_ctx,
                       uint32_t cid, uint8_t err)
{
    fido2_resp_t r;
    resp_init(&r, sink, sink_ctx, cid, FIDO2_CMD_ERROR, 1);
    resp_send(&r, &err, 1);
}

static void send_empty(fido2_sink_t sink, void *sink_ctx,
                       uint32_t cid, uint8_t cmd)
{
    fido2_resp_t r;
    resp_init(&r, sink, sink_ctx, cid, cmd, 0);
    resp_send(&r, NULL, 0);
}

// --- channel table -----------------------------------------------------------

static int channel_find(fido2_ctaphid_t *s, uint32_t cid)
{
    for (int i = 0; i < FIDO2_MAX_CHANNELS; i++) {
        if (s->channels[i].cid == cid) {
            return i;
        }
    }
    return -1;
}

// Reserve (or refresh) a channel slot for cid. When the table is full
// the least-recently-used entry is evicted — never the in-flight
// channel's, so allocation always succeeds.
static void channel_touch(fido2_ctaphid_t *s, uint32_t now_ms, uint32_t cid)
{
    int i = channel_find(s, cid);
    if (i >= 0) {
        s->channels[i].last_tick = now_ms;
        return;
    }

    int free_slot = -1;
    int oldest    = -1;
    for (i = 0; i < FIDO2_MAX_CHANNELS; i++) {
        if (s->inflight && s->channels[i].cid == s->inflight_cid) {
            continue;   // never evict the in-flight channel
        }
        if (0 == s->channels[i].cid) {
            if (free_slot < 0) {
                free_slot = i;
            }
            continue;
        }
        if (oldest < 0 ||
            s->channels[i].last_tick < s->channels[oldest].last_tick) {
            oldest = i;
        }
    }
    i = (free_slot >= 0) ? free_slot : oldest;
    s->channels[i].cid        = cid;
    s->channels[i].last_tick  = now_ms;
}

// Allocate the next CID (0 and 0xFFFFFFFF are reserved).
static uint32_t alloc_cid(fido2_ctaphid_t *s, uint32_t now_ms)
{
    uint32_t cid;
    do {
        cid = ++s->next_cid;
    } while (0 == cid || FIDO2_BROADCAST_CID == cid);
    channel_touch(s, now_ms, cid);
    return cid;
}

// --- in-flight message --------------------------------------------------------

// Clear all in-flight state. Every path that ends a message (complete,
// error, timeout, channel sync) goes through this, so a new message
// always starts from a zeroed buffer — no stale length can survive a
// discard.
static void inflight_clear(fido2_ctaphid_t *s)
{
    s->inflight       = false;
    s->inflight_cid   = 0;
    s->inflight_cmd   = 0;
    s->inflight_seq   = 0;
    s->inflight_len   = 0;
    s->inflight_total = 0;
    s->inflight_tick  = 0;
}

// Append a packet's data (at most `cap` bytes, no more than the message
// total) to the in-flight buffer; returns the new buffered length.
static uint32_t buffer_packet(fido2_ctaphid_t *s, const uint8_t *data,
                              uint32_t cap)
{
    uint32_t room = s->inflight_total - s->inflight_len;
    if (cap > room) {
        cap = room;
    }
    memcpy(&s->msgbuf[s->inflight_len], data, cap);
    s->inflight_len += cap;
    return s->inflight_len;
}

// Dispatch a complete message: run the command and emit its response.
static void dispatch(fido2_ctaphid_t *s, fido2_sink_t sink, void *sink_ctx)
{
    const uint32_t cid = s->inflight_cid;
    const uint8_t  cmd = s->inflight_cmd;
    const uint32_t len = s->inflight_len;

    inflight_clear(s);

    switch (cmd) {
    case FIDO2_CMD_PING: {
        // Echo the message back (CTAP v2.0 8.1.9.1.4).
        fido2_resp_t r;
        resp_init(&r, sink, sink_ctx, cid, FIDO2_CMD_PING, len);
        resp_send(&r, s->msgbuf, len);
        break;
    }
    case FIDO2_CMD_WINK:
        if (s->wink_cb) {
            s->wink_cb(s->wink_ctx);
        }
        send_empty(sink, sink_ctx, cid, FIDO2_CMD_WINK);
        break;
    case FIDO2_CMD_CBOR: {
        if (0 == len) {
            send_error(sink, sink_ctx, cid, FIDO2_ERR_INVALID_LENGTH);
            break;
        }
        uint32_t resp_len = 1;
        s->tx_cid         = cid;   // keep-alives now target this channel
        s->last_keepalive = 0;
        if (s->cbor_cb) {
            s->cbor_cb(s->cbor_ctx, s->msgbuf, len,
                       s->respbuf, sizeof s->respbuf, &resp_len);
        } else {
            s->respbuf[0] = FIDO2_CTAP_ERR_INVALID_COMMAND;
            resp_len      = 1;
        }
        s->tx_cid = 0;
        if (resp_len > sizeof s->respbuf) {
            resp_len = sizeof s->respbuf;   // a well-behaved handler never
        }                                   // overflows; clamp regardless
        fido2_resp_t r;
        resp_init(&r, sink, sink_ctx, cid, FIDO2_CMD_CBOR, resp_len);
        resp_send(&r, s->respbuf, resp_len);
        break;
    }
    case FIDO2_CMD_MSG:
        // U2F tunneling: this is a CTAP2-only device (capability NMSG).
        if (0 == len) {
            send_error(sink, sink_ctx, cid, FIDO2_ERR_INVALID_LENGTH);
        } else {
            send_error(sink, sink_ctx, cid, FIDO2_ERR_INVALID_CMD);
        }
        break;
    case FIDO2_CMD_LOCK:
        // A U2F feature; not implemented.
        send_error(sink, sink_ctx, cid, FIDO2_ERR_INVALID_CMD);
        break;
    case FIDO2_CMD_CANCEL:
        // No response (CTAP v2.0 8.1.9.1.7): there is no pending CBOR in
        // a synchronous transport, and clients do not wait for one.
        s->tx_cid = 0;
        break;
    default:
        send_error(sink, sink_ctx, cid, FIDO2_ERR_INVALID_CMD);
        break;
    }
}

// --- input paths ----------------------------------------------------------------

// CTAPHID_INIT (packet-level; it always fits one packet).
static void input_init(fido2_ctaphid_t *s, uint32_t now_ms, uint32_t cid,
                       const uint8_t *nonce, uint16_t bcnt,
                       fido2_sink_t sink, void *sink_ctx)
{
    if (8 != bcnt) {
        send_error(sink, sink_ctx, cid, FIDO2_ERR_INVALID_LENGTH);
        return;
    }
    if (0 == cid) {
        send_error(sink, sink_ctx, cid, FIDO2_ERR_INVALID_CHANNEL);
        return;
    }

    // INIT on an allocated channel is a channel sync: it discards any
    // in-flight message on that channel (CTAP v2.0 8.1.9.1.3).
    if (s->inflight && cid == s->inflight_cid) {
        inflight_clear(s);
    }

    uint32_t reply_cid = cid;
    if (FIDO2_BROADCAST_CID == cid) {
        reply_cid = alloc_cid(s, now_ms);
    } else {
        channel_touch(s, now_ms, cid);
    }

    // 17-byte payload: nonce(8) | cid(4, BE) | protocol(1) | version(3)
    // | capabilities(1) (CTAP v2.0 8.1.9.1.3).
    uint8_t payload[17];
    memcpy(payload, nonce, 8);
    put32be(&payload[8], reply_cid);
    payload[12] = FIDO2_PROTO_VERSION;
    payload[13] = FIDO2_FW_VERSION_MAJOR;
    payload[14] = FIDO2_FW_VERSION_MINOR;
    payload[15] = FIDO2_FW_VERSION_BUILD;
    payload[16] = FIDO2_CAPABILITIES;

    // The response goes to the request's CID (broadcast for allocation,
    // the same CID for a sync).
    fido2_resp_t r;
    resp_init(&r, sink, sink_ctx, cid, FIDO2_CMD_INIT, sizeof payload);
    resp_send(&r, payload, sizeof payload);
}

// A non-INIT initial packet (PING/CBOR/...): start a new message.
static void input_init_packet(fido2_ctaphid_t *s, uint32_t now_ms,
                              uint32_t cid, uint8_t cmd, uint16_t bcnt,
                              const uint8_t *data,
                              fido2_sink_t sink, void *sink_ctx)
{
    if (FIDO2_BROADCAST_CID == cid) {
        send_error(sink, sink_ctx, cid, FIDO2_ERR_INVALID_CHANNEL);
        return;
    }

    if (s->inflight) {
        if (cid == s->inflight_cid) {
            // A new message on a channel that already has one pending:
            // sequence error; the client must re-INIT to re-synchronize.
            inflight_clear(s);
            send_error(sink, sink_ctx, cid, FIDO2_ERR_INVALID_SEQ);
            return;
        }
        // A different channel wants to start while this one is busy.
        send_error(sink, sink_ctx, cid, FIDO2_ERR_CHANNEL_BUSY);
        return;
    }

    if (FIDO2_MAX_MSG < bcnt) {
        send_error(sink, sink_ctx, cid, FIDO2_ERR_INVALID_LENGTH);
        return;
    }

    channel_touch(s, now_ms, cid);

    s->inflight       = true;
    s->inflight_cid   = cid;
    s->inflight_cmd   = cmd;
    s->inflight_seq   = 0;
    s->inflight_total = bcnt;
    s->inflight_len   = buffer_packet(s, data, FIDO2_INIT_DATA_LEN);
    s->inflight_tick  = now_ms;

    if (s->inflight_len >= s->inflight_total) {
        dispatch(s, sink, sink_ctx);
    }
}

// A continuation packet.
static void input_continuation(fido2_ctaphid_t *s, uint32_t now_ms,
                               uint32_t cid, uint8_t seq,
                               const uint8_t *data,
                               fido2_sink_t sink, void *sink_ctx)
{
    if (FIDO2_BROADCAST_CID == cid) {
        send_error(sink, sink_ctx, cid, FIDO2_ERR_INVALID_CHANNEL);
        return;
    }

    if (!s->inflight || cid != s->inflight_cid) {
        // Stray continuation (no pending message, or another channel):
        // ignore silently (U2FHID 2.5.4).
        return;
    }

    if (seq != s->inflight_seq) {
        inflight_clear(s);
        send_error(sink, sink_ctx, cid, FIDO2_ERR_INVALID_SEQ);
        return;
    }

    channel_touch(s, now_ms, cid);
    s->inflight_seq++;
    s->inflight_len = buffer_packet(s, data, FIDO2_CONT_DATA_LEN);
    s->inflight_tick = now_ms;

    if (s->inflight_len >= s->inflight_total) {
        dispatch(s, sink, sink_ctx);
    }
}

// --- public API -----------------------------------------------------------------

void fido2_ctaphid_init(fido2_ctaphid_t *s)
{
    memset(s, 0, sizeof *s);
    s->next_cid = 1;   // first allocation is 2
}

void fido2_ctaphid_set_cbor(fido2_ctaphid_t *s, fido2_cbor_cb_t cb, void *ctx)
{
    s->cbor_cb  = cb;
    s->cbor_ctx = ctx;
}

void fido2_ctaphid_set_wink(fido2_ctaphid_t *s, fido2_wink_cb_t cb, void *ctx)
{
    s->wink_cb  = cb;
    s->wink_ctx = ctx;
}

void fido2_ctaphid_input(fido2_ctaphid_t *s, uint32_t now_ms,
                         const uint8_t packet[FIDO2_REPORT_LEN],
                         fido2_sink_t sink, void *sink_ctx)
{
    const uint8_t *pkt = packet;
    const uint32_t cid = be32(&pkt[0]);
    const uint8_t  hdr = pkt[4];

    if (hdr & 0x80u) {   // initial packet
        const uint8_t  cmd  = (uint8_t)(hdr & 0x7Fu);
        const uint16_t bcnt = be16(&pkt[5]);
        if (FIDO2_CMD_INIT == cmd) {
            input_init(s, now_ms, cid, &pkt[7], bcnt, sink, sink_ctx);
        } else {
            input_init_packet(s, now_ms, cid, cmd, bcnt, &pkt[7], sink,
                              sink_ctx);
        }
    } else {             // continuation packet
        input_continuation(s, now_ms, cid, hdr, &pkt[5], sink, sink_ctx);
    }
}

void fido2_ctaphid_tick(fido2_ctaphid_t *s, uint32_t now_ms,
                        fido2_sink_t sink, void *sink_ctx)
{
    if (s->inflight &&
        (now_ms - s->inflight_tick) >= FIDO2_BUSY_TIMEOUT_MS) {
        const uint32_t cid = s->inflight_cid;
        inflight_clear(s);
        send_error(sink, sink_ctx, cid, FIDO2_ERR_MESSAGE_TIMEOUT);
    }
}

void fido2_ctaphid_keepalive(fido2_ctaphid_t *s, uint32_t now_ms,
                             uint8_t status,
                             fido2_sink_t sink, void *sink_ctx)
{
    if (0 == s->tx_cid) {
        return;   // keep-alives only while a transaction is active
    }
    if (now_ms - s->last_keepalive < FIDO2_KEEPALIVE_PERIOD_MS) {
        return;   // throttle: at most one per period
    }
    fido2_resp_t r;
    resp_init(&r, sink, sink_ctx, s->tx_cid, FIDO2_CMD_KEEPALIVE, 1);
    resp_send(&r, &status, 1);
    s->last_keepalive = now_ms;
}

// Host unit tests for the fido2 example's CTAPHID transport state
// machine (example/fido2/fido_ctaphid.c) — pure C, no Pico, no TinyUSB.
//
// Covers the wire protocol the device presents to real hosts (Chromium,
// libfido2, a generic HID monitor): INIT channel allocation/sync and its
// 17-byte response layout, PING echo (single and multi-packet, up to the
// 7609-byte maximum), the CTAP2 error table (INVALID_CMD/PARAM/LEN/SEQ,
// MESSAGE_TIMEOUT, CHANNEL_BUSY, INVALID_CHANNEL), the channel rules
// (unknown CIDs auto-accepted, one in-flight message at a time, LRU
// eviction so broadcast INIT can never fail), the 750 ms busy timeout
// (and its reset by continuation packets), and keep-alive throttling —
// plus the deferred-transaction contract (Phase 3): a CBOR handler that
// defers (resp_len 0) holds its channel with no immediate response,
// UP-wait keep-alives flow at the 500 ms throttle, a CANCEL (or a
// channel-sync INIT) on that channel records a cancel, the busy rules
// apply to it (CANCEL exempt), the channel is never LRU-evicted while
// the transaction is active, and fido2_ctaphid_complete() frames the
// late response and releases the channel.

#include <stdio.h>
#include <string.h>

#include "fido_ctaphid.h"

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

// --- report collector (the state machine's sink) ---------------------------------

#define MAX_REPORTS 512

static uint8_t s_reports[MAX_REPORTS][FIDO2_REPORT_LEN];
static int s_nreports = 0;

static void sink(void *ctx, const uint8_t report[FIDO2_REPORT_LEN])
{
    (void)ctx;
    if (s_nreports < MAX_REPORTS) {
        memcpy(s_reports[s_nreports++], report, FIDO2_REPORT_LEN);
    }
}

// --- state under test + hooks -------------------------------------------------------

static fido2_ctaphid_t s;

static int s_winks = 0;

static void wink_cb(void *ctx)
{
    (void)ctx;
    s_winks++;
}

// The CBOR handler under test: answers CTAP2_OK (status byte only) and —
// when s_keepalive_calls is armed — emits keep-alives at 100 ms steps to
// exercise the transport's throttling. s_defer makes it DEFER (resp_len
// 0): the transport must hold the channel for a later
// fido2_ctaphid_complete().
static int s_keepalive_calls = 0;
static uint32_t s_stub_now = 0;
static int s_defer = 0;

static void cbor_stub(void *ctx, const uint8_t *req, uint32_t req_len,
                      uint8_t *resp, uint32_t resp_max, uint32_t *resp_len)
{
    (void)ctx;
    (void)req;
    (void)req_len;
    for (int i = 0; i < s_keepalive_calls; i++) {
        s_stub_now += 100;
        fido2_ctaphid_keepalive(&s, s_stub_now, FIDO2_KEEPALIVE_PROCESSING,
                                sink, NULL);
    }
    if (s_defer) {
        *resp_len = 0;
        return;
    }
    if (resp_max >= 1) {
        resp[0] = FIDO2_CTAP_ERR_OK;
    }
    *resp_len = 1;
}

static void fresh(void)
{
    fido2_ctaphid_init(&s);
    fido2_ctaphid_set_cbor(&s, cbor_stub, NULL);
    fido2_ctaphid_set_wink(&s, wink_cb, NULL);
    s_nreports = 0;
    s_winks = 0;
    s_keepalive_calls = 0;
    s_stub_now = 0;
    s_defer = 0;
}

// --- packet builders / parsers -------------------------------------------------------

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

static uint16_t get16be(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t get32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void build_init(uint8_t *pkt, uint32_t cid, uint8_t cmd, uint32_t bcnt,
                       const uint8_t *data, uint32_t dlen)
{
    memset(pkt, 0, FIDO2_REPORT_LEN);
    put32be(pkt, cid);
    pkt[4] = (uint8_t)(0x80u | cmd);
    put16be(&pkt[5], (uint16_t)bcnt);
    uint32_t n = (dlen > FIDO2_INIT_DATA_LEN) ? FIDO2_INIT_DATA_LEN : dlen;
    memcpy(&pkt[FIDO2_INIT_HDR_LEN], data, n);
}

static void build_cont(uint8_t *pkt, uint32_t cid, uint8_t seq,
                       const uint8_t *data, uint32_t dlen)
{
    memset(pkt, 0, FIDO2_REPORT_LEN);
    put32be(pkt, cid);
    pkt[4] = seq;
    uint32_t n = (dlen > FIDO2_CONT_DATA_LEN) ? FIDO2_CONT_DATA_LEN : dlen;
    memcpy(&pkt[FIDO2_CONT_HDR_LEN], data, n);
}

static void feed(uint32_t now, const uint8_t *pkt)
{
    fido2_ctaphid_input(&s, now, pkt, sink, NULL);
}

// Response parsers (a report is CID(4) | HDR(1) | ...).
static uint32_t rep_cid(const uint8_t *p) { return get32be(&p[0]); }
static uint8_t  rep_cmd(const uint8_t *p) { return (uint8_t)(p[4] & 0x7Fu); }
static uint16_t rep_bcnt(const uint8_t *p) { return get16be(&p[5]); }
static uint8_t  rep_seq(const uint8_t *p) { return p[4]; }

// The INIT response's allocated CID (payload byte 8, packet offset 15).
static uint32_t init_resp_cid(const uint8_t *p) { return get32be(&p[15]); }

// True when report `idx` is an ERROR response to `cid` carrying `err`.
static int is_error(int idx, uint32_t cid, uint8_t err)
{
    if (idx >= s_nreports) {
        return 0;
    }
    const uint8_t *p = s_reports[idx];
    return rep_cid(p) == cid &&
           rep_cmd(p) == FIDO2_CMD_ERROR &&
           rep_bcnt(p) == 1 &&
           p[7] == err;
}

// True when report `idx` is a U2F status-word response to `cid` on command
// `cmd`, carrying the 2-byte status [sw1 | sw2] (BCNT = 2).
static int is_u2f_status(int idx, uint32_t cid, uint8_t cmd,
                         uint8_t sw1, uint8_t sw2)
{
    if (idx >= s_nreports) {
        return 0;
    }
    const uint8_t *p = s_reports[idx];
    return rep_cid(p) == cid &&
           rep_cmd(p) == cmd &&
           rep_bcnt(p) == 2 &&
           p[7] == sw1 &&
           p[8] == sw2;
}

// Send INIT (broadcast or specific) and return the CID the response
// carries (0 if no response came).
static uint32_t do_init(uint32_t now, uint32_t cid)
{
    static const uint8_t nonce[8] =
        {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    uint8_t pkt[FIDO2_REPORT_LEN];
    build_init(pkt, cid, FIDO2_CMD_INIT, 8, nonce, 8);
    feed(now, pkt);
    if (s_nreports == 0) {
        return 0;
    }
    return init_resp_cid(s_reports[s_nreports - 1]);
}

// Send a PING of `len` bytes (init + as many continuations as needed),
// starting at `now`, one packet per ms.
static void send_ping(uint32_t now, uint32_t cid,
                      const uint8_t *data, uint32_t len)
{
    uint8_t pkt[FIDO2_REPORT_LEN];
    uint32_t off, seq;

    build_init(pkt, cid, FIDO2_CMD_PING, len, data, len);
    feed(now, pkt);

    for (off = FIDO2_INIT_DATA_LEN, seq = 0; off < len; seq++) {
        uint32_t chunk = len - off;
        if (chunk > FIDO2_CONT_DATA_LEN) {
            chunk = FIDO2_CONT_DATA_LEN;
        }
        build_cont(pkt, cid, (uint8_t)seq, &data[off], chunk);
        feed(now + off, pkt);
        off += chunk;
    }
}

// Verify that reports at [off, s_nreports) form a PING response on `cid`
// echoing `len` bytes of `data`; returns the number of packets consumed.
static int verify_ping_resp(int off, uint32_t cid,
                            const uint8_t *data, uint32_t len)
{
    uint32_t got = 0;
    uint32_t seq = 0;   // continuation SEQ is 0-based
    int idx = off;

    if (idx >= s_nreports) {
        return -1;
    }
    const uint8_t *p = s_reports[idx];
    if (rep_cid(p) != cid || rep_cmd(p) != FIDO2_CMD_PING ||
        rep_bcnt(p) != len) {
        return -1;
    }
    uint32_t n = (len < FIDO2_INIT_DATA_LEN) ? len : FIDO2_INIT_DATA_LEN;
    if (memcmp(&p[FIDO2_INIT_HDR_LEN], data, n) != 0) {
        return -1;
    }
    got += n;
    idx++;

    while (got < len) {
        if (idx >= s_nreports) {
            return -1;
        }
        p = s_reports[idx];
        // A continuation carries SEQ (not CMD) in byte 4; require the
        // non-init flag clear and the expected SEQ.
        if (rep_cid(p) != cid || (p[4] & 0x80u) ||
            rep_seq(p) != (uint8_t)seq) {
            return -1;
        }
        n = (len - got < FIDO2_CONT_DATA_LEN) ? len - got : FIDO2_CONT_DATA_LEN;
        if (memcmp(&p[FIDO2_CONT_HDR_LEN], &data[got], n) != 0) {
            return -1;
        }
        got += n;
        idx++;
        seq++;
    }
    return idx - off;
}

// --- tests ----------------------------------------------------------------------------

// INIT on the broadcast CID: allocation + full 17-byte response layout
// (the exact shape Chromium's FidoHidDevice::OnPotentialInitReply checks).
static void t_init_broadcast(void)
{
    fresh();
    uint8_t cid;

    cid = do_init(1000, FIDO2_BROADCAST_CID);
    CHECK(s_nreports == 1);
    CHECK(cid == 2);                       // first allocation (0/0xFFFF reserved)

    const uint8_t *p = s_reports[0];
    CHECK(rep_cid(p) == FIDO2_BROADCAST_CID);  // reply on the request's CID
    CHECK(rep_cmd(p) == FIDO2_CMD_INIT);
    CHECK(rep_bcnt(p) == 17);
    static const uint8_t nonce[8] =
        {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    CHECK(memcmp(&p[7], nonce, 8) == 0);   // nonce echoed
    CHECK(init_resp_cid(p) == 2);
    CHECK(p[19] == FIDO2_PROTO_VERSION);   // protocol 2
    CHECK(p[20] == FIDO2_FW_VERSION_MAJOR);
    CHECK(p[21] == FIDO2_FW_VERSION_MINOR);
    CHECK(p[22] == FIDO2_FW_VERSION_BUILD);
    CHECK(p[23] == FIDO2_CAPABILITIES);
    CHECK(p[23] == 0x0D);                  // WINK|CBOR|NMSG (CTAP2-only)
    CHECK(p[24] == 0 && p[25] == 0);       // zero-padded to 64

    // A second allocation hands out the next CID.
    cid = do_init(1100, FIDO2_BROADCAST_CID);
    CHECK(cid == 3);
    CHECK(s_nreports == 2);
}

// INIT on an already-allocated CID is a channel sync: the response goes
// to that CID and carries it (no new allocation).
static void t_init_sync(void)
{
    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);
    CHECK(cid == 2);

    const int before = s_nreports;
    uint32_t got = do_init(1100, cid);
    CHECK(s_nreports == before + 1);
    CHECK(got == cid);
    const uint8_t *p = s_reports[s_nreports - 1];
    CHECK(rep_cid(p) == cid);
    CHECK(rep_cmd(p) == FIDO2_CMD_INIT);
    CHECK(rep_bcnt(p) == 17);
}

// INIT error paths: bad BCNT, CID 0.
static void t_init_errors(void)
{
    uint8_t pkt[FIDO2_REPORT_LEN];
    uint8_t nonce[8] = {0};

    fresh();
    build_init(pkt, FIDO2_BROADCAST_CID, FIDO2_CMD_INIT, 7, nonce, 8);
    feed(1000, pkt);
    CHECK(is_error(0, FIDO2_BROADCAST_CID, FIDO2_ERR_INVALID_LENGTH));

    build_init(pkt, FIDO2_BROADCAST_CID, FIDO2_CMD_INIT, 9, nonce, 8);
    feed(1100, pkt);
    CHECK(is_error(1, FIDO2_BROADCAST_CID, FIDO2_ERR_INVALID_LENGTH));

    build_init(pkt, 0, FIDO2_CMD_INIT, 8, nonce, 8);
    feed(1200, pkt);
    CHECK(is_error(2, 0, FIDO2_ERR_INVALID_CHANNEL));

    // An INIT on a never-seen CID is a sync for that CID (auto-accept).
    build_init(pkt, 0x12345678, FIDO2_CMD_INIT, 8, nonce, 8);
    feed(1300, pkt);
    CHECK(s_nreports == 4);
    CHECK(init_resp_cid(s_reports[3]) == 0x12345678);
}

// PING echo: the three single-packet shapes (0, 5, and 57 = the full
// first-packet data area).
static void t_ping_single(void)
{
    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);
    CHECK(cid == 2);

    {
        uint8_t pkt[FIDO2_REPORT_LEN];
        build_init(pkt, cid, FIDO2_CMD_PING, 0, NULL, 0);
        feed(1100, pkt);
        CHECK(s_nreports == 2);
        const uint8_t *p = s_reports[1];
        CHECK(rep_cid(p) == cid);
        CHECK(rep_cmd(p) == FIDO2_CMD_PING);
        CHECK(rep_bcnt(p) == 0);
        CHECK(p[7] == 0);
    }

    {
        uint8_t data[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01};
        send_ping(1200, cid, data, 5);
        CHECK(verify_ping_resp(2, cid, data, 5) == 1);
    }

    {
        uint8_t data[57];
        for (int i = 0; i < 57; i++) data[i] = (uint8_t)i;
        send_ping(1300, cid, data, 57);
        CHECK(verify_ping_resp(3, cid, data, 57) == 1);
    }
}

// A PING initial packet claiming more than FIDO2_MAX_MSG bytes.
static void build_init_max(uint32_t cid, const uint8_t *data, uint32_t bcnt)
{
    uint8_t pkt[FIDO2_REPORT_LEN];
    build_init(pkt, cid, FIDO2_CMD_PING, bcnt, data, bcnt);
    feed(1200, pkt);
}

// PING echo across packets: 200 bytes (1+3 response packets) and the
// 7609-byte maximum (1 initial + 128 continuations = 129 packets);
// 7610 is rejected.
static void t_ping_multipacket(void)
{
    static uint8_t data[FIDO2_MAX_MSG + 1];
    for (uint32_t i = 0; i < sizeof data; i++) {
        data[i] = (uint8_t)(i & 0xFFu);
    }

    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);
    CHECK(cid == 2);

    {
        send_ping(1100, cid, data, 200);
        // 200 = 57 + 59 + 59 + 25 -> 4 response packets.
        CHECK(verify_ping_resp(1, cid, data, 200) == 4);
    }

    {
        fresh();
        cid = do_init(1000, FIDO2_BROADCAST_CID);
        send_ping(1100, cid, data, FIDO2_MAX_MSG);
        // 7609 = 57 + 128*59 -> 129 response packets.
        CHECK(verify_ping_resp(1, cid, data, FIDO2_MAX_MSG) == 129);
    }

    {
        // Over the maximum: the initial packet is rejected at once.
        build_init_max(cid, data, FIDO2_MAX_MSG + 1);
        CHECK(is_error(s_nreports - 1, cid, FIDO2_ERR_INVALID_LENGTH));
    }
}

// Sequence rules: a wrong continuation SEQ aborts the message with
// INVALID_SEQ (and the channel recovers); stray continuations are
// ignored; continuations on the broadcast CID are rejected.
static void t_seq_rules(void)
{
    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);

    // Start a 100-byte PING (57 buffered), then a wrong SEQ.
    {
        uint8_t data[100];
        for (int i = 0; i < 100; i++) data[i] = (uint8_t)i;
        uint8_t pkt[FIDO2_REPORT_LEN];
        build_init(pkt, cid, FIDO2_CMD_PING, 100, data, 100);
        feed(1100, pkt);
        CHECK(s_nreports == 1);           // still buffering

        build_cont(pkt, cid, 2, &data[57], 43);   // expected SEQ is 0
        feed(1101, pkt);
        CHECK(is_error(1, cid, FIDO2_ERR_INVALID_SEQ));
    }

    // The channel recovered: a fresh PING works.
    {
        uint8_t data[5] = {1, 2, 3, 4, 5};
        send_ping(1200, cid, data, 5);
        CHECK(verify_ping_resp(2, cid, data, 5) == 1);
    }

    // Stray continuation (no in-flight message): ignored silently.
    {
        uint8_t pkt[FIDO2_REPORT_LEN];
        build_cont(pkt, cid, 1, (const uint8_t[]){0xAA, 0xBB}, 2);
        feed(1300, pkt);
        CHECK(s_nreports == 3);           // nothing new
    }

    // Continuation on the broadcast CID: INVALID_CHANNEL.
    {
        uint8_t pkt[FIDO2_REPORT_LEN];
        build_cont(pkt, FIDO2_BROADCAST_CID, 1, (const uint8_t[]){0xAA}, 1);
        feed(1400, pkt);
        CHECK(is_error(3, FIDO2_BROADCAST_CID, FIDO2_ERR_INVALID_CHANNEL));
    }
}

// An initial packet on a never-seen CID is auto-accepted (the
// Nitrokey/SoloKey leniency; browsers always INIT first, so this only
// matters to tools).
static void t_unknown_cid(void)
{
    fresh();
    const uint32_t cid = 0xABCD1234;
    uint8_t data[3] = {0x01, 0x02, 0x03};

    send_ping(1000, cid, data, 3);
    CHECK(verify_ping_resp(0, cid, data, 3) == 1);
}

// CBOR: the stub's status byte is framed as a 1-byte response; bcnt 0
// is INVALID_LENGTH.
static void t_cbor(void)
{
    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);

    {
        uint8_t data[4] = {0xA1, 0x01, 0x02, 0x03};
        uint8_t pkt[FIDO2_REPORT_LEN];
        build_init(pkt, cid, FIDO2_CMD_CBOR, 4, data, 4);
        feed(1100, pkt);
        CHECK(s_nreports == 2);
        const uint8_t *p = s_reports[1];
        CHECK(rep_cid(p) == cid);
        CHECK(rep_cmd(p) == FIDO2_CMD_CBOR);
        CHECK(rep_bcnt(p) == 1);
        CHECK(p[7] == FIDO2_CTAP_ERR_OK);  // the stub's status
    }

    {
        uint8_t pkt[FIDO2_REPORT_LEN];
        build_init(pkt, cid, FIDO2_CMD_CBOR, 0, NULL, 0);
        feed(1200, pkt);
        CHECK(is_error(2, cid, FIDO2_ERR_INVALID_LENGTH));
    }
}

// U2F (CTAP1) commands on a CTAP2-only device: MSG, MRK, ENROLL, VERIFY
// and AUTHENTICATE are all answered with the U2F status word
// SW_COMMAND_NOT_ALLOWED (0x6986), framed as a 2-byte [SW1|SW2] response on
// the same command byte, so a conformant platform abandons U2F and retries
// CTAP2 (CTAP v2.0 §7.2). This is the exact exchange that was hanging the
// browser — Chrome sends CTAPHID_ENROLL (0x83) and the device must reply
// with the status word (not a CTAPHID ERROR) for the platform to switch to
// CTAP2 makeCredential.
static void t_u2f_not_allowed(void)
{
    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);
    uint8_t pkt[FIDO2_REPORT_LEN];
    uint8_t data[4] = {0x00, 0x11, 0x22, 0x33};   // plausible U2F payload

    build_init(pkt, cid, FIDO2_CMD_ENROLL, 4, data, 4);
    feed(1100, pkt);
    CHECK(is_u2f_status(1, cid, FIDO2_CMD_ENROLL, 0x69, 0x86));

    build_init(pkt, cid, FIDO2_CMD_MSG, 4, data, 4);
    feed(1200, pkt);
    CHECK(is_u2f_status(2, cid, FIDO2_CMD_MSG, 0x69, 0x86));

    build_init(pkt, cid, FIDO2_CMD_MRK, 0, NULL, 0);
    feed(1300, pkt);
    CHECK(is_u2f_status(3, cid, FIDO2_CMD_MRK, 0x69, 0x86));

    build_init(pkt, cid, FIDO2_CMD_VERIFY, 4, data, 4);
    feed(1400, pkt);
    CHECK(is_u2f_status(4, cid, FIDO2_CMD_VERIFY, 0x69, 0x86));

    build_init(pkt, cid, FIDO2_CMD_AUTHENTICATE, 4, data, 4);
    feed(1500, pkt);
    CHECK(is_u2f_status(5, cid, FIDO2_CMD_AUTHENTICATE, 0x69, 0x86));
}

// WINK: empty response + the hook fires.
static void t_wink(void)
{
    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);

    uint8_t pkt[FIDO2_REPORT_LEN];
    build_init(pkt, cid, FIDO2_CMD_WINK, 0, NULL, 0);
    feed(1100, pkt);

    CHECK(s_nreports == 2);
    CHECK(s_winks == 1);
    const uint8_t *p = s_reports[1];
    CHECK(rep_cid(p) == cid);
    CHECK(rep_cmd(p) == FIDO2_CMD_WINK);
    CHECK(rep_bcnt(p) == 0);
}

// reset (the unmount/re-plug path): protocol state starts fresh and the
// handlers registered at boot survive. With a full init on this path, a
// re-plugged key answers CTAP but WINK never reaches the hook — the
// bench bug this test guards against.
static void t_reset_preserves_handlers(void)
{
    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);
    CHECK(cid == 2);

    uint8_t pkt[FIDO2_REPORT_LEN];

    // A stale in-flight message must not survive the reset either: start
    // a two-packet PING and reset after only the first packet.
    uint8_t data[60];
    for (int i = 0; i < 60; i++) {
        data[i] = (uint8_t)i;
    }
    build_init(pkt, cid, FIDO2_CMD_PING, 60, data, 60);
    feed(1100, pkt);
    CHECK(s_nreports == 1);   // INIT response only; PING still in flight

    fido2_ctaphid_reset(&s);
    s_nreports = 0;
    s_winks    = 0;

    // Allocation restarts at 2 on the fresh channel table ...
    uint32_t cid2 = do_init(2000, FIDO2_BROADCAST_CID);
    CHECK(cid2 == 2);

    // ... and WINK reaches the hook (stale in-flight did not block it).
    build_init(pkt, cid2, FIDO2_CMD_WINK, 0, NULL, 0);
    feed(2100, pkt);
    CHECK(s_winks == 1);
    CHECK(rep_cmd(s_reports[1]) == FIDO2_CMD_WINK);

    // The CBOR handler survives too: the stub's OK (0x00), not the
    // no-handler fallback INVALID_COMMAND (0x11).
    uint8_t st = 0x01;
    build_init(pkt, cid2, FIDO2_CMD_CBOR, 1, &st, 1);
    feed(2200, pkt);
    CHECK(rep_cmd(s_reports[2]) == FIDO2_CMD_CBOR);
    CHECK(s_reports[2][7] == FIDO2_CTAP_ERR_OK);

    // init, by contrast, is the first-boot full wipe.
    fido2_ctaphid_init(&s);
    CHECK(s.cbor_cb == NULL);
    CHECK(s.wink_cb == NULL);
}

// CANCEL: no response at all (Chromium does not wait for one).
static void t_cancel(void)
{
    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);

    uint8_t pkt[FIDO2_REPORT_LEN];
    build_init(pkt, cid, FIDO2_CMD_CANCEL, 0, NULL, 0);
    feed(1100, pkt);
    CHECK(s_nreports == 1);               // only the INIT response
}

// Unknown command: INVALID_CMD.
static void t_unknown_cmd(void)
{
    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);

    uint8_t pkt[FIDO2_REPORT_LEN];
    build_init(pkt, cid, 0x42, 0, NULL, 0);
    feed(1100, pkt);
    CHECK(is_error(1, cid, FIDO2_ERR_INVALID_CMD));
}

// Channel busy: while one message is in flight on a channel, an initial
// packet on ANOTHER channel gets CHANNEL_BUSY (continuations on it are
// ignored), while an INIT on that other channel still works (channel
// sync is not a message).
static void t_channel_busy(void)
{
    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);
    CHECK(cid == 2);
    const uint32_t other = 3;

    // Start a 100-byte PING on `cid` (leaves 43 bytes to go).
    {
        uint8_t data[100];
        for (int i = 0; i < 100; i++) data[i] = (uint8_t)i;
        uint8_t pkt[FIDO2_REPORT_LEN];
        build_init(pkt, cid, FIDO2_CMD_PING, 100, data, 100);
        feed(1100, pkt);
        CHECK(s_nreports == 1);
    }

    // Initial packet on the other channel: CHANNEL_BUSY.
    {
        uint8_t data[3] = {1, 2, 3};
        uint8_t pkt[FIDO2_REPORT_LEN];
        build_init(pkt, other, FIDO2_CMD_PING, 3, data, 3);
        feed(1200, pkt);
        CHECK(is_error(1, other, FIDO2_ERR_CHANNEL_BUSY));
    }

    // Continuation on the other channel: ignored silently.
    {
        uint8_t pkt[FIDO2_REPORT_LEN];
        build_cont(pkt, other, 1, (const uint8_t[]){0x01}, 1);
        feed(1300, pkt);
        CHECK(s_nreports == 2);
    }

    // INIT on the other channel: a sync, which still works.
    CHECK(do_init(1400, other) == other);
    CHECK(s_nreports == 3);

    // Finish the in-flight PING; then the other channel is usable.
    {
        uint8_t data[100];
        for (int i = 0; i < 100; i++) data[i] = (uint8_t)i;
        uint8_t pkt[FIDO2_REPORT_LEN];
        build_cont(pkt, cid, 0, &data[57], 43);
        feed(1500, pkt);
        CHECK(verify_ping_resp(3, cid, data, 100) == 2);
    }
    {
        uint8_t data[3] = {9, 8, 7};
        send_ping(1600, other, data, 3);
        CHECK(verify_ping_resp(5, other, data, 3) == 1);
    }
}

// INIT on the in-flight CID discards the in-flight message (channel
// sync), then the channel is usable again.
static void t_init_discards_inflight(void)
{
    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);

    uint8_t data[100];
    for (int i = 0; i < 100; i++) data[i] = (uint8_t)i;
    uint8_t pkt[FIDO2_REPORT_LEN];
    build_init(pkt, cid, FIDO2_CMD_PING, 100, data, 100);
    feed(1100, pkt);
    CHECK(s_nreports == 1);

    // Sync the channel: the in-flight PING is discarded.
    CHECK(do_init(1200, cid) == cid);
    CHECK(s_nreports == 2);

    // The continuation of the discarded PING is now a stray: ignored.
    build_cont(pkt, cid, 0, &data[57], 43);
    feed(1300, pkt);
    CHECK(s_nreports == 2);

    // A fresh PING works.
    send_ping(1400, cid, data, 5);
    CHECK(verify_ping_resp(2, cid, data, 5) == 1);
}

// The 750 ms busy timeout: an in-flight message that stalls is aborted
// with MESSAGE_TIMEOUT and the channel recovers; continuation packets
// keep a slow-but-steady message alive.
static void t_busy_timeout(void)
{
    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);

    uint8_t data[100];
    for (int i = 0; i < 100; i++) data[i] = (uint8_t)i;
    uint8_t pkt[FIDO2_REPORT_LEN];

    // Stalled message: init at t=1000, nothing after.
    build_init(pkt, cid, FIDO2_CMD_PING, 100, data, 100);
    feed(1000, pkt);
    fido2_ctaphid_tick(&s, 1700, sink, NULL);
    CHECK(s_nreports == 1);                            // 700 ms: still fine
    fido2_ctaphid_tick(&s, 1750, sink, NULL);
    CHECK(is_error(1, cid, FIDO2_ERR_MESSAGE_TIMEOUT)); // 750 ms: aborted

    // The channel recovered.
    send_ping(2000, cid, data, 5);
    CHECK(verify_ping_resp(2, cid, data, 5) == 1);

    // A slow drip (59-byte continuations, 700 ms apart) never times out.
    fresh();
    cid = do_init(1000, FIDO2_BROADCAST_CID);
    build_init(pkt, cid, FIDO2_CMD_PING, 200, data, 200);
    feed(1000, pkt);
    fido2_ctaphid_tick(&s, 1700, sink, NULL);
    CHECK(s_nreports == 1);
    build_cont(pkt, cid, 0, &data[57], 59);
    feed(1700, pkt);
    fido2_ctaphid_tick(&s, 2400, sink, NULL);
    CHECK(s_nreports == 1);
    build_cont(pkt, cid, 1, &data[116], 59);
    feed(2400, pkt);
    fido2_ctaphid_tick(&s, 3100, sink, NULL);
    CHECK(s_nreports == 1);
    build_cont(pkt, cid, 2, &data[175], 25);
    feed(3100, pkt);
    CHECK(verify_ping_resp(1, cid, data, 200) == 4);   // delivered in full
}

// Keep-alives: emitted only while a transaction is active, throttled to
// one per 500 ms (the stub fires 7 in 700 ms -> exactly 2 go out), on
// the transaction's CID, with the requested status byte.
static void t_keepalive(void)
{
    fresh();
    uint32_t cid = do_init(1000, FIDO2_BROADCAST_CID);

    // No active transaction: keep-alives are dropped.
    fido2_ctaphid_keepalive(&s, 2000, FIDO2_KEEPALIVE_PROCESSING, sink, NULL);
    CHECK(s_nreports == 1);

    // 7 keep-alive attempts over 700 ms inside the CBOR handler:
    // the first goes out immediately, the next only after 500 ms.
    s_stub_now = 2000;
    s_keepalive_calls = 7;
    uint8_t data[4] = {0xA1, 0x01, 0x02, 0x03};
    uint8_t pkt[FIDO2_REPORT_LEN];
    build_init(pkt, cid, FIDO2_CMD_CBOR, 4, data, 4);
    feed(2000, pkt);

    CHECK(s_nreports == 4);          // 2 keep-alives + the CBOR response
    for (int i = 1; i <= 2; i++) {
        const uint8_t *p = s_reports[i];
        CHECK(rep_cid(p) == cid);
        CHECK(rep_cmd(p) == FIDO2_CMD_KEEPALIVE);
        CHECK(rep_bcnt(p) == 1);
        CHECK(p[7] == FIDO2_KEEPALIVE_PROCESSING);
    }
    {
        const uint8_t *p = s_reports[3];
        CHECK(rep_cmd(p) == FIDO2_CMD_CBOR);
        CHECK(rep_bcnt(p) == 1);
        CHECK(p[7] == FIDO2_CTAP_ERR_OK);
    }
    s_keepalive_calls = 0;
}

// The channel table evicts the least-recently-used entry when full, so
// broadcast INIT never fails (9 allocations all succeed; the evicted
// CID is still usable, being re-accepted on first sight).
static void t_channel_eviction(void)
{
    fresh();
    uint32_t expected = 2;

    for (int i = 0; i < FIDO2_MAX_CHANNELS; i++) {
        uint32_t cid = do_init(1000 + i, FIDO2_BROADCAST_CID);
        CHECK(cid == expected++);
    }
    CHECK(s_nreports == FIDO2_MAX_CHANNELS);

    // The 9th allocation evicts the oldest (CID 2) and still succeeds.
    uint32_t cid = do_init(2000, FIDO2_BROADCAST_CID);
    CHECK(cid == expected);
    CHECK(s_nreports == FIDO2_MAX_CHANNELS + 1);

    // The evicted channel is simply unknown again: auto-accept.
    uint8_t data[3] = {1, 2, 3};
    send_ping(2100, 2, data, 3);
    CHECK(verify_ping_resp(s_nreports - 1, 2, data, 3) == 1);
}

// --- deferred transactions (Phase 3) ------------------------------------------------------

// True when `cid` has a slot in the channel table (the struct is fully
// exposed; the tests already reach into its state).
static int channel_known(uint32_t cid)
{
    for (int i = 0; i < FIDO2_MAX_CHANNELS; i++) {
        if (s.channels[i].cid == cid) {
            return 1;
        }
    }
    return 0;
}

// INIT a channel, then send it a single-packet CBOR message that the
// stub defers; returns the channel's CID.
static uint32_t start_deferred(uint32_t now)
{
    const uint32_t cid = do_init(now, FIDO2_BROADCAST_CID);
    s_defer = 1;
    uint8_t pkt[FIDO2_REPORT_LEN];
    uint8_t data[4] = {0xA1, 0x01, 0x02, 0x03};
    build_init(pkt, cid, FIDO2_CMD_CBOR, 4, data, 4);
    feed(now + 100, pkt);
    return cid;
}

// A deferred CBOR holds its channel with no immediate response; the
// UP-wait keep-alives are throttled to one per 500 ms; complete()
// frames the late response (multi-packet) and releases the channel.
static void t_deferred(void)
{
    fresh();
    const uint32_t cid = start_deferred(1000);

    // No response yet (only the INIT's), no cancel recorded.
    CHECK(s_nreports == 1);
    CHECK(!fido2_ctaphid_cancelled(&s));

    // UP-wait keep-alives: 2000 goes out (period since the dispatch),
    // 2400 is throttled, 2600 goes out again.
    fido2_ctaphid_keepalive(&s, 2000, FIDO2_KEEPALIVE_UP_NEEDED, sink, NULL);
    fido2_ctaphid_keepalive(&s, 2400, FIDO2_KEEPALIVE_UP_NEEDED, sink, NULL);
    fido2_ctaphid_keepalive(&s, 2600, FIDO2_KEEPALIVE_UP_NEEDED, sink, NULL);
    CHECK(s_nreports == 3);
    for (int i = 1; i <= 2; i++) {
        const uint8_t *p = s_reports[i];
        CHECK(rep_cid(p) == cid);
        CHECK(rep_cmd(p) == FIDO2_CMD_KEEPALIVE);
        CHECK(rep_bcnt(p) == 1);
        CHECK(p[7] == FIDO2_KEEPALIVE_UP_NEEDED);
    }

    // complete(): the 200-byte response is framed as 4 packets
    // (57 + 59 + 59 + 25).
    uint8_t resp[200];
    for (int i = 0; i < 200; i++) {
        resp[i] = (uint8_t)i;
    }
    const int before = s_nreports;
    fido2_ctaphid_complete(&s, resp, sizeof resp, sink, NULL);
    CHECK(s_nreports == before + 4);
    {
        const uint8_t *p = s_reports[before];
        CHECK(rep_cid(p) == cid);
        CHECK(rep_cmd(p) == FIDO2_CMD_CBOR);
        CHECK(rep_bcnt(p) == 200);
        CHECK(0 == memcmp(&p[FIDO2_INIT_HDR_LEN], resp, FIDO2_INIT_DATA_LEN));
    }
    {   // and the last packet carries the tail
        const uint8_t *p = s_reports[before + 3];
        CHECK(0 == memcmp(&p[FIDO2_CONT_HDR_LEN], &resp[175], 25));
    }

    // The channel is released: a new (non-deferred) CBOR answers at once.
    s_defer = 0;
    uint8_t pkt[FIDO2_REPORT_LEN];
    uint8_t data[4] = {0xA1, 0x01, 0x02, 0x03};
    build_init(pkt, cid, FIDO2_CMD_CBOR, 4, data, 4);
    feed(3000, pkt);
    CHECK(s_nreports == before + 5);
    CHECK(rep_cid(s_reports[before + 4]) == cid);
    CHECK(rep_cmd(s_reports[before + 4]) == FIDO2_CMD_CBOR);
    CHECK(s_reports[before + 4][7] == FIDO2_CTAP_ERR_OK);
}

// complete() with no deferred transaction is a no-op (no report).
static void t_complete_idle(void)
{
    fresh();
    const uint8_t resp[1] = {FIDO2_CTAP_ERR_OK};
    fido2_ctaphid_complete(&s, resp, 1, sink, NULL);
    CHECK(s_nreports == 0);
    CHECK(!fido2_ctaphid_cancelled(&s));
}

// CANCEL: ignored on a foreign channel, recorded on the transaction's
// channel (still no response), and the app's 0x2D completion releases
// the channel and clears the flag.
static void t_deferred_cancel(void)
{
    fresh();
    const uint32_t cid = start_deferred(1000);
    uint8_t pkt[FIDO2_REPORT_LEN];

    build_init(pkt, 3, FIDO2_CMD_CANCEL, 0, NULL, 0);
    feed(1500, pkt);
    CHECK(s_nreports == 1);
    CHECK(!fido2_ctaphid_cancelled(&s));

    build_init(pkt, cid, FIDO2_CMD_CANCEL, 0, NULL, 0);
    feed(1600, pkt);
    CHECK(s_nreports == 1);           // a CANCEL gets no response
    CHECK(fido2_ctaphid_cancelled(&s));

    // The app finishes the transaction with KEEPALIVE_CANCEL (0x2D).
    const uint8_t resp[1] = {0x2D};
    fido2_ctaphid_complete(&s, resp, 1, sink, NULL);
    CHECK(s_nreports == 2);
    CHECK(rep_cid(s_reports[1]) == cid);
    CHECK(rep_cmd(s_reports[1]) == FIDO2_CMD_CBOR);
    CHECK(rep_bcnt(s_reports[1]) == 1);
    CHECK(s_reports[1][7] == 0x2D);
    CHECK(!fido2_ctaphid_cancelled(&s));

    // Released: a new message on the channel works again.
    s_defer = 0;
    uint8_t data[3] = {1, 2, 3};
    send_ping(2000, cid, data, 3);
    CHECK(1 == verify_ping_resp(2, cid, data, 3));
}

// The busy rules apply to a deferred channel exactly as to an in-flight
// one (INVALID_SEQ on the channel itself, CHANNEL_BUSY on others) —
// except CANCEL is exempt — and stray continuations are dropped.
static void t_deferred_busy(void)
{
    fresh();
    const uint32_t cid = start_deferred(1000);
    uint8_t pkt[FIDO2_REPORT_LEN];
    uint8_t data[3] = {1, 2, 3};

    build_init(pkt, cid, FIDO2_CMD_PING, 3, data, 3);
    feed(1500, pkt);
    CHECK(is_error(1, cid, FIDO2_ERR_INVALID_SEQ));

    build_init(pkt, 3, FIDO2_CMD_PING, 3, data, 3);
    feed(1600, pkt);
    CHECK(is_error(2, 3, FIDO2_ERR_CHANNEL_BUSY));

    // CANCEL is exempt from the busy rules (it aborts the transaction).
    build_init(pkt, cid, FIDO2_CMD_CANCEL, 0, NULL, 0);
    feed(1700, pkt);
    CHECK(s_nreports == 3);
    CHECK(fido2_ctaphid_cancelled(&s));

    // A stray continuation (no in-flight message) is dropped silently.
    build_cont(pkt, cid, 0, data, 3);
    feed(1800, pkt);
    CHECK(s_nreports == 3);
}

// A channel-sync INIT on the transaction's channel gets the normal 17-byte
// INIT response AND records the transaction as cancelled; a broadcast INIT
// during the wait still allocates a fresh channel.
static void t_deferred_init_sync(void)
{
    fresh();
    const uint32_t cid = start_deferred(1000);

    const int before = s_nreports;
    CHECK(cid == do_init(1500, cid));
    CHECK(s_nreports == before + 1);
    CHECK(fido2_ctaphid_cancelled(&s));

    const uint8_t resp[1] = {0x2D};
    fido2_ctaphid_complete(&s, resp, 1, sink, NULL);
    CHECK(s_nreports == before + 2);
    CHECK(s_reports[before + 1][7] == 0x2D);
    CHECK(!fido2_ctaphid_cancelled(&s));

    // A broadcast INIT still works during a deferred wait.
    fresh();
    start_deferred(1000);
    CHECK(3 == do_init(1500, FIDO2_BROADCAST_CID));
    CHECK(!fido2_ctaphid_cancelled(&s));
}

// LRU eviction never drops the channel of an active (deferred)
// transaction, so a broadcast INIT can still allocate while the device
// waits for a touch.
static void t_deferred_eviction(void)
{
    fresh();
    const uint32_t cid = start_deferred(1000);   // CID 2, the oldest entry

    // Fill the table with 7 more channels (2..9 = all 8 slots).
    for (int i = 0; i < FIDO2_MAX_CHANNELS - 1; i++) {
        const uint32_t c = do_init(2000 + (uint32_t)i, FIDO2_BROADCAST_CID);
        CHECK(c == (uint32_t)(3 + i));
    }
    CHECK(channel_known(cid));

    // The next allocation must evict — CID 3 is the oldest unprotected
    // entry; the transaction's channel (2) survives.
    CHECK((FIDO2_MAX_CHANNELS + 2) == do_init(3000, FIDO2_BROADCAST_CID));
    CHECK(channel_known(cid));
    CHECK(!channel_known(3));

    // And the transaction is still live on it (a new PING is refused).
    uint8_t pkt[FIDO2_REPORT_LEN];
    uint8_t data[3] = {1, 2, 3};
    build_init(pkt, cid, FIDO2_CMD_PING, 3, data, 3);
    feed(4000, pkt);
    CHECK(is_error(s_nreports - 1, cid, FIDO2_ERR_INVALID_SEQ));
}

// --- main ------------------------------------------------------------------------------

int main(void)
{
    t_init_broadcast();
    t_init_sync();
    t_init_errors();
    t_ping_single();
    t_ping_multipacket();
    t_seq_rules();
    t_unknown_cid();
    t_cbor();
    t_u2f_not_allowed();
    t_wink();
    t_reset_preserves_handlers();
    t_cancel();
    t_unknown_cmd();
    t_channel_busy();
    t_init_discards_inflight();
    t_busy_timeout();
    t_keepalive();
    t_channel_eviction();
    t_deferred();
    t_complete_idle();
    t_deferred_cancel();
    t_deferred_busy();
    t_deferred_init_sync();
    t_deferred_eviction();

    printf("%s: %d checks, %d failures\n",
           (s_failures == 0) ? "PASS" : "FAIL", s_checks, s_failures);
    return (s_failures == 0) ? 0 : 1;
}

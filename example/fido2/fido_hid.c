// fido_hid.c — USB descriptors + TinyUSB glue (see fido_hid.h).
//
// Descriptor facts (verified against the CTAP v2.0 spec, the U2FHID
// spec, Nitrokey/SoloKey firmware, and Chromium's discovery path):
//  - ONE HID interface, NO report IDs: two raw 64-byte reports, IN and
//    OUT. Chromium matches FIDO devices on usage page 0xF1D0 and report
//    size in (7, 64]; libfido2 on the same usage page.
//  - IN EP 0x81 / OUT EP 0x01, interrupt, 64-byte max packet, bInterval
//    5 (the U2FHID spec's own example values).
//  - Report descriptor: 34 bytes, from TinyUSB's own
//    TUD_HID_REPORT_DESC_FIDO_U2F template — byte-identical to
//    Nitrokey's FIDO descriptor (the spec's abstract form,
//    instantiated with 64-byte reports); static-asserted on the size.
//  - The OUT endpoint buffer stays 64 bytes (see tusb_config.h for why
//    it must not grow): the RP2040/RP2350 DCD arms the OUT transfer
//    with that size, and a 64-byte arm carries the hardware LAST bit,
//    so one 64-byte host packet completes the transfer.
//
// Host delivery: every conformant host hands the device exactly the
// 64 report bytes on the OUT endpoint (Linux's usbhid consumes the
// hidraw 0x00 report-ID byte before the wire; Windows/macOS have no ID
// byte for a no-report-ID device), so the state machine sees 64-byte
// reports only.

#include "fido_hid.h"

#include <stdio.h>
#include <string.h>

#include "hardware/gpio.h"

#include "pico/stdio.h"
#include "pico/unique_id.h"

#include "tusb.h"

#include "atecc608/atecc608.h"
#include "atecc608/atecc608_crypto.h"
#include "atecc608/atecc608_prov.h"

#include "pico_littlefs.h"

#include "fido_ctap.h"
#include "fido_ctaphid.h"

// On-board LED (GP25): status indicator + WINK.
#define FIDO2_LED_PIN 25

// --- descriptors -------------------------------------------------------------

// 34-byte FIDO HID report descriptor. Built from TinyUSB's own
// FIDO/U2F template (usage page 0xF1D0, usage 0x01, IN usage 0x20 /
// OUT usage 0x21, no report IDs) with 64-byte reports — byte-identical
// to Nitrokey's FIDO descriptor. The static assert keeps it honest if
// the template ever changes under us.
static const uint8_t s_report_desc[] = {
    TUD_HID_REPORT_DESC_FIDO_U2F(FIDO2_REPORT_LEN)
};
_Static_assert(sizeof s_report_desc == 34,
               "FIDO HID report descriptor must stay 34 bytes");

// Device descriptor. (This pico-sdk fork's TinyUSB ships none of the
// descriptor-builder helpers — no TUD_DESC_TYPE_*, LO16/HI16 — so the
// bytes are written out directly, the same style Nitrokey uses.)
static const uint8_t s_device_desc[] = {
    0x12,                                     // bLength
    TUSB_DESC_DEVICE,                         // bDescriptorType (0x01)
    0x00, 0x02,                               // bcdUSB 2.0
    0x00, 0x00, 0x00,                         // class/subclass/protocol: per interface
    0x40,                                     // bMaxPacketSize0 (full speed)
    (uint8_t)(FIDO2_USB_VID & 0xFFu), (uint8_t)(FIDO2_USB_VID >> 8),
    (uint8_t)(FIDO2_USB_PID & 0xFFu), (uint8_t)(FIDO2_USB_PID >> 8),
    0x00, 0x01,                               // bcdDevice 1.0
    0x01, 0x02, 0x03,                         // iManufacturer/iProduct/iSerial
    0x01,                                     // bNumConfigurations
};

#define FIDO2_CFG_LEN (9 + 9 + 9 + 7 + 7)

static const uint8_t s_config_desc[] = {
    // Configuration
    0x09, TUSB_DESC_CONFIGURATION,
    (uint8_t)(FIDO2_CFG_LEN & 0xFFu), (uint8_t)(FIDO2_CFG_LEN >> 8),
    0x01,                                     // bNumInterfaces
    0x01,                                     // bConfigurationValue
    0x00,                                     // iConfiguration
    0x80,                                     // bmAttributes: bus powered
    0x32,                                     // bMaxPower: 100 mA
    // Interface 0: HID
    0x09, TUSB_DESC_INTERFACE,
    0x00,                                     // bInterfaceNumber
    0x00,                                     // bAlternateSetting
    0x02,                                     // bNumEndpoints
    TUSB_CLASS_HID, 0x00, 0x00,               // HID class, no boot, no protocol
    0x00,                                     // iInterface
    // HID class descriptor
    0x09, 0x21,                               // bDescriptorType: HID (class-specific)
    0x11, 0x01,                               // bcdHID 1.11
    0x00,                                     // bCountryCode
    0x01,                                     // bNumDescriptors
    0x22,                                     //   descriptor type: report (0x22, HID_DT_REPORT
                                              //   — NOT 0x21, which is the HID descriptor
                                              //   type itself; Linux's usbhid rejects the
                                              //   device with -EINVAL unless this is 0x22)
    (uint8_t)sizeof s_report_desc, 0x00,      //   report descriptor length (34)
    // Endpoint 0x81: interrupt IN, 64 bytes, every 5 ms
    0x07, TUSB_DESC_ENDPOINT, 0x81,
    0x03,                                     // bmAttributes: interrupt
    FIDO2_REPORT_LEN, 0x00,
    0x05,                                     // bInterval (5 ms, full speed)
    // Endpoint 0x01: interrupt OUT, 64 bytes, every 5 ms
    0x07, TUSB_DESC_ENDPOINT, 0x01,
    0x03,                                     // bmAttributes: interrupt
    FIDO2_REPORT_LEN, 0x00,
    0x05,                                     // bInterval (5 ms, full speed)
};
_Static_assert(sizeof s_config_desc == FIDO2_CFG_LEN,
               "FIDO HID configuration descriptor length mismatch");

// String descriptors: C strings converted in the callback (the SDK's own
// pattern — this fork has no U16STR helper). Index 3 (serial) is filled
// by fido_hid_init() from the Pico's unique ID; 16 hex chars distinguish
// several of these on one PC.
static const char *const s_strings[] = {
    [1] = "Raspberry Pi",
    [2] = "Pico ATECC608 FIDO2",
    [3] = NULL,
};
static char s_serial[17];

// --- state ---------------------------------------------------------------------

static fido2_ctaphid_t  s_ctaphid;
// The CTAP2 dispatch context (fido_ctap.h) — Phase 2 is read-only
// identity data (AAGUID + capabilities); later phases extend it.
static fido_ctap_ctx_t  s_ctap_ctx;
static bool             s_enabled;

// WINK is non-blocking: the callback only marks the window; fido_hid_tick
// drives the LED (tud_task must not be delayed by a blink delay).
static uint32_t s_wink_until_ms;

static void led_wink_cb(void *ctx)
{
    (void)ctx;
    s_wink_until_ms = osal_time_millis() + 600;
}

// --- deferred IN reports --------------------------------------------------------
// TinyUSB allows ONE IN transfer in flight per endpoint: a
// tud_hid_report() while the previous report still awaits the host's ACK
// fails. The state machine emits a multi-packet response (GET_INFO's
// 64-byte payload = 2 CTAPHID packets) with back-to-back sink calls from
// the OUT handler, where only the just-armed first transfer is visible
// — bench-verified 2026-10-30: the continuation was silently dropped and
// the host's reassembly timed out. The sink therefore enqueues;
// fido_hid_tick() (which runs after tud_task() has seen the host's ACK)
// releases one report per ready endpoint. The queue spans the FULL
// 7609-byte message maximum (57 + 128*59 -> 129 packets), so no
// well-formed response can overflow; a drop would only follow a host
// stalled for >129 ACK intervals, which the spec's message timeouts
// already treat as a dead transaction.
#define FIDO2_OUT_QUEUE_MAX 129
static uint8_t  s_outq[FIDO2_OUT_QUEUE_MAX][FIDO2_REPORT_LEN];
static uint16_t s_outq_head;   // next slot to write
static uint16_t s_outq_tail;   // next slot to read
static uint16_t s_outq_count;

static void outq_push(const uint8_t report[FIDO2_REPORT_LEN])
{
    if (s_outq_count < FIDO2_OUT_QUEUE_MAX) {
        memcpy(&s_outq[s_outq_head], report, FIDO2_REPORT_LEN);
        s_outq_head = (uint16_t)((s_outq_head + 1u) % FIDO2_OUT_QUEUE_MAX);
        s_outq_count++;
    }
    // else: dropped — see above.
}

static void outq_flush(void)
{
    s_outq_head = 0;
    s_outq_tail = 0;
    s_outq_count = 0;
}

static void outq_drain(void)
{
    while (0 != s_outq_count && tud_hid_ready()) {
        if (!tud_hid_report(0, s_outq[s_outq_tail], FIDO2_REPORT_LEN)) {
            break;   // cannot happen (ready checked); retry next tick
        }
        s_outq_tail = (uint16_t)((s_outq_tail + 1u) % FIDO2_OUT_QUEUE_MAX);
        s_outq_count--;
    }
}

// The state machine's report sink: enqueue one 64-byte IN report for
// fido_hid_tick() to release (a direct send here would race the
// endpoint — a dropped continuation is unrecoverable, the host never
// re-requests it).
static void report_sink(void *ctx, const uint8_t report[FIDO2_REPORT_LEN])
{
    (void)ctx;
    outq_push(report);
}

// --- status LED ------------------------------------------------------------------

static void led_init(void)
{
    // gpio_init, NOT just gpio_set_dir: after reset the pin's function
    // select is GPIO_FUNC_NULL (31) — the pad is not routed to the SIO
    // output at all, so set_dir alone leaves a pin whose latch works but
    // whose wire never moves (the WINK-LED bug, bench-verified 2026-10-30:
    // latch=1 dir=1 func=31 pad=0). gpio_init sets function SIO (the GPIO
    // function on RP2350) + input direction + a clean pad config.
    gpio_init(FIDO2_LED_PIN);
    gpio_set_dir(FIDO2_LED_PIN, GPIO_OUT);
}

static void led_tick(uint32_t now_ms)
{
    bool on;
    if (!s_enabled) {
        // Not provisioned: slow blink (1 s period).
        on = ((now_ms / 500u) % 2u) == 0u;
    } else if (now_ms < s_wink_until_ms) {
        // WINK: 100 ms on/off flicker for the rest of the window.
        on = ((now_ms / 100u) % 2u) == 0u;
    } else {
        on = true;   // provisioned and idle: solid
    }
    gpio_put(FIDO2_LED_PIN, on);
}

// --- user-presence console (UART0) ---------------------------------------------------
// The key has no physical touch button yet, so user presence is driven
// from the UART0 console (115200 8N1): typing 'up' records a touch for
// the CTAP layer to consume (Phase 3 MakeCredential; GetAssertion in a
// later phase). A physical button on a free GPIO can feed the same flag
// later without touching the CTAP layer.
//
// Non-blocking by construction: stdio_getchar_timeout_us(0) yields at
// most one character per call (0-255, or PICO_ERROR_TIMEOUT), so the
// main loop's 1 ms cadence bounds the work to the bytes that actually
// arrived. The terminal echoes what the user types; this side prints
// only the result. Both CR and LF terminate a line (a CRLF terminal
// sends both; the second sees an empty line and does nothing).
#define FIDO2_CONSOLE_LINE_MAX 16
static char   s_console_line[FIDO2_CONSOLE_LINE_MAX];
static size_t s_console_len;

static void console_line_done(void)
{
    if (0 != s_console_len) {
        if (0 == strcmp(s_console_line, "up")) {
            s_ctap_ctx.user_present = true;
            printf("fido2: user presence ('up')\n");
        } else {
            printf("fido2: unknown console command '%s' — try 'up'\n",
                   s_console_line);
        }
    }
    s_console_len = 0;
}

static void console_tick(void)
{
    int c;
    while (0 <= (c = stdio_getchar_timeout_us(0))) {
        if (('\n' == c) || ('\r' == c)) {
            console_line_done();
        } else if ((0x20 <= c) && (c <= 0x7e) &&
                   (s_console_len < FIDO2_CONSOLE_LINE_MAX - 1u)) {
            s_console_line[s_console_len++] = (char)c;
            s_console_line[s_console_len] = '\0';
        }
        // else: dropped (control chars, NUL, non-ASCII bytes).
    }
}

// --- ATECC608 key backend (the CTAP layer's vtable) -------------------------------
// The CTAP layer (fido_ctap.h) knows no chip: it calls these hooks.
// Slots 3-6 hold the credential key pairs (slot 1 is the device
// identity key, provisioning-only — the CTAP layer never touches it).

static int be_genkey(void *dev, uint8_t slot, uint8_t pub[64])
{
    (void)dev;
    return (ATECC608_OK == atecc608_genkey(slot, pub)) ? 0 : -1;
}

static int be_sign(void *dev, uint8_t slot, const uint8_t digest[32],
                   uint8_t sig[64])
{
    (void)dev;
    return (ATECC608_OK == atecc608_sign(slot, digest, sig)) ? 0 : -1;
}

static uint32_t be_counter(void *dev)
{
    (void)dev;
    uint32_t v = 0;
    // Counter 0 = the "FIDO2 signature count" (docs/BRINGUP.md). Phase 3
    // READS it (the authData signCount); Phase 4 increments it per
    // signature. A read failure degrades to 0 — the counter is
    // advisory, not security-critical.
    if (ATECC608_OK != atecc608_counter_read(0, &v)) {
        v = 0;
    }
    return v;
}

static int be_rand(void *dev, uint8_t *buf, uint32_t len)
{
    (void)dev;
    return (ATECC608_OK == atecc608_random(buf, len)) ? 0 : -1;
}

static uint32_t be_clock(void *dev)
{
    (void)dev;
    return osal_time_millis();
}

// --- credential DB on littlefs (/f2_<slot>) ------------------------------------------
// One fixed-size file per credential slot: the 236-byte record image
// (fido_cred.h — CRC-32 checked, the vault's /io_key.bin convention).
// Same flash layout as the console/vault apps (littlefs @ 0x80000), so
// a reflashed fido2 keeps its credentials. The store (in the CTAP
// context) persists through these hooks BEFORE it changes RAM — a
// failed flash write leaves RAM and flash in agreement.

static void cred_path(char *out, size_t out_max, uint8_t slot)
{
    snprintf(out, out_max, "/f2_%u", (unsigned)slot);
}

static int cred_save(void *priv, uint8_t slot, const fido_cred_record_t *rec)
{
    (void)priv;
    char path[8];
    uint8_t img[FIDO_CRED_FILE_SIZE];
    cred_path(path, sizeof path, slot);
    fido_cred_record_encode(rec, img);
    return pico_lfs_write_file(path, img, sizeof img);
}

static int cred_erase(void *priv, uint8_t slot)
{
    (void)priv;
    char path[8];
    cred_path(path, sizeof path, slot);
    // A missing file is not an error (nothing to erase).
    const int st = pico_lfs_remove(path);
    return (0 == st || -LFS_ERR_NOENT == st) ? 0 : st;
}

// Boot-load: read /f2_3../f2_6 and install the well-formed records
// (a missing file = an empty slot; a corrupt file = an empty slot +
// the record will be overwritten on the next registration).
static void cred_load_db(fido_ctap_ctx_t *ctx)
{
    for (int i = 0; i < FIDO_CRED_MAX; i++) {
        const uint8_t slot = (uint8_t)(i + FIDO_CRED_SLOT_MIN);
        char path[8];
        uint8_t img[FIDO_CRED_FILE_SIZE];
        fido_cred_record_t rec;
        cred_path(path, sizeof path, slot);
        if ((int)sizeof img != pico_lfs_read_file(path, img, sizeof img)) {
            continue;   // no file (first boot) — slot empty
        }
        if (fido_cred_record_decode(img, &rec) && rec.slot == slot) {
            fido_cred_store_load(&ctx->creds, i, &rec);
        }
    }
}

// --- TinyUSB callbacks ---------------------------------------------------------------

uint8_t const *tud_descriptor_device_cb(void)
{
    return s_device_desc;
}

uint8_t const *tud_descriptor_configuration_cb(uint8_t index)
{
    (void)index;
    return s_config_desc;
}

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
    (void)langid;
    // Longest string is 18 chars ("Pico ATECC608 FIDO2") + the length
    // word.
    static uint16_t desc_str[19 + 1];
    uint8_t len;

    if (0 == index) {
        desc_str[1] = 0x0409;   // supported language: en-US
        len = 1;
    } else if (index < sizeof s_strings / sizeof s_strings[0]) {
        const char *str = s_strings[index];
        if (NULL == str) {
            str = s_serial;
        }
        for (len = 0; str[len] != '\0' && len < 18; len++) {
            desc_str[1 + len] = (uint16_t)(uint8_t)str[len];
        }
    } else {
        return NULL;
    }

    desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2u * len + 2u));
    return desc_str;
}

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance)
{
    (void)instance;
    return s_report_desc;
}

// GET_REPORT control request: not part of the FIDO protocol (responses
// arrive on the interrupt IN endpoint). Answer zero length, which
// STALLs the request; no conformant FIDO host issues it.
uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                               hid_report_type_t report_type,
                               uint8_t *buffer, uint16_t reqlen)
{
    (void)instance;
    (void)report_id;
    (void)report_type;
    (void)buffer;
    (void)reqlen;
    return 0;
}

// OUT report (interrupt OUT data; SET_REPORT control arrives here too).
// For this no-report-ID device every conformant host delivers exactly the
// 64 raw report bytes (see the file header); anything else is dropped.
void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer, uint16_t bufsize)
{
    (void)report_id;
    (void)report_type;
    if (0 != instance) {
        return;
    }
    if (!s_enabled) {
        return;
    }
    if (FIDO2_REPORT_LEN != bufsize) {
        return;
    }
    fido2_ctaphid_input(&s_ctaphid, osal_time_millis(), buffer,
                        report_sink, NULL);
}

// Bus-level mount/unmount (this TinyUSB fork has no per-class
// tud_hid_mount_cb; the device has a single interface, so the bus
// events are the HID events).
void tud_mount_cb(void)
{
    printf("fido2: USB enumerated (HID interface mounted)\n");
}

void tud_umount_cb(void)
{
    printf("fido2: USB unmounted\n");
    // The host's channels die with the connection; start fresh (CID
    // allocation restarts at 2). Safe: all TinyUSB callbacks run in the
    // main-loop (tud_task) context in this app. reset, NOT init: the
    // handlers registered in fido_hid_init must survive a re-plug — with
    // init, a re-plugged key would answer CTAP but WINK would never reach
    // the LED and CBOR would silently take the no-handler path.
    fido2_ctaphid_reset(&s_ctaphid);
    // A deferred (user-presence-waiting) MakeCredential can no longer be
    // completed — the host's channel is gone; drop it without a response
    // so a re-plug starts clean. (The stored credentials and the chip's
    // keys are untouched — nothing was minted yet; the key pair is only
    // generated AFTER the touch.)
    fido_ctap_abort(&s_ctap_ctx);
    // Any queued reports reference this connection's CIDs — dead now.
    outq_flush();
}

// --- public API ------------------------------------------------------------------------

void fido_hid_init(bool enabled)
{
    // 16 hex chars of the Pico's unique ID.
    pico_get_unique_board_id_string(s_serial, sizeof s_serial);

    fido_ctap_ctx_init(&s_ctap_ctx);
    // The key backend: the ATECC608 (see the section above).
    s_ctap_ctx.keys = (fido_ctap_key_ops_t) {
        .genkey  = be_genkey,
        .sign    = be_sign,
        .counter = be_counter,
        .rand    = be_rand,
        .clock   = be_clock,
    };
    // The credential DB on littlefs, one file per record.
    s_ctap_ctx.creds.save  = cred_save;
    s_ctap_ctx.creds.erase = cred_erase;
    // The credential DB's littlefs volume (the console/vault pattern:
    // mount a formatted volume, format on first boot).
    if (0 == pico_lfs_init(NULL)) {
        if (0 != pico_lfs_mount_existing()) {
            printf("littlefs: no formatted volume — formatting (one-time; can take a while)...\n");
            if (0 != pico_lfs_mount()) {
                printf("littlefs mount FAILED — credential persistence unavailable.\n");
            } else {
                printf("littlefs: fresh volume formatted.\n");
            }
        }
        if (pico_lfs_is_mounted()) {
            cred_load_db(&s_ctap_ctx);
        }
    }
    fido2_ctaphid_init(&s_ctaphid);
    outq_flush();
    // The real CTAP2 dispatch (Phase 3: GET_INFO + MakeCredential —
    // the latter defers its response until user presence; unimplemented
    // command codes answer CTAP1_ERR_INVALID_COMMAND per the spec's MUST).
    fido2_ctaphid_set_cbor(&s_ctaphid, fido_ctap_dispatch, &s_ctap_ctx);
    fido2_ctaphid_set_wink(&s_ctaphid, led_wink_cb, NULL);

    s_enabled = enabled;
    led_init();
    tusb_init();
}

void fido_hid_tick(void)
{
    const uint32_t now_ms = osal_time_millis();
    // The console works in both states: when the chip is not
    // provisioned the device answers no CTAP, but the command still
    // gets its confirmation print.
    console_tick();
    if (s_enabled) {
        outq_drain();
        // A deferred (user-presence-waiting) MakeCredential: keep the
        // client alive (UP_NEEDED keep-alives, throttled) and drive the
        // state machine; the moment it finishes, complete the response
        // over the transport (which releases the channel).
        if (fido_ctap_pending(&s_ctap_ctx)) {
            fido2_ctaphid_keepalive(&s_ctaphid, now_ms,
                                    FIDO2_KEEPALIVE_UP_NEEDED,
                                    report_sink, NULL);
            uint8_t resp[FIDO_CTAP_MC_RESP_MAX];
            uint32_t rlen = 0;
            if (1 == fido_ctap_tick(&s_ctap_ctx,
                                    fido2_ctaphid_cancelled(&s_ctaphid),
                                    resp, sizeof resp, &rlen)) {
                fido2_ctaphid_complete(&s_ctaphid, resp, rlen,
                                       report_sink, NULL);
            }
        }
    }
    fido2_ctaphid_tick(&s_ctaphid, now_ms, report_sink, NULL);
    led_tick(now_ms);
}

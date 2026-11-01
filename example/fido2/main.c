// pico-atecc608-fido2 — FIDO2 (CTAP2) passkey authenticator.
//
// Wiring: same as the console app — ATECC608C on I2C0, SDA GP20 / SCL
// GP21, ADR to GND (address 0x60). The USB interface is the security
// key's pure-HID FIDO descriptor (VID/PID 2E8A:000B) and nothing else —
// there is no CDC, so flash via the BOOTSEL UF2 and read debug prints on
// UART0 (GPIO 0 TX / GPIO 1 RX).
//
// Startup contract (house style, deliberately NOT auto-provisioning):
// probe the chip and require the config zone LOCKED and the identity
// key present (atecc608_get_pubkey on slot 1 — the device identity
// private key, the attestation signing half of the 1/2 pair). If the chip is not provisioned, the app still
// enumerates over USB but answers nothing, slow-blinks the LED (GP25),
// and says so on UART0. It never provisions.
//
// Phase 3 implements the CTAPHID transport (INIT channel
// allocation/sync, PING echo, WINK (LED), CANCEL, the CTAP2 error
// table, the keep-alive plumbing) plus the CTAP2 message layer:
// GET_INFO (versions/aaguid/options/maxMsgSize/...) and MAKE_CREDENTIAL
// (deferred until user presence; on-chip keygen, packed self-attestation,
// credential DB on littlefs) over a minimal CBOR codec; every other
// command code answers CTAP1_ERR_INVALID_COMMAND until its phase lands
// (GET_ASSERTION / RESET in Phases 4-5).

#include <stdio.h>

#include "pico/stdlib.h"
#include "pico/time.h"

#include "tusb.h"

#include "atecc608/atecc608.h"
#include "atecc608/atecc608_prov.h"

#include "fido_hid.h"

// ATECC608 on I2C0 GP20/GP21, ADR to GND (same bus as the console app).
static const atecc608_cfg_t s_cfg = {
    .i2c     = i2c0,
    .sda_pin = 20,
    .scl_pin = 21,
    .addr    = ATECC608_ADDR_ADR_LOW,
    .baud    = ATECC608_FAST_BAUD_HZ,
};

// The FIDO2 attestation key is the existing device identity pair: the
// private half lives in slot 1 (sign-external), the public half in
// slot 2. The on-chip private key in slot 1 must be present for the
// app to consider the chip provisioned: get_pubkey recomputes the
// public key FROM the slot's private key (GenKey mode 0x00), and slot
// 2 is public-key-only in the agreed layout — it can never hold one
// (the console's genkey allowlist is 1/3/4/5/6/12).
#define FIDO2_IDENTITY_SLOT 1

// Startup probe: the chip answers AND the config zone is locked AND the
// identity key is present.
static bool chip_provisioned(void)
{
    bool provisioned = false;
    atecc608_status_t st = atecc608_probe();

    if (ATECC608_OK == st) {
        bool locked = false;
        st = atecc608_is_locked(ATECC608_ZONE_CONFIG, &locked);
        if (ATECC608_OK == st && locked) {
            uint8_t pub[ATECC608_PUBKEY_LEN];
            st = atecc608_get_pubkey(FIDO2_IDENTITY_SLOT, pub);
            provisioned = (ATECC608_OK == st);
        }
    }
    return provisioned;
}

int main(void)
{
    // stdio_init_all() is NOT called before main by the SDK — the app
    // must call it (the console/vault apps got it for free via
    // pico-command-line, which calls it; this app does not link that
    // library). Without it clk_uart never starts and GP0/GP1 are never
    // routed to UART0, so every printf is silently dropped. The only
    // stdio driver present is UART0 (no stdio-over-USB — the USB
    // interface is the HID key).

    stdio_init_all();

    printf("pico-atecc608-fido2: ATECC608 FIDO2 authenticator "
           "(Phase 3: CTAPHID + CTAP2 GET_INFO + MakeCredential)\n");
    printf("UART0 console: type 'up' to record a key touch (user "
           "presence) while a registration waits\n");

    atecc608_status_t st = atecc608_init(&s_cfg);
    if (ATECC608_OK != st) {
        printf("ATECC608 init failed: %s (ATCA_STATUS %d) — check I2C wiring.\n",
               atecc608_status_str(st), (int)atecc608_last_error());
    }

    const bool provisioned = chip_provisioned();
    if (provisioned) {
        printf("ATECC608 provisioned (config locked, identity key in slot %d): "
               "CTAPHID enabled.\n", FIDO2_IDENTITY_SLOT);
    } else {
        printf("ATECC608 not provisioned — provision with the console "
               "(pico-atecc608) first.\n");
        printf("The device still enumerates over USB but answers nothing "
               "until it is provisioned (LED slow-blinking).\n");
    }

    fido_hid_init(provisioned);

    // TinyUSB's documented bare-metal pattern: single-threaded polling.
    // All TinyUSB and CTAPHID callbacks run in this loop's context (no
    // IRQ background task, no mutexes); the 1 ms cadence is well under
    // the 500 ms keep-alive / 750 ms busy-timeout granularity.
    while (1) {
        tud_task();
        fido_hid_tick();
        sleep_ms(1);
    }
}

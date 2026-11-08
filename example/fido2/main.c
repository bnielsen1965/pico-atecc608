// pico-atecc608-fido2 — FIDO2 (CTAP2) passkey authenticator.
//
// Wiring: same as the console app — ATECC608C on I2C0, SDA GP20 / SCL
// GP21, ADR to GND (address 0x60). The USB interface is the security
// key's pure-HID FIDO descriptor (VID/PID 2E8A:000B) and nothing else —
// there is no CDC, so flash via the BOOTSEL UF2 and read debug prints on
// UART0 (GPIO 0 TX / GPIO 1 RX). Optional: a user-presence button
// between GP10 and GND (internal pull-up; 'pin' on the console shows
// the raw level) — pressing it records a touch exactly like typing
// 'up'.
//
// Startup contract (house style, deliberately NOT auto-provisioning):
// probe the chip and require the config zone LOCKED and the identity
// key present (atecc608_get_pubkey on slot 1 — the device identity
// private key, the attestation signing half of the 1/2 pair). If the chip is not provisioned, the app still
// enumerates over USB but answers nothing, slow-blinks the LED (GP25),
// and says so on UART0. It never provisions.
//
// Phases 3-4 implement the CTAPHID transport (INIT channel
// allocation/sync, PING echo, WINK (LED), CANCEL, the CTAP2 error
// table, the keep-alive plumbing) plus the CTAP2 message layer:
// GET_INFO (versions/aaguid/options/maxMsgSize/...), MAKE_CREDENTIAL
// (deferred until user presence; on-chip keygen, packed self-attestation,
// credential DB on littlefs), GET_ASSERTION + GET_NEXT_ASSERTION
// (resident enumeration, on-chip GetPubKey for the assertion COSE_Key,
// sync counter incremented before the authData is built) and RESET
// (store wipe + counter zero, 10-s power-on window) — over a minimal
// CBOR codec. CLIENT_PIN answers CTAP1_ERR_INVALID_COMMAND (no PIN
// support is advertised).

#include <stdio.h>

#include "pico/stdlib.h"
#include "pico/time.h"
#include "pico/multicore.h"

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
           "(CTAPHID + CTAP2 GET_INFO + MakeCredential + "
           "GetAssertion + Reset)\n");
    printf("User presence: press the button on GP10, or type 'up' on "
           "the UART0 console, while a registration or login waits\n");

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

    // Dual-core split (the makeCredential delivery fix — see fido_hid.c):
    // core 1 runs the USB task in a tight spin (tud_task + IN-report
    // release) so the next report is armed the instant the host ACKs the
    // previous one; core 0 (this loop) carries the slow CTAP / ATECC608 /
    // console work at a 1 ms cadence. The two cores exchange 64-byte
    // reports through the lock-free queues set up in fido_hid_init, so
    // init must complete (and it does) before core 1 is launched.
    multicore_launch_core1(fido_usb_core1_task);

    // Core 0 (the card task): 1 ms cadence, well under the 500 ms
    // keep-alive / 750 ms busy-timeout granularity. The USB re-arm is on
    // core 1, so this loop can sleep freely — there is no report to
    // arm between host ACKs from here.
    while (1) {
        fido_card_tick();
        sleep_ms(1);
    }
}

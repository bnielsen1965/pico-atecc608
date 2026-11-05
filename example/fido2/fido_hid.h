// fido_hid.h
//
// TinyUSB glue for the FIDO2 app: the USB descriptors (a pure-HID
// security key, 2E8A:000B) and the bridge between TinyUSB's report
// callbacks and the pure-C CTAPHID state machine (fido_ctaphid.*).

#pragma once

#include <stdbool.h>

// USB identity. VID 0x2E8A is Raspberry Pi's; PID 0x000B avoids the
// pico-sdk assignments (0x0009/0x000A = stdio-USB CDC for RP2040/RP2350,
// 0x000F = BOOTSEL).
#define FIDO2_USB_VID 0x2E8A
#define FIDO2_USB_PID 0x000B

// Initialize TinyUSB (device mode) and the CTAPHID state machine.
// `enabled` gates the state machine: false = enumerate but answer
// nothing (chip not provisioned; the app says why on UART0). Call on
// core 0 BEFORE launching core 1 (fido_usb_core1_task): the report
// queues the two cores share must be ready before the USB task spins.
void fido_hid_init(bool enabled);

// Core 1 (the USB task): a tight spin of tud_task + IN-report release,
// nothing else. Launch with multicore_launch_core1(). The next IN report
// is armed the instant the host ACKs the previous one — the re-arm
// latency that a single shared main loop could not beat (see fido_hid.c).
void fido_usb_core1_task(void);

// Core 0 (the card task), one call per main-loop iteration: the CTAP
// dispatch, the ATECC608 key work, the CTAPHID timeouts, the console
// and the status LED — the slow work that must stay off the USB
// re-arm path.
void fido_card_tick(void);

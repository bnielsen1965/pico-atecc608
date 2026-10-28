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
// nothing (chip not provisioned; the app says why on UART0).
void fido_hid_init(bool enabled);

// One main-loop iteration after tud_task(): CTAPHID timeout
// housekeeping and the status LED.
void fido_hid_tick(void);

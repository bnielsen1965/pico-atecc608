// ATECC608 crypto co-processor module for Raspberry Pi Pico 2 (RP2350).
//
// Phase 2: the module is a thin init layer over Microchip cryptoauthlib
// v3.8.0 plus our own RP2350 I2C HAL (src/hal_rp2350.c). The library owns
// the I2C command protocol — wake handshake, CRC, response polling,
// retries; the module owns the HAL, the packaging, and the API surface.
// The curated atecc608_* command API arrives in Phase 3; for now this
// header exposes init/deinit (and the hex-print helper the demo console
// uses).

#pragma once

#include <stdint.h>
#include <stddef.h>

#include "hardware/i2c.h"
#include "atca_status.h"

// 7-bit I2C address, selected by the ADR pin on the package.
#define ATECC608_ADDR_ADR_LOW  0x60  // ADR to GND
#define ATECC608_ADDR_ADR_HIGH 0x61  // ADR to VDD

// Normal command-traffic baud. The wake pulse is always sent at 100 kHz
// (handled inside the HAL).
#define ATECC608_FAST_BAUD_HZ  400000u

// Interface configuration for atecc608_init().
typedef struct {
    i2c_inst_t *i2c;     // I2C peripheral to use (i2c0 or i2c1)
    uint32_t    sda_pin; // SDA GPIO
    uint32_t    scl_pin; // SCL GPIO
    uint8_t     addr;    // 7-bit I2C address (ATECC608_ADDR_*)
    uint32_t    baud;    // normal-traffic baud (e.g. ATECC608_FAST_BAUD_HZ)
} atecc608_cfg_t;

// Bring up I2C (pins, pull-ups, stuck-bus recovery) and initialize
// cryptoauthlib for an ATECC608 on the given bus/address. Does not touch
// the chip; the first command performs the wake handshake (the library's
// device state machine triggers it).
// Re-initializing is safe: any previous init is released first.
ATCA_STATUS atecc608_init(const atecc608_cfg_t *cfg);

// Release cryptoauthlib and deinit the I2C peripheral.
void atecc608_deinit(void);

// Print a byte array as uppercase hex, grouped in blocks of 8 bytes.
void atecc608_print_hex(const uint8_t *data, size_t len);

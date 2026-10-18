// RP2350 I2C HAL for Microchip cryptoauthlib — module-internal header.
//
// hal_rp2350.c implements the atca_hal I2C interface (hal_i2c_*, delays)
// that cryptoauthlib v3.8.0 expects, on top of the pico-sdk hardware_i2c
// driver. It is compiled into the cryptoauth_core target (see the root
// CMakeLists.txt) rather than the atecc608 library, because atca_hal.c in
// that archive references the hal_i2c_* symbols and a static archive cannot
// satisfy references from an archive listed earlier on the link line.

#pragma once

#include <stdint.h>

#include "hardware/i2c.h"

// Passed to cryptoauthlib as ATCAIfaceCfg.cfg_data (opaque to the library).
typedef struct hal_rp2350_ctx {
    i2c_inst_t *i2c;      // I2C peripheral to use (i2c0 or i2c1)
    uint32_t    sda_pin;  // SDA GPIO, used for stuck-bus recovery
    uint32_t    scl_pin;  // SCL GPIO, used for stuck-bus recovery
    uint32_t    baud;     // normal-traffic baud; restored after the 100 kHz wake pulse
} hal_rp2350_ctx_t;

// If SDA is held low, release it and clock up to 9 SCL pulses so a stuck
// slave finishes its byte, then issue a STOP. No-op when SDA is already
// high (idle bus).
void hal_rp2350_bus_recover(const hal_rp2350_ctx_t *ctx);

// ATECC608 crypto co-processor module for Raspberry Pi Pico 2 (RP2350).
//
// The module wraps Microchip cryptoauthlib v3.8.0 (fetched at build time)
// behind a small, stable atecc608_* API. cryptoauthlib owns the I2C command
// protocol — wake handshake, CRC, response polling, retries; the module
// owns the RP2350 I2C HAL, the packaging, and this API surface.
//
// The API is blocking and single-threaded (one chip, one module instance).
// Every function returns an atecc608_status_t; on failure,
// atecc608_last_error() returns the raw ATCA_STATUS code from
// cryptoauthlib for diagnostics.
//
// This header covers lifecycle, diagnostics, and zone/slot read-write.
// The rest of the API family: the config-zone builder
// (atecc608_config.h), the guarded provisioning API (atecc608_prov.h),
// and the crypto pass-through (atecc608_crypto.h).

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hardware/i2c.h"
#include "atca_status.h"

#include "atecc608/atecc608_types.h"

// --- chip constants -------------------------------------------------------

// 7-bit I2C address, selected by the ADR pin on the package.
#define ATECC608_ADDR_ADR_LOW   0x60  // ADR to GND
#define ATECC608_ADDR_ADR_HIGH  0x61  // ADR to VDD

// Normal command-traffic baud. The wake pulse is always sent at 100 kHz
// (handled inside the HAL).
#define ATECC608_FAST_BAUD_HZ   400000u

// --- types -----------------------------------------------------------------

// Interface configuration for atecc608_init().
typedef struct {
    i2c_inst_t *i2c;     // I2C peripheral to use (i2c0 or i2c1)
    uint32_t    sda_pin; // SDA GPIO
    uint32_t    scl_pin; // SCL GPIO
    uint8_t     addr;    // 7-bit I2C address (ATECC608_ADDR_*)
    uint32_t    baud;    // normal-traffic baud (e.g. ATECC608_FAST_BAUD_HZ)
} atecc608_cfg_t;

// Zones for atecc608_is_locked(). The values deliberately match the
// cryptoauthlib LOCK_ZONE_* ids (0x00 config, 0x01 data) — NOT the
// ATCA_ZONE_* command ids, where the data zone is 0x02.
typedef enum {
    ATECC608_ZONE_CONFIG = 0x00,
    ATECC608_ZONE_DATA   = 0x01,
} atecc608_zone_t;

// Decoded INFO (revision) response.
typedef struct {
    uint8_t part;      // INFO byte 2 (0x60 = ATECC608 family)
    uint8_t revision;  // INFO byte 3 (silicon revision)
} atecc608_info_t;

// --- lifecycle --------------------------------------------------------------

// Bring up I2C (pins, pull-ups, stuck-bus recovery) and initialize
// cryptoauthlib for an ATECC608 on the given bus/address. Does not touch
// the chip; the first command performs the wake handshake (the library's
// device state machine triggers it).
// Re-initializing is safe: any previous init is released first.
atecc608_status_t atecc608_init(const atecc608_cfg_t *cfg);

// Release cryptoauthlib and deinit the I2C peripheral.
void atecc608_deinit(void);

// --- diagnostics -------------------------------------------------------------

// Perform the wake handshake and report whether the chip answered.
// This is the presence check: ATECC608_ERR_WAKE means no chip (or a bus
// problem) at the configured address.
atecc608_status_t atecc608_probe(void);

// Read the INFO (revision) command: part id and silicon revision.
atecc608_status_t atecc608_info(atecc608_info_t *out);

// Read the 9-byte factory serial number (config zone bytes [0:4] and
// [8:13]).
atecc608_status_t atecc608_serial(uint8_t serial[ATECC608_SERIAL_LEN]);

// Fill out with n bytes of chip-generated randomness. The chip's RANDOM
// command always produces 32 bytes: larger requests are served by
// repeated commands, smaller ones by discarding the tail of the final
// chunk.
atecc608_status_t atecc608_random(uint8_t *out, size_t n);

// --- zone / slot access -------------------------------------------------------

// Read the full 128-byte config zone.
atecc608_status_t atecc608_read_config_zone(uint8_t zone[ATECC608_CONFIG_ZONE_LEN]);

// Write the full config zone. Only usable while the config zone is
// unlocked. The chip's Write command skips the first 16 factory bytes
// (serial etc.), so they need not be meaningful in the input.
atecc608_status_t atecc608_write_config_zone(const uint8_t zone[ATECC608_CONFIG_ZONE_LEN]);

// Query the lock state of a zone (config or data).
atecc608_status_t atecc608_is_locked(atecc608_zone_t zone, bool *locked);

// Read a full 32-byte data slot. Requires a clear-read slot
// configuration (the slot must not be secret).
atecc608_status_t atecc608_read_slot(uint8_t slot, uint8_t data[ATECC608_DATA_SLOT_LEN]);

// Write a full 32-byte data slot. Only usable while the data zone is
// unlocked (and the slot's SlotConfig permits writes).
atecc608_status_t atecc608_write_slot(uint8_t slot, const uint8_t data[ATECC608_DATA_SLOT_LEN]);

// Read the 64-byte ECC P-256 public key STORED in a slot via a data-zone
// READ (slots 8-15 only — the only ones large enough for a 72-byte stored
// key; the slot must permit a clear read in the current config). For
// "the public key of the ECC private key in slot N" use
// atecc608_get_pubkey() from atecc608_prov.h instead: the public key of
// an on-chip private key is never stored in a data slot and comes from
// the GenKey command.
atecc608_status_t atecc608_read_pubkey(uint8_t slot, uint8_t pub[ATECC608_PUBKEY_LEN]);

// --- status --------------------------------------------------------------------

// Raw cryptoauthlib ATCA_STATUS of the last failed atecc608_* call, or
// ATCA_SUCCESS if there was no failure (or the last call succeeded).
ATCA_STATUS atecc608_last_error(void);

// Short human-readable text for an atecc608_status_t.
const char *atecc608_status_str(atecc608_status_t st);

// Print a byte array as uppercase hex, grouped in blocks of 8 bytes.
// Convenience for diagnostic consoles.
void atecc608_print_hex(const uint8_t *data, size_t len);

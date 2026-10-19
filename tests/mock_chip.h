// Mock ATECC608 chip + I2C HAL for host unit tests (Phase 4A).
//
// This file models just enough of the ATECC608 wire protocol and memory to
// drive the module's provisioning code (src/atecc608_prov.c) through the
// real cryptoauthlib atcab_* / calib layers — no chip, no Pico. The HAL
// functions (hal_i2c_*, hal_delay_*) are defined with the exact signatures
// cryptoauthlib v3.8.0 expects (see atca_hal.h); the module's RP2350 HAL
// (src/hal_rp2350.c) is NOT compiled into the host build, so these symbols
// resolve to this mock instead.
//
// What the mock models (enough for provisioning):
//   - config zone (128 B), data zone (16 x 32 B); factory defaults on reset;
//   - wake handshake (the chip's I2C general-call + 4-byte reply);
//   - READ / WRITE (word and 32-byte block, config + data zones);
//   - LOCK (config / data / slot, with the summary-CRC-verified config lock);
//   - GENKEY (fake deterministic public key — no P-256 math);
//   - COUNTER (read / increment of the two monotonic counters, which live in
//     the config zone);
//   - UPDATE_EXTRA (the one-shot UserExtra / Selector bytes 84 / 85);
//   - command CRC verification (via the library's own atCRC, so parity is
//     guaranteed) and chip error frames (0x0F execution error, etc.).
//
// The model is intentionally faithful where it matters for the provisioning
// guards (lock ordering, one-shot extras, counter limits, lockable slots) and
// deliberately simple elsewhere (no real ECC, no secret-read enforcement).

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MOCK_CONFIG_ZONE_LEN  128u
#define MOCK_DATA_SLOTS       16u
#define MOCK_DATA_SLOT_LEN    32u
#define MOCK_OTP_LEN          64u
#define MOCK_MAX_RESP         75u  // ATCA_RSP_SIZE_MAX

typedef struct {
    // --- chip memory -------------------------------------------------------
    uint8_t config[MOCK_CONFIG_ZONE_LEN];
    uint8_t data[MOCK_DATA_SLOTS * MOCK_DATA_SLOT_LEN];
    uint8_t otp[MOCK_OTP_LEN];

    // --- wire state (the pending response to the last command) -------------
    uint8_t  resp[MOCK_MAX_RESP];
    uint16_t resp_len;   // total frame length (count .. crc_hi)
    uint16_t resp_pos;   // read cursor

    // --- state -------------------------------------------------------------
    bool     awake;      // true after a successful wake handshake
    bool     present;    // false => every I2C transaction NACKs (chip absent)

    // --- test hooks (observables) -----------------------------------------
    uint32_t writes_config;  // WRITE commands applied to the config zone
    uint32_t writes_data;    // WRITE commands applied to the data zone
    uint32_t wakes;          // successful wake handshakes
} mock_chip_t;

// Reset the chip to the factory (unprovisioned, both zones unlocked) state
// matching the physical ATECC608C baseline.
void mock_chip_reset(mock_chip_t *chip);

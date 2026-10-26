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
// What the mock models (enough for provisioning + the Phase 5 KDF):
//   - config zone (128 B), data zone (16 x 32 B); factory defaults on reset;
//   - wake handshake (the chip's I2C general-call + 4-byte reply);
//   - READ / WRITE (word and 32-byte block, config + data zones);
//   - LOCK (config / data / slot, with the summary-CRC-verified config lock);
//   - GENKEY (fake deterministic public key — no P-256 math);
//   - COUNTER (read / increment of the two monotonic counters, which live in
//     the config zone);
//   - UPDATE_EXTRA (the one-shot UserExtra / Selector bytes 84 / 85);
//   - NONCE (pass-through load into the TempKey register — the payload's
//     contents are stored, bench-verified);
//   - KDF (PRF, source=slot, target=output only — the combination the
//     module uses; fake deterministic PRF, no SHA-256 math; the bench
//     gate: refused while the data zone is unlocked; optional I/O
//     protection of the output, see mock_chip_set_kdf_io_prot);
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
// The library's ATCA_RSP_SIZE_MAX is 75 (GenKey / Verify), but a KDF with
// the 64-byte PRF target plus I/O protection returns 64 + 32 = 96 data
// bytes (99 with the frame) — the real chip does this too (bench
// 2026-10-25), and the library's receive buffer (CA_MAX_PACKET_SIZE 198)
// fits it, so the staging buffer must as well.
#define MOCK_MAX_RESP         99u

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
    uint8_t  tempkey[32];// TempKey register (NONCE pass-through target)

    // --- I/O protection model (minimal: the KDF output side only) ---------
    // kdf_prot=1 as bench-verified on the provisioned chip: every KDF
    // target=output response is encrypted with kdf_io_key (the library's
    // own atcah_io_decrypt keystream — a symmetric XOR, so it doubles as
    // encryption) and carries a 32-byte response nonce. The request
    // direction is NOT modeled (as in the rest of the mock).
    bool     kdf_io_prot;
    uint8_t  kdf_io_key[32];

    // --- test hooks (observables) -----------------------------------------
    uint32_t writes_config;  // WRITE commands applied to the config zone
    uint32_t writes_data;    // WRITE commands applied to the data zone
    uint32_t wakes;          // successful wake handshakes
} mock_chip_t;

// Reset the chip to the factory (unprovisioned, both zones unlocked) state
// matching the physical ATECC608C baseline. Also clears the I/O protection
// model (kdf_io_prot off).
void mock_chip_reset(mock_chip_t *chip);

// Test hooks for the KDF I/O protection model (see mock_chip_t).
void mock_chip_set_kdf_io_prot(mock_chip_t *chip, const uint8_t io_key[32]);
void mock_chip_clear_kdf_io_prot(mock_chip_t *chip);

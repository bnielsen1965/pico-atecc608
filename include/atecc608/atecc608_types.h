// Platform-independent types and constants shared by the atecc608 module
// headers. No pico-sdk or cryptoauthlib includes here, so headers that need
// only these (atecc608_config.h, atecc608_prov.h) compile on a host build
// for unit testing.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// --- chip geometry ----------------------------------------------------------

// Zone / slot geometry of the ATECC608.
#define ATECC608_CONFIG_ZONE_LEN 128  // config zone, bytes
#define ATECC608_DATA_SLOT_LEN   32   // one data slot, bytes
#define ATECC608_MAX_DATA_SLOT   15   // slots 0..15
#define ATECC608_PUBKEY_LEN      64   // ECC P-256 public key
#define ATECC608_SERIAL_LEN      9    // factory serial number
#define ATECC608_INFO_LEN        4    // INFO (revision) response
#define ATECC608_RNG_CHUNK_LEN   32   // one chip RANDOM command

// Writable part of the config zone: the chip's Write command skips the
// first 16 factory bytes (serial, revision, AES/I2C enable, address) and
// the lock bytes [86:88] (LockValue/LockConfig, only set by the Lock
// command).
#define ATECC608_CONFIG_FACTORY_LEN   16
#define ATECC608_CONFIG_LOCK_OFFSET   86
#define ATECC608_CONFIG_WRITABLE_LEN  (ATECC608_CONFIG_ZONE_LEN - 16 - 2)

// --- status ------------------------------------------------------------------

// Curated error status returned by every atecc608_* function. For the
// runtime API (atecc608.h) the raw cryptoauthlib ATCA_STATUS of the last
// failure is available via atecc608_last_error().
typedef enum {
    ATECC608_OK = 0,        // success
    ATECC608_ERR,           // other/unknown error (see atecc608_last_error())
    ATECC608_ERR_BAD_PARAM, // argument or buffer-size problem
    ATECC608_ERR_NOT_INIT,  // library not initialized (call atecc608_init)
    ATECC608_ERR_WAKE,      // wake handshake failed (chip absent or asleep)
    ATECC608_ERR_COMM,      // I2C transmit failure / timeout
    ATECC608_ERR_RX,        // I2C response not received / corrupt
    ATECC608_ERR_EXEC,      // chip rejected the command (status byte)
    ATECC608_ERR_CHIP_STATE,// chip state prevents the operation (e.g. locked)
} atecc608_status_t;

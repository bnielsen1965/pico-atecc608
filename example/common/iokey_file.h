/*
 * iokey_file.h - the littlefs I/O key file format, shared by the console
 * and vault examples.
 *
 * The console writes /io_key.bin (its `prov iokey` command); the console
 * and the vault both read it back. Both apps include this header, so the
 * on-flash format is one compile-time contract: any change here is
 * visible (and deliberate) in every consumer.
 *
 * File: a fixed 44-byte struct (little-endian on the RP2350):
 *   u32 magic  = 'I''O''K''1'
 *   u32 len    = 32
 *   u8  key[32]
 *   u32 crc32  = standard reflected CRC-32 over all preceding bytes
 *
 * Pure C (no pico-sdk dependency): the format, the CRC, and the check are
 * host-testable; the Pico-side read is a few lines in each app
 * (pico_lfs_read_file + iokey_file_check).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IOKEY_FILE_PATH     "/io_key.bin"
#define IOKEY_FILE_KEY_LEN  32
#define IOKEY_FILE_MAGIC    0x494F4B31u  // 'I''O''K''1'

// The /io_key.bin layout.
typedef struct {
    uint32_t magic;
    uint32_t len;
    uint8_t  key[IOKEY_FILE_KEY_LEN];
    uint32_t crc32;
} iokey_file_t;

// Standard reflected CRC-32 (poly 0xEDB88320, init/xorout 0xFFFFFFFF).
static uint32_t iokey_file_crc32(const uint8_t *buf, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int)(crc & 1u)));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

// Validate a file buffer already read into f (magic, key length, and the
// CRC-32 over all preceding bytes) and copy the key on success. On
// failure, detail (if non-NULL) receives the short reason.
static bool iokey_file_check(const iokey_file_t *f,
                             uint8_t key[IOKEY_FILE_KEY_LEN],
                             char *detail, size_t detail_size)
{
    if ((IOKEY_FILE_MAGIC != f->magic) || (IOKEY_FILE_KEY_LEN != f->len)) {
        if (detail) {
            snprintf(detail, detail_size, "%s missing or corrupt", IOKEY_FILE_PATH);
        }
        return false;
    }
    if (iokey_file_crc32((const uint8_t *)f, offsetof(iokey_file_t, crc32)) != f->crc32) {
        if (detail) {
            snprintf(detail, detail_size, "%s CRC-32 mismatch", IOKEY_FILE_PATH);
        }
        return false;
    }
    memcpy(key, f->key, IOKEY_FILE_KEY_LEN);
    return true;
}

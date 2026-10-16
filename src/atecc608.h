// Minimal I2C driver for the Microchip ATECC608B crypto co-processor.
//
// Reference protocol (ATECC608B datasheet DS40002223, "I/O Transactions",
// and Microchip cryptoauthlib's CA I2C implementation):
//
//   * 7-bit I2C address is 0x60 or 0x61, selected by the ADR pin on the
//     package (ADR to GND -> 0x60, ADR to VDD -> 0x61).
//
//   * After power-up the device sleeps until it is woken:
//         1. I2C general call (write 0 bytes to address 0x00) -- pulls SDA
//            low; the device NACKs, which is expected.
//         2. Wait 1.5 ms.
//         3. Read 4 bytes at the device address: 04 11 33 43
//            (count, status 0x11 "woken up", CRC).
//
//   * A command is sent as one I2C write:
//         03 | count | opcode | param1 | param2_lo | param2_hi | data... | crc_lo | crc_hi
//     where 0x03 is the "command" I/O token, count includes itself and both
//     CRC bytes, and the CRC covers everything from count through data.
//
//   * The response is read by writing the 0x00 "read" I/O token and then
//     reading:
//         count | data... | crc_lo | crc_hi
//     The device NACKs while a command is still executing, so the read must
//     be retried (polling). A response of count 4 is an error status:
//         04 | status | crc_lo | crc_hi
//
//   * After a command the device should be returned to idle by writing the
//     0x02 "idle" I/O token.
//
//   * CRC: 16-bit, polynomial 0x8005, initial value 0, bits processed MSB
//     first, low byte transmitted first.

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "hardware/i2c.h"

#define ATECC608_ADDR_ADR_LOW  0x60  // 7-bit address, ADR to GND
#define ATECC608_ADDR_ADR_HIGH 0x61  // 7-bit address, ADR to VDD

// I2C baud rates: the wake pulse is sent at 100 kHz (reference behaviour),
// normal command traffic runs at 400 kHz (fast mode).
#define ATECC608_WAKE_BAUD_HZ   100000
#define ATECC608_NORMAL_BAUD_HZ 400000

// I/O tokens
#define ATECC608_TOKEN_COMMAND 0x03
#define ATECC608_TOKEN_READ    0x00
#define ATECC608_TOKEN_IDLE    0x02

// Command opcodes
#define ATECC608_OPCODE_RANDOM 0x1B  // 32 bytes of random data
#define ATECC608_OPCODE_READ   0x02  // read 4/32 bytes from a zone
#define ATECC608_OPCODE_INFO   0x30  // device information (modes in param1)

// Read command zones / param1 encoding
#define ATECC608_ZONE_CONFIG  0x00
#define ATECC608_ZONE_READ32  0x80  // OR into zone to read a full 32-byte block

// Info command modes (param1)
#define ATECC608_INFO_MODE_REVISION 0x00

// Driver result codes
#define ATECC608_OK         0
#define ATECC608_ERR_NACK   (-1)  // device did not ACK (not present / bus error)
#define ATECC608_ERR_TIMEOUT (-2) // no response within the polling budget
#define ATECC608_ERR_CRC    (-3)  // response CRC mismatch
#define ATECC608_ERR_PROTO  (-4)  // response count out of range
#define ATECC608_ERR_CHIP   (-5)  // chip returned an error status (see chip_status)

typedef struct {
    i2c_inst_t *bus;
    uint8_t addr;            // 7-bit I2C address of the detected device
    bool found;
    uint8_t chip_status;     // chip error status byte from the last failed command
} atecc608_t;

// Wake handshake against dev->addr (dev->bus must already be set).
// Returns true if the chip answered with the wake packet 04 11 33 43.
bool atecc608_wake(atecc608_t *dev);

// Try the wake handshake at both possible addresses; sets dev->found/addr.
bool atecc608_probe(atecc608_t *dev, i2c_inst_t *bus);

// RANDOM (0x1B): 32 bytes of random data. A good "is the chip alive" test.
int atecc608_random(atecc608_t *dev, uint8_t out[32]);

// INFO (0x30), revision mode: 4 response bytes. For an ATECC608B this is
// 00 00 60 03 (the last byte is the silicon revision).
int atecc608_info(atecc608_t *dev, uint8_t out[4]);

// READ (0x02): 32-byte config zone block 0. The factory serial number is
// stored here in bytes [0:3] and [8:12] (9 bytes total).
int atecc608_read_config_block0(atecc608_t *dev, uint8_t out[32]);

// Human readable text for driver result codes.
const char *atecc608_result_str(int result);

// Print a byte array as uppercase hex, grouped in blocks of 8 bytes.
void atecc608_print_hex(const uint8_t *data, size_t len);

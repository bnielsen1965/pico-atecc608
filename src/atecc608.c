#include "atecc608.h"

#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"

// Polling parameters for reading a command response, mirroring the
// reference implementation: first attempt after 1 ms, then every 2 ms.
#define ATECC608_POLL_INIT_US     1000
#define ATECC608_POLL_INTERVAL_US 2000
#define ATECC608_POLL_ATTEMPTS    150  // 150 * 2 ms = 300 ms budget

// Wake response: count, status 0x11 (woken up), CRC.
static const uint8_t wake_response[4] = { 0x04, 0x11, 0x33, 0x43 };


// CRC-16: polynomial 0x8005, initial value 0, MSB first, no reflection or
// final XOR; low byte stored first. (Ported from cryptoauthlib atCRC.)
static void crc16(size_t length, const uint8_t *data, uint8_t *crc_le) {
    uint16_t crc_register = 0;
    const uint16_t polynom = 0x8005u;
    for (size_t counter = 0; counter < length; counter++) {
        for (uint8_t shift_register = 0x01; shift_register > 0x00u; shift_register <<= 1) {
            uint8_t data_bit = ((data[counter] & shift_register) != 0u) ? 1u : 0u;
            uint8_t crc_bit = (uint8_t)(crc_register >> 15);
            crc_register <<= 1;
            if (data_bit != crc_bit) {
                crc_register ^= polynom;
            }
        }
    }
    crc_le[0] = (uint8_t)(crc_register & 0x00FFu);
    crc_le[1] = (uint8_t)(crc_register >> 8u);
}


// Wake handshake at dev->addr. Dips SDA via an I2C general call at 100 kHz,
// waits, then expects the 4-byte wake packet back from the device.
bool atecc608_wake(atecc608_t *dev) {
    i2c_set_baudrate(dev->bus, ATECC608_WAKE_BAUD_HZ);

    // General call: START, address 0x00 (write), STOP. The device NACKs;
    // the SDA dip is the wake pulse. (The SDK rejects zero-length writes,
    // so we send one dummy byte; the NACK happens before it is clocked.)
    (void)i2c_write_blocking(dev->bus, 0x00, (const uint8_t[]){ 0x00 }, 1, false);
    sleep_us(1500);

    uint8_t response[4];
    int rc = i2c_read_blocking(dev->bus, dev->addr, response, sizeof(response), false);

    i2c_set_baudrate(dev->bus, ATECC608_NORMAL_BAUD_HZ);

    if (rc != (int)sizeof(response)) {
        return false;
    }
    return memcmp(response, wake_response, sizeof(wake_response)) == 0;
}

// Scan both possible addresses.
bool atecc608_probe(atecc608_t *dev, i2c_inst_t *bus) {
    memset(dev, 0, sizeof(*dev));
    dev->bus = bus;

    dev->addr = ATECC608_ADDR_ADR_LOW;
    if (atecc608_wake(dev)) {
        dev->found = true;
        return true;
    }
    dev->addr = ATECC608_ADDR_ADR_HIGH;
    if (atecc608_wake(dev)) {
        dev->found = true;
        return true;
    }
    return false;
}


// Send a command and read its response. resp must be at least
// ATECC608_MAX_RESPONSE (40) bytes. On success *resp_len is set to the
// response data length (count - 3) and resp[1..resp_len] holds the data.
//
// A command that times out may mean the device dropped to sleep, so the
// transaction is retried once after a fresh wake.
static int transact(atecc608_t *dev, uint8_t opcode, uint8_t param1, uint16_t param2,
                    uint8_t *resp, size_t resp_size, size_t *resp_len) {
    // Command packet: count | opcode | param1 | param2 (little endian).
    // Minimal command count is 7 (count..crc_hi), CRC over the first 5 bytes.
    uint8_t packet[5] = { 7, opcode, param1, (uint8_t)(param2 & 0xFF), (uint8_t)(param2 >> 8) };
    uint8_t crc[2];
    crc16(sizeof(packet), packet, crc);
    uint8_t tx[8] = {
        ATECC608_TOKEN_COMMAND,
        packet[0], packet[1], packet[2], packet[3], packet[4],
        crc[0], crc[1],
    };

    for (int pass = 0; pass < 2; pass++) {
        if (pass == 1 && !atecc608_wake(dev)) {
            return ATECC608_ERR_NACK;
        }

        if (i2c_write_blocking(dev->bus, dev->addr, tx, sizeof(tx), false) != (int)sizeof(tx)) {
            dev->chip_status = 0;
            return ATECC608_ERR_NACK;
        }

        // Poll for the response. The device NACKs the read token while the
        // command is still executing, so retry with a short delay.
        sleep_us(ATECC608_POLL_INIT_US);
        for (int attempt = 0; attempt < ATECC608_POLL_ATTEMPTS; attempt++) {
            if (attempt > 0) {
                sleep_us(ATECC608_POLL_INTERVAL_US);
            }
            uint8_t token = ATECC608_TOKEN_READ;
            if (i2c_write_blocking(dev->bus, dev->addr, &token, 1, false) != 1) {
                continue;  // device busy, try again
            }

            uint8_t count;
            if (i2c_read_blocking(dev->bus, dev->addr, &count, 1, false) != 1) {
                continue;  // device busy, try again
            }

            // count covers the whole response: count byte + data + 2 CRC.
            if (count < 4 || count - 1 > resp_size) {
                dev->chip_status = 0;
                return ATECC608_ERR_PROTO;
            }
            if (i2c_read_blocking(dev->bus, dev->addr, resp + 1, count - 1, false) != (int)(count - 1)) {
                continue;  // truncated read, try again
            }

            // Verify the response CRC (covers count byte through data).
            uint8_t rx_crc[2];
            crc16((size_t)(count - 2), resp, rx_crc);
            if (rx_crc[0] != resp[count - 2] || rx_crc[1] != resp[count - 1]) {
                dev->chip_status = 0;
                return ATECC608_ERR_CRC;
            }

            // Put the device back to idle (0x02 I/O token).
            (void)i2c_write_blocking(dev->bus, dev->addr, (uint8_t[]){ ATECC608_TOKEN_IDLE }, 1, false);

            // A 4-byte response carries a chip error status, not data.
            if (count == 4) {
                dev->chip_status = resp[1];
                return ATECC608_ERR_CHIP;
            }

            *resp_len = (size_t)(count - 3);
            return ATECC608_OK;
        }
    }

    dev->chip_status = 0;
    return ATECC608_ERR_TIMEOUT;
}


int atecc608_random(atecc608_t *dev, uint8_t out[32]) {
    uint8_t resp[40];
    size_t resp_len = 0;
    int rc = transact(dev, ATECC608_OPCODE_RANDOM, 0, 0, resp, sizeof(resp), &resp_len);
    if (rc != ATECC608_OK || resp_len != 32) {
        return rc == ATECC608_OK ? ATECC608_ERR_PROTO : rc;
    }
    memcpy(out, resp + 1, 32);
    return ATECC608_OK;
}

int atecc608_info(atecc608_t *dev, uint8_t out[4]) {
    uint8_t resp[40];
    size_t resp_len = 0;
    int rc = transact(dev, ATECC608_OPCODE_INFO, ATECC608_INFO_MODE_REVISION, 0,
                      resp, sizeof(resp), &resp_len);
    if (rc != ATECC608_OK || resp_len != 4) {
        return rc == ATECC608_OK ? ATECC608_ERR_PROTO : rc;
    }
    memcpy(out, resp + 1, 4);
    return ATECC608_OK;
}

int atecc608_read_config_block0(atecc608_t *dev, uint8_t out[32]) {
    uint8_t resp[40];
    size_t resp_len = 0;
    int rc = transact(dev, ATECC608_OPCODE_READ,
                      ATECC608_ZONE_CONFIG | ATECC608_ZONE_READ32, 0,
                      resp, sizeof(resp), &resp_len);
    if (rc != ATECC608_OK || resp_len != 32) {
        return rc == ATECC608_OK ? ATECC608_ERR_PROTO : rc;
    }
    memcpy(out, resp + 1, 32);
    return ATECC608_OK;
}


const char *atecc608_result_str(int result) {
    switch (result) {
    case ATECC608_OK:        return "ok";
    case ATECC608_ERR_NACK:  return "no response from device (NACK)";
    case ATECC608_ERR_TIMEOUT: return "no response (timeout)";
    case ATECC608_ERR_CRC:   return "response CRC mismatch";
    case ATECC608_ERR_PROTO: return "bad response length";
    case ATECC608_ERR_CHIP:  return "chip reported an error status";
    default:                 return "unknown error";
    }
}

void atecc608_print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X%s", data[i],
               (i + 1 == len) ? "\n" : ((i % 8 == 7) ? "  " : " "));
    }
}

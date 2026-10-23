// Mock ATECC608 chip + I2C HAL implementation (see mock_chip.h).
//
// Wire protocol modeled (verified against cryptoauthlib v3.8.0 source and
// the ATECC608 datasheet):
//
//   command:  S [addr|W] 03 count opcode param1 param2_lo param2_hi
//             [payload...] crc_lo crc_hi P
//             count = total frame length (incl. count byte and CRC);
//             command CRC (atCRC) over the first count-2 bytes.
//   read tok: S [addr|W] 00 P       NACKs while no response is pending
//   read:     S [addr|R] count data... crc_lo crc_hi P
//             count = 3 + data length; CRC over count + data
//   idle:     S [addr|W] 02 P
//   sleep:    S [addr|W] 01 P
//   wake:     handled entirely inside hal_i2c_control(ATCA_HAL_CONTROL_WAKE)
//             (the library's calib_wakeup_i2c routes the whole handshake
//             through that control when CHANGE_BAUD is UNIMPLEMENTED)
//
// Command encodings (calib_command.h):
//   READ 0x02   param1 = zone | (0x80: 32 bytes), param2 = word address
//               config: word = (block << 3) | word; data: (slot << 3) | word
//               | (block << 8)
//   WRITE 0x12  as READ, payload = the 4 / 32 data bytes
//   LOCK 0x17   param1 = 0 config (param2 = summary CRC LE16) / 1 data /
//               2|slot<<2 slot; bit 0x80 = no summary CRC
//   COUNTER 0x24 param1 = 0 read / 1 increment, param2 = id; response =
//               4-byte binary value
//   UPDATE_EXTRA 0x20 param1 = 0 UserExtra (byte 84) / 1 Selector (85),
//               param2 = new value; one-shot per byte
//   GENKEY 0x40 param1 = 0x04 (private), param2 = slot; response = 64-byte
//               public key
//   INFO 0x30   param1 = 0 (revision); response = 4 bytes 00 00 60 05
//   RANDOM 0x1B response = 32 bytes
//
// Lock-state bytes: config locked iff config[87] != 0x55, data locked iff
// config[86] != 0x55 (calib_is_locked reads the block-2 word 5).

#include "mock_chip.h"

#include <string.h>

#include "atecc608/atecc608_types.h"  // ATECC608_PUBKEY_LEN
#include "cryptoauthlib.h"            // ATCAIface / ATCAIfaceCfg / hal_check_wake / atCRC / opcodes

// --- helpers --------------------------------------------------------------------

static uint16_t mock_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint16_t mock_slot_cfg(const mock_chip_t *chip, uint16_t slot)
{
    return mock_le16(&chip->config[20 + 2 * slot]);
}

static uint16_t mock_key_cfg(const mock_chip_t *chip, uint16_t slot)
{
    return mock_le16(&chip->config[96 + 2 * slot]);
}

static bool mock_cfg_locked(const mock_chip_t *chip)
{
    return chip->config[87] != 0x55u;
}

static bool mock_data_locked(const mock_chip_t *chip)
{
    return chip->config[86] != 0x55u;
}

// Encode a counter value into the chip's 8-byte dual linear + binary format
// (identical to cryptoauthlib's calib_write_config_counter).
static void mock_encode_counter(uint32_t v, uint8_t b[8])
{
    const uint16_t lin_a = (uint16_t)(0xFFFFu >> (v % 32u));
    const uint16_t lin_b = (v >= 16u) ? (uint16_t)(0xFFFFu >> ((v - 16u) % 32u))
                                      : 0xFFFFu;
    const uint16_t bin_a = (uint16_t)(v / 32u);
    const uint16_t bin_b = (v >= 16u) ? (uint16_t)((v - 16u) / 32u) : 0u;

    b[0] = (uint8_t)(lin_a >> 8);
    b[1] = (uint8_t)(lin_a & 0xFFu);
    b[2] = (uint8_t)(lin_b >> 8);
    b[3] = (uint8_t)(lin_b & 0xFFu);
    b[4] = (uint8_t)(bin_a >> 8);
    b[5] = (uint8_t)(bin_a & 0xFFu);
    b[6] = (uint8_t)(bin_b >> 8);
    b[7] = (uint8_t)(bin_b & 0xFFu);
}

// Inverse of mock_encode_counter, with consistency checks on both halves of
// the encoding (a real chip would not accept a corrupt encoding).
static bool mock_decode_counter(const uint8_t b[8], uint32_t *out)
{
    // Words are stored big-endian (see mock_encode_counter).
    const uint16_t lin_a = (uint16_t)(((uint16_t)b[0] << 8) | b[1]);
    const uint16_t lin_b = (uint16_t)(((uint16_t)b[2] << 8) | b[3]);
    const uint16_t bin_a = (uint16_t)(((uint16_t)b[4] << 8) | b[5]);
    const uint16_t bin_b = (uint16_t)(((uint16_t)b[6] << 8) | b[7]);
    uint32_t r;
    uint32_t v;
    uint32_t want_bin_b;
    uint16_t want_lin_b;

    if (lin_a != 0u) {
        // lin_a = 0xFFFF >> r with r in 0..15.
        uint32_t ones = 0;
        for (uint16_t x = lin_a; (x & 1u) != 0u; x >>= 1) {
            ones++;
        }
        r = 16u - ones;
        if ((r > 15u) || (lin_a != (uint16_t)(0xFFFFu >> r))) {
            return false;
        }
    } else {
        // lin_a == 0: r in 16..31; lin_b = 0xFFFF >> (r - 16).
        uint32_t ones = 0;
        for (uint16_t x = lin_b; (x & 1u) != 0u; x >>= 1) {
            ones++;
        }
        r = 32u - ones;
        if ((r < 16u) || (r > 31u) || (lin_b != (uint16_t)(0xFFFFu >> (r - 16u)))) {
            return false;
        }
    }

    v = ((uint32_t)bin_a * 32u) + r;
    if (v > 0x1FFFFFu) {
        return false;
    }

    if (v < 16u) {
        want_bin_b = 0u;
        want_lin_b = 0xFFFFu;
    } else if (r >= 16u) {
        want_bin_b = (uint32_t)bin_a;
        want_lin_b = (uint16_t)(0xFFFFu >> (r - 16u));
    } else {
        // v >= 16 with r < 16 implies bin_a >= 1.
        if (bin_a < 1u) {
            return false;
        }
        want_bin_b = (uint32_t)bin_a - 1u;
        want_lin_b = 0u;
    }
    if ((bin_b != want_bin_b) || (lin_b != want_lin_b)) {
        return false;
    }

    *out = v;
    return true;
}

// --- response framing -------------------------------------------------------------

static void mock_resp_data(mock_chip_t *chip, const uint8_t *data, uint16_t len)
{
    uint8_t frame[MOCK_MAX_RESP];
    const uint16_t count = (uint16_t)(len + 3u);

    frame[0] = (uint8_t)count;
    memcpy(&frame[1], data, len);
    atCRC((size_t)(count - 2u), frame, &frame[count - 2u]);

    memcpy(chip->resp, frame, count);
    chip->resp_len = count;
    chip->resp_pos = 0;
}

static void mock_resp_ok(mock_chip_t *chip)
{
    const uint8_t st = 0x00;
    mock_resp_data(chip, &st, 1);
}

static void mock_resp_exec(mock_chip_t *chip)
{
    const uint8_t st = 0x0F; // execution error
    mock_resp_data(chip, &st, 1);
}

// --- command dispatch ---------------------------------------------------------------

static void mock_handle_read(mock_chip_t *chip, uint8_t param1, uint16_t param2)
{
    const uint8_t zone = (uint8_t)(param1 & 0x03u);
    const uint16_t len = ((param1 & ATCA_ZONE_READWRITE_32) != 0u) ? 32u : 4u;

    if (zone == ATCA_ZONE_CONFIG) {
        const uint16_t byte_addr = (uint16_t)(param2 * 4u);
        if (byte_addr + len > MOCK_CONFIG_ZONE_LEN) {
            mock_resp_exec(chip);
        } else {
            // The config zone can always be read (even when locked).
            mock_resp_data(chip, &chip->config[byte_addr], len);
        }
    } else if (zone == ATCA_ZONE_DATA) {
        const uint16_t slot  = (uint16_t)((param2 >> 3) & 0x0Fu);
        const uint16_t block = (uint16_t)((param2 >> 8) & 0x0Fu);
        const uint16_t word  = (uint16_t)(param2 & 0x07u);
        const uint16_t byte_addr = (uint16_t)(slot * 32u + block * 32u + word * 4u);

        // Data slots are only readable once the data zone is locked, and
        // never when the slot is a secret or a private key.
        if (!mock_data_locked(chip)) {
            mock_resp_exec(chip);
        } else if ((mock_slot_cfg(chip, slot) & 0x80u) != 0u) {
            mock_resp_exec(chip);
        } else if ((mock_key_cfg(chip, slot) & 0x01u) != 0u) {
            mock_resp_exec(chip);
        } else if (byte_addr + len > (MOCK_DATA_SLOTS * MOCK_DATA_SLOT_LEN)) {
            mock_resp_exec(chip);
        } else {
            mock_resp_data(chip, &chip->data[byte_addr], len);
        }
    } else {
        mock_resp_exec(chip); // OTP zone: not modeled
    }
}

static void mock_handle_write(mock_chip_t *chip, uint8_t param1, uint16_t param2,
                              const uint8_t *payload, uint16_t payload_len)
{
    const uint8_t zone = (uint8_t)(param1 & 0x03u);
    const bool block_write = ((param1 & ATCA_ZONE_READWRITE_32) != 0u);
    const uint16_t len = block_write ? 32u : 4u;

    if (payload_len != len) {
        mock_resp_exec(chip);
        return;
    }

    if (zone == ATCA_ZONE_CONFIG) {
        const uint16_t byte_addr = (uint16_t)(param2 * 4u);

        if (mock_cfg_locked(chip)) {
            mock_resp_exec(chip); // config zone locked: no writes
        } else if (byte_addr + len > MOCK_CONFIG_ZONE_LEN) {
            mock_resp_exec(chip);
        } else {
            for (uint16_t i = 0; i < len; i++) {
                const uint16_t b = (uint16_t)(byte_addr + i);
                // Factory bytes 0-15 are write-protected; 84-87 (UserExtra /
                // Selector / LockValue / LockConfig) can only change via
                // UPDATE_EXTRA / LOCK. The library already skips that word,
                // but the chip ignores stray writes to it as well.
                if ((b < 16u) || ((b >= 84u) && (b <= 87u))) {
                    continue;
                }
                chip->config[b] = payload[i];
            }
            chip->writes_config++;
            mock_resp_ok(chip);
        }
    } else if (zone == ATCA_ZONE_DATA) {
        const uint16_t slot  = (uint16_t)((param2 >> 3) & 0x0Fu);
        const uint16_t block = (uint16_t)((param2 >> 8) & 0x0Fu);
        const uint16_t word  = (uint16_t)(param2 & 0x07u);
        const uint16_t byte_addr = (uint16_t)(slot * 32u + block * 32u + word * 4u);

        if (mock_data_locked(chip)) {
            mock_resp_exec(chip); // locked zone: no writes
        } else if (!block_write) {
            // Unlocked data zone: only 32-byte slot writes are allowed.
            mock_resp_exec(chip);
        } else if ((mock_key_cfg(chip, slot) & 0x01u) != 0u) {
            // Private key slots may only be written by GenKey / PrivWrite.
            mock_resp_exec(chip);
        } else if (byte_addr + len > (MOCK_DATA_SLOTS * MOCK_DATA_SLOT_LEN)) {
            mock_resp_exec(chip);
        } else {
            memcpy(&chip->data[byte_addr], payload, len);
            chip->writes_data++;
            mock_resp_ok(chip);
        }
    } else {
        mock_resp_exec(chip);
    }
}

static void mock_handle_lock(mock_chip_t *chip, uint8_t param1, uint16_t param2)
{
    const uint8_t mode = (uint8_t)(param1 & 0x03u);
    const bool no_crc = ((param1 & 0x80u) != 0u);

    if (mode == LOCK_ZONE_CONFIG) {
        if (mock_cfg_locked(chip)) {
            mock_resp_exec(chip);
            return;
        }
        if (!no_crc) {
            // Summary CRC over the full 128-byte config zone.
            uint8_t crc[2];
            atCRC(MOCK_CONFIG_ZONE_LEN, chip->config, crc);
            if ((uint16_t)(crc[0] | ((uint16_t)crc[1] << 8)) != param2) {
                mock_resp_exec(chip);
                return;
            }
        }
        chip->config[87] = 0x00;
        mock_resp_ok(chip);
    } else if (mode == LOCK_ZONE_DATA) {
        if (mock_data_locked(chip)) {
            mock_resp_exec(chip);
            return;
        }
        if (!mock_cfg_locked(chip)) {
            mock_resp_exec(chip); // the data zone locks only after the config zone
            return;
        }
        chip->config[86] = 0x00;
        mock_resp_ok(chip);
    } else if (mode == LOCK_ZONE_DATA_SLOT) {
        const uint16_t slot = (uint16_t)((param1 >> 2) & 0x0Fu);

        if ((mock_key_cfg(chip, slot) & 0x20u) == 0u) {
            mock_resp_exec(chip); // slot not marked lockable
            return;
        }
        // SlotLocked polarity (verified against the chip's factory value
        // 0xFFFF = no slot locked, and cryptoauthlib's own hardware test
        // atca_tests_write.c "write_upper_slots"): bit n = 1 -> slot n
        // unlocked, bit n = 0 -> slot n locked. The Lock command clears the
        // bit.
        if ((mock_le16(&chip->config[88]) & (uint16_t)(1u << slot)) == 0u) {
            mock_resp_exec(chip); // already locked
            return;
        }
        if (slot < 8u) {
            chip->config[88] &= (uint8_t)~(1u << slot);
        } else {
            chip->config[89] &= (uint8_t)~(1u << (slot - 8u));
        }
        mock_resp_ok(chip);
    } else {
        mock_resp_exec(chip);
    }
}

static void mock_handle_counter(mock_chip_t *chip, uint8_t param1, uint16_t param2)
{
    const uint8_t mode = (uint8_t)(param1 & 0x01u);
    const uint16_t id = param2;
    uint8_t val[4];
    uint32_t v;

    if (id > 1u) {
        mock_resp_exec(chip);
        return;
    }
    if (!mock_decode_counter(&chip->config[52 + 8 * id], &v)) {
        mock_resp_exec(chip); // corrupt encoding
        return;
    }
    if (mode == COUNTER_MODE_INCREMENT) {
        if (v >= 0x1FFFFFu) {
            mock_resp_exec(chip); // counter maxed out
            return;
        }
        v++;
        mock_encode_counter(v, &chip->config[52 + 8 * id]);
    }
    val[0] = (uint8_t)(v & 0xFFu);
    val[1] = (uint8_t)((v >> 8) & 0xFFu);
    val[2] = (uint8_t)((v >> 16) & 0xFFu);
    val[3] = (uint8_t)((v >> 24) & 0xFFu);
    mock_resp_data(chip, val, 4);
}

static void mock_handle_update_extra(mock_chip_t *chip, uint8_t param1, uint16_t param2)
{
    const uint8_t mode = (uint8_t)(param1 & 0x03u);
    const uint8_t value = (uint8_t)(param2 & 0xFFu);

    // One-shot semantics: once the byte is non-zero, any further UpdateExtra
    // for it fails (even with the same value); writing 0 while still 0 is a
    // successful no-op.
    if (mode == UPDATE_MODE_USER_EXTRA) {
        if (chip->config[84] != 0x00u) {
            mock_resp_exec(chip);
            return;
        }
        chip->config[84] = value;
        mock_resp_ok(chip);
    } else if (mode == UPDATE_MODE_SELECTOR) {
        if (chip->config[85] != 0x00u) {
            mock_resp_exec(chip);
            return;
        }
        chip->config[85] = value;
        mock_resp_ok(chip);
    } else {
        mock_resp_exec(chip); // e.g. decrement counter: not modeled
    }
}

static void mock_handle_genkey(mock_chip_t *chip, uint8_t param1, uint16_t param2)
{
    const uint16_t slot = param2;
    uint8_t pub[ATECC608_PUBKEY_LEN];

    if ((param1 & 0x1Cu) != 0x04u) { // GENKEY_MODE_PRIVATE
        mock_resp_exec(chip);
        return;
    }
    if (slot > 15u) {
        mock_resp_exec(chip);
        return;
    }
    if ((mock_key_cfg(chip, slot) & 0x01u) == 0u) {
        mock_resp_exec(chip); // not a private key slot
        return;
    }
    if ((mock_slot_cfg(chip, slot) & 0x2000u) == 0u) {
        // Datasheet Table 2-10: private key regeneration requires the
        // SlotConfig GenKey bit (bit 13).
        mock_resp_exec(chip);
        return;
    }
    if (mock_data_locked(chip)) {
        mock_resp_exec(chip); // key material cannot change in a locked zone
        return;
    }
    // Fake, deterministic "public key" (no P-256 math in the mock).
    for (int i = 0; i < ATECC608_PUBKEY_LEN; i++) {
        pub[i] = (uint8_t)((slot * 7u + (uint16_t)i * 3u + 1u) & 0xFFu);
    }
    mock_resp_data(chip, pub, sizeof(pub));
}

// One command frame arrives with word address 0x03; the chip replies are
// staged in chip->resp for the read-token / two-read sequence.
static void mock_process_command(mock_chip_t *chip, const uint8_t *frame, uint16_t count)
{
    const uint8_t opcode = frame[1];
    const uint8_t param1 = frame[2];
    const uint16_t param2 = (uint16_t)(frame[3] | ((uint16_t)frame[4] << 8));
    const uint8_t *payload = &frame[5];
    const uint16_t payload_len = (count >= 7u) ? (uint16_t)(count - 7u) : 0u;
    uint8_t crc[2];

    // Verify the command CRC exactly as the chip does.
    atCRC((size_t)(count - 2u), frame, crc);
    if ((crc[0] != frame[count - 2u]) || (crc[1] != frame[count - 1u])) {
        mock_resp_exec(chip);
        return;
    }

    switch (opcode) {
    case ATCA_READ:
        mock_handle_read(chip, param1, param2);
        break;
    case ATCA_WRITE:
        mock_handle_write(chip, param1, param2, payload, payload_len);
        break;
    case ATCA_LOCK:
        mock_handle_lock(chip, param1, param2);
        break;
    case ATCA_COUNTER:
        mock_handle_counter(chip, param1, param2);
        break;
    case ATCA_UPDATE_EXTRA:
        mock_handle_update_extra(chip, param1, param2);
        break;
    case ATCA_GENKEY:
        mock_handle_genkey(chip, param1, param2);
        break;
    case ATCA_INFO:
        if (param1 == 0x00u) { // INFO_MODE_REVISION
            const uint8_t rev[4] = { 0x00, 0x00, 0x60, 0x05 };
            mock_resp_data(chip, rev, 4);
        } else {
            mock_resp_exec(chip);
        }
        break;
    case ATCA_RANDOM: {
        uint8_t rnd[32];
        for (int i = 0; i < 32; i++) {
            rnd[i] = (uint8_t)(0xA5u + (uint16_t)i);
        }
        mock_resp_data(chip, rnd, 32);
        break;
    }
    default:
        mock_resp_exec(chip);
        break;
    }
}

// --- factory state -------------------------------------------------------------------

void mock_chip_reset(mock_chip_t *chip)
{
    memset(chip, 0, sizeof(*chip));

    // Factory identification bytes. Bytes 0-15 are write-protected; the
    // library assembles the 9-byte serial as config[0:4] + config[8:13].
    // Values match the physical ATECC608C baseline (serial
    // 01 23 06 40 AE B6 B9 B7 EE, part 0x60, silicon rev 0x05).
    static const uint8_t factory[17] = {
        0x01, 0x23, 0x06, 0x40, // SN[0:3]
        0x00, 0x00, 0x60, 0x05, // RevNum (INFO response)
        0xAE, 0xB6, 0xB9, 0xB7, // SN[4:7]
        0xEE,                    // SN[8]
        0x01,                    // AES_Enable
        0x01,                    // I2C_Enable (bit 0: I2C mode)
        0x00,                    // reserved
        0xC0,                    // I2C address, 8-bit form (0x60 << 1)
    };
    memcpy(chip->config, factory, 16);
    chip->config[16] = factory[16];

    // Monotonic counters, value 0 (dual linear + binary encoding).
    mock_encode_counter(0, &chip->config[52]);
    mock_encode_counter(0, &chip->config[60]);

    chip->config[86] = 0x55; // LockValue  (data zone, unlocked)
    chip->config[87] = 0x55; // LockConfig (config zone, unlocked)

    // SlotLocked: the factory ships 0xFFFF (verified on the bench chip
    // 2026-10-23). Lock-command-managed; the prov path preserves it, so the
    // mock's write path never has to decide what it does with the field.
    chip->config[88] = 0xFF;
    chip->config[89] = 0xFF;

    chip->present = true;
}

// --- the HAL (the symbols cryptoauthlib v3.8.0 expects) --------------------------------

ATCA_STATUS hal_i2c_init(ATCAIface iface, ATCAIfaceCfg *cfg)
{
    if ((NULL == iface) || (NULL == cfg) || (NULL == cfg->cfg_data)) {
        return ATCA_BAD_PARAM;
    }
    // The chip lives in the test; hand it to the rest of the HAL through the
    // same slot the RP2350 HAL uses for its context.
    iface->hal_data = cfg->cfg_data;
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    (void)iface;
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength)
{
    mock_chip_t *chip = (mock_chip_t *)iface->hal_data;

    if ((NULL == chip) || (!chip->present)) {
        return ATCA_COMM_FAIL;
    }

    switch (word_address) {
    case 0x00:
        // Read token: NACKs while no response is pending.
        return (chip->resp_pos < chip->resp_len) ? ATCA_SUCCESS : ATCA_COMM_FAIL;
    case 0x01:
        chip->awake = false; // sleep token
        return ATCA_SUCCESS;
    case 0x02:
        return ATCA_SUCCESS; // idle token
    case 0x03:
        if (!chip->awake) {
            return ATCA_COMM_FAIL; // asleep: no ACK
        }
        if ((NULL == txdata) || (txlength < 7) || ((uint16_t)txlength != txdata[0])) {
            return ATCA_COMM_FAIL; // malformed frame
        }
        mock_process_command(chip, txdata, (uint16_t)txlength);
        return ATCA_SUCCESS;
    default:
        return ATCA_COMM_FAIL;
    }
}

ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength)
{
    mock_chip_t *chip = (mock_chip_t *)iface->hal_data;
    uint16_t n;
    uint16_t avail;

    (void)word_address;

    if ((NULL == chip) || (!chip->present)) {
        return ATCA_COMM_FAIL;
    }
    if ((NULL == rxdata) || (NULL == rxlength)) {
        return ATCA_BAD_PARAM;
    }

    avail = (uint16_t)(chip->resp_len - chip->resp_pos);
    if (0u == avail) {
        return ATCA_COMM_FAIL;
    }
    n = (*rxlength < avail) ? *rxlength : avail;
    memcpy(rxdata, &chip->resp[chip->resp_pos], n);
    chip->resp_pos = (uint16_t)(chip->resp_pos + n);
    *rxlength = n;
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_control(ATCAIface iface, uint8_t option, void *param, size_t paramlen)
{
    mock_chip_t *chip = (mock_chip_t *)iface->hal_data;

    (void)param;
    (void)paramlen;

    if (NULL == chip) {
        return ATCA_BAD_PARAM;
    }

    switch (option) {
    case (uint8_t)ATCA_HAL_CONTROL_WAKE:
        // The whole wake handshake happens inside the HAL (the library's
        // calib_wakeup_i2c takes the UNIMPLEMENTED-CHANGE_BAUD path). The
        // general-call pulse always succeeds on a present chip, even when it
        // is already awake.
        if (!chip->present) {
            return ATCA_COMM_FAIL;
        }
        chip->awake = true;
        chip->wakes++;
        {
            const uint8_t wake_rsp[4] = { 0x04, 0x11, 0x33, 0x43 };
            return hal_check_wake(wake_rsp, 4);
        }
    case (uint8_t)ATCA_HAL_CONTROL_IDLE:
        return ATCA_SUCCESS;
    case (uint8_t)ATCA_HAL_CONTROL_SLEEP:
        chip->awake = false;
        return ATCA_SUCCESS;
    case (uint8_t)ATCA_HAL_CONTROL_SELECT:
    case (uint8_t)ATCA_HAL_CONTROL_DESELECT:
        return ATCA_SUCCESS;
    default:
        return ATCA_UNIMPLEMENTED; // CHANGE_BAUD, FLUSH_BUFFER, DIRECTION, RESET
    }
}

ATCA_STATUS hal_i2c_release(void *hal_data)
{
    (void)hal_data;
    return ATCA_SUCCESS;
}

void hal_delay_ms(uint32_t delay)
{
    (void)delay;
}

void hal_delay_us(uint32_t delay)
{
    (void)delay;
}

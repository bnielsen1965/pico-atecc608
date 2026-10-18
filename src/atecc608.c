#include "atecc608/atecc608.h"

#include <stdio.h>
#include <string.h>

#include "cryptoauthlib.h"
#include "hal_rp2350.h"

// The HAL context and interface configuration live in module storage so
// they outlive the caller's stack frame: cryptoauthlib retains the
// ATCAIfaceCfg (and its cfg_data pointer) for the whole session.
static hal_rp2350_ctx_t s_hal_ctx;
static ATCAIfaceCfg s_iface_cfg;

// Raw ATCA_STATUS of the last failed call (module storage; the API is
// single-threaded and blocking).
static ATCA_STATUS s_last_error = ATCA_SUCCESS;

// Map a raw cryptoauthlib status onto the curated atecc608_status_t and
// record the raw code for atecc608_last_error(). The raw code is always
// preserved, so no diagnostic information is lost in the mapping.
static atecc608_status_t atecc608_map_status(ATCA_STATUS atca_status)
{
    if (ATCA_SUCCESS == atca_status) {
        s_last_error = ATCA_SUCCESS;
        return ATECC608_OK;
    }

    s_last_error = atca_status;

    switch (atca_status) {
    case ATCA_BAD_PARAM:
    case ATCA_INVALID_SIZE:
    case ATCA_SMALL_BUFFER:
        return ATECC608_ERR_BAD_PARAM;

    case ATCA_NOT_INITIALIZED:
        return ATECC608_ERR_NOT_INIT;

    case ATCA_WAKE_FAILED:
    case ATCA_NO_DEVICES:
    case ATCA_TOO_MANY_COMM_RETRIES:
        return ATECC608_ERR_WAKE;

    case ATCA_COMM_FAIL:
    case ATCA_TX_FAIL:
    case ATCA_TIMEOUT:
    case ATCA_TX_TIMEOUT:
    case ATCA_RX_TIMEOUT:
        return ATECC608_ERR_COMM;

    case ATCA_RX_FAIL:
    case ATCA_RX_NO_RESPONSE:
    case ATCA_RX_CRC_ERROR:
    case ATCA_STATUS_CRC:
    case ATCA_PARITY_ERROR:
        return ATECC608_ERR_RX;

    case ATCA_EXECUTION_ERROR:
    case ATCA_FUNC_FAIL:
    case ATCA_BAD_OPCODE:
    case ATCA_PARSE_ERROR:
    case ATCA_STATUS_ECC:
    case ATCA_STATUS_SELFTEST_ERROR:
    case ATCA_STATUS_UNKNOWN:
    case ATCA_CHECKMAC_VERIFY_FAILED:
        return ATECC608_ERR_EXEC;

    case ATCA_NOT_LOCKED:
    case ATCA_USE_FLAGS_CONSUMED:
        return ATECC608_ERR_CHIP_STATE;

    default:
        return ATECC608_ERR;
    }
}

atecc608_status_t atecc608_init(const atecc608_cfg_t *cfg)
{
    if ((NULL == cfg) || (NULL == cfg->i2c) || (0 == cfg->baud)) {
        return atecc608_map_status(ATCA_BAD_PARAM);
    }

    // atcab_release() is a no-op when nothing is initialized; call it
    // unconditionally so re-init is safe.
    (void)atcab_release();

    s_hal_ctx.i2c = cfg->i2c;
    s_hal_ctx.sda_pin = cfg->sda_pin;
    s_hal_ctx.scl_pin = cfg->scl_pin;
    s_hal_ctx.baud = cfg->baud;

    s_iface_cfg = (ATCAIfaceCfg) {
        .iface_type = ATCA_I2C_IFACE,
        .devtype    = ATECC608,
        .atcai2c = {
            .address = (uint8_t)(cfg->addr << 1), // 8-bit form; I2C LSB is 0
            .bus     = 0,                         // logical bus (unused; the HAL uses cfg_data)
            .baud    = cfg->baud,
        },
        .wake_delay = 1500, // tWHI + tWLO for the ATECC608 (the library's own default)
        .rx_retries = 20,   // library default
        .cfg_data   = &s_hal_ctx,
    };

    return atecc608_map_status(atcab_init(&s_iface_cfg));
}

void atecc608_deinit(void)
{
    (void)atcab_release();
}

atecc608_status_t atecc608_probe(void)
{
    return atecc608_map_status(atcab_wakeup());
}

atecc608_status_t atecc608_info(atecc608_info_t *out)
{
    uint8_t raw[ATECC608_INFO_LEN];

    if (NULL == out) {
        return atecc608_map_status(ATCA_BAD_PARAM);
    }

    ATCA_STATUS status = atcab_info(raw);
    if (ATCA_SUCCESS != status) {
        return atecc608_map_status(status);
    }

    // INFO (revision) response: bytes 0-1 are reserved (0x00), byte 2 is
    // the part id, byte 3 the silicon revision.
    out->part = raw[2];
    out->revision = raw[3];
    return ATECC608_OK;
}

atecc608_status_t atecc608_serial(uint8_t serial[ATECC608_SERIAL_LEN])
{
    if (NULL == serial) {
        return atecc608_map_status(ATCA_BAD_PARAM);
    }

    return atecc608_map_status(atcab_read_serial_number(serial));
}

atecc608_status_t atecc608_random(uint8_t *out, size_t n)
{
    uint8_t chunk[ATECC608_RNG_CHUNK_LEN];

    if ((NULL == out) && (0 != n)) {
        return atecc608_map_status(ATCA_BAD_PARAM);
    }

    while (0 < n) {
        const size_t take = (n < sizeof(chunk)) ? n : sizeof(chunk);

        ATCA_STATUS status = atcab_random(chunk);
        if (ATCA_SUCCESS != status) {
            return atecc608_map_status(status);
        }

        (void)memcpy(out, chunk, take);
        out += take;
        n -= take;
    }

    return ATECC608_OK;
}

atecc608_status_t atecc608_read_config_zone(uint8_t zone[ATECC608_CONFIG_ZONE_LEN])
{
    if (NULL == zone) {
        return atecc608_map_status(ATCA_BAD_PARAM);
    }

    return atecc608_map_status(atcab_read_config_zone(zone));
}

atecc608_status_t atecc608_write_config_zone(const uint8_t zone[ATECC608_CONFIG_ZONE_LEN])
{
    if (NULL == zone) {
        return atecc608_map_status(ATCA_BAD_PARAM);
    }

    return atecc608_map_status(atcab_write_config_zone(zone));
}

atecc608_status_t atecc608_is_locked(atecc608_zone_t zone, bool *locked)
{
    uint8_t lock_zone;

    if (NULL == locked) {
        return atecc608_map_status(ATCA_BAD_PARAM);
    }

    // Explicit mapping onto the cryptoauthlib LOCK_ZONE_* ids — the
    // ATCA_ZONE_* command ids differ for the data zone (0x01 vs 0x02) and
    // must not be passed here.
    switch (zone) {
    case ATECC608_ZONE_CONFIG:
        lock_zone = LOCK_ZONE_CONFIG;
        break;
    case ATECC608_ZONE_DATA:
        lock_zone = LOCK_ZONE_DATA;
        break;
    default:
        return atecc608_map_status(ATCA_BAD_PARAM);
    }

    return atecc608_map_status(atcab_is_locked(lock_zone, locked));
}

atecc608_status_t atecc608_read_slot(uint8_t slot, uint8_t data[ATECC608_DATA_SLOT_LEN])
{
    if ((slot > ATECC608_MAX_DATA_SLOT) || (NULL == data)) {
        return atecc608_map_status(ATCA_BAD_PARAM);
    }

    return atecc608_map_status(
        atcab_read_bytes_zone(ATCA_ZONE_DATA, slot, 0, data, ATECC608_DATA_SLOT_LEN));
}

atecc608_status_t atecc608_write_slot(uint8_t slot, const uint8_t data[ATECC608_DATA_SLOT_LEN])
{
    if ((slot > ATECC608_MAX_DATA_SLOT) || (NULL == data)) {
        return atecc608_map_status(ATCA_BAD_PARAM);
    }

    return atecc608_map_status(
        atcab_write_bytes_zone(ATCA_ZONE_DATA, slot, 0, data, ATECC608_DATA_SLOT_LEN));
}

atecc608_status_t atecc608_read_pubkey(uint8_t slot, uint8_t pub[ATECC608_PUBKEY_LEN])
{
    if ((slot > ATECC608_MAX_DATA_SLOT) || (NULL == pub)) {
        return atecc608_map_status(ATCA_BAD_PARAM);
    }

    return atecc608_map_status(atcab_read_pubkey(slot, pub));
}

ATCA_STATUS atecc608_last_error(void)
{
    return s_last_error;
}

const char *atecc608_status_str(atecc608_status_t st)
{
    switch (st) {
    case ATECC608_OK:              return "ok";
    case ATECC608_ERR:             return "error";
    case ATECC608_ERR_BAD_PARAM:   return "bad parameter";
    case ATECC608_ERR_NOT_INIT:    return "not initialized";
    case ATECC608_ERR_WAKE:        return "wake handshake failed (chip absent or asleep)";
    case ATECC608_ERR_COMM:        return "I2C transmit failed";
    case ATECC608_ERR_RX:          return "I2C receive failed";
    case ATECC608_ERR_EXEC:        return "chip execution error";
    case ATECC608_ERR_CHIP_STATE:  return "chip state prevents operation";
    default:                       return "unknown status";
    }
}

void atecc608_print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02X%s", data[i],
               (i + 1 == len) ? "\n" : ((i % 8 == 7) ? "  " : " "));
    }
}

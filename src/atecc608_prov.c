// ATECC608 guarded provisioning (Phase 4A). See
// include/atecc608/atecc608_prov.h for the guarantees each function makes.
//
// This file talks to cryptoauthlib's atcab_* layer directly (it is
// HAL-agnostic: the same code runs on the Pico target and in the host unit
// tests against the mock HAL).

#include "atecc608/atecc608_prov.h"

#include <string.h>

#include "cryptoauthlib.h"
#include "atecc608_int.h"

// Read a zone's lock state; maps transport-level failures.
static atecc608_status_t get_locked(uint8_t lock_zone, bool *locked)
{
    ATCA_STATUS st = atcab_is_locked(lock_zone, locked);
    return (ATCA_SUCCESS == st) ? ATECC608_OK : atecc608_map_status(st);
}

atecc608_status_t atecc608_provision_config(const atecc608_config_intent_t *cfg)
{
    uint8_t intent[ATECC608_CONFIG_ZONE_LEN];
    uint8_t current[ATECC608_CONFIG_ZONE_LEN];
    uint8_t readback[ATECC608_CONFIG_ZONE_LEN];
    bool locked = false;
    ATCA_STATUS st;

    if (NULL == cfg) {
        return ATECC608_ERR_BAD_PARAM;
    }
    if (ATECC608_OK != atecc608_config_build(cfg, intent)) {
        return ATECC608_ERR_BAD_PARAM;
    }

    st = get_locked(LOCK_ZONE_CONFIG, &locked);
    if (ATECC608_OK != st) {
        return st;
    }
    if (locked) {
        return ATECC608_ERR_CHIP_STATE; // config zone is locked: no writes
    }

    st = atcab_read_config_zone(current);
    if (ATCA_SUCCESS != st) {
        return atecc608_map_status(st);
    }

    // The I2C address byte (16) is factory-programmed and is NOT modeled by
    // the builder (it would emit 0). The library's write covers it, and the
    // datasheet is explicit: write it with the chip's current address. Always
    // preserve the chip's value so provisioning can never change (and lose)
    // the device's bus address.
    intent[16] = current[16];

    // Idempotent: if the writable region already matches, no writes at all.
    if (atecc608_config_writable_equal(current, intent, NULL)) {
        return ATECC608_OK;
    }

    st = atcab_write_config_zone(intent);
    if (ATCA_SUCCESS != st) {
        return atecc608_map_status(st);
    }

    // Ground rule 1: verify by read-back before reporting success.
    st = atcab_read_config_zone(readback);
    if (ATCA_SUCCESS != st) {
        return atecc608_map_status(st);
    }
    if (!atecc608_config_writable_equal(readback, intent, NULL)) {
        // The write command was accepted but the chip does not hold the
        // intended bytes; treat as a chip-level failure (the raw
        // last_error is ATCA_SUCCESS — every command individually passed).
        return ATECC608_ERR_EXEC;
    }

    return ATECC608_OK;
}

atecc608_status_t atecc608_lock_config_zone(const atecc608_config_intent_t *cfg,
                                            atecc608_confirm_fn confirm, void *ctx)
{
    uint8_t intent[ATECC608_CONFIG_ZONE_LEN];
    uint8_t zone[ATECC608_CONFIG_ZONE_LEN];
    bool locked = false;
    ATCA_STATUS st;

    if ((NULL == cfg) || (NULL == confirm)) {
        return ATECC608_ERR_BAD_PARAM;
    }
    if (ATECC608_OK != atecc608_config_build(cfg, intent)) {
        return ATECC608_ERR_BAD_PARAM;
    }

    st = get_locked(LOCK_ZONE_CONFIG, &locked);
    if (ATECC608_OK != st) {
        return st;
    }
    if (locked) {
        return ATECC608_ERR_CHIP_STATE; // already locked
    }

    // Re-verify the zone against the intent immediately before locking,
    // and lock with the summary CRC of the bytes just read back: a
    // corrupted or concurrently modified zone cannot be locked.
    st = atcab_read_config_zone(zone);
    if (ATCA_SUCCESS != st) {
        return atecc608_map_status(st);
    }

    // The builder does not model the I2C address byte (16); preserve the
    // chip's value for the comparison (see atecc608_provision_config).
    intent[16] = zone[16];

    if (!atecc608_config_writable_equal(zone, intent, NULL)) {
        return ATECC608_ERR_EXEC;
    }

    if (!confirm("lock config zone (irreversible)", ctx)) {
        return ATECC608_ERR_CHIP_STATE;
    }

    st = atcab_lock_config_zone_crc(atecc608_config_crc16(zone));
    return atecc608_map_status(st);
}

atecc608_status_t atecc608_lock_data_zone(atecc608_confirm_fn confirm, void *ctx)
{
    bool data_locked = false;
    bool cfg_locked = false;
    ATCA_STATUS st;

    if (NULL == confirm) {
        return ATECC608_ERR_BAD_PARAM;
    }

    st = get_locked(LOCK_ZONE_DATA, &data_locked);
    if (ATECC608_OK != st) {
        return st;
    }
    if (data_locked) {
        return ATECC608_ERR_CHIP_STATE; // already locked
    }

    // The data zone can only be locked after the config zone is.
    st = get_locked(LOCK_ZONE_CONFIG, &cfg_locked);
    if (ATECC608_OK != st) {
        return st;
    }
    if (!cfg_locked) {
        return ATECC608_ERR_CHIP_STATE;
    }

    if (!confirm("lock data zone + OTP (irreversible)", ctx)) {
        return ATECC608_ERR_CHIP_STATE;
    }

    st = atcab_lock_data_zone();
    return atecc608_map_status(st);
}

atecc608_status_t atecc608_lock_data_slot(uint8_t slot,
                                          atecc608_confirm_fn confirm, void *ctx)
{
    ATCA_STATUS st;

    if ((slot > ATECC608_MAX_DATA_SLOT) || (NULL == confirm)) {
        return ATECC608_ERR_BAD_PARAM;
    }

    if (!confirm("lock data slot (irreversible)", ctx)) {
        return ATECC608_ERR_CHIP_STATE;
    }

    // The chip enforces the slot's Lockable flag and the lock ordering.
    st = atcab_lock_data_slot(slot);
    return atecc608_map_status(st);
}

atecc608_status_t atecc608_genkey(uint8_t slot, uint8_t pub[ATECC608_PUBKEY_LEN])
{
    ATCA_STATUS st;

    if ((slot > ATECC608_MAX_DATA_SLOT) || (NULL == pub)) {
        return ATECC608_ERR_BAD_PARAM;
    }

    st = atcab_genkey(slot, pub);
    return atecc608_map_status(st);
}

atecc608_status_t atecc608_counter_read(uint8_t counter_id, uint32_t *value)
{
    ATCA_STATUS st;

    if ((counter_id > 1u) || (NULL == value)) {
        return ATECC608_ERR_BAD_PARAM;
    }

    st = atcab_counter_read(counter_id, value);
    return atecc608_map_status(st);
}

atecc608_status_t atecc608_counter_increment(uint8_t counter_id,
                                             uint32_t *new_value,
                                             atecc608_confirm_fn confirm, void *ctx)
{
    ATCA_STATUS st;

    if ((counter_id > 1u) || (NULL == new_value) || (NULL == confirm)) {
        return ATECC608_ERR_BAD_PARAM;
    }

    if (!confirm("increment monotonic counter (one-way)", ctx)) {
        return ATECC608_ERR_CHIP_STATE;
    }

    st = atcab_counter_increment(counter_id, new_value);
    return atecc608_map_status(st);
}

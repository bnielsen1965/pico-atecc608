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

    // Bytes the builder does not model (it would emit 0 for both) but the
    // library's write path DOES cover. Preserve the chip's values so
    // provisioning can never change them.
    //
    // Byte 16 (I2C address, 8-bit on-the-wire form): factory-programmed;
    // writing anything else would change (and lose) the bus address.
    intent[16] = current[16];
    //
    // Bytes 88..89 (SlotLocked): Lock-command-managed; the factory ships
    // 0xFFFF (verified on the bench chip). Whether the Write command takes
    // effect on them is not documented, so preserve the chip's value either
    // way: if the chip honors the write, we write back exactly what it holds
    // (a no-op); if it ignores the write, the read-back verify below still
    // sees the same bytes. Writing the builder's 0x0000 instead would fail
    // the verify (and the lock re-verify) in the ignore case.
    intent[88] = current[88];
    intent[89] = current[89];

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

    // The builder does not model byte 16 (I2C address) or bytes 88..89
    // (SlotLocked); preserve the chip's values for the comparison (see
    // atecc608_provision_config).
    intent[16] = zone[16];
    intent[88] = zone[88];
    intent[89] = zone[89];

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

atecc608_status_t atecc608_get_pubkey(uint8_t slot, uint8_t pub[ATECC608_PUBKEY_LEN])
{
    ATCA_STATUS st;

    if ((slot > ATECC608_MAX_DATA_SLOT) || (NULL == pub)) {
        return ATECC608_ERR_BAD_PARAM;
    }

    // GenKey mode 0x00: recompute the public key from the stored private
    // key. Read-only (the chip changes nothing), so no confirm gate, and
    // it works even with the data zone locked — the point of the mode.
    st = atcab_get_pubkey(slot, pub);
    return atecc608_map_status(st);
}

atecc608_status_t atecc608_write_iokey(uint8_t slot,
                                       const uint8_t key[ATECC608_DATA_SLOT_LEN])
{
    uint8_t zone[ATECC608_CONFIG_ZONE_LEN];
    atecc608_config_intent_t cfg;
    bool locked = false;
    ATCA_STATUS st;

    if ((slot > ATECC608_MAX_DATA_SLOT) || (NULL == key)) {
        return ATECC608_ERR_BAD_PARAM;
    }

    st = get_locked(LOCK_ZONE_CONFIG, &locked);
    if (ATECC608_OK != st) {
        return st;
    }
    if (!locked) {
        // The chip refuses any data-zone write while the config zone is
        // unlocked (verified on the bench: a 32-byte Write to a plain
        // factory slot returns ATCA_EXECUTION_ERROR; all of Microchip's
        // data-write conformance tests run with the config zone locked).
        // The approved 4B order is config -> lock -> iokey.
        return ATECC608_ERR_CHIP_STATE;
    }

    st = get_locked(LOCK_ZONE_DATA, &locked);
    if (ATECC608_OK != st) {
        return st;
    }
    if (locked) {
        return ATECC608_ERR_CHIP_STATE; // locked zone: no writes
    }

    // The slot must accept a clear Write in the CURRENT config (the
    // config zone is readable even when locked). A read-back verify of
    // the data write is impossible — see the header — so this is the
    // only pre-write check the hardware allows.
    st = atcab_read_config_zone(zone);
    if (ATCA_SUCCESS != st) {
        return atecc608_map_status(st);
    }
    if (ATECC608_OK != atecc608_config_parse(zone, &cfg)) {
        return ATECC608_ERR;
    }
    if (cfg.key[slot].private_key
        || (cfg.slot[slot].write_key != 0u)
        || (cfg.slot[slot].write_config != 0u)) {
        return ATECC608_ERR_CHIP_STATE;
    }

    // The chip's OK response commits the write.
    st = atcab_write_bytes_zone(ATCA_ZONE_DATA, slot, 0, (uint8_t *)key,
                                ATECC608_DATA_SLOT_LEN);
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

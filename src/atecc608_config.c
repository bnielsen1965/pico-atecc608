// ATECC608 config-zone builder (pure logic — see include/atecc608/
// atecc608_config.h for the field encodings and their sources).
//
// Bit positions mirror cryptoauthlib v3.8.0's calib_device.h
// (atecc608_config_s and the ATCA_*_SHIFT/_MASK defines); the values are
// emitted little-endian exactly as the chip stores them. The one
// deliberate exception is the GenKey/PrivWrite bits of ECC private key
// slots: the datasheet (Tables 2-10/2-11) puts them at bits 13/14, which
// the library's bit 8/9 defines contradict (see the builder below).

#include "atecc608/atecc608_config.h"

#include <string.h>

// --- little-endian helpers ----------------------------------------------------

static void put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)(v >> 8);
}

static uint16_t get_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint32_t get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// --- validation ----------------------------------------------------------------

// Internal codes for the cross-field rules; the public API reports
// ATECC608_ERR_BAD_PARAM for all of them (tests exercise each rule
// individually).
typedef enum {
    VAL_OK = 0,
    VAL_KEY_RANGE,       // a 4-bit key/slot reference > 15
    VAL_CLK_DIV,         // clk_div > 31
    VAL_KEY_TYPE,        // key_type not ECC(4) / NON_ECC(7)
    VAL_PRIV_SECRET,     // private key slot without is_secret
    VAL_PRIV_TYPE,       // private key slot with non-ECC key_type
    VAL_PRIV_NORMAL,     // normal-slot fields set on a private key slot
    VAL_ENC_READ,        // enc_read without is_secret
    VAL_WRITE_CFG,       // write_config/enc_read without is_secret
    VAL_AUTH_KEY,        // auth_key inconsistent with req_auth
    VAL_X509,            // x509_id on a slot without a public key
    VAL_COUNTER,         // counter value out of range
    VAL_SB_MODE,         // reserved secure boot mode
    VAL_SB_SLOT,         // secure boot enabled without required slots
    VAL_COUNT_MATCH,     // count_match enabled without a key
    VAL_USE_LOCK,        // use_lock enabled without a key
    VAL_IO_PROT,         // io_prot enabled without a key
    VAL_PROT2,           // ecdh_prot/kdf_prot > 1
    VAL_ALT_ADDR,        // user_extra_add not a valid 8-bit write address
} val_code_t;

static bool le15(uint8_t v)
{
    return v <= 15u;
}

static val_code_t validate_slot_key(const atecc608_slot_cfg_t *s,
                                    const atecc608_key_cfg_t *k)
{
    if (!(le15(s->read_key) && le15(s->write_key) && le15(s->write_config) &&
          le15(k->auth_key))) {
        return VAL_KEY_RANGE;
    }

    if (k->key_type != ATECC608_KEY_TYPE_ECC &&
        k->key_type != ATECC608_KEY_TYPE_NON_ECC) {
        return VAL_KEY_TYPE;
    }

    if (k->private_key) {
        if (!s->is_secret) {
            return VAL_PRIV_SECRET;
        }
        if (k->key_type != ATECC608_KEY_TYPE_ECC) {
            return VAL_PRIV_TYPE;
        }
        // The normal-slot fields are not used on ECC private key slots
        // (bits 0-3 carry the ECC permission bits, bit 7 is IsSecret,
        // bits 13/14 are GenKey/PrivWrite); require them to be clear so
        // the intent is unambiguous.
        if (s->read_key != 0 || s->write_key != 0 || s->write_config != 0 ||
            s->no_mac || s->limited_use || s->enc_read) {
            return VAL_PRIV_NORMAL;
        }
    }

    if (s->enc_read && !s->is_secret) {
        return VAL_ENC_READ;
    }
    if ((s->write_config != 0 || s->enc_read) && !s->is_secret) {
        return VAL_WRITE_CFG;
    }

    if (k->req_auth) {
        if (k->auth_key < 1 || k->auth_key > 15) {
            return VAL_AUTH_KEY;
        }
    } else if (k->auth_key != 0) {
        return VAL_AUTH_KEY;
    }

    if (k->x509_id != 0 &&
        (k->key_type != ATECC608_KEY_TYPE_ECC || k->private_key)) {
        return VAL_X509;
    }
    if (k->x509_id > 3) {
        return VAL_KEY_RANGE;
    }

    return VAL_OK;
}

static val_code_t validate(const atecc608_config_intent_t *c)
{
    for (int i = 0; i <= ATECC608_MAX_DATA_SLOT; i++) {
        const val_code_t r = validate_slot_key(&c->slot[i], &c->key[i]);
        if (r != VAL_OK) {
            return r;
        }
    }

    if (!le15(c->count_match_key) || !le15(c->use_lock_key) ||
        !le15(c->vol_key_perm_slot) || !le15(c->sb_digest_slot) ||
        !le15(c->sb_pubkey_slot) || !le15(c->kdf_lv_loc) ||
        !le15(c->kdf_lv_slot) || !le15(c->io_prot_key)) {
        return VAL_KEY_RANGE;
    }
    if (c->clk_div > 31u) {
        return VAL_CLK_DIV;
    }

    for (int i = 0; i < 2; i++) {
        if (c->counter[i].value > ATECC608_COUNTER_MAX) {
            return VAL_COUNTER;
        }
    }

    if (c->sb_mode != ATECC608_SB_MODE_OFF &&
        c->sb_mode != ATECC608_SB_MODE_FULL_COPY &&
        c->sb_mode != ATECC608_SB_MODE_FULL_STORE) {
        return VAL_SB_MODE;
    }
    if (c->sb_mode != ATECC608_SB_MODE_OFF) {
        if (c->sb_pubkey_slot < 1 || c->sb_pubkey_slot > 15) {
            return VAL_SB_SLOT;
        }
        if (c->sb_mode == ATECC608_SB_MODE_FULL_STORE &&
            (c->sb_digest_slot < 1 || c->sb_digest_slot > 15)) {
            return VAL_SB_SLOT;
        }
    }

    if (c->count_match_en && (c->count_match_key < 1 || c->count_match_key > 15)) {
        return VAL_COUNT_MATCH;
    }
    if (c->use_lock_en && (c->use_lock_key < 1 || c->use_lock_key > 15)) {
        return VAL_USE_LOCK;
    }
    if (c->io_prot_en && (c->io_prot_key < 1 || c->io_prot_key > 15)) {
        return VAL_IO_PROT;
    }
    if (c->ecdh_prot > 1u || c->kdf_prot > 1u) {
        return VAL_PROT2;
    }
    // Byte 85 holds the full 8-bit I2C write address when non-zero; the
    // R/W bit (LSB) is 0 on write addresses.
    if (c->user_extra_add != 0 && (c->user_extra_add & 1u) != 0u) {
        return VAL_ALT_ADDR;
    }

    return VAL_OK;
}

// --- default ---------------------------------------------------------------------

void atecc608_config_default(atecc608_config_intent_t *cfg)
{
    if (NULL == cfg) {
        return;
    }

    memset(cfg, 0, sizeof(*cfg));

    for (int i = 0; i <= ATECC608_MAX_DATA_SLOT; i++) {
        cfg->key[i].key_type = ATECC608_KEY_TYPE_NON_ECC;
    }
    // counter value = 0 is already the zeroed state.
}

// --- build ---------------------------------------------------------------------

atecc608_status_t atecc608_config_build(const atecc608_config_intent_t *cfg,
                                        uint8_t zone[ATECC608_CONFIG_ZONE_LEN])
{
    if ((NULL == cfg) || (NULL == zone)) {
        return ATECC608_ERR_BAD_PARAM;
    }
    if (VAL_OK != validate(cfg)) {
        return ATECC608_ERR_BAD_PARAM;
    }

    memset(zone, 0, ATECC608_CONFIG_ZONE_LEN);

    // Byte 18: CountMatch
    zone[18] = (uint8_t)((cfg->count_match_en ? 1u : 0u) |
                         ((uint8_t)cfg->count_match_key << 4));

    // Byte 19: ChipMode
    zone[19] = (uint8_t)((cfg->i2c_extra ? 1u : 0u) |
                         ((cfg->ttl_en ? 1u : 0u) << 1) |
                         ((cfg->wd_long ? 1u : 0u) << 2) |
                         ((uint8_t)cfg->clk_div << 3));

    // Bytes 20..51: SlotConfig[16]
    for (int i = 0; i <= ATECC608_MAX_DATA_SLOT; i++) {
        const atecc608_slot_cfg_t *s = &cfg->slot[i];
        uint16_t v;

        if (cfg->key[i].private_key) {
            // ECC private key layout: bits 0-3 are the permission bits,
            // bit 7 (IsSecret) is mandatory, bit 13 is GenKey, bit 14 is
            // PrivWrite. NOTE: this deviates from cryptoauthlib's
            // ATCA_SLOT_CONFIG_GEN_KEY_SHIFT (8) / PRIV_WRITE_SHIFT (9);
            // the ATECC508A/608A datasheet (Tables 2-10/2-11, "Write
            // Configuration Bits: GenKey/PrivWrite Command") puts GenKey at
            // bit 13 and PrivWrite at bit 14, and the library's own
            // ATECC608 test vector agrees (slot word 0x208F = GenKey set).
            v = (uint16_t)((s->ext_sig ? 1u : 0u) |
                           ((s->int_sig ? 1u : 0u) << 1) |
                           ((s->ecdh ? 1u : 0u) << 2) |
                           ((s->ecdh_to_next ? 1u : 0u) << 3) |
                           (1u << 7) |                  // IsSecret, required
                           ((s->gen_key ? 1u : 0u) << 13) |
                           ((s->priv_write ? 1u : 0u) << 14));
        } else {
            v = (uint16_t)(s->read_key |
                           ((s->no_mac ? 1u : 0u) << 4) |
                           ((s->limited_use ? 1u : 0u) << 5) |
                           ((s->enc_read ? 1u : 0u) << 6) |
                           ((s->is_secret ? 1u : 0u) << 7) |
                           ((uint16_t)s->write_key << 8) |
                           ((uint16_t)s->write_config << 12));
        }
        put_le16(&zone[20 + 2 * i], v);
    }

    // Bytes 52..59 / 60..67: monotonic counters in the chip's dual
    // linear + binary encoding (identical to cryptoauthlib's
    // calib_write_config_counter). See the header for the layout.
    for (int i = 0; i < 2; i++) {
        const uint32_t v = cfg->counter[i].value;
        const uint16_t lin_a = (uint16_t)(0xFFFFu >> (v % 32u));
        const uint16_t lin_b = (v >= 16u) ? (uint16_t)(0xFFFFu >> ((v - 16u) % 32u))
                                          : 0xFFFFu;
        const uint16_t bin_a = (uint16_t)(v / 32u);
        const uint16_t bin_b = (v >= 16u) ? (uint16_t)((v - 16u) / 32u) : 0u;
        uint8_t *p = &zone[52 + 8 * i];

        p[0] = (uint8_t)(lin_a >> 8);
        p[1] = (uint8_t)(lin_a & 0xFFu);
        p[2] = (uint8_t)(lin_b >> 8);
        p[3] = (uint8_t)(lin_b & 0xFFu);
        p[4] = (uint8_t)(bin_a >> 8);
        p[5] = (uint8_t)(bin_a & 0xFFu);
        p[6] = (uint8_t)(bin_b >> 8);
        p[7] = (uint8_t)(bin_b & 0xFFu);
    }

    // Byte 68: UseLock
    zone[68] = (uint8_t)((cfg->use_lock_en ? 1u : 0u) |
                         ((uint8_t)cfg->use_lock_key << 4));

    // Byte 69: VolatileKeyPermission
    zone[69] = (uint8_t)(cfg->vol_key_perm_slot |
                         ((cfg->vol_key_perm_en ? 1u : 0u) << 7));

    // Bytes 70..71: SecureBoot
    put_le16(&zone[70], (uint16_t)(cfg->sb_mode |
                                   ((cfg->sb_persist ? 1u : 0u) << 3) |
                                   ((cfg->sb_rand_nonce ? 1u : 0u) << 4) |
                                   ((uint16_t)cfg->sb_digest_slot << 8) |
                                   ((uint16_t)cfg->sb_pubkey_slot << 12)));

    // Byte 72: KdflvLoc (4 bits), bytes 73..74: KdflvStr (slot in low byte)
    zone[72] = (uint8_t)(cfg->kdf_lv_loc & 0x0Fu);
    put_le16(&zone[73], (uint16_t)(cfg->kdf_lv_slot & 0x0Fu));

    // Byte 84/85: UserExtra / UserExtraAdd (bytes 75..83 stay zero)
    zone[84] = cfg->user_extra;
    zone[85] = cfg->user_extra_add;

    // Bytes 86..87: lock bytes — unlocked sentinel (the Write command
    // skips them; the Lock command is the only thing that changes them).
    zone[ATECC608_CONFIG_LOCK_OFFSET]     = ATECC608_CONFIG_UNLOCKED;
    zone[ATECC608_CONFIG_LOCK_OFFSET + 1] = ATECC608_CONFIG_UNLOCKED;

    // Bytes 88..89: SlotLocked
    put_le16(&zone[88], cfg->slot_locked);

    // Bytes 90..91: ChipOptions
    put_le16(&zone[90], (uint16_t)((cfg->post_en ? 1u : 0u) |
                                   ((cfg->io_prot_en ? 1u : 0u) << 1) |
                                   ((cfg->kdf_aes_en ? 1u : 0u) << 2) |
                                   ((uint16_t)cfg->ecdh_prot << 8) |
                                   ((uint16_t)cfg->kdf_prot << 10) |
                                   ((uint16_t)cfg->io_prot_key << 12)));

    // Bytes 92..95: X509format (LE32)
    put_le32(&zone[92], (uint32_t)cfg->x509_format[0] |
                        ((uint32_t)cfg->x509_format[1] << 8) |
                        ((uint32_t)cfg->x509_format[2] << 16) |
                        ((uint32_t)cfg->x509_format[3] << 24));

    // Bytes 96..127: KeyConfig[16]
    for (int i = 0; i <= ATECC608_MAX_DATA_SLOT; i++) {
        const atecc608_key_cfg_t *k = &cfg->key[i];
        put_le16(&zone[96 + 2 * i],
                 (uint16_t)((k->private_key ? 1u : 0u) |
                            ((k->pub_info ? 1u : 0u) << 1) |
                            ((uint16_t)k->key_type << 2) |
                            ((k->lockable ? 1u : 0u) << 5) |
                            ((k->req_random ? 1u : 0u) << 6) |
                            ((k->req_auth ? 1u : 0u) << 7) |
                            ((uint16_t)k->auth_key << 8) |
                            ((k->persist_dis ? 1u : 0u) << 12) |
                            ((uint16_t)(k->x509_id & 3u) << 14)));
    }

    return ATECC608_OK;
}

// --- parse ---------------------------------------------------------------------

// Recover the counter value from its 8-byte dual linear + binary encoding
// (inverse of the build-time encoding). Faithful, not strict: it takes the
// value the chip would report for the Counter command (the binary part plus
// the low bits recovered from the linear masks) and does not reject
// inconsistent images.
static uint32_t parse_counter_value(const uint8_t p[8])
{
    // The words are stored big-endian (see the build-side encoding and
    // cryptoauthlib's calib_write_config_counter).
    const uint16_t lin_a = (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
    const uint16_t bin_a = (uint16_t)(((uint16_t)p[4] << 8) | p[5]);
    uint32_t r;

    if (lin_a != 0u) {
        // lin_a = 0xFFFF >> r with r in 0..15: r trailing-one count rule.
        uint32_t ones = 0;
        for (uint16_t x = lin_a; (x & 1u) != 0u; x >>= 1) {
            ones++;
        }
        r = 16u - ones;
    } else {
        // lin_a == 0 means r in 16..31; lin_b = 0xFFFF >> (r - 16).
        const uint16_t lin_b = (uint16_t)(((uint16_t)p[2] << 8) | p[3]);
        uint32_t ones = 0;
        for (uint16_t x = lin_b; (x & 1u) != 0u; x >>= 1) {
            ones++;
        }
        r = 32u - ones;
        if (r < 16u) {
            r = 16u;  // corrupted image: fall back to the smallest r in range
        }
    }
    return ((uint32_t)bin_a * 32u) + r;
}

atecc608_status_t atecc608_config_parse(const uint8_t zone[ATECC608_CONFIG_ZONE_LEN],
                                        atecc608_config_intent_t *cfg)
{
    if ((NULL == zone) || (NULL == cfg)) {
        return ATECC608_ERR_BAD_PARAM;
    }

    atecc608_config_default(cfg);

    cfg->count_match_en  = (zone[18] & 0x01u) != 0u;
    cfg->count_match_key = (uint8_t)((zone[18] >> 4) & 0x0Fu);

    cfg->i2c_extra = (zone[19] & 0x01u) != 0u;
    cfg->ttl_en    = (zone[19] & 0x02u) != 0u;
    cfg->wd_long   = (zone[19] & 0x04u) != 0u;
    cfg->clk_div   = (uint8_t)((zone[19] >> 3) & 0x1Fu);

    // KeyConfig first: it decides how to read each SlotConfig word.
    for (int i = 0; i <= ATECC608_MAX_DATA_SLOT; i++) {
        const uint16_t v = get_le16(&zone[96 + 2 * i]);
        atecc608_key_cfg_t *k = &cfg->key[i];

        k->private_key = (v & 0x0001u) != 0u;
        k->pub_info    = (v & 0x0002u) != 0u;
        k->key_type    = (uint8_t)((v >> 2) & 0x07u);
        k->lockable    = (v & 0x0020u) != 0u;
        k->req_random  = (v & 0x0040u) != 0u;
        k->req_auth    = (v & 0x0080u) != 0u;
        k->auth_key    = (uint8_t)((v >> 8) & 0x0Fu);
        k->persist_dis = (v & 0x1000u) != 0u;
        k->x509_id     = (uint8_t)((v >> 14) & 0x03u);
    }

    for (int i = 0; i <= ATECC608_MAX_DATA_SLOT; i++) {
        const uint16_t v = get_le16(&zone[20 + 2 * i]);
        atecc608_slot_cfg_t *s = &cfg->slot[i];

        s->is_secret = (v & 0x0080u) != 0u;
        if (cfg->key[i].private_key) {
            s->ext_sig      = (v & 0x0001u) != 0u;
            s->int_sig      = (v & 0x0002u) != 0u;
            s->ecdh         = (v & 0x0004u) != 0u;
            s->ecdh_to_next = (v & 0x0008u) != 0u;
            s->gen_key      = (v & 0x2000u) != 0u;
            s->priv_write   = (v & 0x4000u) != 0u;
        } else {
            s->read_key     = (uint8_t)(v & 0x0Fu);
            s->no_mac       = (v & 0x0010u) != 0u;
            s->limited_use  = (v & 0x0020u) != 0u;
            s->enc_read     = (v & 0x0040u) != 0u;
            s->write_key    = (uint8_t)((v >> 8) & 0x0Fu);
            s->write_config = (uint8_t)((v >> 12) & 0x0Fu);
        }
    }

    for (int i = 0; i < 2; i++) {
        cfg->counter[i].value = parse_counter_value(&zone[52 + 8 * i]);
    }

    cfg->use_lock_en  = (zone[68] & 0x01u) != 0u;
    cfg->use_lock_key = (uint8_t)((zone[68] >> 4) & 0x0Fu);

    cfg->vol_key_perm_en   = (zone[69] & 0x80u) != 0u;
    cfg->vol_key_perm_slot = (uint8_t)(zone[69] & 0x0Fu);

    {
        const uint16_t v = get_le16(&zone[70]);
        cfg->sb_mode        = (uint8_t)(v & 0x03u);
        cfg->sb_persist     = (v & 0x0008u) != 0u;
        cfg->sb_rand_nonce  = (v & 0x0010u) != 0u;
        cfg->sb_digest_slot = (uint8_t)((v >> 8) & 0x0Fu);
        cfg->sb_pubkey_slot = (uint8_t)((v >> 12) & 0x0Fu);
    }

    cfg->kdf_lv_loc  = (uint8_t)(zone[72] & 0x0Fu);
    cfg->kdf_lv_slot = (uint8_t)(get_le16(&zone[73]) & 0x0Fu);

    cfg->user_extra     = zone[84];
    cfg->user_extra_add = zone[85];
    cfg->slot_locked    = get_le16(&zone[88]);

    {
        const uint16_t v = get_le16(&zone[90]);
        cfg->post_en     = (v & 0x0001u) != 0u;
        cfg->io_prot_en  = (v & 0x0002u) != 0u;
        cfg->kdf_aes_en  = (v & 0x0004u) != 0u;
        cfg->ecdh_prot   = (uint8_t)((v >> 8) & 0x03u);
        cfg->kdf_prot    = (uint8_t)((v >> 10) & 0x03u);
        cfg->io_prot_key = (uint8_t)((v >> 12) & 0x0Fu);
    }

    {
        const uint32_t v = get_le32(&zone[92]);
        cfg->x509_format[0] = (uint8_t)(v & 0xFFu);
        cfg->x509_format[1] = (uint8_t)((v >> 8) & 0xFFu);
        cfg->x509_format[2] = (uint8_t)((v >> 16) & 0xFFu);
        cfg->x509_format[3] = (uint8_t)((v >> 24) & 0xFFu);
    }

    return ATECC608_OK;
}

// --- compare / crc ----------------------------------------------------------------

bool atecc608_config_writable_equal(const uint8_t a[ATECC608_CONFIG_ZONE_LEN],
                                    const uint8_t b[ATECC608_CONFIG_ZONE_LEN],
                                    uint32_t diff[4])
{
    bool equal = true;

    if (NULL != diff) {
        diff[0] = diff[1] = diff[2] = diff[3] = 0;
    }

    for (int byte = 0; byte < ATECC608_CONFIG_ZONE_LEN; byte++) {
        // Skip the factory region [0:16] and the lock bytes [86:88].
        if (byte < ATECC608_CONFIG_FACTORY_LEN ||
            ((uint16_t)byte >= ATECC608_CONFIG_LOCK_OFFSET &&
             (uint16_t)byte < ATECC608_CONFIG_LOCK_OFFSET + 2u)) {
            continue;
        }
        if (a[byte] != b[byte]) {
            equal = false;
            if (NULL != diff) {
                diff[byte / 32] |= (1u << (byte % 32));
            }
        }
    }

    return equal;
}

uint16_t atecc608_config_crc16(const uint8_t zone[ATECC608_CONFIG_ZONE_LEN])
{
    // Bit-serial CRC-16 identical to cryptoauthlib's atCRC() (the command
    // packet checksum): poly 0x8005, initial 0x0000, MSB-first, no final
    // XOR.
    uint16_t crc = 0;

    for (int i = 0; i < ATECC608_CONFIG_ZONE_LEN; i++) {
        // uint8_t on purpose: 0x80 << 1 must wrap to 0 and end the loop
        // after 8 bits (a wider type would run a 9th, bogus iteration).
        for (uint8_t bit = 0x01; bit != 0u; bit <<= 1) {
            const uint8_t data_bit = (zone[i] & (uint8_t)bit) != 0u;
            const uint8_t crc_bit  = (crc & 0x8000u) != 0u;

            crc <<= 1;
            if (crc_bit != data_bit) {
                crc ^= 0x8005u;
            }
        }
    }

    return crc;
}

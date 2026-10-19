// Host unit tests for the ATECC608 config-zone builder (Phase 4A).
//
// Pure logic: no chip, no HAL. The only cryptoauthlib dependency is atCRC()
// (the command checksum), used to prove atecc608_config_crc16() is
// byte-identical to the library's implementation.

#include <stdio.h>
#include <string.h>

#include "atecc608/atecc608_config.h"
#include "cryptoauthlib.h"  // atCRC

#include "test_golden.h"

// --- tiny harness ---------------------------------------------------------------

static int s_checks = 0;
static int s_failures = 0;

#define CHECK(cond) do { \
    s_checks++; \
    if (!(cond)) { \
        s_failures++; \
        printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
    } \
} while (0)

static void dump_zone(const char *label, const uint8_t *p)
{
    printf("  %s:\n", label);
    for (int row = 0; row < ATECC608_CONFIG_ZONE_LEN / 16; row++) {
        printf("    %02X: ", row * 16);
        for (int col = 0; col < 16; col++) {
            printf("%02X ", p[row * 16 + col]);
        }
        printf("\n");
    }
}

// --- t_default_build --------------------------------------------------------------

static void t_default_build(void)
{
    printf("t_default_build\n");
    atecc608_config_intent_t cfg;
    uint8_t z[ATECC608_CONFIG_ZONE_LEN];

    atecc608_config_default(&cfg);
    CHECK(ATECC608_OK == atecc608_config_build(&cfg, z));

    // Everything the builder models is cleared; every key is NON_ECC (0x1C).
    for (int i = 0; i <= ATECC608_MAX_DATA_SLOT; i++) {
        CHECK(0x1Cu == z[96 + 2 * i]);
        CHECK(0x00u == z[97 + 2 * i]);
    }
    // Counters at zero (the dual encoding of 0).
    static const uint8_t ctr0[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0 };
    CHECK(0 == memcmp(&z[52], ctr0, 8));
    CHECK(0 == memcmp(&z[60], ctr0, 8));
    // Unlocked sentinel.
    CHECK(ATECC608_CONFIG_UNLOCKED == z[86]);
    CHECK(ATECC608_CONFIG_UNLOCKED == z[87]);
    // Everything else zero (factory region included).
    for (int b = 0; b < ATECC608_CONFIG_ZONE_LEN; b++) {
        const bool modeled = (b >= 52 && b <= 67) ||
                             (b >= 86 && b <= 87) ||
                             (b >= 96 && b <= 127);
        if (!modeled) {
            CHECK(0u == z[b]);
        }
    }
}

// --- t_golden (byte-exact) ---------------------------------------------------------

static void t_golden(void)
{
    printf("t_golden\n");
    atecc608_config_intent_t cfg;
    uint8_t z[ATECC608_CONFIG_ZONE_LEN];

    fill_golden_config(&cfg);
    CHECK(ATECC608_OK == atecc608_config_build(&cfg, z));

    static const uint8_t expect[ATECC608_CONFIG_ZONE_LEN] = {
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  //  0  factory
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  //  8
        0x00, 0x00, 0x51, 0x12,  0x85, 0x60, 0x00, 0x00,  // 16  CM=0x51, mode=0x12
        // slot0 = 0x6085: ext_sig|ecdh|is_secret|gen_key(bit13)|priv_write(bit14).
        0x8B, 0x20, 0xD3, 0x00,  0x00, 0x00, 0x00, 0x00,  // 24  slots 2..5
        // slot2 = 0x208B: ext_sig|int_sig|ecdh_to_next|is_secret|gen_key(bit13).
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  // 32  slots 6..9
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  // 40  slots 10..13
        0x00, 0x00, 0x80, 0x22,  0x07, 0xFF, 0xFF, 0xFF,  // 48  slot15, ctr0=5
        0x00, 0x00, 0x00, 0x00,  0xFF, 0xFF, 0xFF, 0xFF,  // 56  ctr1=0
        0x00, 0x00, 0x00, 0x00,  0x81, 0x8C, 0x13, 0xF7,  // 64  UseLock, VKeyPerm, SB
        0x02, 0x03, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  // 72  KDF, reserved
        0x00, 0x00, 0x00, 0x00,  0xA5, 0xC4, 0x55, 0x55,  // 80  extras, unlocked
        0x05, 0x00, 0x07, 0x41,  0x11, 0x22, 0x33, 0x44,  // 88  SlotLocked, ChipOpt, X509
        // key1 = 0xC692: pub_info | ECC | req_auth | auth_key 6 | x509 3
        //   (x509 id is 2 bits at 14:15 — ATCA_KEY_CONFIG_X509_ID_MASK).
        0x33, 0x00, 0x92, 0xC6,  0x53, 0x00, 0x1C, 0x00,  // 96  keys 0..3
        0x1C, 0x00, 0x1C, 0x00,  0x1C, 0x00, 0x1C, 0x00,  // 104 keys 4..7
        0x1C, 0x00, 0x1C, 0x00,  0x1C, 0x00, 0x1C, 0x00,  // 112 keys 8..11
        0x1C, 0x00, 0x1C, 0x00,  0x1C, 0x00, 0x5C, 0x10,  // 120 keys 12..15
        // key15 = 0x105C: NON_ECC | req_random | persist_dis.
    };

    if (0 != memcmp(z, expect, sizeof(expect))) {
        for (int b = 0; b < ATECC608_CONFIG_ZONE_LEN; b++) {
            if (z[b] != expect[b]) {
                printf("  byte %d: got %02X expected %02X\n", b, z[b], expect[b]);
            }
        }
    }
    CHECK(0 == memcmp(z, expect, sizeof(expect)));
}

// --- t_golden_roundtrip -------------------------------------------------------------

static void t_golden_roundtrip(void)
{
    printf("t_golden_roundtrip\n");
    atecc608_config_intent_t cfg, cfg2;
    uint8_t z1[ATECC608_CONFIG_ZONE_LEN];
    uint8_t z2[ATECC608_CONFIG_ZONE_LEN];

    fill_golden_config(&cfg);
    CHECK(ATECC608_OK == atecc608_config_build(&cfg, z1));
    CHECK(ATECC608_OK == atecc608_config_parse(z1, &cfg2));
    CHECK(ATECC608_OK == atecc608_config_build(&cfg2, z2));
    if (0 != memcmp(z1, z2, sizeof(z1))) {
        dump_zone("first build", z1);
        dump_zone("rebuilt", z2);
    }
    CHECK(0 == memcmp(z1, z2, sizeof(z1)));
}

// --- t_counter_encoding --------------------------------------------------------------

// The chip's dual linear + binary counter encoding (see the header comment in
// atecc608_config.h; identical to cryptoauthlib's calib_write_config_counter).
static void t_counter_encoding(void)
{
    printf("t_counter_encoding\n");

    struct {
        uint32_t v;
        uint8_t  bytes[8];
    } cases[] = {
        { 0u,        { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 } },
        { 1u,        { 0x7F, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 } },
        { 5u,        { 0x07, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 } },
        { 15u,       { 0x00, 0x01, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 } },
        { 16u,       { 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 } },
        { 17u,       { 0x00, 0x00, 0x7F, 0xFF, 0x00, 0x00, 0x00, 0x00 } },
        { 31u,       { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 } },
        { 32u,       { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 } },
        { 48u,       { 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x01, 0x00, 0x01 } },
        { 0x1FFFFFu, { 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF } },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        atecc608_config_intent_t cfg, back;
        uint8_t z[ATECC608_CONFIG_ZONE_LEN];

        atecc608_config_default(&cfg);
        cfg.counter[0].value = cases[i].v;
        CHECK(ATECC608_OK == atecc608_config_build(&cfg, z));
        if (0 != memcmp(&z[52], cases[i].bytes, 8)) {
            printf("  counter v=%u: got %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   (unsigned)cases[i].v, z[52], z[53], z[54], z[55],
                   z[56], z[57], z[58], z[59]);
        }
        CHECK(0 == memcmp(&z[52], cases[i].bytes, 8));

        // And our parser recovers the same value.
        CHECK(ATECC608_OK == atecc608_config_parse(z, &back));
        CHECK(cases[i].v == back.counter[0].value);
    }
}

// --- t_vector_decode -----------------------------------------------------------------

// ATECC608_DEVICE_CONFIG_VECTOR from the cryptoauthlib v3.8.0 test reference
// (a fully provisioned, LOCKED test device — parse-fidelity only; the builder
// cannot reproduce the factory region or the lock bytes).
static const uint8_t s_vector[ATECC608_CONFIG_ZONE_LEN] = {
    0x01, 0x23, 0x72, 0xE8,  0x00, 0x00, 0x60, 0x02,  //  0
    0xB9, 0x63, 0xB2, 0xD3,  0xEE, 0x01, 0x2D, 0x00,  //  8
    0xB0, 0x00, 0x55, 0x01,  0x8F, 0x20, 0xC4, 0x44,  // 16
    0x87, 0x20, 0x87, 0x20,  0x8F, 0x0F, 0xC4, 0x36,  // 24
    0x9F, 0x0F, 0x82, 0x20,  0x0F, 0x0F, 0xC4, 0x44,  // 32
    0x0F, 0x0F, 0x0F, 0x0F,  0x0F, 0x0F, 0x0F, 0x0F,  // 40
    0x0F, 0x0F, 0x0F, 0x0F,  0xFF, 0xFF, 0xFF, 0xFF,  // 48
    0x00, 0x00, 0x00, 0x00,  0xFF, 0xFF, 0xFF, 0xFF,  // 56
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  // 64
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  // 72
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  // 80
    0xFF, 0xFF, 0x06, 0x40,  0x00, 0x00, 0x00, 0x00,  // 88
    0x33, 0x00, 0x1C, 0x00,  0x13, 0x00, 0x13, 0x00,  // 96
    0x7C, 0x00, 0x1C, 0x00,  0x3C, 0x00, 0x33, 0x00,  // 104
    0x3C, 0x00, 0x3C, 0x00,  0x3C, 0x00, 0x30, 0x00,  // 112
    0x3C, 0x00, 0x3C, 0x00,  0x3C, 0x00, 0x30, 0x00,  // 120
};

static void t_vector_decode(void)
{
    printf("t_vector_decode\n");
    atecc608_config_intent_t cfg;

    CHECK(ATECC608_OK == atecc608_config_parse(s_vector, &cfg));

    CHECK(cfg.count_match_en);
    CHECK(5u == cfg.count_match_key);
    CHECK(cfg.i2c_extra);
    CHECK(!cfg.ttl_en);
    CHECK(0u == cfg.clk_div);

    // key0 = 0x0033: private, pub_info, ECC, lockable.
    CHECK(cfg.key[0].private_key);
    CHECK(cfg.key[0].pub_info);
    CHECK(ATECC608_KEY_TYPE_ECC == cfg.key[0].key_type);
    CHECK(cfg.key[0].lockable);
    // slot0 = 0x208F (private layout).
    CHECK(cfg.slot[0].is_secret);
    CHECK(cfg.slot[0].ext_sig);
    CHECK(cfg.slot[0].int_sig);
    CHECK(cfg.slot[0].ecdh);
    CHECK(cfg.slot[0].ecdh_to_next);
    CHECK(cfg.slot[0].gen_key);
    CHECK(!cfg.slot[0].priv_write);

    // key2 = 0x0013: private ECC with pub_info. slot2 = 0x2087 (gen_key bit 13).
    CHECK(cfg.key[2].private_key);
    CHECK(cfg.key[2].pub_info);
    CHECK(cfg.slot[2].ext_sig);
    CHECK(cfg.slot[2].int_sig);
    CHECK(cfg.slot[2].ecdh);
    CHECK(!cfg.slot[2].ecdh_to_next);
    CHECK(cfg.slot[2].gen_key);

    // key4 = 0x007C: NON_ECC with req_random.
    // slot4 = 0x0F8F (normal layout): only read_key 0xF, is_secret and
    // write_key 0xF are set (0x8F = 0x80 | 0x0F; bits 4-6 are clear).
    CHECK(!cfg.key[4].private_key);
    CHECK(ATECC608_KEY_TYPE_NON_ECC == cfg.key[4].key_type);
    CHECK(cfg.key[4].req_random);
    CHECK(15u == cfg.slot[4].read_key);
    CHECK(!cfg.slot[4].no_mac);
    CHECK(!cfg.slot[4].limited_use);
    CHECK(!cfg.slot[4].enc_read);
    CHECK(cfg.slot[4].is_secret);
    CHECK(15u == cfg.slot[4].write_key);
    CHECK(0u == cfg.slot[4].write_config);

    // key11 = 0x0030: ECC key_type, lockable, neither private nor pub_info —
    // the slot word is therefore read in the NORMAL layout.
    CHECK(!cfg.key[11].private_key);
    CHECK(!cfg.key[11].pub_info);
    CHECK(ATECC608_KEY_TYPE_ECC == cfg.key[11].key_type);
    CHECK(cfg.key[11].lockable);
    CHECK(15u == cfg.slot[11].read_key);
    CHECK(!cfg.slot[11].is_secret); // 0x0F0F: not secret.

    CHECK(0u == cfg.counter[0].value);
    CHECK(0u == cfg.counter[1].value);

    CHECK(!cfg.use_lock_en);
    CHECK(!cfg.vol_key_perm_en);
    CHECK(0u == cfg.sb_mode);
    CHECK(0u == cfg.kdf_lv_loc);
    CHECK(0u == cfg.kdf_lv_slot);
    CHECK(0x00u == cfg.user_extra);
    CHECK(0x00u == cfg.user_extra_add);
    CHECK(0xFFFFu == cfg.slot_locked);
    CHECK(!cfg.post_en);
    // ChipOptions = 0x4006: io_prot_en, kdf_aes_en, io_prot_key 4.
    CHECK(cfg.io_prot_en);
    CHECK(cfg.kdf_aes_en);
    CHECK(0u == cfg.ecdh_prot);
    CHECK(0u == cfg.kdf_prot);
    CHECK(4u == cfg.io_prot_key);
    CHECK(0 == memcmp(cfg.x509_format, (const uint8_t[4]){ 0 }, 4));
}

// --- t_crc16_equivalence ---------------------------------------------------------------

static void t_crc16_equivalence(const uint8_t *zones, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        const uint8_t *z = zones + i * ATECC608_CONFIG_ZONE_LEN;
        uint8_t crc_le[2];
        uint16_t ref;

        atCRC(ATECC608_CONFIG_ZONE_LEN, z, crc_le);
        ref = (uint16_t)(crc_le[0] | ((uint16_t)crc_le[1] << 8));
        CHECK(atecc608_config_crc16(z) == ref);
    }
}

static void t_crc16(void)
{
    printf("t_crc16\n");
    atecc608_config_intent_t cfg;
    uint8_t zones[4 * ATECC608_CONFIG_ZONE_LEN];
    size_t n = 0;

    // Default build.
    atecc608_config_default(&cfg);
    CHECK(ATECC608_OK == atecc608_config_build(&cfg, &zones[n++ * ATECC608_CONFIG_ZONE_LEN]));

    // Golden build.
    fill_golden_config(&cfg);
    CHECK(ATECC608_OK == atecc608_config_build(&cfg, &zones[n++ * ATECC608_CONFIG_ZONE_LEN]));

    // A non-buildable pattern (all 0xA5).
    memset(&zones[n * ATECC608_CONFIG_ZONE_LEN], 0xA5u, ATECC608_CONFIG_ZONE_LEN);
    n++;

    // The locked test vector.
    memcpy(&zones[n * ATECC608_CONFIG_ZONE_LEN], s_vector, ATECC608_CONFIG_ZONE_LEN);
    n++;

    t_crc16_equivalence(zones, n);
}

// --- t_writable_equal -------------------------------------------------------------------

static void t_writable_equal(void)
{
    printf("t_writable_equal\n");
    atecc608_config_intent_t cfg;
    uint8_t a[ATECC608_CONFIG_ZONE_LEN];
    uint8_t b[ATECC608_CONFIG_ZONE_LEN];
    uint32_t diff[4];

    fill_golden_config(&cfg);
    CHECK(ATECC608_OK == atecc608_config_build(&cfg, a));
    memcpy(b, a, sizeof(a));

    // Identical.
    CHECK(atecc608_config_writable_equal(a, b, diff));
    CHECK(0u == diff[0] && 0u == diff[1] && 0u == diff[2] && 0u == diff[3]);

    // A difference in the writable region: reported, with the diff bit set.
    // Diff words cover 32-byte chunks: byte 100 is word 3, bit 4.
    b[100] ^= 0x01u;  // KeyConfig[2] low byte
    CHECK(!atecc608_config_writable_equal(a, b, diff));
    CHECK(0u == diff[0]);
    CHECK(0u == diff[1]);
    CHECK(0u == diff[2]);
    CHECK((1u << (100 % 32)) == diff[3]);

    // Factory-region and lock-byte differences are ignored.
    memcpy(b, a, sizeof(a));
    b[5] ^= 0xFFu;    // factory serial byte
    b[15] ^= 0xFFu;
    b[86] ^= 0xFFu;   // LockValue
    b[87] ^= 0xFFu;   // LockConfig
    CHECK(atecc608_config_writable_equal(a, b, diff));

    // Byte 16 (I2C address) is in the writable region and IS compared.
    memcpy(b, a, sizeof(a));
    b[16] ^= 0x01u;
    CHECK(!atecc608_config_writable_equal(a, b, diff));
    CHECK((1u << (16 % 32)) == diff[0]);
}

// --- t_rejections ------------------------------------------------------------------------

// Each case: start from a valid (default) intent, break exactly one rule.
static void break_rule(atecc608_config_intent_t *c, int rule)
{
    switch (rule) {
    case 0:  c->key[1].key_type = 5u; break;  // RFU key type
    case 1:  c->key[1].private_key = true;
             c->key[1].key_type = ATECC608_KEY_TYPE_NON_ECC; break;
    case 2:  c->key[1].private_key = true; break;  // slot not secret
    case 3:  c->key[1].private_key = true;
             c->slot[1].is_secret = true;
             c->slot[1].read_key = 1u; break;
    case 4:  c->slot[1].enc_read = true; break;
    case 5:  c->slot[1].write_config = 1u; break;
    case 6:  c->key[1].req_auth = true; break;  // auth_key 0
    case 7:  c->key[1].auth_key = 1u; break;  // no req_auth
    case 8:  c->key[1].x509_id = 1u; break;  // NON_ECC slot
    case 9:  c->key[1].private_key = true;
             c->slot[1].is_secret = true;
             c->key[1].x509_id = 1u; break;
    case 10: c->counter[1].value = ATECC608_COUNTER_MAX + 1u; break;
    case 11: c->sb_mode = 1u; break;  // reserved
    case 12: c->sb_mode = ATECC608_SB_MODE_FULL_COPY; break;  // no pubkey slot
    case 13: c->sb_mode = ATECC608_SB_MODE_FULL_STORE;
             c->sb_pubkey_slot = 3u; break;  // no digest slot
    case 14: c->count_match_en = true; break;  // key 0
    case 15: c->use_lock_en = true; break;  // key 0
    case 16: c->io_prot_en = true; break;  // key 0
    case 17: c->ecdh_prot = 2u; break;
    case 18: c->user_extra_add = 0xC5u; break;  // odd
    case 19: c->clk_div = 32u; break;
    default: c->slot[1].read_key = 16u; break;
    }
}

static const char *const s_rule_names[] = {
    "key_type RFU",
    "private non-ECC",
    "private without is_secret",
    "private with normal-slot field",
    "enc_read without is_secret",
    "write_config without is_secret",
    "req_auth with auth_key 0",
    "auth_key without req_auth",
    "x509_id on non-ECC slot",
    "x509_id on private slot",
    "counter above max",
    "sb_mode reserved",
    "sb without pubkey slot",
    "sb full-store without digest slot",
    "count_match without key",
    "use_lock without key",
    "io_prot without key",
    "ecdh_prot out of range",
    "user_extra_add odd",
    "clk_div out of range",
    "read_key out of range",
};

static void t_rejections(void)
{
    printf("t_rejections\n");
    uint8_t z[ATECC608_CONFIG_ZONE_LEN];

    // NULL arguments.
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_config_build(NULL, z));
    {
        atecc608_config_intent_t cfg;
        CHECK(ATECC608_ERR_BAD_PARAM == atecc608_config_build(&cfg, NULL));
        CHECK(ATECC608_ERR_BAD_PARAM == atecc608_config_parse(NULL, &cfg));
        CHECK(ATECC608_ERR_BAD_PARAM == atecc608_config_parse(z, NULL));
    }

    for (size_t i = 0; i < sizeof(s_rule_names) / sizeof(s_rule_names[0]); i++) {
        atecc608_config_intent_t cfg;

        atecc608_config_default(&cfg);
        break_rule(&cfg, (int)i);
        if (ATECC608_ERR_BAD_PARAM != atecc608_config_build(&cfg, z)) {
            printf("  expected rejection: %s\n", s_rule_names[i]);
        }
        CHECK(ATECC608_ERR_BAD_PARAM == atecc608_config_build(&cfg, z));
    }
}

// --- main --------------------------------------------------------------------------------

int main(void)
{
    t_default_build();
    t_golden();
    t_golden_roundtrip();
    t_counter_encoding();
    t_vector_decode();
    t_crc16();
    t_writable_equal();
    t_rejections();

    printf("%s: %d checks, %d failures\n",
           (s_failures == 0) ? "PASS" : "FAIL", s_checks, s_failures);
    return (s_failures == 0) ? 0 : 1;
}

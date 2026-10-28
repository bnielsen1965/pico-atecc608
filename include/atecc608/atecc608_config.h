// ATECC608 config-zone builder: field-level intent → 128-byte config zone
// image, plus decode, writable-region comparison, and the Lock-command
// summary CRC.
//
// This is pure logic: no HAL, no cryptoauthlib, no chip access. It compiles
// and is unit-tested on the host (tests/). The authoritative layout and bit
// positions are cryptoauthlib v3.8.0's `calib_device.h`
// (`atecc608_config_s`); the field *semantics* (what each value means)
// are the public ATECC508A/ATECC608 datasheet tables.
//
// Field encodings worth knowing before using the builder:
//
//  - 4-bit "key reference" fields (read_key, write_key, write_config,
//    auth_key, ...): 0 = no key required, 1..15 = the key slot number.
//    ATECC608_KEY_NONE is 0. For read_key, 0 additionally marks the slot
//    as a CheckMac/Copy source — the datasheet says "do not use zero as a
//    default".
//  - KeyConfig.key_type is a 3-bit field with only two legal values:
//    0b100 (ATECC608_KEY_TYPE_ECC, an ECC P-256 key) and 0b111
//    (ATECC608_KEY_TYPE_NON_ECC: AES / HMAC / secret / data). All other
//    values are RFU and rejected by atecc608_config_build().
//  - ECC private key slots use a *distinct* SlotConfig bit layout: bits
//    0-3 become EXT_SIG / INT_SIG / ECDH / ECDH-to-slot-N+1 instead of the
//    ReadKey nibble, bit 7 = IsSecret (mandatory), bit 13 = GenKey-
//    allowed, bit 14 = PrivWrite-allowed, and the key/usage bits of a
//    normal slot (read_key, write_key, write_config, no_mac,
//    limited_use, enc_read) are not used. The bit 13/14 positions come
//    from the ATECC508A/608A datasheet (Tables 2-10/2-11); they
//    deliberately deviate from cryptoauthlib's ATCA_SLOT_CONFIG_GEN_KEY_
//    SHIFT / PRIV_WRITE_SHIFT (8/9), which contradict the datasheet and
//    the library's own ATECC608 test vector (slot word 0x208F).
//  - The 8-byte counters hold the current value in the chip's dual
//    linear + binary encoding (verified against cryptoauthlib v3.8.0's
//    calib_write_config_counter and the ATECC608 datasheet; there is NO
//    per-counter limit field on the chip — the value simply caps at
//    ATECC608_COUNTER_MAX). For value v the 8 bytes (big-endian u16s) are:
//      [0:2] = 0xFFFF >> (v % 32)
//      [2:4] = v < 16 ? 0xFFFF : 0xFFFF >> ((v - 16) % 32)
//      [4:6] = v / 32
//      [6:8] = v < 16 ? 0      : (v - 16) / 32
//    The factory value FF FF FF FF 00 00 00 00 is v = 0 under this
//    encoding. The Counter command reports the value in plain binary
//    (4 bytes LE), which is what atecc608_counter_read() returns.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "atecc608/atecc608_types.h"

// --- field value constants --------------------------------------------------

// 4-bit key reference: no key required.
#define ATECC608_KEY_NONE   0u

// Legal KeyConfig.key_type values (3-bit field; others are RFU).
#define ATECC608_KEY_TYPE_ECC     4u  // 0b100 — ECC P-256 key
#define ATECC608_KEY_TYPE_NON_ECC 7u  // 0b111 — AES / HMAC / secret / data

// Legal SecureBoot modes (2-bit field; 1 is reserved).
#define ATECC608_SB_MODE_OFF        0u
#define ATECC608_SB_MODE_FULL_COPY  2u
#define ATECC608_SB_MODE_FULL_STORE 3u

// Maximum monotonic counter value (2^21 - 1). The chip has no separate
// per-counter limit; incrementing past this value fails on the chip.
#define ATECC608_COUNTER_MAX    0x1FFFFFu

// Lock byte values (config zone bytes 86-87):
// 0x55 = unlocked, 0x00 = locked (set by the chip on the Lock command).
#define ATECC608_CONFIG_UNLOCKED  0x55u
#define ATECC608_CONFIG_LOCKED    0x00u

// --- per-slot types ----------------------------------------------------------

// Access policy for one data slot (config zone bytes 20..51, 16 bits per
// slot, little-endian). The interpretation of bits 0-3, 8 and 9 depends on
// whether the slot holds an ECC private key (key[n].private_key): see the
// field comments.
typedef struct {
    // --- normal slots (no ECC private key) ---
    uint8_t read_key;      // 0..15; 0 = no key (also: CheckMac/Copy source)
    bool    no_mac;        // bit 4: key used for verify only (no MAC/HMAC)
    bool    limited_use;   // bit 5: key uses consume Counter 0
    bool    enc_read;      // bit 6: encrypted read via read_key (needs is_secret)
    bool    is_secret;     // bit 7: secret slot, no clear reads
    uint8_t write_key;     // 0..15; key that encrypts writes (0 = clear write)
    uint8_t write_config;  // 0..15; key required to write this slot at all

    // --- ECC private key slots only (ignored / must be clear otherwise) ---
    bool    ext_sig;       // bit 0: Sign on external (arbitrary) messages
    bool    int_sig;       // bit 1: Sign on internal GenKey/GenDig messages
    bool    ecdh;          // bit 2: ECDH allowed
    bool    ecdh_to_next;  // bit 3: ECDH master secret goes to slot n+1
    // GenKey/PrivWrite live at bits 13/14 per the ATECC508A/608A datasheet
    // (Tables 2-10/2-11). cryptoauthlib's ATCA_SLOT_CONFIG_GEN_KEY_SHIFT /
    // PRIV_WRITE_SHIFT (8/9) contradict the datasheet and the library's own
    // ATECC608 test vector; the datasheet wins.
    bool    gen_key;       // bit 13: GenKey may regenerate this slot
    bool    priv_write;    // bit 14: PrivWrite may write this slot
} atecc608_slot_cfg_t;

// One 8-byte monotonic counter (config zone bytes 52..59 / 60..67).
typedef struct {
    uint32_t value;  // initial value, 0..ATECC608_COUNTER_MAX (0 = factory)
} atecc608_counter_cfg_t;

// Per-slot key capabilities (config zone bytes 96..127, 16 bits per slot).
typedef struct {
    bool    private_key;  // bit 0: slot holds an ECC P-256 private key
    bool    pub_info;     // bit 1: public key derivable (priv) / usable to verify (pub)
    uint8_t key_type;     // ATECC608_KEY_TYPE_ECC or ATECC608_KEY_TYPE_NON_ECC
    bool    lockable;     // bit 5: slot can be locked individually later
    bool    req_random;   // bit 6: use requires a random nonce
    bool    req_auth;     // bit 7: use requires prior authorization (auth_key)
    uint8_t auth_key;     // 1..15 if req_auth; must be 0 otherwise
    bool    persist_dis;  // bit 12: persistent latch / intrusion disable
    uint8_t x509_id;      // 0..3; must be 0 unless the slot holds a public key
} atecc608_key_cfg_t;

// --- the full intent ----------------------------------------------------------

// The complete writable intent for the ATECC608 config zone.
//
// Not modeled (by design): the 16 factory bytes [0:16] (serial, revision,
// AES/I2C enable, I2C address — written at the factory; the Write command
// skips them) and the two lock bytes [86:88] (only the Lock command may
// change them). atecc608_config_build() emits zeros for the factory region
// and ATECC608_CONFIG_UNLOCKED for the lock bytes, mirroring an unlocked
// chip.
typedef struct {
    // Byte 18: CountMatch
    bool   count_match_en;      // bit 0
    uint8_t count_match_key;    // 4 bits, 1..15 when enabled

    // Byte 19: ChipMode
    bool   i2c_extra;           // bit 0: alternate I2C address via byte 85
    bool   ttl_en;              // bit 1: I/O levels referenced to VCC
    bool   wd_long;             // bit 2: 10 s watchdog (default 1.3 s)
    uint8_t clk_div;            // 5 bits, 0..31 (0 = fast)

    // Bytes 20..51
    atecc608_slot_cfg_t slot[ATECC608_MAX_DATA_SLOT + 1];

    // Bytes 52..59 / 60..67
    atecc608_counter_cfg_t counter[2];

    // Byte 68: UseLock (Lock command must be authorized by a key)
    bool   use_lock_en;
    uint8_t use_lock_key;       // 4 bits, 1..15 when enabled

    // Byte 69: VolatileKeyPermission (RAM-only key loading)
    bool   vol_key_perm_en;     // bit 7
    uint8_t vol_key_perm_slot;  // 4 bits, 0..15

    // Bytes 70..71: SecureBoot
    uint8_t sb_mode;            // ATECC608_SB_MODE_*
    bool    sb_persist;         // bit 3: persistent latch
    bool    sb_rand_nonce;      // bit 4: random nonce required
    uint8_t sb_digest_slot;     // 4 bits, 1..15 (0 = none)
    uint8_t sb_pubkey_slot;     // 4 bits, 1..15 (0 = none)

    // Bytes 72..74: KDF IV source (only has effect when ChipOptions
    // ecdh_prot/kdf_prot forces output encryption)
    uint8_t kdf_lv_loc;         // 4 bits, 0..15
    uint8_t kdf_lv_slot;        // 4 bits, 0..15 (low byte of the 2-byte field)

    // Byte 84: UserExtra (one-time writable via UpdateExtra)
    uint8_t user_extra;

    // Byte 85: UserExtraAdd — 8-bit I2C write address used instead of the
    // factory address when i2c_extra is set (0 = keep factory address).
    uint8_t user_extra_add;

    // Bytes 88..89: SlotLocked (bit n = slot n locked; informational — set
    // by the Lock command, not by writes)
    uint16_t slot_locked;

    // Bytes 90..91: ChipOptions
    bool   post_en;             // bit 0: power-on self test on wake
    bool   io_prot_en;          // bit 1: I/O protection key active
    bool   kdf_aes_en;          // bit 2: KDF AES mode enabled
    uint8_t ecdh_prot;          // 2 bits: 0 = clear ECDH output ok, 1 = encryption forced
    uint8_t kdf_prot;           // 2 bits: 0 = clear KDF output ok, 1 = encryption forced
    uint8_t io_prot_key;        // 4 bits, slot holding the I/O protection key

    // Bytes 92..95: X509format (per key group; 0 = ignored)
    uint8_t x509_format[4];

    // Bytes 96..127
    atecc608_key_cfg_t key[ATECC608_MAX_DATA_SLOT + 1];
} atecc608_config_intent_t;

// --- API -----------------------------------------------------------------------

// Initialize cfg to a safe, all-disabled intent: no keys, no secrets,
// non-ECC key type everywhere, counters at zero, everything else cleared.
void atecc608_config_default(atecc608_config_intent_t *cfg);

// Validate the intent and encode it into the 128-byte config zone image.
// Returns ATECC608_ERR_BAD_PARAM if any field is outside its legal range or
// contradicts another (e.g. enc_read without is_secret, an ECC private key
// slot without is_secret, RFU key_type). On success, zone[0:16] is zeroed
// (factory region) and zone[86:88] holds the unlocked sentinel.
atecc608_status_t atecc608_config_build(const atecc608_config_intent_t *cfg,
                                        uint8_t zone[ATECC608_CONFIG_ZONE_LEN]);

// Decode a 128-byte config zone image into the intent struct (inverse of
// build). The factory region and the lock bytes are ignored. Unlike build,
// parse is faithful rather than strict: it accepts raw 3-bit key_type
// values 0..7 (a build() of the decoded intent will still reject RFU
// values) and does not re-apply the cross-field rules.
atecc608_status_t atecc608_config_parse(const uint8_t zone[ATECC608_CONFIG_ZONE_LEN],
                                        atecc608_config_intent_t *cfg);

// Compare two zone images over the writable region only (bytes 16..85 and
// 88..127 — the factory region and lock bytes are excluded). Returns true
// if identical. If diff is non-NULL, diff[i] gets the bits of the differing
// bytes (bit n of diff[i] = byte i*32 + n differs).
bool atecc608_config_writable_equal(const uint8_t a[ATECC608_CONFIG_ZONE_LEN],
                                    const uint8_t b[ATECC608_CONFIG_ZONE_LEN],
                                    uint32_t diff[4]);

// CRC-16 over a full 128-byte zone image, using the chip's command CRC
// algorithm (poly 0x8005, initial 0x0000, MSB-first, no reflection). This is
// the summary CRC expected by the Lock command when the summary check is
// enabled: compute it over the zone exactly as read from the chip (lock
// bytes still 0x55).
uint16_t atecc608_config_crc16(const uint8_t zone[ATECC608_CONFIG_ZONE_LEN]);

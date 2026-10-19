// Shared "golden" config intent for the Phase 4A unit tests.
//
// A hand-computed provisioning intent that exercises the encoding of nearly
// every builder field: ECC private key slots, an authorized public key slot
// with an X509 id, secret/encrypted normal slots, key-protected writes, both
// monotonic counters, SecureBoot, KDF IV, the one-shot UserExtra bytes and
// ChipOptions.
//
// The byte-exact 128-byte image this intent must build to lives in
// test_config.c (t_golden); test_prov.c provisions it through the mock chip.

#pragma once

#include "atecc608/atecc608_config.h"

static void fill_golden_config(atecc608_config_intent_t *cfg)
{
    atecc608_config_default(cfg);

    // Byte 18: CountMatch enabled, key 5.
    cfg->count_match_en = true;
    cfg->count_match_key = 5;

    // Byte 19: TTL I/O levels, clock divider 2.
    cfg->ttl_en = true;
    cfg->clk_div = 2;

    // Slot 0: ECC private key (external signing, ECDH, GenKey, PrivWrite).
    cfg->key[0].private_key = true;
    cfg->key[0].pub_info = true;
    cfg->key[0].key_type = ATECC608_KEY_TYPE_ECC;
    cfg->key[0].lockable = true;
    cfg->slot[0].is_secret = true;
    cfg->slot[0].ext_sig = true;
    cfg->slot[0].ecdh = true;
    cfg->slot[0].gen_key = true;
    cfg->slot[0].priv_write = true;

    // Slot 1: public ECC key; use requires authorization by key 6; X509 3.
    cfg->key[1].pub_info = true;
    cfg->key[1].key_type = ATECC608_KEY_TYPE_ECC;
    cfg->key[1].req_auth = true;
    cfg->key[1].auth_key = 6;
    cfg->key[1].x509_id = 3;

    // Slot 2: ECC private key (ext + int signing, ECDH to slot 3).
    cfg->key[2].private_key = true;
    cfg->key[2].pub_info = true;
    cfg->key[2].key_type = ATECC608_KEY_TYPE_ECC;
    cfg->key[2].req_random = true;
    cfg->slot[2].is_secret = true;
    cfg->slot[2].ext_sig = true;
    cfg->slot[2].int_sig = true;
    cfg->slot[2].ecdh_to_next = true;
    cfg->slot[2].gen_key = true;

    // Slot 3: secret slot, encrypted read via key 3, verify-only key.
    cfg->slot[3].is_secret = true;
    cfg->slot[3].read_key = 3;
    cfg->slot[3].no_mac = true;
    cfg->slot[3].enc_read = true;

    // Slot 15: secret slot, writes encrypted with key 2, key-2 write gate.
    cfg->slot[15].is_secret = true;
    cfg->slot[15].write_key = 2;
    cfg->slot[15].write_config = 2;
    cfg->key[15].req_random = true;
    cfg->key[15].persist_dis = true;

    // Counters: 5 and 0.
    cfg->counter[0].value = 5u;
    cfg->counter[1].value = 0u;

    // Bytes 68/69.
    cfg->use_lock_en = true;
    cfg->use_lock_key = 8u;
    cfg->vol_key_perm_en = true;
    cfg->vol_key_perm_slot = 12u;

    // SecureBoot: full store, random nonce, digest in slot 7, key in slot 15.
    cfg->sb_mode = ATECC608_SB_MODE_FULL_STORE;
    cfg->sb_rand_nonce = true;
    cfg->sb_digest_slot = 7u;
    cfg->sb_pubkey_slot = 15u;

    // KDF IV: level location 2, slot 3.
    cfg->kdf_lv_loc = 2u;
    cfg->kdf_lv_slot = 3u;

    // One-shot extras (written via UpdateExtra, not the Write command).
    cfg->user_extra = 0xA5u;
    cfg->user_extra_add = 0xC4u;

    // Informational slot lock bitmap.
    cfg->slot_locked = 0x0005u;

    // ChipOptions.
    cfg->post_en = true;
    cfg->io_prot_en = true;
    cfg->kdf_aes_en = true;
    cfg->ecdh_prot = 1u;
    cfg->io_prot_key = 4u;

    // X509 format.
    cfg->x509_format[0] = 0x11u;
    cfg->x509_format[1] = 0x22u;
    cfg->x509_format[2] = 0x33u;
    cfg->x509_format[3] = 0x44u;
}

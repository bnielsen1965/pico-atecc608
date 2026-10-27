/*
 * test_vault_gcm.c - host known-answer tests for the vault example's
 * software AES-256-GCM (example/vault/vault_gcm.c).
 *
 * Vectors: the GCM-spec / NIST SP 800-38D AES-256 cases (the zero key and
 * the FEFF key), cross-checked with Python's `cryptography` (OpenSSL
 * backend) before being baked in. During development the GF(2^128)
 * multiply behind them was also cross-checked against a
 * carryless-polynomial reference on random inputs, and the AES core
 * against the FIPS-197 Appendix C.3 vector.
 */

#include <stdio.h>
#include <string.h>

#include "vault_gcm.h"

static int s_failures = 0;

static void check(bool ok, const char *what)
{
    printf("%s  %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        s_failures++;
    }
}

static void from_hex(const char *hex, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned v;
        (void)sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static bool to_hex_eq(const uint8_t *buf, size_t len, const char *hex)
{
    uint8_t ref[128];
    if (len > sizeof(ref)) {
        return false;
    }
    from_hex(hex, ref, len);
    return 0 == memcmp(buf, ref, len);
}

static const uint8_t k_zero[VAULT_GCM_KEY_LEN]   = { 0 };
static const uint8_t iv_zero[VAULT_GCM_NONCE_LEN] = { 0 };

int main(void)
{
    // --- NIST / GCM-spec known answers (AES-256) ---------------------------

    // 1. K=0^256, IV=0^96, empty PT, no AAD: tag only.
    {
        uint8_t tag[VAULT_GCM_TAG_LEN];
        bool ok = vault_gcm_encrypt(k_zero, iv_zero, NULL, 0, NULL, 0, NULL, 0, tag);
        check(ok, "1: encrypt empty (sizes)");
        check(to_hex_eq(tag, 16, "530f8afbc74536b9a963b4f1c4cb738b"), "1: empty-PT tag");
    }

    // 2. K=0^256, IV=0^96, PT = 16 zero bytes.
    {
        uint8_t pt[16] = { 0 }, ct[16], tag[VAULT_GCM_TAG_LEN];
        bool ok = vault_gcm_encrypt(k_zero, iv_zero, NULL, 0, pt, 16, ct, 16, tag);
        check(ok, "2: encrypt 16 B (sizes)");
        check(to_hex_eq(ct, 16, "cea7403d4d606b6e074ec5d3baf39d18"), "2: 16 B ciphertext");
        check(to_hex_eq(tag, 16, "d0d1c8a799996bf0265b98b5d48ab919"), "2: 16 B tag");
    }

    // 3. K=0^256, IV=0^96, PT = 32 zero bytes.
    {
        uint8_t pt[32] = { 0 }, ct[32], tag[VAULT_GCM_TAG_LEN];
        bool ok = vault_gcm_encrypt(k_zero, iv_zero, NULL, 0, pt, 32, ct, 32, tag);
        check(ok &&
              to_hex_eq(ct, 32, "cea7403d4d606b6e074ec5d3baf39d18"
                              "726003ca37a62a74d1a2f58e7506358e") &&
              to_hex_eq(tag, 16, "d1d3084c99aa8a9fdabb3e83eb28c15d"),
              "3: 32 B ciphertext + tag");
    }

    // 4..10. FEFF key, IV cafe..., 64 B PT, with and without 20 B AAD, plus
    // the negative paths.
    {
        uint8_t key[VAULT_GCM_KEY_LEN], iv[VAULT_GCM_NONCE_LEN];
        uint8_t pt[64], ct[64], tag[VAULT_GCM_TAG_LEN];
        from_hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", key, 32);
        from_hex("cafebabefacedbaddecaf888", iv, 12);
        from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                 "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", pt, 64);

        check(vault_gcm_encrypt(key, iv, NULL, 0, pt, 64, ct, 64, tag) &&
              to_hex_eq(ct, 64,
                        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad") &&
              to_hex_eq(tag, 16, "b094dac5d93471bdec1a502270e3cc6c"),
              "4: 64 B ciphertext + tag (no AAD)");

        uint8_t aad[20];
        from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, 20);
        check(vault_gcm_encrypt(key, iv, aad, 20, pt, 64, ct, 64, tag) &&
              to_hex_eq(tag, 16, "2df7cd675b4f09163b41ebf980a7f638"),
              "5: 64 B + 20 B AAD tag");

        // 6. decrypt round-trip (correct key, AAD bound).
        uint8_t pt_out[64];
        check(vault_gcm_decrypt(key, iv, aad, 20, ct, 64, tag, pt_out, 64)
              && (0 == memcmp(pt_out, pt, 64)),
              "6: decrypt round-trip (with AAD)");

        // 7. corrupted tag -> fail, pt untouched.
        memset(pt_out, 0xAA, sizeof(pt_out));
        uint8_t bad_tag[VAULT_GCM_TAG_LEN];
        memcpy(bad_tag, tag, 16);
        bad_tag[0] ^= 0x01;
        check(!vault_gcm_decrypt(key, iv, aad, 20, ct, 64, bad_tag, pt_out, 64)
              && (0xAA == pt_out[0]) && (0xAA == pt_out[63]),
              "7: corrupt tag rejected, pt untouched");

        // 8. wrong key -> fail.
        uint8_t wrong_key[VAULT_GCM_KEY_LEN];
        memcpy(wrong_key, key, 32);
        wrong_key[31] ^= 0x01;
        check(!vault_gcm_decrypt(wrong_key, iv, aad, 20, ct, 64, tag, pt_out, 64),
              "8: wrong key rejected");

        // 9. tampered ciphertext -> fail.
        uint8_t bad_ct[64];
        memcpy(bad_ct, ct, 64);
        bad_ct[5] ^= 0x80;
        check(!vault_gcm_decrypt(key, iv, aad, 20, bad_ct, 64, tag, pt_out, 64),
              "9: tampered ciphertext rejected");

        // 10. tampered AAD -> fail (the name binding).
        uint8_t bad_aad[20];
        memcpy(bad_aad, aad, 20);
        bad_aad[0] ^= 0x01;
        check(!vault_gcm_decrypt(key, iv, bad_aad, 20, ct, 64, tag, pt_out, 64),
              "10: tampered AAD rejected");
    }

    // 11. non-multiple-of-16 length (33 B) round-trip with an arbitrary key
    //     and a partial AAD block: covers the partial-block GHASH path.
    {
        uint8_t key[VAULT_GCM_KEY_LEN], iv[VAULT_GCM_NONCE_LEN];
        uint8_t pt[33], ct[33], tag[VAULT_GCM_TAG_LEN], pt_out[33];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0xA5 ^ i);
        for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(0x5A ^ (3 * i));
        for (int i = 0; i < 33; i++) pt[i] = (uint8_t)(i * 7);

        check(vault_gcm_encrypt(key, iv, (const uint8_t *)"some-name", 9,
                                pt, 33, ct, 33, tag),
              "11: encrypt 33 B (sizes)");
        check(vault_gcm_decrypt(key, iv, (const uint8_t *)"some-name", 9,
                                ct, 33, tag, pt_out, 33)
              && (0 == memcmp(pt_out, pt, 33)),
              "11: 33 B round-trip");

        // 12. undersized output buffer -> fail.
        check(!vault_gcm_encrypt(key, iv, NULL, 0, pt, 33, ct, 32, tag),
              "12: undersized ct buffer rejected");
    }

    printf("%s: %s\n", s_failures ? "FAIL" : "PASS",
           s_failures ? "some vault GCM checks failed" : "all vault GCM checks passed");
    return s_failures ? 1 : 0;
}

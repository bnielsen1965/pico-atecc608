// Host unit tests for the ATECC608 crypto pass-through API (Phase 5: KDF
// PRF; Phase 0 of the FIDO2 example: Sign / Verify over an external
// digest), driven through the real cryptoauthlib atcab_*/calib layers
// against the mock chip (tests/mock_chip.c) — no Pico, no physical
// device.
//
// The mock's KDF is a fake, deterministic PRF (documented in mock_chip.c:
// out[i] = key[i%32] ^ nonce[i%32] ^ msg[i%msg_len] ^ i). The tests check
// the module's plumbing — TempKey nonce loading, parameter encoding,
// response parsing, and the enforced I/O-protection decrypt path — by
// comparing against values computed with the same formula, plus the
// mock's I/O-protection model (kdf_prot=1, as bench-verified on the real
// chip).
//
// The mock's Sign is a fake, deterministic signature (sig[i] =
// priv[i%32] ^ digest[i%32] ^ i/32) and its Verify recomputes it — no
// P-256 math (the mock's house style; the real-curve cross-check happens
// on the bench, where openssl verifies a chip signature). The tests
// check the plumbing: the digest load into the Message Digest Buffer
// (Nonce pass-through), the Sign mode/key_id encoding, the 64-byte
// signature parsing, the chip gates (private key slot, EXT_SIG bit, key
// present), and the verify-failure path (the chip's 0x01 error frame
// coming back as ATECC608_OK with is_verified=false).

#include <stdio.h>
#include <string.h>

#include "atecc608/atecc608_crypto.h"
#include "atecc608/atecc608_prov.h"
#include "cryptoauthlib.h"
#include "mock_chip.h"

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

// --- shared state -----------------------------------------------------------------

static mock_chip_t s_chip;
static ATCAIfaceCfg s_cfg;

static bool s_confirm = true;

static bool confirm_hook(const char *prompt, void *ctx)
{
    (void)prompt;
    (void)ctx;
    return s_confirm;
}

// The mock's fake PRF (see mock_chip.c): the expected derived value for
// (slot key, nonce, message).
static void fake_prf(const uint8_t key[32], const uint8_t nonce[32],
                     const uint8_t *msg, uint8_t msg_len, uint8_t out[32])
{
    for (int i = 0; i < 32; i++) {
        out[i] = (uint8_t)(key[i] ^ nonce[i] ^ msg[i % msg_len] ^ (uint8_t)i);
    }
}

// The key provision_locked() writes to slot 7.
#define KDF_TEST_KEY_SLOT 7u
static const uint8_t kdf_test_key[32] = {
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
};

// Fresh factory chip + initialized atcab layer (mirrors test_prov.c).
static void setup(void)
{
    mock_chip_reset(&s_chip);
    s_confirm = true;

    s_cfg = (ATCAIfaceCfg) {
        .iface_type = ATCA_I2C_IFACE,
        .devtype    = ATECC608,
        .atcai2c    = { .address = 0xC0, .bus = 0, .baud = 400000 },
        .wake_delay = 1500,
        .rx_retries = 20,
        .cfg_data   = &s_chip,
    };
    CHECK(ATCA_SUCCESS == atcab_release());
    CHECK(ATCA_SUCCESS == atcab_init(&s_cfg));
}

// Provision (safe defaults — every slot a non-ECC key slot) + lock the
// config zone + write the test key to slot 7 + lock the data zone: the
// state a KDF with target=output needs (the data-zone gate, bench
// verified).
static void provision_locked(void)
{
    atecc608_config_intent_t cfg;

    atecc608_config_default(&cfg);
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));
    CHECK(ATECC608_OK == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));
    CHECK(ATCA_SUCCESS == atcab_write_zone(ATCA_ZONE_DATA, KDF_TEST_KEY_SLOT, 0, 0,
                                           kdf_test_key, ATECC608_DATA_SLOT_LEN));
    CHECK(ATECC608_OK == atecc608_lock_data_zone(confirm_hook, NULL));
}

// --- tests ---------------------------------------------------------------------------

static void t_kdf_gate(void)
{
    atecc608_config_intent_t cfg;
    uint8_t msg[16];
    uint8_t out[ATECC608_KDF_OUT_LEN];

    printf("t_kdf_gate\n");
    setup();
    for (int i = 0; i < 16; i++) {
        msg[i] = (uint8_t)i;
    }

    // A KDF with target=output is refused while the data zone is
    // UNLOCKED (bench-verified: ATCA_EXECUTION_ERROR, "clear KDF failed:
    // -12" on 2026-10-24) — even with the config zone locked.
    atecc608_config_default(&cfg);
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));
    CHECK(ATECC608_OK == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));
    CHECK(ATECC608_ERR_EXEC ==
          atecc608_kdf_prf(KDF_TEST_KEY_SLOT, NULL, msg, sizeof(msg), NULL, out));

    // After the data-zone lock the same call succeeds.
    CHECK(ATECC608_OK == atecc608_lock_data_zone(confirm_hook, NULL));
    CHECK(ATECC608_OK ==
          atecc608_kdf_prf(KDF_TEST_KEY_SLOT, NULL, msg, sizeof(msg), NULL, out));
}

static void t_kdf_basic(void)
{
    static const uint8_t zero_nonce[ATECC608_KDF_NONCE_LEN] = { 0 };
    uint8_t nonce[ATECC608_KDF_NONCE_LEN];
    uint8_t msg[16];
    uint8_t out[ATECC608_KDF_OUT_LEN];
    uint8_t ref[ATECC608_KDF_OUT_LEN];

    printf("t_kdf_basic\n");
    setup();
    provision_locked();
    for (int i = 0; i < 16; i++) {
        msg[i] = (uint8_t)(0xA0u + i);
    }

    // NULL nonce = a fixed zero TempKey: the output is deterministic and
    // matches the PRF formula.
    CHECK(ATECC608_OK ==
          atecc608_kdf_prf(KDF_TEST_KEY_SLOT, NULL, msg, sizeof(msg), NULL, out));
    fake_prf(kdf_test_key, zero_nonce, msg, sizeof(msg), ref);
    CHECK(0 == memcmp(out, ref, sizeof(out)));
    uint8_t out0[ATECC608_KDF_OUT_LEN];
    memcpy(out0, out, sizeof(out0));

    // Re-run with the same inputs: identical (the vault's requirement —
    // the derived key must re-derive on every unlock).
    CHECK(ATECC608_OK ==
          atecc608_kdf_prf(KDF_TEST_KEY_SLOT, NULL, msg, sizeof(msg), NULL, out));
    CHECK(0 == memcmp(out, ref, sizeof(out)));
    CHECK(0 == memcmp(out, out0, sizeof(out)));

    // An explicit nonce changes the PRF input: different output, still
    // matching the formula.
    for (int i = 0; i < ATECC608_KDF_NONCE_LEN; i++) {
        nonce[i] = (uint8_t)(0x40u + i);
    }
    CHECK(ATECC608_OK ==
          atecc608_kdf_prf(KDF_TEST_KEY_SLOT, nonce, msg, sizeof(msg), NULL, out));
    fake_prf(kdf_test_key, nonce, msg, sizeof(msg), ref);
    CHECK(0 == memcmp(out, ref, sizeof(out)));
    CHECK(0 != memcmp(out, out0, sizeof(out)));

    // A different message changes the output.
    uint8_t out2[ATECC608_KDF_OUT_LEN];
    msg[0] ^= 0x01u;
    CHECK(ATECC608_OK ==
          atecc608_kdf_prf(KDF_TEST_KEY_SLOT, nonce, msg, sizeof(msg), NULL, out2));
    CHECK(0 != memcmp(out, out2, sizeof(out)));
}

static void t_kdf_io_prot(void)
{
    static const uint8_t io_key[32] = {
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
        0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
        0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
    };
    static const uint8_t wrong_key[32] = {
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    static const uint8_t zero_nonce[ATECC608_KDF_NONCE_LEN] = { 0 };
    uint8_t msg[16];
    uint8_t out[ATECC608_KDF_OUT_LEN];
    uint8_t ref[ATECC608_KDF_OUT_LEN];

    printf("t_kdf_io_prot\n");
    setup();
    provision_locked();
    for (int i = 0; i < 16; i++) {
        msg[i] = (uint8_t)i;
    }
    fake_prf(kdf_test_key, zero_nonce, msg, sizeof(msg), ref);

    // Enforced I/O protection (kdf_prot=1, the provisioned chip's mode):
    // the response arrives encrypted with a nonce; the wrapper decrypts
    // it with the right key and hands back the clear derived value.
    mock_chip_set_kdf_io_prot(&s_chip, io_key);
    CHECK(ATECC608_OK ==
          atecc608_kdf_prf(KDF_TEST_KEY_SLOT, NULL, msg, sizeof(msg), io_key, out));
    CHECK(0 == memcmp(out, ref, sizeof(out)));

    // No I/O key: the encrypted output cannot be decrypted.
    CHECK(ATECC608_ERR_BAD_PARAM ==
          atecc608_kdf_prf(KDF_TEST_KEY_SLOT, NULL, msg, sizeof(msg), NULL, out));

    // Wrong I/O key: the decrypt "succeeds" but yields a different value
    // (accidental equality probability 2^-256).
    CHECK(ATECC608_OK ==
          atecc608_kdf_prf(KDF_TEST_KEY_SLOT, NULL, msg, sizeof(msg), wrong_key, out));
    CHECK(0 != memcmp(out, ref, sizeof(out)));

    // Without enforcement (opt-in / no I/O protection): the response
    // carries no nonce, the data is already clear, io_key unused.
    mock_chip_clear_kdf_io_prot(&s_chip);
    CHECK(ATECC608_OK ==
          atecc608_kdf_prf(KDF_TEST_KEY_SLOT, NULL, msg, sizeof(msg), NULL, out));
    CHECK(0 == memcmp(out, ref, sizeof(out)));
}

static void t_kdf_source_slot(void)
{
    uint8_t msg[16];
    uint8_t out[ATECC608_KDF_OUT_LEN];

    printf("t_kdf_source_slot\n");
    setup();
    provision_locked();
    for (int i = 0; i < 16; i++) {
        msg[i] = (uint8_t)(0x50u + i);
    }

    // A slot with no key in KeyConfig is refused by the chip.
    s_chip.config[96 + 2 * 15] = 0x00u;
    s_chip.config[96 + 2 * 15 + 1] = 0x00u;
    CHECK(ATECC608_ERR_EXEC ==
          atecc608_kdf_prf(15, NULL, msg, sizeof(msg), NULL, out));

    // A configured slot works.
    CHECK(ATECC608_OK ==
          atecc608_kdf_prf(KDF_TEST_KEY_SLOT, NULL, msg, sizeof(msg), NULL, out));
}

static void t_kdf_params(void)
{
    uint8_t msg[1];
    uint8_t out[ATECC608_KDF_OUT_LEN];

    printf("t_kdf_params\n");
    setup();
    msg[0] = 0u;

    // Bad parameters are refused before any chip command.
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_kdf_prf(7, NULL, NULL, 1, NULL, out));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_kdf_prf(7, NULL, msg, 0, NULL, out));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_kdf_prf(7, NULL, msg, 129, NULL, out));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_kdf_prf(7, NULL, msg, 1, NULL, NULL));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_kdf_prf(16, NULL, msg, 1, NULL, out));
}

// --- sign / verify (external digest, Phase 0) -------------------------------------------

// The mock's fake "private key" (see mock_chip.c): what GenKey
// "generates" into slot `slot`.
static void fake_priv(uint16_t slot, uint8_t priv[ATECC608_DATA_SLOT_LEN])
{
    for (int i = 0; i < ATECC608_DATA_SLOT_LEN; i++) {
        priv[i] = (uint8_t)((slot * 11u + (uint16_t)i * 5u + 2u) & 0xFFu);
    }
}

// The mock's fake ECDSA signature (see mock_chip.c): the expected
// signature for (private key, digest).
static void fake_sig(const uint8_t priv[ATECC608_DATA_SLOT_LEN],
                     const uint8_t digest[ATECC608_DIGEST_LEN],
                     uint8_t sig[ATECC608_SIG_LEN])
{
    for (int i = 0; i < ATECC608_SIG_LEN; i++) {
        sig[i] = (uint8_t)(priv[i % ATECC608_DATA_SLOT_LEN]
                           ^ digest[i % ATECC608_DATA_SLOT_LEN]
                           ^ (uint8_t)(i / ATECC608_DATA_SLOT_LEN));
    }
}

// The sign/verify test slots (as in the agreed config: ECC private,
// ext_sig, gen_key):
//   3 = fully provisioned (GenKey'd) — the happy path;
//   4 = fully provisioned (GenKey'd) — a second, different key;
//   5 = provisioned but WITHOUT the EXT_SIG bit — Sign must refuse;
//   6 = fully configured but NEVER GenKey'd — no key in the slot.
#define SIGN_TEST_SLOT_A 3u
#define SIGN_TEST_SLOT_B 4u
#define SIGN_TEST_SLOT_NO_EXT_SIG 5u
#define SIGN_TEST_SLOT_NO_KEY     6u

static void provision_sign_slots(void)
{
    atecc608_config_intent_t cfg;
    uint8_t pub[ATECC608_PUBKEY_LEN];

    atecc608_config_default(&cfg);
    for (uint8_t slot = 0; slot <= ATECC608_MAX_DATA_SLOT; slot++) {
        if (slot == SIGN_TEST_SLOT_A || slot == SIGN_TEST_SLOT_B
            || slot == SIGN_TEST_SLOT_NO_EXT_SIG || slot == SIGN_TEST_SLOT_NO_KEY) {
            cfg.key[slot].key_type    = ATECC608_KEY_TYPE_ECC;
            cfg.key[slot].private_key = true;
            cfg.key[slot].pub_info    = true;
            cfg.slot[slot].is_secret  = true;
            cfg.slot[slot].gen_key    = true;
            if (slot != SIGN_TEST_SLOT_NO_EXT_SIG) {
                cfg.slot[slot].ext_sig = true;
            }
        }
    }
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));
    CHECK(ATECC608_OK == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));
    // GenKey while the data zone is still unlocked, then lock it: the
    // state of a provisioned device (slot 6 is deliberately not GenKey'd).
    CHECK(ATECC608_OK == atecc608_genkey(SIGN_TEST_SLOT_A, pub));
    CHECK(ATECC608_OK == atecc608_genkey(SIGN_TEST_SLOT_B, pub));
    CHECK(ATECC608_OK == atecc608_genkey(SIGN_TEST_SLOT_NO_EXT_SIG, pub));
    CHECK(ATECC608_OK == atecc608_lock_data_zone(confirm_hook, NULL));
}

static void fill_digest(uint8_t digest[ATECC608_DIGEST_LEN], uint8_t seed)
{
    for (int i = 0; i < ATECC608_DIGEST_LEN; i++) {
        digest[i] = (uint8_t)(seed + (uint16_t)i);
    }
}

static void t_sign_basic(void)
{
    uint8_t digest[ATECC608_DIGEST_LEN];
    uint8_t sig[ATECC608_SIG_LEN];
    uint8_t expect[ATECC608_SIG_LEN];
    uint8_t priv[ATECC608_DATA_SLOT_LEN];

    printf("t_sign_basic\n");
    setup();
    provision_sign_slots();
    fill_digest(digest, 0xC0u);
    fake_priv(SIGN_TEST_SLOT_A, priv);

    // The signature matches the mock's formula — i.e. the wrapper's
    // parameter encoding (digest load into the Message Digest Buffer,
    // Sign external mode, slot number) and 64-byte response parsing are
    // right.
    CHECK(ATECC608_OK == atecc608_sign(SIGN_TEST_SLOT_A, digest, sig));
    fake_sig(priv, digest, expect);
    CHECK(0 == memcmp(sig, expect, sizeof(sig)));

    // Deterministic in the mock (real ECDSA would be randomized): same
    // inputs, same signature.
    uint8_t sig2[ATECC608_SIG_LEN];
    CHECK(ATECC608_OK == atecc608_sign(SIGN_TEST_SLOT_A, digest, sig2));
    CHECK(0 == memcmp(sig, sig2, sizeof(sig)));

    // A different digest gives a different signature.
    uint8_t digest2[ATECC608_DIGEST_LEN];
    memcpy(digest2, digest, sizeof(digest2));
    digest2[0] ^= 0x01u;
    CHECK(ATECC608_OK == atecc608_sign(SIGN_TEST_SLOT_A, digest2, sig2));
    CHECK(0 != memcmp(sig, sig2, sizeof(sig)));
}

static void t_verify_roundtrip(void)
{
    uint8_t digest[ATECC608_DIGEST_LEN];
    uint8_t sig[ATECC608_SIG_LEN];
    uint8_t priv[ATECC608_DATA_SLOT_LEN];
    bool ok;

    printf("t_verify_roundtrip\n");
    setup();
    provision_sign_slots();
    fill_digest(digest, 0x10u);

    // A genuine signature verifies.
    CHECK(ATECC608_OK == atecc608_sign(SIGN_TEST_SLOT_A, digest, sig));
    CHECK(ATECC608_OK == atecc608_verify(SIGN_TEST_SLOT_A, digest, sig, &ok));
    CHECK(ok);

    // A corrupted signature fails — and the command still "succeeds":
    // the chip reports the bad signature with its 0x01 error frame,
    // which the library normalizes to ATECC608_OK with ok=false.
    sig[5] ^= 0x40u;
    CHECK(ATECC608_OK == atecc608_verify(SIGN_TEST_SLOT_A, digest, sig, &ok));
    CHECK(!ok);

    // A wrong digest fails.
    CHECK(ATECC608_OK == atecc608_sign(SIGN_TEST_SLOT_A, digest, sig));
    digest[31] ^= 0x01u;
    CHECK(ATECC608_OK == atecc608_verify(SIGN_TEST_SLOT_A, digest, sig, &ok));
    CHECK(!ok);

    // A signature from slot 3 does not verify against slot 4's key
    // (different keys in different slots, as on a real chip).
    digest[31] ^= 0x01u; // restore
    CHECK(ATECC608_OK == atecc608_sign(SIGN_TEST_SLOT_A, digest, sig));
    CHECK(ATECC608_OK == atecc608_verify(SIGN_TEST_SLOT_B, digest, sig, &ok));
    CHECK(!ok);

    // The EXT_SIG bit gates SIGN only: slot 5 cannot sign, but a
    // signature under its own key verifies (checked against the mock's
    // formula, since the API cannot produce one).
    memset(sig, 0, sizeof(sig));
    CHECK(ATECC608_ERR_EXEC == atecc608_sign(SIGN_TEST_SLOT_NO_EXT_SIG, digest, sig));
    {
        bool untouched = true;
        for (int i = 0; i < ATECC608_SIG_LEN; i++) {
            untouched = untouched && (0u == sig[i]);
        }
        CHECK(untouched); // a refused sign leaves the buffer unwritten
    }
    fake_priv(SIGN_TEST_SLOT_NO_EXT_SIG, priv);
    fake_sig(priv, digest, sig);
    CHECK(ATECC608_OK == atecc608_verify(SIGN_TEST_SLOT_NO_EXT_SIG, digest, sig, &ok));
    CHECK(ok);
}

static void t_sign_gates(void)
{
    uint8_t digest[ATECC608_DIGEST_LEN];
    uint8_t sig[ATECC608_SIG_LEN];
    bool ok;

    printf("t_sign_gates\n");
    setup();
    provision_sign_slots();
    fill_digest(digest, 0x55u);

    // Never GenKey'd (slot 6): no key in the slot to sign or verify
    // with.
    CHECK(ATECC608_ERR_EXEC == atecc608_sign(SIGN_TEST_SLOT_NO_KEY, digest, sig));
    CHECK(ATECC608_ERR_EXEC == atecc608_verify(SIGN_TEST_SLOT_NO_KEY, digest, sig, &ok));

    // Not a key slot at all (slot 7: a normal non-ECC slot in the
    // default config).
    CHECK(ATECC608_ERR_EXEC == atecc608_sign(7, digest, sig));
    CHECK(ATECC608_ERR_EXEC == atecc608_verify(7, digest, sig, &ok));
}

static void t_sign_verify_params(void)
{
    uint8_t digest[ATECC608_DIGEST_LEN];
    uint8_t sig[ATECC608_SIG_LEN];
    bool ok = true;

    printf("t_sign_verify_params\n");
    setup();
    memset(digest, 0, sizeof(digest));
    memset(sig, 0, sizeof(sig));

    // Bad parameters are refused before any chip command.
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_sign(3, NULL, sig));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_sign(3, digest, NULL));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_sign(16, digest, sig));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_verify(3, NULL, sig, &ok));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_verify(3, digest, NULL, &ok));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_verify(3, digest, sig, NULL));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_verify(16, digest, sig, &ok));
}

// --- main ------------------------------------------------------------------------------

int main(void)
{
    t_kdf_gate();
    t_kdf_basic();
    t_kdf_io_prot();
    t_kdf_source_slot();
    t_kdf_params();
    t_sign_basic();
    t_verify_roundtrip();
    t_sign_gates();
    t_sign_verify_params();

    printf("%s: %d checks, %d failures\n",
           (s_failures == 0) ? "PASS" : "FAIL", s_checks, s_failures);
    return (s_failures == 0) ? 0 : 1;
}

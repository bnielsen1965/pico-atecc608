/*
 * vault_gcm.c - AES-256-GCM for the vault example (see vault_gcm.h).
 *
 * Pure C, no pico-sdk / cryptoauthlib dependency: compiles identically on
 * the host (tests/test_vault_gcm) and on the RP2350.
 *
 * Correctness:
 *   - AES-256 block encryption: FIPS-197 Appendix C.3 vector (key
 *     000102...1f, block 00112233...ff).
 *   - GCM: the GCM-spec / NIST SP 800-38D AES-256 cases, cross-checked
 *     with Python's `cryptography` (OpenSSL) before being baked into
 *     tests/test_vault_gcm.c. The GF(2^128) multiply behind them was
 *     additionally cross-checked against a carryless-polynomial reference
 *     on random inputs during development.
 */

#include "vault_gcm.h"

#include <string.h>

// --- AES-256 (forward only: GCM needs E_K, never the inverse) --------------

// S-box: GF(2^8) multiplicative inverse + affine transform (FIPS-197
// 5.1.1). Generated and verified in Python (see the test header) before
// hardcoding.
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// Rcon (first byte only) for key expansion rounds 1..14.
static const uint8_t rcon[14] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d
};

static const uint8_t zeros16[16] = { 0 };

// Round keys: 15 x 16 bytes for AES-256 (14 rounds, Nk = 8).
typedef struct {
    uint8_t rk[15][16];
} aes256_ctx_t;

// Multiply by 2 in GF(2^8) (xtime, FIPS-197 5.1.1).
static uint8_t xtime(uint8_t a)
{
    // Sign trick: the TESTED bit must be the sign bit of the int operand —
    // (a >> 7) is 0 or 1, so -(int) is 0 or -1 (0x00 or 0xFF all-ones).
    // Testing (a & 0x80) instead gives 0 or 128, and (uint8_t)(-128) is
    // 0x80, NOT 0xFF (the 0x1B reduction would then never apply).
    uint8_t m = (uint8_t)(-(int)(a >> 7));
    return (uint8_t)((a << 1) ^ (0x1b & m));
}

static void aes256_init(aes256_ctx_t *ctx, const uint8_t key[VAULT_GCM_KEY_LEN])
{
    uint8_t *w = &ctx->rk[0][0];
    memcpy(w, key, 32);
    for (int i = 8; i < 60; i++) {
        uint8_t t[4] = { w[(i - 1) * 4 + 0], w[(i - 1) * 4 + 1],
                         w[(i - 1) * 4 + 2], w[(i - 1) * 4 + 3] };
        if (0 == (i % 8)) {
            // RotWord + SubWord + Rcon
            uint8_t r = t[0];
            t[0] = (uint8_t)(sbox[t[1]] ^ rcon[i / 8 - 1]);
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[r];
        } else if (4 == (i % 8)) {
            t[0] = sbox[t[0]];
            t[1] = sbox[t[1]];
            t[2] = sbox[t[2]];
            t[3] = sbox[t[3]];
        }
        for (int j = 0; j < 4; j++) {
            w[i * 4 + j] = (uint8_t)(w[(i - 8) * 4 + j] ^ t[j]);
        }
    }
}

// Encrypt one block. The state is held column-major in memory (AES's
// input layout), so the input bytes land in s[i] unchanged.
static void aes256_block(const aes256_ctx_t *ctx, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    for (int i = 0; i < 16; i++) {
        s[i] = (uint8_t)(in[i] ^ ctx->rk[0][i]);
    }
    for (int round = 1; round <= 14; round++) {
        for (int i = 0; i < 16; i++) {
            s[i] = sbox[s[i]];
        }
        // ShiftRows
        uint8_t t;
        t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
        t = s[2];  s[2]  = s[10]; s[10] = t;
        t = s[6];  s[6]  = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = s[3];  s[3]  = t;
        if (round < 14) {
            // MixColumns
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
                s[4 * c + 0] = (uint8_t)(xtime(a0) ^ (uint8_t)(xtime(a1) ^ a1) ^ a2 ^ a3);
                s[4 * c + 1] = (uint8_t)(a0 ^ xtime(a1) ^ (uint8_t)(xtime(a2) ^ a2) ^ a3);
                s[4 * c + 2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (uint8_t)(xtime(a3) ^ a3));
                s[4 * c + 3] = (uint8_t)(xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3));
            }
        }
        for (int i = 0; i < 16; i++) {
            s[i] = (uint8_t)(s[i] ^ ctx->rk[round][i]);
        }
    }
    memcpy(out, s, 16);
}

// --- GCM --------------------------------------------------------------------

// GF(2^128) multiply, GCM right-shift convention (NIST SP 800-38D 8.2):
// bit k of a block (k = 0 is the leftmost bit) is the coefficient of x^k,
// reduced mod x^128 + x^7 + x^2 + x + 1 (0xE1 in the leftmost byte).
// Z = X*Y = sum_k x_k * (Y*x^k): X's bits are read directly from the
// original block while Y advances one *x (right shift with reduction) per
// step.
static void gf_mult(const uint8_t X[16], const uint8_t Y[16], uint8_t Z[16])
{
    uint8_t V[16];
    // Local copy: the caller may alias X and Z (ghash_update calls
    // gf_mult(X, H, X)), and the accumulation XORs into Z every iteration.
    uint8_t xb[16];
    memcpy(xb, X, 16);
    memcpy(V, Y, 16);
    memset(Z, 0, 16);
    for (int k = 0; k < 128; k++) {
        if ((xb[k >> 3] >> (7 - (k & 7))) & 1u) {
            for (int j = 0; j < 16; j++) {
                Z[j] ^= V[j];
            }
        }
        uint8_t lsb = V[15] & 1u;
        for (int j = 15; j > 0; j--) {
            V[j] = (uint8_t)((V[j] >> 1) | ((V[j - 1] & 1u) << 7));
        }
        V[0] >>= 1;
        if (lsb) {
            V[0] ^= 0xE1u;
        }
    }
}

// X = (X ^ block) * H
static void ghash_update(uint8_t X[16], const uint8_t block[16], const uint8_t H[16])
{
    for (int j = 0; j < 16; j++) {
        X[j] ^= block[j];
    }
    gf_mult(X, H, X);
}

// Big-endian 32-bit counter in the last four bytes of the counter block.
static void ctr_inc(uint8_t ctr[16])
{
    for (int j = 15; j >= 12; j--) {
        if (++ctr[j] != 0) {
            break;
        }
    }
}

// J0 = nonce || 0^31 || 1 (the nonce here is always 12 bytes).
static void gcm_j0(const uint8_t nonce[VAULT_GCM_NONCE_LEN], uint8_t J0[16])
{
    memcpy(J0, nonce, VAULT_GCM_NONCE_LEN);
    J0[12] = 0;
    J0[13] = 0;
    J0[14] = 0;
    J0[15] = 1;
}

// AES-CTR (GCM's keystream): out = in ^ E_K(J0+1) ^ E_K(J0+2) ^ ...
// (the keystream starts at counter 2; counter 1 / J0 is reserved for H).
static void ctr_xcrypt(const uint8_t key[VAULT_GCM_KEY_LEN],
                       const uint8_t nonce[VAULT_GCM_NONCE_LEN],
                       const uint8_t *in, size_t len,
                       uint8_t *out)
{
    aes256_ctx_t ctx;
    aes256_init(&ctx, key);

    uint8_t J0[16];
    gcm_j0(nonce, J0);

    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    ctr_inc(ctr);  // keystream starts at counter 2
    size_t off = 0;
    while (off < len) {
        size_t n = len - off;
        if (n > 16) {
            n = 16;
        }
        uint8_t ks[16];
        aes256_block(&ctx, ctr, ks);
        ctr_inc(ctr);
        for (size_t i = 0; i < n; i++) {
            out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
        }
        off += n;
    }
}

// GCM authentication tag: GHASH over the AAD blocks, then the CIPHERTEXT
// blocks (never the plaintext — GCM authenticates what is stored on the
// wire/flash), then the 128-bit length block; tag = GHASH ^ E_K(J0).
static void gcm_tag(const uint8_t key[VAULT_GCM_KEY_LEN],
                    const uint8_t nonce[VAULT_GCM_NONCE_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len,
                    uint8_t tag[VAULT_GCM_TAG_LEN])
{
    aes256_ctx_t ctx;
    aes256_init(&ctx, key);

    uint8_t H[16];
    aes256_block(&ctx, zeros16, H);

    uint8_t J0[16];
    gcm_j0(nonce, J0);

    uint8_t ekJ0[16];
    aes256_block(&ctx, J0, ekJ0);

    uint8_t X[16] = { 0 };
    uint8_t blk[16];

    // GHASH over the AAD (partial final block zero-padded).
    size_t off = 0;
    while (off < aad_len) {
        size_t n = aad_len - off;
        if (n > 16) {
            n = 16;
        }
        memset(blk, 0, sizeof(blk));
        memcpy(blk, aad + off, n);
        ghash_update(X, blk, H);
        off += n;
    }

    // GHASH over the raw ciphertext blocks (zero-padded final block).
    off = 0;
    while (off < ct_len) {
        size_t n = ct_len - off;
        if (n > 16) {
            n = 16;
        }
        memset(blk, 0, sizeof(blk));
        memcpy(blk, ct + off, n);
        ghash_update(X, blk, H);
        off += n;
    }

    // Length block: bit lengths, 64 bits each, big-endian.
    uint64_t a_bits = aad_len * 8u;
    uint64_t c_bits = ct_len * 8u;
    for (int i = 0; i < 8; i++) {
        blk[i]     = (uint8_t)(a_bits >> (56 - 8 * i));
        blk[8 + i] = (uint8_t)(c_bits >> (56 - 8 * i));
    }
    ghash_update(X, blk, H);

    for (int j = 0; j < VAULT_GCM_TAG_LEN; j++) {
        tag[j] = (uint8_t)(X[j] ^ ekJ0[j]);
    }
}

bool vault_gcm_encrypt(const uint8_t key[VAULT_GCM_KEY_LEN],
                       const uint8_t nonce[VAULT_GCM_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, size_t ct_cap,
                       uint8_t tag[VAULT_GCM_TAG_LEN])
{
    if (ct_cap < pt_len) {
        return false;
    }
    ctr_xcrypt(key, nonce, pt, pt_len, ct);
    gcm_tag(key, nonce, aad, aad_len, ct, pt_len, tag);
    return true;
}

bool vault_gcm_decrypt(const uint8_t key[VAULT_GCM_KEY_LEN],
                       const uint8_t nonce[VAULT_GCM_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t tag[VAULT_GCM_TAG_LEN],
                       uint8_t *pt, size_t pt_cap)
{
    if (pt_cap < ct_len) {
        return false;
    }
    // Verify the tag BEFORE releasing any plaintext: a wrong PIN derives a
    // wrong key, so this tag check is what makes `get` fail. The tag is
    // computed over the RAW stored ciphertext.
    uint8_t expect[VAULT_GCM_TAG_LEN];
    gcm_tag(key, nonce, aad, aad_len, ct, ct_len, expect);
    uint8_t diff = 0;
    for (int j = 0; j < VAULT_GCM_TAG_LEN; j++) {
        diff |= (uint8_t)(tag[j] ^ expect[j]);
    }
    if (0 != diff) {
        return false;  // pt untouched
    }
    ctr_xcrypt(key, nonce, ct, ct_len, pt);
    return true;
}

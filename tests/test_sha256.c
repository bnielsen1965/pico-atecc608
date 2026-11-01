// Host unit tests for the fido2 example's SHA-256
// (example/fido2/fido_sha256.c) — pure C, no Pico.
//
// Covers the FIPS 180-4 known-answer vectors (including the
// million-'a' vector) and the split-update paths (block boundaries and
// the padding boundary), which the CTAP layer exercises (the
// attestation digest is fed as authData ‖ clientDataHash in two
// updates).

#include <stdio.h>
#include <string.h>

#include "fido_sha256.h"

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

// "e3b0c4..." -> 32 bytes; returns the byte count (must be 32).
static int from_hex(const char *hex, uint8_t *out)
{
    int n = 0;
    while (hex[0] && hex[1]) {
        int hi = (hex[0] <= '9') ? hex[0] - '0' : hex[0] - 'a' + 10;
        int lo = (hex[1] <= '9') ? hex[1] - '0' : hex[1] - 'a' + 10;
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

static void check_digest(const char *name, const uint8_t *in, uint32_t len,
                         const char *want_hex)
{
    uint8_t got[FIDO_SHA256_DIGEST_LEN];
    uint8_t want[64];
    fido_sha256(in, len, got);
    if (32 != from_hex(want_hex, want)) {
        printf("  FAIL %s: bad vector\n", name);
        s_checks++;
        s_failures++;
        return;
    }
    if (0 != memcmp(got, want, 32)) {
        s_checks++;
        s_failures++;
        printf("  FAIL %s: digest mismatch\n", name);
    } else {
        s_checks++;
    }
}

// --- FIPS 180-4 vectors -----------------------------------------------------------

static void t_kats(void)
{
    // SHA-256 of the empty string.
    check_digest("empty", (const uint8_t *)"", 0,
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    // SHA-256("abc").
    check_digest("abc", (const uint8_t *)"abc", 3,
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // The two-block vector.
    static const char two_block[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    check_digest("two-block", (const uint8_t *)two_block,
                 (uint32_t)strlen(two_block),
                 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

// The million-'a' vector (the standard long-input KAT).
static void t_million_a(void)
{
    enum { N = 1000000 };
    static uint8_t in[N];
    memset(in, 'a', sizeof in);
    check_digest("million-a", in, N,
                 "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

// --- split updates -------------------------------------------------------------

// Feeding the input in arbitrary splits must give the one-shot digest —
// the update() buffer-boundary arithmetic.
static void t_split(void)
{
    static const char msg[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    enum { N = (int)sizeof msg - 1 };
    static const char want_hex[] =
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

    // (a) the exact pattern the CTAP layer uses: two updates.
    {
        fido_sha256_ctx_t c;
        uint8_t got[FIDO_SHA256_DIGEST_LEN];
        fido_sha256_init(&c);
        fido_sha256_update(&c, (const uint8_t *)msg, N / 2);
        fido_sha256_update(&c, (const uint8_t *)msg + (N / 2), N - N / 2);
        fido_sha256_final(&c, got);
        uint8_t want[64];
        from_hex(want_hex, want);
        CHECK(0 == memcmp(got, want, 32));
    }

    // (b) one byte at a time (every update fills the block partially).
    {
        fido_sha256_ctx_t c;
        uint8_t got[FIDO_SHA256_DIGEST_LEN];
        fido_sha256_init(&c);
        for (int i = 0; i < N; i++) {
            fido_sha256_update(&c, (const uint8_t *)msg + i, 1);
        }
        fido_sha256_final(&c, got);
        uint8_t want[64];
        from_hex(want_hex, want);
        CHECK(0 == memcmp(got, want, 32));
    }

    // (c) block boundary: a 64-byte input fed as 63 + 1 (the pad byte
    // lands exactly on the block edge).
    {
        uint8_t in64[64];
        for (int i = 0; i < 64; i++) in64[i] = (uint8_t)i;

        uint8_t one[FIDO_SHA256_DIGEST_LEN];
        fido_sha256(in64, 64, one);

        fido_sha256_ctx_t c;
        uint8_t got[FIDO_SHA256_DIGEST_LEN];
        fido_sha256_init(&c);
        fido_sha256_update(&c, in64, 63);
        fido_sha256_update(&c, &in64[63], 1);
        fido_sha256_final(&c, got);
        CHECK(0 == memcmp(got, one, 32));
    }

    // (d) padding boundary: 55 + 9 (the 0x80 pad byte and the length
    // field end up in different blocks).
    {
        uint8_t in64[64];
        for (int i = 0; i < 64; i++) in64[i] = (uint8_t)(0xA0 + i);

        uint8_t one[FIDO_SHA256_DIGEST_LEN];
        fido_sha256(in64, 64, one);

        fido_sha256_ctx_t c;
        uint8_t got[FIDO_SHA256_DIGEST_LEN];
        fido_sha256_init(&c);
        fido_sha256_update(&c, in64, 55);
        fido_sha256_update(&c, &in64[55], 9);
        fido_sha256_final(&c, got);
        CHECK(0 == memcmp(got, one, 32));
    }

    // (e) a zero-length update is a no-op.
    {
        fido_sha256_ctx_t c;
        uint8_t got[FIDO_SHA256_DIGEST_LEN];
        fido_sha256_init(&c);
        fido_sha256_update(&c, (const uint8_t *)"abc", 0);
        fido_sha256_update(&c, (const uint8_t *)"abc", 3);
        fido_sha256_update(&c, (const uint8_t *)"abc", 0);
        fido_sha256_final(&c, got);
        uint8_t want[64];
        from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                 want);
        CHECK(0 == memcmp(got, want, 32));
    }
}

int main(void)
{
    t_kats();
    t_million_a();
    t_split();

    printf("%s: %d checks, %d failures\n",
           (s_failures == 0) ? "PASS" : "FAIL", s_checks, s_failures);
    return (s_failures == 0) ? 0 : 1;
}

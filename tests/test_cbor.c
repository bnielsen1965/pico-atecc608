// Host unit tests for the fido2 example's minimal CBOR codec
// (example/fido2/fido_cbor.c) — pure C, no Pico.
//
// Covers: RFC 8949 §3 known-answer vectors for every width of integer,
// byte string, text string, array and map encoding; the CTAP2
// canonical-form rules (integers/lengths as short as possible — the
// decoder REJECTS non-canonical widths); definite-length-only (indefinite
// forms rejected); tags rejected by item() but walkable by skip();
// booleans; decode round-trips of nested structures; skip() over
// hostile nesting (including past the 32-deep safety rail); and the
// encoder's sticky-overflow behavior on a too-small buffer.

#include <stdio.h>
#include <string.h>

#include "fido_cbor.h"

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

// --- encoder: integers (RFC 8949 §3) ---------------------------------------------

static void t_uint(void)
{
    struct { uint64_t v; const uint8_t *exp; size_t len; } vecs[] = {
        { 0,                 (const uint8_t[]){ 0x00 }, 1 },
        { 5,                 (const uint8_t[]){ 0x05 }, 1 },
        { 10,                (const uint8_t[]){ 0x0A }, 1 },
        { 18,                (const uint8_t[]){ 0x12 }, 1 },
        { 23,                (const uint8_t[]){ 0x17 }, 1 },
        { 24,                (const uint8_t[]){ 0x18, 0x18 }, 2 },
        { 25,                (const uint8_t[]){ 0x18, 0x19 }, 2 },
        { 100,               (const uint8_t[]){ 0x18, 0x64 }, 2 },
        { 255,               (const uint8_t[]){ 0x18, 0xFF }, 2 },
        { 256,               (const uint8_t[]){ 0x19, 0x01, 0x00 }, 3 },
        { 1000,              (const uint8_t[]){ 0x19, 0x03, 0xE8 }, 3 },
        { 65535,             (const uint8_t[]){ 0x19, 0xFF, 0xFF }, 3 },
        { 65536,             (const uint8_t[]){ 0x1A, 0x00, 0x01, 0x00, 0x00 }, 5 },
        { 1000000,           (const uint8_t[]){ 0x1A, 0x00, 0x0F, 0x42, 0x40 }, 5 },
        { 4294967295u,       (const uint8_t[]){ 0x1A, 0xFF, 0xFF, 0xFF, 0xFF }, 5 },
        { 4294967296u,       (const uint8_t[]){ 0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }, 9 },
        { 1000000000000u,    (const uint8_t[]){ 0x1B, 0x00, 0x00, 0x00, 0xE8, 0xD4, 0xA5, 0x10, 0x00 }, 9 },
        { 18446744073709551615ULL,
                          (const uint8_t[]){ 0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, 9 },
    };
    for (size_t i = 0; i < sizeof vecs / sizeof vecs[0]; i++) {
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_uint(&e, vecs[i].v);
        CHECK(!e.overflow);
        CHECK(e.len == vecs[i].len);
        CHECK(0 == memcmp(out, vecs[i].exp, vecs[i].len));
    }
}

static void t_negint(void)
{
    struct { int64_t v; const uint8_t *exp; size_t len; } vecs[] = {
        { -1,    (const uint8_t[]){ 0x20 }, 1 },
        { -10,   (const uint8_t[]){ 0x29 }, 1 },
        { -100,  (const uint8_t[]){ 0x38, 0x63 }, 2 },
        { -1000, (const uint8_t[]){ 0x39, 0x03, 0xE7 }, 3 },
    };
    for (size_t i = 0; i < sizeof vecs / sizeof vecs[0]; i++) {
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_negint(&e, vecs[i].v);
        CHECK(!e.overflow);
        CHECK(e.len == vecs[i].len);
        CHECK(0 == memcmp(out, vecs[i].exp, vecs[i].len));
    }
}

static void t_bytes_text(void)
{
    {
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_bytes(&e, NULL, 0);
        CHECK(!e.overflow && e.len == 1 && out[0] == 0x40);
    }
    {   // b"foobar" — byte string (major 2)
        static const uint8_t foobar[6] = { 'f', 'o', 'o', 'b', 'a', 'r' };
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_bytes(&e, foobar, 6);
        const uint8_t exp[] = { 0x46, 'f', 'o', 'o', 'b', 'a', 'r' };
        CHECK(!e.overflow && e.len == 7 && 0 == memcmp(out, exp, 7));
    }
    {   // "Iét" — RFC 8949 vector, as text (major 3; UTF-8: 49 C3 A9 74)
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_text(&e, "I\xc3\xa9t");
        const uint8_t exp[] = { 0x64, 0x49, 0xC3, 0xA9, 0x74 };
        CHECK(!e.overflow && e.len == 5 && 0 == memcmp(out, exp, 5));
    }
    {   // the same bytes as a byte string (major 2)
        static const uint8_t iet[4] = { 0x49, 0xC3, 0xA9, 0x74 };
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_bytes(&e, iet, 4);
        const uint8_t exp[] = { 0x44, 0x49, 0xC3, 0xA9, 0x74 };
        CHECK(!e.overflow && e.len == 5 && 0 == memcmp(out, exp, 5));
    }
    {
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_text(&e, "a");
        CHECK(!e.overflow && e.len == 2 && out[0] == 0x61 && out[1] == 'a');
    }
    {
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_text(&e, NULL);
        CHECK(!e.overflow && e.len == 1 && out[0] == 0x60);
    }
}

static void t_array_map_bool(void)
{
    {
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_array(&e, 0);
        CHECK(!e.overflow && e.len == 1 && out[0] == 0x80);
    }
    {   // [1, 2, 3]
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_array(&e, 3);
        fido_cbor_enc_uint(&e, 1);
        fido_cbor_enc_uint(&e, 2);
        fido_cbor_enc_uint(&e, 3);
        const uint8_t exp[] = { 0x83, 0x01, 0x02, 0x03 };
        CHECK(!e.overflow && e.len == 4 && 0 == memcmp(out, exp, 4));
    }
    {   // [[], [[], [], []]]
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_array(&e, 2);
        fido_cbor_enc_array(&e, 0);
        fido_cbor_enc_array(&e, 3);
        fido_cbor_enc_array(&e, 0);
        fido_cbor_enc_array(&e, 0);
        fido_cbor_enc_array(&e, 0);
        const uint8_t exp[] = { 0x82, 0x80, 0x83, 0x80, 0x80, 0x80 };
        CHECK(!e.overflow && e.len == 6 && 0 == memcmp(out, exp, 6));
    }
    {
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_map(&e, 0);
        CHECK(!e.overflow && e.len == 1 && out[0] == 0xA0);
    }
    {   // {"a": 1}
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_map(&e, 1);
        fido_cbor_enc_text(&e, "a");
        fido_cbor_enc_uint(&e, 1);
        const uint8_t exp[] = { 0xA1, 0x61, 'a', 0x01 };
        CHECK(!e.overflow && e.len == 4 && 0 == memcmp(out, exp, 4));
    }
    {
        uint8_t out[32];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_bool(&e, true);
        fido_cbor_enc_bool(&e, false);
        CHECK(!e.overflow && e.len == 2 && out[0] == 0xF5 && out[1] == 0xF4);
    }
    {   // A GET_INFO-shaped map: mixed keys, a 16-byte string, a
        // nested options map, a negative integer — the exact mix the
        // CTAP layer emits, pinned as a byte KAT.
        uint8_t out[64];
        fido_cbor_enc_t e;
        fido_cbor_enc_init(&e, out, sizeof out);
        fido_cbor_enc_map(&e, 4);
        fido_cbor_enc_uint(&e, 1);
        fido_cbor_enc_array(&e, 1);
        fido_cbor_enc_uint(&e, 256);
        fido_cbor_enc_uint(&e, 3);
        {
            const uint8_t zero16[16] = { 0 };
            fido_cbor_enc_bytes(&e, zero16, 16);
        }
        fido_cbor_enc_uint(&e, 4);
        fido_cbor_enc_map(&e, 1);
        fido_cbor_enc_text(&e, "rk");
        fido_cbor_enc_bool(&e, true);
        fido_cbor_enc_uint(&e, 10);
        fido_cbor_enc_array(&e, 1);
        fido_cbor_enc_negint(&e, -7);
        const uint8_t exp[] = {
            0xA4,
            0x01, 0x81, 0x19, 0x01, 0x00,
            0x03, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x04, 0xA1, 0x62, 0x72, 0x6B, 0xF5,
            0x0A, 0x81, 0x26,
        };
        CHECK(!e.overflow && e.len == sizeof exp);
        CHECK(0 == memcmp(out, exp, sizeof exp));
    }
}

// --- decoder: round-trips -----------------------------------------------------------

static void t_roundtrip(void)
{
    // { 1: [10, "hello", h'AB', true], 2: { 3: [-5] } }
    uint8_t buf[64];
    fido_cbor_enc_t e;
    fido_cbor_enc_init(&e, buf, sizeof buf);
    fido_cbor_enc_map(&e, 2);
    fido_cbor_enc_uint(&e, 1);
    fido_cbor_enc_array(&e, 4);
    fido_cbor_enc_uint(&e, 10);
    fido_cbor_enc_text(&e, "hello");
    {
        const uint8_t ab[2] = { 0xAB, 0xCD };
        fido_cbor_enc_bytes(&e, ab, 2);
    }
    fido_cbor_enc_bool(&e, true);
    fido_cbor_enc_uint(&e, 2);
    fido_cbor_enc_map(&e, 1);
    fido_cbor_enc_uint(&e, 3);
    fido_cbor_enc_negint(&e, -5);
    CHECK(!e.overflow);

    fido_cbor_dec_t d;
    fido_cbor_type_t t;
    uint64_t         u;
    const uint8_t   *data = NULL;
    uint32_t         dlen = 0;

    fido_cbor_dec_init(&d, buf, e.len);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_MAP && u == 2);

    // pair 1
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 1);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_ARRAY && u == 4);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 10);
    CHECK(fido_cbor_dec_item(&d, &t, &u, &data, &dlen));
    CHECK(t == FIDO_CBOR_TEXT && dlen == 5 && 0 == memcmp(data, "hello", 5));
    CHECK(fido_cbor_dec_item(&d, &t, &u, &data, &dlen));
    CHECK(t == FIDO_CBOR_BYTES && dlen == 2 && data[0] == 0xAB && data[1] == 0xCD);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_BOOL && u == 1);

    // pair 2
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 2);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_MAP && u == 1);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_UINT && u == 3);
    CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
    CHECK(t == FIDO_CBOR_NEGINT && u == 4);   // -(4 + 1) = -5

    // exactly consumed
    CHECK(d.p == d.end);
}

// --- decoder: strictness ---------------------------------------------------------------

static void t_strict(void)
{
    fido_cbor_dec_t d;
    fido_cbor_type_t t;
    uint64_t         u;

#define FAIL_ITEM(bytes...) do { \
        const uint8_t in[] = { bytes }; \
        fido_cbor_dec_init(&d, in, sizeof in); \
        CHECK(!fido_cbor_dec_item(&d, &t, &u, NULL, NULL)); \
        CHECK(d.error); \
    } while (0)

    FAIL_ITEM(0x19, 0x03);                  // truncated u16 argument
    FAIL_ITEM(0x1B, 0x00, 0x00, 0x00);      // truncated u64 argument
    FAIL_ITEM(0x50, 0, 0, 0, 0);            // bytes(16) with 4 bytes
    FAIL_ITEM(0x9F);                        // indefinite-length array
    FAIL_ITEM(0x5F);                        // indefinite-length bytes
    FAIL_ITEM(0x7F);                        // indefinite-length text
    FAIL_ITEM(0x18, 0x05);                  // 5 encoded wide (non-canonical)
    FAIL_ITEM(0x19, 0x00, 0x18);            // 24 encoded wide (non-canonical)
    FAIL_ITEM(0x1A, 0x00, 0x00, 0x01, 0x00);// 256 encoded wide (non-canonical)
    FAIL_ITEM(0x38, 0x00);                  // -1 encoded wide (non-canonical)
    FAIL_ITEM(0xC0, 0x00);                  // tag — forbidden by CTAP2
    FAIL_ITEM(0xF6);                        // null — not exposed
    FAIL_ITEM(0xF7);                        // undefined — not exposed
    FAIL_ITEM(0xF9, 0x3C, 0x00);            // float16 — not exposed
    FAIL_ITEM();                            // empty input

#undef FAIL_ITEM

    {   // the error flag is sticky
        const uint8_t in[] = { 0x9F };
        fido_cbor_dec_init(&d, in, sizeof in);
        CHECK(!fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
        CHECK(d.error);
        CHECK(!fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
        CHECK(!fido_cbor_dec_skip(&d));
    }
    {   // a truncated NESTED item errors too
        const uint8_t in[] = { 0x82, 0x01, 0x52, 0x61 };  // [1, h'(claims 2, has 1)]
        fido_cbor_dec_init(&d, in, sizeof in);
        CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
        CHECK(t == FIDO_CBOR_ARRAY && u == 2);
        CHECK(fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
        CHECK(t == FIDO_CBOR_UINT && u == 1);
        CHECK(!fido_cbor_dec_item(&d, &t, &u, NULL, NULL));
        CHECK(d.error);
    }
}

// --- decoder: skip --------------------------------------------------------------------

static void t_skip(void)
{
    fido_cbor_dec_t d;

    {   // [ [1, 2.0, 3], 4, tag(0, 5) ] — one skip walks the whole array
        const uint8_t in[] = {
            0x83,
                0x83, 0x01, 0xF9, 0x3C, 0x00, 0x03,
                0x04,
                0xC0, 0x05,
        };
        fido_cbor_dec_init(&d, in, sizeof in);
        CHECK(fido_cbor_dec_skip(&d));
        CHECK(d.p == d.end);
    }
    {   // a map with a nested map and a float64
        const uint8_t in[] = {
            0xA2,
                0x61, 'a',
                    0xA1, 0x61, 'b', 0xFB, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                0x61, 'c', 0x07,
        };
        fido_cbor_dec_init(&d, in, sizeof in);
        CHECK(fido_cbor_dec_skip(&d));
        CHECK(d.p == d.end);
    }
    {   // null and simple values
        const uint8_t in[] = { 0xF6, 0xF8, 0x5A };
        fido_cbor_dec_init(&d, in, sizeof in);
        CHECK(fido_cbor_dec_skip(&d));
        CHECK(fido_cbor_dec_skip(&d));
        CHECK(d.p == d.end);
    }
    {   // nesting past the 32-deep rail: 33 open arrays + 1 uint
        uint8_t in[40];
        memset(in, 0x81, 33);
        in[33] = 0x00;
        fido_cbor_dec_init(&d, in, 34);
        CHECK(!fido_cbor_dec_skip(&d));
        CHECK(d.error);
    }
    {   // truncated nested skip: inner array declares 1 element, none present
        const uint8_t in[] = { 0x81, 0x81 };
        fido_cbor_dec_init(&d, in, sizeof in);
        CHECK(!fido_cbor_dec_skip(&d));
        CHECK(d.error);
    }
}

// --- encoder: overflow ------------------------------------------------------------------

static void t_overflow(void)
{
    uint8_t out[8];
    fido_cbor_enc_t e;

    {   // an item that only partly fits: the bytes that fit are
        // written, then overflow latches (the caller checks the flag
        // before using the buffer)
        fido_cbor_enc_init(&e, out, 2);
        fido_cbor_enc_uint(&e, 1000);   // needs 3 bytes
        CHECK(e.overflow);
        CHECK(e.len == 2);
    }
    {   // overflow mid-way is sticky: later calls are no-ops
        fido_cbor_enc_init(&e, out, 2);
        fido_cbor_enc_uint(&e, 5);      // fits
        CHECK(!e.overflow && e.len == 1);
        fido_cbor_enc_uint(&e, 1000);   // overflows on its 3rd byte
        CHECK(e.overflow);
        CHECK(e.len == 2);
        fido_cbor_enc_text(&e, "abc");  // no-op
        CHECK(e.len == 2);
        fido_cbor_enc_map(&e, 1);       // no-op
        CHECK(e.overflow && e.len == 2);
    }
    {   // a byte string whose header fits but payload does not
        static const uint8_t five[5] = { 1, 2, 3, 4, 5 };
        fido_cbor_enc_init(&e, out, 3);
        fido_cbor_enc_bytes(&e, five, 5);   // header (1) + 5 > 3
        CHECK(e.overflow);
        CHECK(e.len == 1);
    }
    {   // zero capacity
        fido_cbor_enc_init(&e, out, 0);
        fido_cbor_enc_uint(&e, 0);
        CHECK(e.overflow);
        CHECK(e.len == 0);
    }
    {   // NULL buffer
        fido_cbor_enc_init(&e, NULL, 0);
        fido_cbor_enc_uint(&e, 0);
        CHECK(e.overflow);
    }
}

int main(void)
{
    t_uint();
    t_negint();
    t_bytes_text();
    t_array_map_bool();
    t_roundtrip();
    t_strict();
    t_skip();
    t_overflow();

    printf("%s: %d checks, %d failures\n",
           (s_failures == 0) ? "PASS" : "FAIL", s_checks, s_failures);
    return (s_failures == 0) ? 0 : 1;
}

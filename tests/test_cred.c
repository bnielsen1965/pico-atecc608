// Host unit tests for the fido2 example's credential store
// (example/fido2/fido_cred.c) — pure C, no Pico.
//
// Covers the standard reflected CRC-32 (its published check value),
// record encode/decode round-trips, the rejection paths (a corrupted
// byte, every out-of-range field), the persist-first rule (a failed
// save/erase leaves the RAM store unchanged), and the store operations
// (alloc, load at boot, find by credential ID and by (rp, user),
// insert, erase).

#include <stdio.h>
#include <string.h>

#include "fido_cred.h"

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

// --- a valid record with known fields -------------------------------------------

static void rec_fill(fido_cred_record_t *rec, uint8_t slot)
{
    memset(rec, 0, sizeof *rec);
    rec->slot = slot;
    for (int i = 0; i < 32; i++) {
        rec->rp_id_hash[i] = (uint8_t)(0x40 + i);
    }
    rec->cred_id_len = 8;
    for (int i = 0; i < 8; i++) {
        rec->cred_id[i] = (uint8_t)(0x10 + i);
    }
    rec->user_handle_len = 4;
    for (int i = 0; i < 4; i++) {
        rec->user_handle[i] = (uint8_t)(0x60 + i);
    }
    memcpy(rec->name, "user", 4);
    rec->name_len = 4;
    memcpy(rec->display_name, "User", 4);
    rec->display_name_len = 4;
}

// --- persistence hooks ------------------------------------------------------------

static int s_save_calls  = 0;
static int s_save_fail   = 0;
static uint8_t s_last_slot = 0;
static int fake_save(void *priv, uint8_t slot, const fido_cred_record_t *rec)
{
    (void)priv;
    (void)rec;
    s_save_calls++;
    s_last_slot = slot;
    return s_save_fail ? -1 : 0;
}

static int s_erase_calls  = 0;
static int s_erase_fail   = 0;
static uint8_t s_last_erased = 0;
static int fake_erase(void *priv, uint8_t slot)
{
    (void)priv;
    s_erase_calls++;
    s_last_erased = slot;
    return s_erase_fail ? -1 : 0;
}

// --- tests --------------------------------------------------------------------------

// The published check value of CRC-32/ISO-HDLC (the reflected
// 0xEDB88320 polynomial with init/xorout 0xFFFFFFFF).
static void t_crc(void)
{
    CHECK(0xCBF43926u == fido_cred_crc32((const uint8_t *)"123456789", 9));
    CHECK(0x00000000u == fido_cred_crc32((const uint8_t *)"", 0));
}

// Encode then decode returns the same record, and the CRC in the image
// is over the preceding 232 bytes (big-endian).
static void t_roundtrip(void)
{
    fido_cred_record_t rec;
    rec_fill(&rec, 5);

    uint8_t img[FIDO_CRED_FILE_SIZE];
    fido_cred_record_encode(&rec, img);

    // The trailing 4 bytes are the CRC as a native-endian uint32 (the
    // vault's /io_key.bin convention): read them back as the struct
    // field and compare against a recomputation.
    fido_cred_record_t view;
    memcpy(&view, img, sizeof view);
    CHECK(view.crc32 == fido_cred_crc32(img, FIDO_CRED_FILE_SIZE - 4));

    fido_cred_record_t out;
    memset(&out, 0xAA, sizeof out);
    CHECK(fido_cred_record_decode(img, &out));
    // Everything but the CRC field, which is 0 in the source record and
    // computed in the decoded one.
    CHECK(0 == memcmp(&rec, &out, sizeof rec - 4));
}

// Any single corrupted byte (payload or CRC) is rejected, and the
// output is left zeroed.
static void t_corrupt(void)
{
    fido_cred_record_t rec;
    rec_fill(&rec, 3);
    uint8_t img[FIDO_CRED_FILE_SIZE];
    fido_cred_record_encode(&rec, img);

    for (size_t i = 0; i < FIDO_CRED_FILE_SIZE; i += 29) { // stride: payload + CRC
        fido_cred_record_t out;
        uint8_t bad[FIDO_CRED_FILE_SIZE];
        memcpy(bad, img, sizeof bad);
        bad[i] ^= 0x01;
        CHECK(!fido_cred_record_decode(bad, &out));
        CHECK(0 == out.slot && 0 == out.cred_id_len && 0 == out.crc32);
    }
}

// Every field limit, with a VALID CRC over the bad content: the range
// check must reject what the CRC cannot — and the boundaries are
// accepted.
static void t_range(void)
{
#define RANGE_CASE(label, mutate) do { \
        fido_cred_record_t rec; \
        rec_fill(&rec, 4); \
        mutate; \
        uint8_t img[FIDO_CRED_FILE_SIZE]; \
        fido_cred_record_encode(&rec, img); \
        fido_cred_record_t out; \
        CHECK(!fido_cred_record_decode(img, &out)); \
        printf("    %s rejected\n", label); \
    } while (0)

    RANGE_CASE("slot low",             rec.slot = 2);
    RANGE_CASE("slot high",            rec.slot = 7);
    RANGE_CASE("cred_id_len 0",        rec.cred_id_len = 0);
    RANGE_CASE("cred_id_len 65",       rec.cred_id_len = 65);
    RANGE_CASE("user_handle_len 65",   rec.user_handle_len = 65);
    RANGE_CASE("name_len 33",          rec.name_len = 33);
    RANGE_CASE("display_name_len 33",  rec.display_name_len = 33);

    // The boundaries themselves are accepted.
#define RANGE_EDGE(label, mutate) do { \
        fido_cred_record_t rec; \
        rec_fill(&rec, 3); \
        mutate; \
        uint8_t img[FIDO_CRED_FILE_SIZE]; \
        fido_cred_record_encode(&rec, img); \
        fido_cred_record_t out; \
        CHECK(fido_cred_record_decode(img, &out)); \
        printf("    %s accepted\n", label); \
    } while (0)

    RANGE_EDGE("cred_id_len 1",        rec.cred_id_len = 1);
    RANGE_EDGE("cred_id_len 64",       rec.cred_id_len = 64);
    RANGE_EDGE("user_handle_len 0",    rec.user_handle_len = 0);
    RANGE_EDGE("user_handle_len 64",   rec.user_handle_len = 64);
    RANGE_EDGE("name_len 32",          rec.name_len = 32);
    RANGE_EDGE("display_name_len 32",  rec.display_name_len = 32);

#undef RANGE_CASE
#undef RANGE_EDGE
}

// alloc() hands out 0, 1, 2, 3 and then -1.
static void t_alloc(void)
{
    fido_cred_store_t s;
    fido_cred_store_init(&s);
    CHECK(0 == fido_cred_store_alloc(&s));

    for (int i = 0; i < FIDO_CRED_MAX; i++) {
        fido_cred_record_t rec;
        rec_fill(&rec, (uint8_t)(i + FIDO_CRED_SLOT_MIN));
        CHECK(0 == fido_cred_store_insert(&s, i, &rec));
    }
    CHECK(-1 == fido_cred_store_alloc(&s));
}

// store_load: NULL / out-of-range / corrupt / out-of-range records are
// ignored; a valid record is installed.
static void t_load(void)
{
    fido_cred_store_t s;
    fido_cred_store_init(&s);

    fido_cred_record_t rec;
    rec_fill(&rec, FIDO_CRED_SLOT_MIN);

    fido_cred_store_load(&s, 0, NULL);
    CHECK(!s.present[0]);
    fido_cred_store_load(&s, -1, &rec);
    fido_cred_store_load(&s, FIDO_CRED_MAX, &rec);
    CHECK(!s.present[0] && !s.present[1]);

    // Bad CRC.
    fido_cred_record_t bad = rec;
    bad.crc32 = 0xDEADBEEFu;
    fido_cred_store_load(&s, 0, &bad);
    CHECK(!s.present[0]);

    // Out-of-range field (CRC valid).
    fido_cred_record_t oor = rec;
    oor.slot = 2;
    oor.crc32 = fido_cred_crc32((const uint8_t *)&oor, FIDO_CRED_FILE_SIZE - 4);
    fido_cred_store_load(&s, 0, &oor);
    CHECK(!s.present[0]);

    // Valid.
    rec.crc32 = fido_cred_crc32((const uint8_t *)&rec, FIDO_CRED_FILE_SIZE - 4);
    fido_cred_store_load(&s, 0, &rec);
    CHECK(s.present[0]);
    CHECK(0 == memcmp(&s.rec[0], &rec, sizeof rec));
}

// find_by_cred_id / find_by_user.
static void t_find(void)
{
    fido_cred_store_t s;
    fido_cred_store_init(&s);

    fido_cred_record_t a, b;
    rec_fill(&a, 3);
    rec_fill(&b, 4);
    b.cred_id[0] ^= 0xFF;
    CHECK(0 == fido_cred_store_insert(&s, 0, &a));
    CHECK(0 == fido_cred_store_insert(&s, 1, &b));

    uint8_t rp[32];
    memcpy(rp, a.rp_id_hash, 32);

    CHECK(0 == fido_cred_store_find_by_cred_id(&s, rp, a.cred_id, a.cred_id_len));
    CHECK(1 == fido_cred_store_find_by_cred_id(&s, rp, b.cred_id, b.cred_id_len));

    // A different RP hash never matches, even with the same credential ID.
    uint8_t other_rp[32];
    memcpy(other_rp, rp, sizeof other_rp);
    other_rp[0] ^= 0x01;
    CHECK(-1 == fido_cred_store_find_by_cred_id(&s, other_rp, a.cred_id, a.cred_id_len));

    // A different length never matches (no prefix matching).
    CHECK(-1 == fido_cred_store_find_by_cred_id(&s, rp, a.cred_id, a.cred_id_len - 1));
    CHECK(-1 == fido_cred_store_find_by_cred_id(&s, rp, a.cred_id, 0));
    CHECK(-1 == fido_cred_store_find_by_cred_id(&s, rp, a.cred_id,
                                                FIDO_CRED_CRED_ID_MAX + 1));

    CHECK(0 == fido_cred_store_find_by_user(&s, rp, a.user_handle, a.user_handle_len));
    // Same user, different RP: no match.
    CHECK(-1 == fido_cred_store_find_by_user(&s, other_rp, a.user_handle,
                                             a.user_handle_len));
    uint8_t other_user[4];
    memcpy(other_user, a.user_handle, 4);
    other_user[0] ^= 0x01;
    CHECK(-1 == fido_cred_store_find_by_user(&s, rp, other_user, 4));
    CHECK(-1 == fido_cred_store_find_by_user(&s, rp, a.user_handle,
                                             FIDO_CRED_USER_HANDLE_MAX + 1));
}

// insert(): range checks, persist-first, CRC computed on the way in.
static void t_insert(void)
{
    fido_cred_store_t s;
    fido_cred_store_init(&s);
    s.save = fake_save;

    fido_cred_record_t rec;
    rec_fill(&rec, FIDO_CRED_SLOT_MAX); // slot 6 — the hook must see 6
    rec.crc32 = 0;                      // insert() must compute the CRC

    CHECK(-1 == fido_cred_store_insert(&s, -1, &rec));
    CHECK(-1 == fido_cred_store_insert(&s, FIDO_CRED_MAX, &rec));
    CHECK(-1 == fido_cred_store_insert(&s, 0, NULL));

    fido_cred_record_t oor = rec;
    oor.slot = 2;
    CHECK(-1 == fido_cred_store_insert(&s, 0, &oor));
    CHECK(0 == s_save_calls); // nothing persisted for a rejected record

    CHECK(0 == fido_cred_store_insert(&s, 2, &rec));
    CHECK(1 == s_save_calls);
    CHECK(6 == s_last_slot);
    CHECK(s.present[2]);
    // The stored record carries a valid CRC even though the caller did
    // not compute one.
    CHECK(fido_cred_crc32((const uint8_t *)&s.rec[2],
                          FIDO_CRED_FILE_SIZE - 4) == s.rec[2].crc32);

    // Persist-first: a failed save leaves the store unchanged.
    s_save_fail = 1;
    fido_cred_record_t rec2;
    rec_fill(&rec2, 5);
    CHECK(-1 == fido_cred_store_insert(&s, 3, &rec2));
    CHECK(!s.present[3]);
    s_save_fail = 0;
}

// erase(): persist-first, only present indices.
static void t_erase(void)
{
    fido_cred_store_t s;
    fido_cred_store_init(&s);
    s.save  = fake_save;
    s.erase = fake_erase;

    fido_cred_record_t rec;
    rec_fill(&rec, 3);
    CHECK(0 == fido_cred_store_insert(&s, 0, &rec));

    CHECK(-1 == fido_cred_store_erase(&s, 1)); // no record there
    CHECK(-1 == fido_cred_store_erase(&s, -1));
    CHECK(-1 == fido_cred_store_erase(&s, FIDO_CRED_MAX));
    CHECK(0 == s_erase_calls);

    s_erase_fail = 1;
    CHECK(-1 == fido_cred_store_erase(&s, 0));
    CHECK(s.present[0]); // unchanged on a failed erase
    s_erase_fail = 0;

    CHECK(0 == fido_cred_store_erase(&s, 0));
    CHECK(!s.present[0]);
    CHECK(3 == s_last_erased);
    CHECK(0 == fido_cred_store_alloc(&s)); // slot handed out again
}

int main(void)
{
    t_crc();
    t_roundtrip();
    t_corrupt();
    t_range();
    t_alloc();
    t_load();
    t_find();
    t_insert();
    t_erase();

    printf("%s: %d checks, %d failures\n",
           (s_failures == 0) ? "PASS" : "FAIL", s_checks, s_failures);
    return (s_failures == 0) ? 0 : 1;
}

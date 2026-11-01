// fido_cred.c — the FIDO2 credential store (see fido_cred.h for the
// record layout and the persist-first rule).

#include "fido_cred.h"

#include <string.h>

// --- CRC-32 (standard reflected, as the vault's /io_key.bin) -------------

uint32_t fido_cred_crc32(const uint8_t *buf, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int)(crc & 1u)));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

// --- record (de)serialization ------------------------------------------------

// Every field within its committed range (the CRC is checked by the
// caller of decode / by insert; a freshly encoded record is assumed).
static bool record_valid(const fido_cred_record_t *rec)
{
    return (FIDO_CRED_SLOT_MIN <= rec->slot) && (rec->slot <= FIDO_CRED_SLOT_MAX) &&
           (1 <= rec->cred_id_len) && (rec->cred_id_len <= FIDO_CRED_CRED_ID_MAX) &&
           (rec->user_handle_len <= FIDO_CRED_USER_HANDLE_MAX) &&
           (rec->name_len <= FIDO_CRED_NAME_MAX) &&
           (rec->display_name_len <= FIDO_CRED_DISPLAY_NAME_MAX);
}

static bool crc_ok(const fido_cred_record_t *rec)
{
    return rec->crc32 == fido_cred_crc32((const uint8_t *)rec,
                                         FIDO_CRED_FILE_SIZE - 4);
}

void fido_cred_record_encode(const fido_cred_record_t *rec,
                             uint8_t img[FIDO_CRED_FILE_SIZE])
{
    // The CRC is a plain (native-endian) uint32 field, the vault's
    // /io_key.bin convention — the file is only ever read back into the
    // same struct on the same chip, so no byte-ordering is needed.
    fido_cred_record_t full = *rec;
    full.crc32 = fido_cred_crc32((const uint8_t *)&full,
                                 FIDO_CRED_FILE_SIZE - 4);
    memcpy(img, &full, FIDO_CRED_FILE_SIZE);
}

bool fido_cred_record_decode(const uint8_t img[FIDO_CRED_FILE_SIZE],
                             fido_cred_record_t *rec)
{
    memcpy(rec, img, FIDO_CRED_FILE_SIZE);
    if (!crc_ok(rec) || !record_valid(rec)) {
        memset(rec, 0, sizeof *rec);
        return false;
    }
    return true;
}

// --- store --------------------------------------------------------------------

void fido_cred_store_init(fido_cred_store_t *s)
{
    memset(s->rec, 0, sizeof s->rec);
    memset(s->present, 0, sizeof s->present);
    s->save  = NULL;
    s->erase = NULL;
    s->priv  = NULL;
}

void fido_cred_store_load(fido_cred_store_t *s, int idx,
                          const fido_cred_record_t *rec)
{
    if ((idx < 0) || (idx >= FIDO_CRED_MAX) || (NULL == rec)) {
        return;
    }
    if (!record_valid(rec) || !crc_ok(rec)) {
        return;   // corrupt image: the slot stays empty
    }
    s->rec[idx]    = *rec;
    s->present[idx] = true;
}

int fido_cred_store_alloc(const fido_cred_store_t *s)
{
    for (int i = 0; i < FIDO_CRED_MAX; i++) {
        if (!s->present[i]) {
            return i;
        }
    }
    return -1;
}

int fido_cred_store_find_by_cred_id(const fido_cred_store_t *s,
                                    const uint8_t rp_id_hash[32],
                                    const uint8_t *cred_id, uint8_t cred_id_len)
{
    if ((cred_id_len < 1) || (cred_id_len > FIDO_CRED_CRED_ID_MAX)) {
        return -1;
    }
    for (int i = 0; i < FIDO_CRED_MAX; i++) {
        if (s->present[i] &&
            0 == memcmp(s->rec[i].rp_id_hash, rp_id_hash, 32) &&
            s->rec[i].cred_id_len == cred_id_len &&
            0 == memcmp(s->rec[i].cred_id, cred_id, cred_id_len)) {
            return i;
        }
    }
    return -1;
}

int fido_cred_store_find_by_user(const fido_cred_store_t *s,
                                 const uint8_t rp_id_hash[32],
                                 const uint8_t *user_handle, uint8_t len)
{
    if (len > FIDO_CRED_USER_HANDLE_MAX) {
        return -1;
    }
    for (int i = 0; i < FIDO_CRED_MAX; i++) {
        if (s->present[i] &&
            0 == memcmp(s->rec[i].rp_id_hash, rp_id_hash, 32) &&
            s->rec[i].user_handle_len == len &&
            0 == memcmp(s->rec[i].user_handle, user_handle, len)) {
            return i;
        }
    }
    return -1;
}

int fido_cred_store_insert(fido_cred_store_t *s, int idx,
                           const fido_cred_record_t *rec)
{
    if ((idx < 0) || (idx >= FIDO_CRED_MAX) || (NULL == rec) ||
        !record_valid(rec)) {
        return -1;
    }
    // Persist first: a failed save leaves the RAM store unchanged.
    if (s->save && 0 != s->save(s->priv, rec->slot, rec)) {
        return -1;
    }
    fido_cred_record_t full = *rec;
    full.crc32 = fido_cred_crc32((const uint8_t *)&full,
                                 FIDO_CRED_FILE_SIZE - 4);
    s->rec[idx]     = full;
    s->present[idx] = true;
    return 0;
}

int fido_cred_store_erase(fido_cred_store_t *s, int idx)
{
    if ((idx < 0) || (idx >= FIDO_CRED_MAX) || !s->present[idx]) {
        return -1;
    }
    if (s->erase && 0 != s->erase(s->priv, s->rec[idx].slot)) {
        return -1;
    }
    memset(&s->rec[idx], 0, sizeof s->rec[idx]);
    s->present[idx] = false;
    return 0;
}

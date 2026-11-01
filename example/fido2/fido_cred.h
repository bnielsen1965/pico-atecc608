// fido_cred.h
//
// The FIDO2 credential store — the resident-credential database of the
// FIDO2 app: one fixed-size record per credential key slot (ATECC608
// slots 3-6; slot 1 is the device identity key), kept in RAM and
// persisted one record per littlefs file (/f2_<slot>) by the app
// (fido_hid.c). Pure C: the record format, its CRC-32, and the store
// operations are host-tested in tests/test_cred.c.
//
// A record is the littlefs file image itself: a 236-byte fixed layout
// (no padding — the struct is a byte-exact serialization), the last
// four bytes being a standard reflected CRC-32 over all the bytes
// before them (the vault's /io_key.bin convention).

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// The credential key slots of the ATECC608 (the provisioning genkey
// allowlist 1/3/4/5/6/12 minus slot 1 = device identity).
#define FIDO_CRED_SLOT_MIN   3
#define FIDO_CRED_SLOT_MAX   6
// Four records — also the GET_INFO remainingDiscoverableCredentials
// (FIDO_CTAP_MAX_CREDENTIALS must stay in sync).
#define FIDO_CRED_MAX        4

// Field limits (the WebAuthn entity sizes we commit to storing):
#define FIDO_CRED_CRED_ID_MAX      64   // credential ID
#define FIDO_CRED_USER_HANDLE_MAX  64   // user.id (the account ID)
#define FIDO_CRED_NAME_MAX         32   // user.name
#define FIDO_CRED_DISPLAY_NAME_MAX 32   // user.displayName

typedef struct {
    uint8_t  slot;                        // the chip key slot (3-6)
    uint8_t  rp_id_hash[32];              // SHA-256(rp.id) — the RP binding
    uint8_t  cred_id_len;
    uint8_t  cred_id[FIDO_CRED_CRED_ID_MAX];
    uint8_t  user_handle_len;
    uint8_t  user_handle[FIDO_CRED_USER_HANDLE_MAX];
    uint8_t  name_len;
    char     name[FIDO_CRED_NAME_MAX];
    uint8_t  display_name_len;
    char     display_name[FIDO_CRED_DISPLAY_NAME_MAX];
    uint32_t crc32;                       // over all preceding bytes
} fido_cred_record_t;

// The file size — the struct is padding-free, so the image IS the struct.
#define FIDO_CRED_FILE_SIZE (sizeof(fido_cred_record_t))
_Static_assert(sizeof(fido_cred_record_t) == 236,
               "credential record must stay a 236-byte fixed image");

// Encode a record into the file image (computes the CRC).
void fido_cred_record_encode(const fido_cred_record_t *rec,
                             uint8_t img[FIDO_CRED_FILE_SIZE]);
// Decode a file image into a record: true when well-formed (CRC valid and
// every field within range); *rec is untouched otherwise.
bool fido_cred_record_decode(const uint8_t img[FIDO_CRED_FILE_SIZE],
                             fido_cred_record_t *rec);

// Standard reflected CRC-32 (poly 0xEDB88320, init/xorout 0xFFFFFFFF) —
// the same as the vault's /io_key.bin.
uint32_t fido_cred_crc32(const uint8_t *buf, size_t len);

// The in-RAM store: one record per slot index (0 = slot 3 ... 3 = slot 6)
// plus optional persistence hooks the app installs (NULL in host tests =
// RAM-only). insert()/erase() persist FIRST: a failed persistence leaves
// the RAM store unchanged, so RAM and flash always agree.
typedef struct {
    fido_cred_record_t rec[FIDO_CRED_MAX];
    bool               present[FIDO_CRED_MAX];
    // Persist one record / drop one slot's file. 0 on success.
    int  (*save)(void *priv, uint8_t slot, const fido_cred_record_t *rec);
    int  (*erase)(void *priv, uint8_t slot);
    void *priv;
} fido_cred_store_t;

void fido_cred_store_init(fido_cred_store_t *s);

// Boot-load: install a (decoded) record at index idx WITHOUT touching the
// persistence hooks (the file already exists). A NULL or out-of-range
// record leaves the slot empty.
void fido_cred_store_load(fido_cred_store_t *s, int idx,
                          const fido_cred_record_t *rec);

// The first empty index (0..FIDO_CRED_MAX-1), or -1 when full.
int fido_cred_store_alloc(const fido_cred_store_t *s);

// The index of the record with this credential ID under this RP, or -1.
int fido_cred_store_find_by_cred_id(const fido_cred_store_t *s,
                                    const uint8_t rp_id_hash[32],
                                    const uint8_t *cred_id, uint8_t cred_id_len);
// The index of the record for (rp, user) — the rk-overwrite target, or -1.
int fido_cred_store_find_by_user(const fido_cred_store_t *s,
                                 const uint8_t rp_id_hash[32],
                                 const uint8_t *user_handle, uint8_t len);

// Install a record at index idx (validates range + CRC; persists first —
// a failed persistence returns -1 and leaves the store unchanged). -1 on
// a bad index or record.
int fido_cred_store_insert(fido_cred_store_t *s, int idx,
                           const fido_cred_record_t *rec);
// Remove the record at index idx (same persist-first rule). -1 when the
// index holds no record.
int fido_cred_store_erase(fido_cred_store_t *s, int idx);

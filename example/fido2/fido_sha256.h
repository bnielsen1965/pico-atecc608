// fido_sha256.h
//
// Pure-C SHA-256 (FIPS 180-4) — the digest the CTAP2 layer needs:
// rpIdHash = SHA-256(rp.id) and the packed-attestation signature over
// SHA-256(authData ‖ clientDataHash). No dependencies, host-tested
// against the FIPS 180-4 vectors in tests/test_sha256.c.

#pragma once

#include <stdint.h>

#define FIDO_SHA256_DIGEST_LEN 32

typedef struct {
    uint32_t state[8];
    uint64_t nbytes;      // total bytes fed to update()
    uint8_t  buf[64];
    uint32_t buflen;
} fido_sha256_ctx_t;

void fido_sha256_init(fido_sha256_ctx_t *c);
void fido_sha256_update(fido_sha256_ctx_t *c, const uint8_t *data, uint32_t len);
void fido_sha256_final(fido_sha256_ctx_t *c, uint8_t out[FIDO_SHA256_DIGEST_LEN]);

// One-shot: SHA-256 of data[0..len) into out.
void fido_sha256(const uint8_t *data, uint32_t len, uint8_t out[FIDO_SHA256_DIGEST_LEN]);

/*
 * vault_gcm.h - AES-256-GCM for the vault example.
 *
 * DEMO-ONLY software crypto: this pico-sdk fork (2.3.1) has no
 * hardware_crypto module and the ATECC608 performs no bulk encryption, so
 * the example carries a small, self-contained AES-256-GCM. Pure C (no
 * pico-sdk dependency), so it compiles and is verified identically on the
 * host (tests/test_vault_gcm.c, NIST GCM vectors) and on the RP2350. Not
 * side-channel hardened; not for production.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VAULT_GCM_KEY_LEN   32
#define VAULT_GCM_NONCE_LEN 12
#define VAULT_GCM_TAG_LEN   16

// Encrypt pt[0..pt_len) with AES-256-GCM under key/nonce, binding aad.
// Writes pt_len bytes to ct (which must hold at least pt_len bytes) and
// the 16-byte tag. Returns false if ct_cap < pt_len.
bool vault_gcm_encrypt(const uint8_t key[VAULT_GCM_KEY_LEN],
                       const uint8_t nonce[VAULT_GCM_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, size_t ct_cap,
                       uint8_t tag[VAULT_GCM_TAG_LEN]);

// Verify the tag (constant time) BEFORE decrypting; on failure returns
// false and pt is left untouched. On success writes ct_len bytes to pt
// (which must hold at least ct_len bytes) and returns true.
bool vault_gcm_decrypt(const uint8_t key[VAULT_GCM_KEY_LEN],
                       const uint8_t nonce[VAULT_GCM_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t tag[VAULT_GCM_TAG_LEN],
                       uint8_t *pt, size_t pt_cap);

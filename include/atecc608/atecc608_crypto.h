// ATECC608 crypto pass-through API (Phase 5).
//
// Curated wrappers over the chip's crypto commands, added as consumers
// need them (kdf today; sign/verify land with the FIDO2 example — see
// PLAN.md). Like the
// provisioning API (atecc608_prov.h), the implementation is HAL-agnostic
// (it only calls atcab_* / atcah_*), so it compiles in the host unit-test
// build and is exercised against the mock chip (tests/).
//
// I/O protection (bench-verified 2026-10-25): this chip runs with
// kdf_prot=1, which ENFORCES I/O protection on KDF — every target=output
// KDF returns its data ENCRYPTED, plus a 32-byte response nonce.
// atecc608_kdf_prf() detects the nonce and decrypts in place
// (atcah_io_decrypt) with the caller's I/O key, so the caller always
// receives the clear derived value; with a chip that does not enforce
// I/O protection the response carries no nonce, the data is already
// clear, and the key is unused.
//
// Data-zone gate (bench-verified 2026-10-24/25): the chip refuses a KDF
// with target=output (ATCA_EXECUTION_ERROR) while the data zone is
// UNLOCKED. The provisioned device's data zone is locked, so the gate
// never triggers there; the mock models it.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "atecc608/atecc608_types.h"

// KDF (PRF mode) geometry.
#define ATECC608_KDF_NONCE_LEN   32  // TempKey nonce, loaded before the KDF
#define ATECC608_KDF_OUT_LEN     32  // derived value (PRF target length 32)
#define ATECC608_KDF_MSG_MAX_LEN 128 // KDF input message, bytes

// Derive a 32-byte value with the chip's KDF command in PRF mode:
//
//   out = PRF( key   = the 32 bytes of data slot `slot`,
//              nonce = the 32-byte TempKey nonce,
//              data  = msg[0..msg_len) )
//
// The TempKey nonce is part of the PRF input: it is loaded into the chip's
// TempKey register (pass-through nonce load — the buffer's CONTENTS are
// stored) immediately before the KDF command. For a DETERMINISTIC output
// — which the password-store vault needs, because the derived key must
// re-derive identically on every unlock — the caller must supply a fixed
// nonce (pass NULL to load 32 bytes of zero); uniqueness then comes from
// msg (e.g. a per-vault salt || PIN || context). A random nonce per call
// would derive a different key every time.
//
// I/O protection: if the KDF response carries a 32-byte nonce (the chip
// enforces I/O protection on KDF), out arrives encrypted and is decrypted
// in place with io_key, which must then be non-NULL (else
// ATECC608_ERR_BAD_PARAM — the value cannot be recovered). If the
// response carries no nonce, out is already clear and io_key is unused
// (it may be NULL).
//
// Chip gates (surface as ATECC608_ERR_EXEC): a KDF with target=output is
// refused while the data zone is unlocked, and the source slot must be
// configured as a key slot in the (locked) config zone.
atecc608_status_t atecc608_kdf_prf(uint8_t slot,
                                   const uint8_t nonce[ATECC608_KDF_NONCE_LEN],
                                   const uint8_t *msg, uint8_t msg_len,
                                   const uint8_t io_key[ATECC608_DATA_SLOT_LEN],
                                   uint8_t out[ATECC608_KDF_OUT_LEN]);

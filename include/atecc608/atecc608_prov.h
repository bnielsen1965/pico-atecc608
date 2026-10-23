// ATECC608 guarded provisioning API (Phase 4A).
//
// These functions perform the chip writes that provision the device —
// config-zone write, zone/slot locks, key generation, counter increment.
// The guards follow the PLAN.md ground rules:
//
//   - nothing irreversible is issued without a read-back verification
//     (provision_config re-reads and byte-compares before it reports
//     success, and lock_config_zone re-verifies before locking);
//   - write and lock are separate calls (a failure in between leaves a
//     recoverable state);
//   - locks and counter increments go through a caller-supplied confirm
//     hook — the module has no UI, so the caller decides (e.g. by making
//     the user type an exact string);
//   - everything is idempotent / re-runnable while the zone is unlocked.
//
// Phase 4A implements and unit-tests these against a mock chip (tests/);
// they are never exercised on the physical chip without an explicit user
// go-ahead on the exact byte plan (Phase 4B).
//
// Notes / known limitations:
//   - atecc608_provision_config preserves the chip's I2C address byte
//     (byte 16), which the builder does not model; provisioning can
//     never change the device's bus address.
//   - atecc608_provision_config also preserves the chip's SlotLocked
//     bytes (88..89; the factory ships 0xFFFF), which the builder does
//     not model and the Lock command manages. The library's write path
//     covers these bytes but whether the chip honors the write is not
//     documented, so preserving the chip's value keeps the read-back
//     verify correct either way.
//   - Config bytes 84/85 (UserExtra / UserExtraAdd) are ONE-SHOT on the
//     chip: once non-zero they can never be changed again. The library's
//     atcab_write_config_zone() issues 13 Write commands followed by two
//     UpdateExtra commands, so if the chip already holds a different
//     non-zero UserExtra the call fails (ATECC608_ERR_EXEC) after the
//     config Writes have already been applied — the zone may then match
//     neither the old nor the new intent. Provision the same user_extra
//     value the chip already has (read it first).
//   - UseLock (byte 69): the mock does not model UseLock enforcement.
//     Keep use_lock_en=false in intents until an authentication flow
//     exists (Phase 4B verification item).
//   - Data-zone access through the library is atcab_read_zone()/
//     atcab_write_zone(): slots 0 and 3 (key slots) are rejected and the
//     length must be exactly 32 (16 for the config zone). Secret slots
//     cannot be read back in the clear.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "atecc608/atecc608_types.h"
#include "atecc608/atecc608_config.h"

// Caller-supplied gate for an irreversible operation. prompt is a short
// human-readable description of what is about to happen; ctx is the
// caller's opaque pointer. Return true to proceed, false to abort
// (ATECC608_ERR_CHIP_STATE is returned and nothing is written).
typedef bool (*atecc608_confirm_fn)(const char *prompt, void *ctx);

// Idempotently provision the config zone from an intent:
//   1. refuse if the config zone is already locked;
//   2. read the current zone;
//   3. build the intent image;
//   4. if the writable region already matches: stop (no writes at all);
//   5. otherwise write the zone, read it back, and byte-compare the
//      writable region again.
// Returns ATECC608_OK both when it had to write and when the chip already
// matched (idempotent).
atecc608_status_t atecc608_provision_config(const atecc608_config_intent_t *cfg);

// Lock the config zone. IRREVERSIBLE.
// Guard: re-read the zone, verify its writable region matches cfg, compute
// the summary CRC over the read-back bytes, and only if confirm() agrees
// issue the CRC-verified Lock (a corrupted or concurrently modified zone
// cannot be locked).
atecc608_status_t atecc608_lock_config_zone(const atecc608_config_intent_t *cfg,
                                            atecc608_confirm_fn confirm, void *ctx);

// Lock the data zone (all slots + OTP). IRREVERSIBLE.
// Guard: confirm() only — the data-zone summary CRC cannot be computed by
// the host (factory OTP contents are unknown and ECC private key slots are
// excluded from it), so the CRC-verified variant is not usable. The caller
// is responsible for having verified slot contents beforehand.
atecc608_status_t atecc608_lock_data_zone(atecc608_confirm_fn confirm, void *ctx);

// Lock a single data slot (IRREVERSIBLE for that slot). The slot must be
// marked KeyConfig.Lockable in the (locked) config zone. Guard: confirm().
atecc608_status_t atecc608_lock_data_slot(uint8_t slot,
                                          atecc608_confirm_fn confirm, void *ctx);

// Generate a new ECC P-256 key pair in a private key slot and return the
// 64-byte public key. The slot must be configured (KeyConfig.Private,
// KeyType ECC); while the data zone is unlocked a fresh key can be
// generated again, so this is re-runnable and is not confirm-gated.
atecc608_status_t atecc608_genkey(uint8_t slot, uint8_t pub[ATECC608_PUBKEY_LEN]);

// Write a 32-byte I/O protection key to a plain data slot (Phase 4B).
// Preconditions (ATECC608_ERR_CHIP_STATE, no write issued if violated):
// the config zone is LOCKED (the chip refuses any data-zone write while
// the config zone is unlocked — verified on the bench 2026-10-23; the
// approved 4B order is provision_config -> lock_config_zone ->
// write_iokey), the data zone is unlocked (our flow never locks it; the
// guard stays conservative), and the slot accepts a clear Write in the
// current config (not an ECC private key slot; write_key and
// write_config both 0 — the config zone is readable even when locked).
// The chip's OK response commits the write. A read-back verify is
// impossible on the ATECC608: data slots cannot be read while the data
// zone is unlocked (Microchip's own conformance test asserts this), and
// provisioning marks the I/O key slot is_secret. The key is verified
// functionally by an I/O-protected transaction. Note that I/O
// protection (io_prot_en) protects the I/O of the ECDH / KDF / Verify /
// SecureBoot commands, not the transport: the chip stays reachable with
// plain commands after the config zone lock, so write_iokey works there.
// Re-runnable (re-keys) while the data zone is unlocked.
atecc608_status_t atecc608_write_iokey(uint8_t slot,
                                       const uint8_t key[ATECC608_DATA_SLOT_LEN]);

// Read a monotonic counter (read-only; safe at any time).
atecc608_status_t atecc608_counter_read(uint8_t counter_id, uint32_t *value);

// Increment a monotonic counter. ONE WAY: counter values never decrease.
// Guard: confirm().
atecc608_status_t atecc608_counter_increment(uint8_t counter_id,
                                             uint32_t *new_value,
                                             atecc608_confirm_fn confirm, void *ctx);

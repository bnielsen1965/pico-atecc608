// fido_cbor.h
//
// Minimal CBOR codec for CTAP2 — the RFC 8949 definite-length subset the
// protocol actually uses, in the CTAP2 canonical form (CTAP v2.0 §6):
// integers and string/sequence lengths as short as possible, definite
// lengths only, no tags. Pure C, no dependencies — host-tested in
// tests/test_cbor.c.
//
// Scope: unsigned and negative integers, byte strings, text strings,
// arrays, maps, booleans. CTAP2 forbids tags (MUST NOT be present) and
// canonicalizes away indefinite lengths, so the decoder rejects both;
// the skip function additionally walks floats and other simple values
// so an unknown map entry can be stepped over without a per-type parser.
//
// Encoder: cursor-based into a fixed buffer. Overflow is sticky — after
// the first overflow every later call is a no-op, so a too-small buffer
// degrades to "the response could not be built" without a crash. Map key
// ORDERING is a CTAP2 requirement the caller owns (keys ascending).
//
// Decoder: a single-item iterator over a read-only input buffer.
// fido_cbor_dec_item() reports the next item in place — byte/text
// payloads point INTO the input (no copies) — and fido_cbor_dec_skip()
// drops any definite-length item. Truncated input, indefinite lengths,
// and non-canonical integer encodings are errors; the error flag is
// sticky (once set, every later call fails).

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// --- encoder -----------------------------------------------------------------

typedef struct {
    uint8_t *buf;
    uint32_t len;       // bytes written so far
    uint32_t cap;       // buffer capacity
    bool     overflow;  // sticky; every later call is a no-op
} fido_cbor_enc_t;

void fido_cbor_enc_init(fido_cbor_enc_t *e, uint8_t *buf, uint32_t cap);

// Major 0 (unsigned integer) and major 1 (negative integer, v <= -1),
// encoded as short as possible (CTAP2 canonical form).
void fido_cbor_enc_uint(fido_cbor_enc_t *e, uint64_t v);
void fido_cbor_enc_negint(fido_cbor_enc_t *e, int64_t v);

// Major 7: the two booleans CTAP2 uses (0xF4 / 0xF5).
void fido_cbor_enc_bool(fido_cbor_enc_t *e, bool v);

// Major 2 (byte string) and major 3 (text string, NUL-terminated).
// data may be NULL with len 0.
void fido_cbor_enc_bytes(fido_cbor_enc_t *e, const uint8_t *data, uint32_t len);
void fido_cbor_enc_text(fido_cbor_enc_t *e, const char *s);

// Major 4 (array) and major 5 (map) headers; the caller then encodes the
// n elements (2*n items for a map: key, value, key, value, ...).
void fido_cbor_enc_array(fido_cbor_enc_t *e, uint32_t n);
void fido_cbor_enc_map(fido_cbor_enc_t *e, uint32_t n);

// --- decoder -------------------------------------------------------------------

typedef enum {
    FIDO_CBOR_UINT = 0,   // major 0
    FIDO_CBOR_NEGINT,     // major 1
    FIDO_CBOR_BYTES,      // major 2
    FIDO_CBOR_TEXT,       // major 3
    FIDO_CBOR_ARRAY,      // major 4
    FIDO_CBOR_MAP,        // major 5
    FIDO_CBOR_BOOL,       // major 7 (the two booleans only)
} fido_cbor_type_t;

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
    bool error;    // sticky
} fido_cbor_dec_t;

void fido_cbor_dec_init(fido_cbor_dec_t *d, const uint8_t *buf, uint32_t len);

// Report the next item and advance past it. Returns false (and sets the
// error flag) on truncated input, an indefinite-length item, a
// non-canonical integer, or a major type this codec does not expose
// (tags, floats, null, undefined — use fido_cbor_dec_skip to walk over
// those).
//
// On success, per type:
//   FIDO_CBOR_UINT:    *uvalue = the value
//   FIDO_CBOR_NEGINT:  *uvalue = n; the value is -(n + 1)
//   FIDO_CBOR_BYTES /
//   FIDO_CBOR_TEXT:    *data points INTO the input, *data_len = length
//   FIDO_CBOR_ARRAY /
//   FIDO_CBOR_MAP:     *uvalue = element count (pairs for a map)
//   FIDO_CBOR_BOOL:    *uvalue = 0 or 1
// For types other than bytes/text, *data / *data_len are untouched —
// pass NULL for them.
bool fido_cbor_dec_item(fido_cbor_dec_t *d, fido_cbor_type_t *type,
                        uint64_t *uvalue,
                        const uint8_t **data, uint32_t *data_len);

// Drop the next item of ANY definite-length major type (0-7, including
// tags, floats and null) without interpreting it. Nested arrays and maps
// are consumed in full. Returns false (and sets the error flag) on
// truncated input, an indefinite-length item, or nesting deeper than
// 32 (CTAP2 caps nesting at 4; 32 is a safety rail for hostile input).
bool fido_cbor_dec_skip(fido_cbor_dec_t *d);

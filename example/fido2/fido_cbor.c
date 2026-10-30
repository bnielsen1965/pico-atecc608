// fido_cbor.c — implementation of the minimal CTAP2 CBOR codec (see
// fido_cbor.h for the scope and the canonical-form rules).

#include "fido_cbor.h"

#include <string.h>

// --- encoder -----------------------------------------------------------------

static void enc_put(fido_cbor_enc_t *e, uint8_t b)
{
    if (!e->overflow && e->len < e->cap) {
        e->buf[e->len++] = b;
    } else {
        e->overflow = true;
    }
}

// One major-type + argument header, the argument encoded as short as
// possible (CTAP2 canonical form: the 1/2/4/8-byte forms must actually
// need their width).
static void enc_arg(fido_cbor_enc_t *e, uint8_t major, uint64_t v)
{
    const uint8_t mt = (uint8_t)(major << 5);

    if (v <= 23u) {
        enc_put(e, (uint8_t)(mt | v));
    } else if (v <= 0xFFu) {
        enc_put(e, (uint8_t)(mt | 24u));
        enc_put(e, (uint8_t)v);
    } else if (v <= 0xFFFFu) {
        enc_put(e, (uint8_t)(mt | 25u));
        enc_put(e, (uint8_t)(v >> 8));
        enc_put(e, (uint8_t)v);
    } else if (v <= 0xFFFFFFFFu) {
        enc_put(e, (uint8_t)(mt | 26u));
        enc_put(e, (uint8_t)(v >> 24));
        enc_put(e, (uint8_t)(v >> 16));
        enc_put(e, (uint8_t)(v >> 8));
        enc_put(e, (uint8_t)v);
    } else {
        enc_put(e, (uint8_t)(mt | 27u));
        enc_put(e, (uint8_t)(v >> 56));
        enc_put(e, (uint8_t)(v >> 48));
        enc_put(e, (uint8_t)(v >> 40));
        enc_put(e, (uint8_t)(v >> 32));
        enc_put(e, (uint8_t)(v >> 24));
        enc_put(e, (uint8_t)(v >> 16));
        enc_put(e, (uint8_t)(v >> 8));
        enc_put(e, (uint8_t)v);
    }
}

void fido_cbor_enc_init(fido_cbor_enc_t *e, uint8_t *buf, uint32_t cap)
{
    e->buf      = buf;
    e->len      = 0;
    e->cap      = cap;
    e->overflow = (NULL == buf) || (0 == cap);
}

void fido_cbor_enc_uint(fido_cbor_enc_t *e, uint64_t v)
{
    enc_arg(e, 0, v);
}

void fido_cbor_enc_negint(fido_cbor_enc_t *e, int64_t v)
{
    // Major 1 encodes -(n + 1); v <= -1, so n = -v - 1 >= 0.
    enc_arg(e, 1, (uint64_t)(-v - 1));
}

void fido_cbor_enc_bool(fido_cbor_enc_t *e, bool v)
{
    enc_put(e, v ? 0xF5u : 0xF4u);
}

// Shared by bytes (major 2) and text (major 3): header, then the payload.
static void enc_string(fido_cbor_enc_t *e, uint8_t major,
                       const uint8_t *data, uint64_t len)
{
    enc_arg(e, major, len);
    if (!e->overflow && len > 0) {
        if (NULL == data) {
            e->overflow = true;
            return;
        }
        if (e->len + len <= e->cap) {
            memcpy(&e->buf[e->len], data, len);
            e->len += (uint32_t)len;
        } else {
            e->overflow = true;
        }
    }
}

void fido_cbor_enc_bytes(fido_cbor_enc_t *e, const uint8_t *data, uint32_t len)
{
    enc_string(e, 2, data, (uint64_t)len);
}

void fido_cbor_enc_text(fido_cbor_enc_t *e, const char *s)
{
    enc_string(e, 3, (const uint8_t *)s, NULL == s ? 0u : (uint64_t)strlen(s));
}

void fido_cbor_enc_array(fido_cbor_enc_t *e, uint32_t n)
{
    enc_arg(e, 4, (uint64_t)n);
}

void fido_cbor_enc_map(fido_cbor_enc_t *e, uint32_t n)
{
    enc_arg(e, 5, (uint64_t)n);
}

// --- decoder -------------------------------------------------------------------

// Read one major-type + argument header starting at *pp. The canonical
// form check (each wide form must actually need its width) is part of
// the CTAP2 rules, so it applies to every major type here. Returns
// false (leaving *pp pointing at the leading byte) on truncation, a
// reserved argument code (28-31), or a non-canonical width.
static bool dec_arg(const uint8_t **pp, const uint8_t *end, uint8_t major,
                    uint64_t *val)
{
    const uint8_t *p = *pp;
    uint8_t        b;
    uint32_t       extra;
    uint64_t       v;
    uint32_t       width;

    if (p >= end) {
        return false;
    }
    b     = *p++;
    extra = b & 0x1Fu;

    if (extra < 24u) {
        v = (uint64_t)extra;   // values 0-23 are inline in the header byte
    } else {
        switch (extra) {
        case 24:
            if (p + 1 > end) {
                return false;
            }
            v = *p++;
            if (v < 24u) {
                return false;   // needed no width
            }
            break;
        case 25:
            if (p + 2 > end) {
                return false;
            }
            v = ((uint64_t)p[0] << 8) | p[1];
            p += 2;
            if (v < 256u) {
                return false;
            }
            break;
        case 26:
            if (p + 4 > end) {
                return false;
            }
            v = ((uint64_t)p[0] << 24) | ((uint64_t)p[1] << 16) |
                ((uint64_t)p[2] << 8) | p[3];
            p += 4;
            if (v < 65536u) {
                return false;
            }
            break;
        case 27:
            if (p + 8 > end) {
                return false;
            }
            v = 0;
            for (width = 0; width < 8u; width++) {
                v = (v << 8) | p[width];
            }
            p += 8;
            if (v < 0x100000000u) {
                return false;
            }
            break;
        default:
            return false;   // 28-31 are reserved
        }
    }

    (void)major;
    *val = v;
    *pp  = p;
    return true;
}

void fido_cbor_dec_init(fido_cbor_dec_t *d, const uint8_t *buf, uint32_t len)
{
    d->p     = buf;
    d->end   = buf + len;
    d->error = false;
}

bool fido_cbor_dec_item(fido_cbor_dec_t *d, fido_cbor_type_t *type,
                        uint64_t *uvalue,
                        const uint8_t **data, uint32_t *data_len)
{
    uint8_t b;
    uint8_t major;

    if (d->error) {
        return false;
    }
    if (d->p >= d->end) {
        d->error = true;
        return false;
    }

    b     = *d->p;
    major = (uint8_t)(b >> 5);

    switch (major) {
    case 0:
    case 1: {
        uint64_t v;
        if (!dec_arg(&d->p, d->end, major, &v)) {
            d->error = true;
            return false;
        }
        *type   = (FIDO_CBOR_UINT == (fido_cbor_type_t)major)
                       ? FIDO_CBOR_UINT
                       : FIDO_CBOR_NEGINT;
        *uvalue = v;
        return true;
    }
    case 2:
    case 3: {
        uint64_t n;
        if (!dec_arg(&d->p, d->end, major, &n)) {
            d->error = true;
            return false;
        }
        if (n > (uint64_t)(d->end - d->p)) {
            d->error = true;   // payload runs past the buffer
            return false;
        }
        *type = (FIDO_CBOR_BYTES == (fido_cbor_type_t)major)
                    ? FIDO_CBOR_BYTES
                    : FIDO_CBOR_TEXT;
        if (NULL != data) {
            *data = d->p;
        }
        if (NULL != data_len) {
            *data_len = (uint32_t)n;
        }
        d->p += (uint32_t)n;
        return true;
    }
    case 4:
    case 5: {
        uint64_t n;
        if (!dec_arg(&d->p, d->end, major, &n)) {
            d->error = true;
            return false;
        }
        *type   = (FIDO_CBOR_ARRAY == (fido_cbor_type_t)major)
                      ? FIDO_CBOR_ARRAY
                      : FIDO_CBOR_MAP;
        *uvalue = n;
        return true;
    }
    case 7:
        // The two booleans only — null/undefined/floats are not part of
        // the CTAP2 surface; use fido_cbor_dec_skip to walk over them.
        if (0xF4u == b) {
            *type   = FIDO_CBOR_BOOL;
            *uvalue = 0;
            d->p++;
            return true;
        }
        if (0xF5u == b) {
            *type   = FIDO_CBOR_BOOL;
            *uvalue = 1;
            d->p++;
            return true;
        }
        d->error = true;
        return false;
    default:
        d->error = true;   // major 6 (tag) is forbidden by CTAP2
        return false;
    }
}

// Skip one definite-length item of any major type (0-7). Recursive in
// the nesting depth (bounded: CTAP2 caps it at 4, the 32 rail catches
// hostile input before the stack does).
static bool dec_skip_item(fido_cbor_dec_t *d, int depth)
{
    uint8_t b;
    uint8_t major;
    uint64_t n;
    uint64_t i;

    if (depth > 32) {
        d->error = true;
        return false;
    }
    if (d->error || d->p >= d->end) {
        d->error = true;
        return false;
    }

    b     = *d->p;
    major = (uint8_t)(b >> 5);

    switch (major) {
    case 0:
    case 1:
    case 4:
    case 5:
        if (!dec_arg(&d->p, d->end, major, &n)) {
            d->error = true;
            return false;
        }
        if (4 == major) {
            // Every element is at least one byte; the count must fit the
            // remainder. Also keeps 2*n below the buffer size for maps.
            if ((uint64_t)(d->end - d->p) < n) {
                d->error = true;
                return false;
            }
            for (i = 0; i < n; i++) {
                if (!dec_skip_item(d, depth + 1)) {
                    return false;
                }
            }
        } else if (5 == major) {
            // n pairs = 2n one-byte-minimum items; divide first so the
            // multiplication cannot wrap.
            if (n > (uint64_t)(d->end - d->p) / 2u) {
                d->error = true;
                return false;
            }
            for (i = 0; i < 2u * n; i++) {
                if (!dec_skip_item(d, depth + 1)) {
                    return false;
                }
            }
        }
        return true;
    case 2:
    case 3: {
        uint64_t len;
        if (!dec_arg(&d->p, d->end, major, &len)) {
            d->error = true;
            return false;
        }
        if (len > (uint64_t)(d->end - d->p)) {
            d->error = true;
            return false;
        }
        d->p += (uint32_t)len;
        return true;
    }
    case 6:
        // Tag: skip the argument, then the tagged item.
        if (!dec_arg(&d->p, d->end, major, &n)) {
            d->error = true;
            return false;
        }
        return dec_skip_item(d, depth + 1);
    case 7:
        // d->p still points at the header byte: the advances include it.
        switch (b) {
        case 0xF4: case 0xF5: case 0xF6: case 0xF7:   // simple, 1 byte
            d->p++;
            return true;
        case 0xF8:                                    // simple(1)
            if (d->p + 2 > d->end) {
                d->error = true;
                return false;
            }
            d->p += 2;
            return true;
        case 0xF9:                                    // float16
            if (d->p + 3 > d->end) {
                d->error = true;
                return false;
            }
            d->p += 3;
            return true;
        case 0xFA:                                    // float32
            if (d->p + 5 > d->end) {
                d->error = true;
                return false;
            }
            d->p += 5;
            return true;
        case 0xFB:                                    // float64
            if (d->p + 9 > d->end) {
                d->error = true;
                return false;
            }
            d->p += 9;
            return true;
        default:
            // 0xE0-0xEF are one-byte simple values; 0xFF is reserved.
            if (b < 0xF0u) {
                d->p++;
                return true;
            }
            d->error = true;
            return false;
        }
    default:
        d->error = true;
        return false;
    }
}

bool fido_cbor_dec_skip(fido_cbor_dec_t *d)
{
    return dec_skip_item(d, 0);
}

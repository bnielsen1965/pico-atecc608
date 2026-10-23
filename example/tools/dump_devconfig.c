// Phase 4B: dump the agreed development config zone (128 bytes) for the
// on-bench ATECC608, as produced by the real builder
// (atecc608_config_build). Pure host tool — no HAL, no chip access.
//
// The config is the one agreed in RESUME.md ("Agreed 4B config",
// 2026-10-22): lock the layout, keep the contents open.
//
// Build (host, one line):
//   gcc -std=c11 -Wall -Wextra -Iinclude tools/dump_devconfig.c
//       src/atecc608_config.c -o dump_devconfig && ./dump_devconfig

#include <stdio.h>
#include <string.h>

#include "atecc608/atecc608_config.h"

// Encode the agreed 4B config as a build intent.
static void dev_config(atecc608_config_intent_t *c)
{
    atecc608_config_default(c);

    // --- Slot table -------------------------------------------------------
    // ECC public key slots: key_type ECC, pub_info (usable to verify), no
    // access key. SlotConfig stays all-clear.
    //   0  = firmware validation (primary), lockable
    //   2  = device identity public, not lockable
    //   11 = second firmware key, lockable
    //   13 = spare pair public, not lockable
    for (int i = 0; i <= 15; i++) {
        if (i == 0 || i == 2 || i == 11 || i == 13) {
            c->key[i].key_type = ATECC608_KEY_TYPE_ECC;
            c->key[i].pub_info = true;
        }
    }
    c->key[0].lockable  = true;
    c->key[11].lockable = true;

    // ECC private key slots (distinct SlotConfig layout): is_secret is
    // mandatory, gen_key=1 so slots can be re-bound after a DB loss.
    //   1  = device identity: sign external + ECDH
    //   3-6 = FIDO2 credentials: sign external (asserts sign the
    //         challenge digest computed on the Pico)
    //   12 = spare pair: ECDH / second identity
    for (int i = 0; i <= 15; i++) {
        if (i == 1 || (i >= 3 && i <= 6) || i == 12) {
            c->key[i].key_type    = ATECC608_KEY_TYPE_ECC;
            c->key[i].private_key = true;
            c->key[i].pub_info    = true;
            c->slot[i].is_secret  = true;
            c->slot[i].ext_sig    = true;
            c->slot[i].gen_key    = true;
        }
    }
    c->slot[1].ecdh  = true;
    c->slot[12].ecdh = true;

    // Non-ECC unreadable secret slots (key_type NON_ECC is the default):
    // is_secret = no clear reads at all; KDF/sign stay internal.
    //   7-10 = password-store master + spare compartments, lockable
    //   14   = I/O protection key, LOCKABLE (user decision 2026-10-22):
    //          contents stay re-writable in development (lost copy =
    //          re-key); production hardening slot-locks it after the
    //          recorded copy is verified, closing the bus-attacker
    //          re-key hole.
    //   15   = plain data spare (all clear)
    for (int i = 7; i <= 10; i++) {
        c->slot[i].is_secret = true;
        c->key[i].lockable   = true;
    }
    c->slot[14].is_secret = true;
    c->key[14].lockable   = true;

    // --- Counters ----------------------------------------------------------
    // 0 = FIDO2 signature count (CTAP global), 1 = firmware
    // anti-rollback. Both start at the factory value (0).
    // (Defaults are already 0; stated here for the plan's completeness.)

    // --- ChipOptions: I/O protection ON from the start ----------------------
    c->io_prot_en  = true;
    c->io_prot_key = 14;
    c->kdf_aes_en  = true; // required for KDF (library ATECC608 KDF test)
    c->ecdh_prot   = 1;    // ECDH output encrypted on the bus
    c->kdf_prot    = 1;    // KDF output encrypted on the bus

    // Everything else stays at the safe defaults: use_lock_en=false,
    // secure boot off, no volatile key permission, no CountMatch,
    // counters 0, slot_locked 0, x509 0.
}

static void print_row(const uint8_t *z, int off)
{
    printf("%04X: ", off);
    for (int i = 0; i < 16; i++) {
        printf("%02X ", z[off + i]);
    }
    printf("\n");
}

int main(void)
{
    atecc608_config_intent_t cfg;
    uint8_t zone[ATECC608_CONFIG_ZONE_LEN];

    dev_config(&cfg);

    atecc608_status_t st = atecc608_config_build(&cfg, zone);
    if (ATECC608_OK != st) {
        fprintf(stderr, "build FAILED (status %d) — intent rejected by validation\n", st);
        return 1;
    }

    printf("Agreed 4B dev config — 128-byte config zone image (builder output)\n");
    printf("====================================================================\n\n");

    printf("Config zone (row per 16 bytes):\n");
    for (int off = 0; off < ATECC608_CONFIG_ZONE_LEN; off += 16) {
        print_row(zone, off);
    }
    printf("\nLock summary CRC (Lock command with summary check): %04X\n",
           atecc608_config_crc16(zone));

    printf("\nSlot table (SlotConfig word / KeyConfig word, both LE16):\n");
    printf("%-24s %-18s %-18s %s\n", "slot", "SlotConfig[bytes 20..51]",
           "KeyConfig[bytes 96..127]", "role");
    const char *roles[] = {
        "EC pub: fw validation", "EC priv: identity",
        "EC pub: identity",      "EC priv: FIDO2 #1",
        "EC priv: FIDO2 #2",     "EC priv: FIDO2 #3",
        "EC priv: FIDO2 #4",     "secret: pw-store master",
        "secret: spare",         "secret: spare",
        "secret: spare",         "EC pub: 2nd fw key",
        "EC priv: spare (ECDH)", "EC pub: spare",
        "secret: I/O protection","data: spare",
    };
    for (int i = 0; i <= 15; i++) {
        const uint16_t sc = (uint16_t)(zone[20 + 2 * i] |
                                       ((uint16_t)zone[21 + 2 * i] << 8));
        const uint16_t kc = (uint16_t)(zone[96 + 2 * i] |
                                       ((uint16_t)zone[97 + 2 * i] << 8));
        printf("%2d: SlotConfig %04X  KeyConfig %04X  %s\n",
               i, sc, kc, roles[i]);
    }

    printf("\nCounters: 0 = FIDO2 signature count, 1 = firmware anti-rollback"
           " (both start at 0 = FF FF FF FF 00 00 00 00)\n");
    printf("ChipOptions [90:92] = %02X %02X (LE16): io_prot_en + kdf_aes_en,"
           " ecdh_prot=1, kdf_prot=1, io key slot 14\n", zone[90], zone[91]);
    printf("Note: bytes 0..15 are the factory region (chip keeps its own);\n");
    printf("byte 16 (I2C address) is preserved by the prov path from the\n");
    printf("chip's current value; lock bytes [86:88] read 55 55 on an\n");
    printf("unlocked chip and are written by the Lock command, not us.\n");

    return 0;
}

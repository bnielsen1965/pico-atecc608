// Phase 4B: dump the agreed development config zone (128 bytes) for the
// on-bench ATECC608, as produced by the real builder
// (atecc608_config_build). Pure host tool — no HAL, no chip access.
//
// The config is the one agreed in RESUME.md ("Agreed 4B config",
// 2026-10-22): lock the layout, keep the contents open.
//
// Build (host, one line, from the repo root):
//   gcc -std=c11 -Wall -Wextra -Iinclude -Iexample/common example/tools/dump_devconfig.c src/atecc608_config.c -o dump_devconfig && ./dump_devconfig

#include <stdio.h>
#include <string.h>

#include "atecc608/atecc608_config.h"
#include "dev_config.h"  // the agreed 4B config (shared with the console)

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
    printf("byte 16 (I2C address) and bytes 88..89 (SlotLocked, factory\n");
    printf("0xFFFF) are preserved by the prov path from the chip's current\n");
    printf("values, so the on-chip planned-image CRC (printed by `prov\n");
    printf("status` / `prov config`) differs from the CRC above; lock bytes\n");
    printf("[86:88] read 55 55 on an unlocked chip and are written by the\n");
    printf("Lock command, not us.\n");

    return 0;
}

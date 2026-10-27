// pico-atecc608
//
// Raspberry Pi Pico 2 (RP2350) + Microchip ATECC608C crypto co-processor.
//
// Wiring:
//   I2C0  GP20 (SDA), GP21 (SCL)  -> ATECC608C SDA/SCL  (needs pull-ups to 3V3)
//   UART0 GP0  (TX),  GP1 (RX)    -> USB-serial console
//   USB   flashing / optional CDC console
//
// The console exercises the module's curated atecc608_* API.
//
// Console commands:
//   help     - list commands
//   bootrom  - reset into BOOTSEL mode (USB bootloader)
//   probe    - atecc608_probe: wake handshake
//   random   - atecc608_random: 32 bytes of chip-generated randomness
//   info     - atecc608_info: part id + silicon revision
//   serial   - atecc608_serial: 9-byte factory serial
//   lock     - atecc608_is_locked: config/data zone lock status
//   diag     - raw I2C bus diagnostics (levels, general call, wake read)
//   config   - Phase 6 demo: decoded config-zone read-back
//              (atecc608_read_config_zone + atecc608_config_parse);
//              read-only
//   selftest - Phase 7: read-only on-hardware validation suite — the
//              generic invariants of the agreed (fully locked) config +
//              the bench chip's golden values (regression gate);
//              `selftest generic` = invariants only (fresh chip);
//              [PASS]/[FAIL] per check + a final verdict
//   prov ... - Phase 4B provisioning command set (see below)
//
// Phase 4B provisioning commands (the agreed config is
// example/common/dev_config.h; scenarios in example/README.md):
//   prov status    - read-only: chip state + config-zone dump + diff vs
//                    the planned image + /io_key.bin littlefs persistence
//                    (did the I/O-key file survive the last reflash?)
//   prov randtest  - read-only: chip RNG x2; the 0xFFFF0000 factory pattern
//                    is expected while the config zone is unlocked
//   prov iokey     - WRITE (AFTER `prov lock CONFIRM` — the chip refuses
//                    data-zone writes until the config zone is locked):
//                    Pico TRNG -> slot 14 (write ACK; no read-back
//                    possible — data slots are unreadable while the data
//                    zone is unlocked) -> print 64 hex chars -> save
//                    /io_key.bin (littlefs)
//   prov iokeytest - READ-ONLY: functional check that slot 14's I/O key
//                    matches /io_key.bin, via an I/O-protected KDF
//                    round-trip (clear KDF vs decrypted output-encrypted
//                    KDF). Safe any time after `prov iokey`; it writes
//                    nothing and locks nothing.
//   prov kdf <slot> - READ-ONLY: 32-B KDF (PRF, source = data slot) via
//                    the Phase 5 wrapper (atecc608_kdf_prf); fixed nonce
//                    and message, so two runs print the SAME value — the
//                    on-hardware KDF round-trip that closes PLAN.md
//                    Phase 5. I/O key from /io_key.bin.
//   prov iokeyshow - DEV-ONLY (do not ship in a production application):
//                    print the I/O key saved in /io_key.bin so it can be
//                    compared against the out-of-band durable copy.
//                    Chip-free (littlefs read only).
//   prov config    - WRITE: agreed intent -> config zone (byte 16 +
//                    SlotLocked 88..89 preserved), read-back verified;
//                    idempotent
//   prov lock      - WRITE, IRREVERSIBLE: verify zone vs intent -> typed
//                    confirm -> Lock with the summary CRC
//
// Phase 5+ commands (the on-chip ECC key lifecycle, see PLAN.md):
//   prov genkey <slot> - WRITE: fresh ECC P-256 key pair in slot 1/3/4/5/6/12
//                    (data zone must be UNLOCKED; prints the 64-B public
//                    key; re-running REPLACES the key and voids any binding
//                    to the previous one)
//   prov pubkey <slot> - READ-ONLY: public key of the slot's stored ECC
//                    private key (GenKey mode 0x00; works at any time,
//                    even after the data-zone lock)
//   prov lockdata      - WRITE, IRREVERSIBLE: lock the data zone (typed
//                    CONFIRM); afterwards no fresh keys, and
//                    `prov iokeytest` should pass
//   prov lockslot <slot> - WRITE, IRREVERSIBLE: lock one data slot (typed
//                    CONFIRM); the chip enforces the slot's Lockable flag
//
// The agreed Phase 5+ bench order: prov genkey 1; prov genkey 3..6;
// prov genkey 12 (RECORD every printed public key) -> prov lockdata
// CONFIRM -> prov iokeytest (must PASS) -> prov lockslot 14 CONFIRM.
//
// Typed confirm on lock: the command handlers run on core1 while the
// console's stdin loop runs on core0, so an interactive "type yes" prompt
// inside a command would have its keystrokes split between the two cores.
// The confirm is therefore the command line itself: `prov lock` verifies
// the zone and aborts, `prov lock CONFIRM` carries the typed confirm. Both
// pass through the module's confirm-callback API
// (atecc608_lock_config_zone), which re-verifies the zone right before it
// calls the callback.

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>

#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/flash.h"
#include "pico/bootrom.h"
#include "pico/rand.h"
#include "hardware/gpio.h"
#include "pico-command-line.h"
#include "pico_littlefs.h"

#include "atecc608/atecc608.h"
#include "atecc608/atecc608_config.h"
#include "atecc608/atecc608_crypto.h"
#include "atecc608/atecc608_prov.h"
#include "dev_config.h"
// The I/O key file format is shared with the vault example (it reads the
// file `prov iokey` writes here) — one contract in one header.
#include "iokey_file.h"
// The I/O-key functional test (prov iokeytest) uses the raw KDF command and
// the host-side I/O decrypt directly: it needs the 64-byte target length and
// the opt-in output-encrypted variant, which the module's curated 32-byte
// KDF wrapper (atecc608_kdf_prf, used by `prov kdf`) does not cover — fine
// here because it is a diagnostic, not a library feature.
//
// Note: including cryptoauthlib.h (via atca_basic.h) re-surfaces the known
// cosmetic `ATCA_TA_SUPPORT redefined` warning that the cryptoauth_core build
// already emits — our generated atca_config.h defines it as `0`
// (#cmakedefine01) and cryptoauthlib's atca_config_check.h redefines it as
// `DEFAULT_DISABLED` (same value, different tokens; GCC has no flag to
// silence an ordinary macro redefinition). It is harmless and unchanged.
#include "atca_basic.h"
#include "atca_host.h"

#define I2C_BUS     i2c0
#define I2C_SDA_PIN 20
#define I2C_SCL_PIN 21

// --- provisioning: littlefs layout ------------------------------------------

// The I/O key file format (path/len/magic/struct/CRC-32) lives in
// common/iokey_file.h — it is a cross-app contract (the vault example
// reads the file this app writes).
#define PROV_LOCK_TOKEN   "CONFIRM"
#define PROV_IO_KEY_SLOT  14

// littlefs volume state, recorded at boot in main(). Distinguishes a volume
// that SURVIVED the last reflash (an existing volume mounted) from one that
// had to be formatted (first boot, or a full-flash erase). A normal uf2 reflash
// writes only the app region (flash 0x0..~0x19000) and never touches the
// littlefs volume (flash offset 0x80000), so the volume — and /io_key.bin —
// normally survive; only a full-flash erase (or an app that grows past
// 0x80000) loses them.
enum { LFS_STATE_NONE = 0, LFS_STATE_EXISTING = 1, LFS_STATE_FRESH = 2 };
static int s_lfs_state = LFS_STATE_NONE;

// Validate the saved I/O key file (present, full size, and valid per
// common/iokey_file.h) and return the key. On failure fills detail (if
// non-NULL) with the short reason; it prints nothing itself, so the
// selftest can report the reason inside its own [FAIL] line.
static bool iokey_file_valid(uint8_t key[IOKEY_FILE_KEY_LEN],
                             char *detail, size_t detail_size)
{
    iokey_file_t f;
    int rd = pico_lfs_read_file(IOKEY_FILE_PATH, (uint8_t *)&f, sizeof(f));
    if ((int)sizeof(f) != rd) {
        if (detail) {
            snprintf(detail, detail_size, "%s missing or corrupt", IOKEY_FILE_PATH);
        }
        return false;
    }
    return iokey_file_check(&f, key, detail, detail_size);
}

// Load the I/O key saved in /io_key.bin (magic/len/CRC-32 checked). Prints
// the reason and returns false if the file is missing or corrupt.
static bool load_io_key_file(uint8_t key[IOKEY_FILE_KEY_LEN])
{
    char detail[64];
    if (!iokey_file_valid(key, detail, sizeof(detail))) {
        printf("cannot load the I/O key: %s — run `prov iokey` first.\n", detail);
        return false;
    }
    return true;
}

// The planned config image for this bench chip: the agreed intent, with the
// bytes the prov path preserves from the chip patched in the same way (the
// builder does not model them). Returns false if the intent is rejected by
// validation.
static bool planned_image(const uint8_t chip[ATECC608_CONFIG_ZONE_LEN],
                          uint8_t img[ATECC608_CONFIG_ZONE_LEN])
{
    atecc608_config_intent_t cfg;
    dev_config(&cfg);
    if (ATECC608_OK != atecc608_config_build(&cfg, img)) {
        return false;
    }
    img[16] = chip[16]; // I2C address (8-bit on-the-wire form)
    img[88] = chip[88]; // SlotLocked (Lock-command-managed, factory FF FF)
    img[89] = chip[89];
    return true;
}

static atecc608_cfg_t s_cfg = {
    .i2c     = I2C_BUS,
    .sda_pin = I2C_SDA_PIN,
    .scl_pin = I2C_SCL_PIN,
    .addr    = ATECC608_ADDR_ADR_LOW,
    .baud    = ATECC608_FAST_BAUD_HZ,
};

// Report a failed atecc608_* call: curated status text plus the raw
// cryptoauthlib ATCA_STATUS for diagnostics.
static void report_fail(const char *op, atecc608_status_t st)
{
    printf("%s failed: %s (ATCA_STATUS %d)\n", op,
           atecc608_status_str(st), (int)atecc608_last_error());
}

static void commandHelp(char *cmdLine)
{
    (void)cmdLine;
    printf("pico-atecc608: Pico 2 + ATECC608C over I2C0 (GP20/GP21)\n");
    printf("help    - display this message\n");
    printf("bootrom - reset into BOOTSEL mode (USB bootloader)\n");
    printf("probe   - atecc608_probe (wake handshake)\n");
    printf("diag    - raw I2C bus diagnostics (levels, wake handshake bytes)\n");
    printf("random  - atecc608_random (32 random bytes from the chip)\n");
    printf("info    - atecc608_info (part id + silicon revision)\n");
    printf("serial  - atecc608_serial (9-byte factory serial)\n");
    printf("lock    - atecc608_is_locked (config / data zone)\n");
    printf("config  - decoded config-zone read-back (Phase 6 demo, read-only)\n");
    printf("selftest [generic]- read-only on-hardware validation suite (Phase 7;\n");
    printf("                    generic = invariants only, no bench goldens)\n");
    printf("prov status   - chip state + config zone + diff + /io_key.bin persistence\n");
    printf("prov randtest - chip RNG x2 (0xFFFF0000 pattern while unlocked)\n");
    printf("prov iokey    - Pico TRNG -> slot 14 (after prov lock) -> print -> save\n");
    printf("prov iokeytest- verify slot 14's I/O key via an I/O-protected KDF\n");
    printf("                (read-only; uses the key saved in /io_key.bin)\n");
    printf("prov iokeyshow- DEV-ONLY: print the I/O key saved in /io_key.bin\n");
    printf("                (compare against the out-of-band copy; never ship)\n");
    printf("prov config   - write the agreed config zone (idempotent)\n");
    printf("prov lock     - LOCK the config zone (IRREVERSIBLE; add CONFIRM)\n");
    printf("prov genkey <slot>  - fresh ECC key pair in slot 1/3/4/5/6/12 (data zone unlocked)\n");
    printf("prov pubkey <slot>  - public key of the slot's private key (read-only; works locked)\n");
    printf("prov lockdata [CONFIRM]    - LOCK the data zone (IRREVERSIBLE)\n");
    printf("prov lockslot <slot> [CONFIRM] - LOCK one data slot (IRREVERSIBLE)\n");
    printf("prov kdf <slot> - 32-B KDF PRF from the slot (read-only; bench: run twice)\n");
}

static void commandBootrom(char *cmdLine)
{
    (void)cmdLine;
    printf("Rebooting into BOOTSEL mode... (watch for the RP2350 drive)\n");
    // Give the console a moment to flush the message out the UART.
    sleep_ms(200);
    rom_reset_usb_boot(0, 0);
}

static void commandProbe(char *cmdLine)
{
    (void)cmdLine;
    atecc608_status_t st = atecc608_probe();
    if (ATECC608_OK == st) {
        printf("ATECC608 found at I2C address 0x%02X (wake handshake ok)\n", s_cfg.addr);
    } else {
        printf("ATECC608 not found @ 0x%02X: %s (ATCA_STATUS %d)\n",
               s_cfg.addr, atecc608_status_str(st), (int)atecc608_last_error());
    }
}

static void commandRandom(char *cmdLine)
{
    (void)cmdLine;
    uint8_t rand[ATECC608_RNG_CHUNK_LEN];
    atecc608_status_t st = atecc608_random(rand, sizeof(rand));
    if (ATECC608_OK != st) {
        report_fail("RANDOM", st);
        return;
    }
    printf("32 random bytes from ATECC608 @ 0x%02X:\n", s_cfg.addr);
    atecc608_print_hex(rand, sizeof(rand));
}

static void commandInfo(char *cmdLine)
{
    (void)cmdLine;
    atecc608_info_t info;
    atecc608_status_t st = atecc608_info(&info);
    if (ATECC608_OK != st) {
        report_fail("INFO", st);
        return;
    }
    // Part 0x60 is the ATECC608 family; the chip on this board is a
    // 608C. (The API reports raw part/revision; the label is
    // board-specific.)
    const char *model = (info.part == 0x60) ? "ATECC608C" : "ATECC (unknown part)";
    printf("ATECC @ 0x%02X info: %s, part 0x%02X, silicon revision %u\n",
           s_cfg.addr, model, info.part, info.revision);
}

static void commandSerial(char *cmdLine)
{
    (void)cmdLine;
    uint8_t serial[ATECC608_SERIAL_LEN];
    atecc608_status_t st = atecc608_serial(serial);
    if (ATECC608_OK != st) {
        report_fail("SERIAL", st);
        return;
    }
    printf("Serial @ 0x%02X: ", s_cfg.addr);
    atecc608_print_hex(serial, sizeof(serial));
}

static void commandLock(char *cmdLine)
{
    (void)cmdLine;
    bool config_locked = false;
    bool data_locked = false;
    atecc608_status_t st;

    st = atecc608_is_locked(ATECC608_ZONE_CONFIG, &config_locked);
    if (ATECC608_OK != st) {
        report_fail("IS_LOCKED (config)", st);
        return;
    }
    st = atecc608_is_locked(ATECC608_ZONE_DATA, &data_locked);
    if (ATECC608_OK != st) {
        report_fail("IS_LOCKED (data)", st);
        return;
    }
    printf("Config zone: %s\n", config_locked ? "LOCKED" : "unlocked");
    printf("Data zone:   %s\n", data_locked ? "LOCKED" : "unlocked");
}

// Bus diagnostics: pin levels and the raw bytes of the wake handshake at
// both addresses. Note that the wake read only returns the 04 11 33 43
// packet when the chip was ASLEEP; a chip that is still awake NACKs the
// read, so rc=-1 shortly after a command is normal. rc=-2 (timeout) would
// indicate a stuck bus instead.
static void commandDiag(char *cmdLine)
{
    (void)cmdLine;
    uint8_t r[4];
    int rc;

    printf("bus levels: SDA=%u SCL=%u\n",
           gpio_get(I2C_SDA_PIN), gpio_get(I2C_SCL_PIN));

    rc = i2c_write_timeout_us(I2C_BUS, 0x00, (const uint8_t[]){ 0x00 }, 1, false, 10000);
    printf("general call: rc=%d (%s)\n", rc,
           rc == -1 ? "NACK (expected)" : (rc == 1 ? "ack" : "bus fault"));
    sleep_us(1500);

    for (uint8_t addr = ATECC608_ADDR_ADR_LOW; addr <= ATECC608_ADDR_ADR_HIGH; addr++) {
        rc = i2c_read_timeout_us(I2C_BUS, addr, r, sizeof(r), false, 10000);
        printf("wake read @0x%02X: rc=%d", addr, rc);
        if (rc == (int)sizeof(r)) {
            printf(" %02X %02X %02X %02X", r[0], r[1], r[2], r[3]);
        }
        printf("\n");
    }
}

// --- Phase 6: config read-back demo (see the top-of-file list) --------------

// Append " flag" to the row text (or "flag" when it is still empty).
static void add_flag(char *buf, size_t size, size_t *n, const char *flag)
{
    *n += (size_t)snprintf(buf + *n, size - *n, (*n > 0) ? " %s" : "%s", flag);
}

// One table row: the raw words plus the decoded flags, "slot policy |
// key policy". For an ECC private key slot, SlotConfig bits 0-3 carry the
// usage flags (not the read-key nibble), so the slot fields are only
// meaningful under that interpretation.
static void print_slot_row(int n, const uint8_t zone[ATECC608_CONFIG_ZONE_LEN],
                           const atecc608_config_intent_t *cfg)
{
    const atecc608_slot_cfg_t *s = &cfg->slot[n];
    const atecc608_key_cfg_t *k = &cfg->key[n];
    char slotpol[80];
    char keypol[80];
    size_t sn = 0, kn = 0;
    char t[24];

    const uint16_t sw = (uint16_t)zone[20 + 2 * n] | ((uint16_t)zone[21 + 2 * n] << 8);
    const uint16_t kw = (uint16_t)zone[96 + 2 * n] | ((uint16_t)zone[97 + 2 * n] << 8);

    if (k->private_key) {
        if (s->is_secret)    { add_flag(slotpol, sizeof(slotpol), &sn, "secret"); }
        if (s->ext_sig)      { add_flag(slotpol, sizeof(slotpol), &sn, "ext-sig"); }
        if (s->int_sig)      { add_flag(slotpol, sizeof(slotpol), &sn, "int-sig"); }
        if (s->ecdh)         { add_flag(slotpol, sizeof(slotpol), &sn, "ecdh"); }
        if (s->ecdh_to_next) { add_flag(slotpol, sizeof(slotpol), &sn, "ecdh-to-next"); }
        if (s->gen_key)      { add_flag(slotpol, sizeof(slotpol), &sn, "gen-key"); }
        if (s->priv_write)   { add_flag(slotpol, sizeof(slotpol), &sn, "priv-write"); }
    } else {
        if (s->is_secret)    { add_flag(slotpol, sizeof(slotpol), &sn, "secret"); }
        if (s->enc_read)     { add_flag(slotpol, sizeof(slotpol), &sn, "enc-read"); }
        if (s->no_mac)       { add_flag(slotpol, sizeof(slotpol), &sn, "no-mac"); }
        if (s->limited_use)  { add_flag(slotpol, sizeof(slotpol), &sn, "limited-use"); }
        if (s->read_key)     { snprintf(t, sizeof(t), "read-key=%u", s->read_key);
                               add_flag(slotpol, sizeof(slotpol), &sn, t); }
        if (s->write_key)    { snprintf(t, sizeof(t), "write-key=%u", s->write_key);
                               add_flag(slotpol, sizeof(slotpol), &sn, t); }
        if (s->write_config) { snprintf(t, sizeof(t), "write-config=%u", s->write_config);
                               add_flag(slotpol, sizeof(slotpol), &sn, t); }
    }
    if (sn == 0) {
        snprintf(slotpol, sizeof(slotpol), "plain");
    }

    add_flag(keypol, sizeof(keypol), &kn, k->private_key ? "ECC-priv"
             : (ATECC608_KEY_TYPE_ECC == k->key_type) ? "ECC-pub" : "non-ECC");
    if (k->pub_info)    { add_flag(keypol, sizeof(keypol), &kn, "pub-info"); }
    if (k->lockable)    { add_flag(keypol, sizeof(keypol), &kn, "lockable"); }
    if (k->req_random)  { add_flag(keypol, sizeof(keypol), &kn, "req-random"); }
    if (k->req_auth)    { snprintf(t, sizeof(t), "req-auth(key=%u)", k->auth_key);
                           add_flag(keypol, sizeof(keypol), &kn, t); }
    if (k->persist_dis) { add_flag(keypol, sizeof(keypol), &kn, "persist-dis"); }
    if (k->x509_id)     { snprintf(t, sizeof(t), "x509=%u", k->x509_id);
                           add_flag(keypol, sizeof(keypol), &kn, t); }

    printf("%4d  0x%04X  0x%04X  %-42s | %s\n", n, sw, kw, slotpol, keypol);
}

// config — Phase 6 demo: decoded read-back of the config zone. Reads the
// zone with the module API (atecc608_read_config_zone) and decodes it with
// the Phase 4A config builder (atecc608_config_parse), printing every
// field in human form — including the per-slot policy table. READ-ONLY; a
// demo of the module API, not a provisioning tool (`prov status` keeps the
// raw byte dump, the planned-image diff and the littlefs persistence state).
static void commandConfig(char *cmdLine)
{
    (void)cmdLine;
    uint8_t zone[ATECC608_CONFIG_ZONE_LEN];
    atecc608_config_intent_t cfg;
    atecc608_status_t st;

    st = atecc608_read_config_zone(zone);
    if (ATECC608_OK != st) {
        report_fail("READ CONFIG ZONE", st);
        return;
    }
    if (ATECC608_OK != atecc608_config_parse(zone, &cfg)) {
        printf("config zone parse FAILED (unexpected raw values)\n");
        return;
    }

    char locked[64];
    size_t ln = 0;
    char d[8];
    for (int n = 0; n <= ATECC608_MAX_DATA_SLOT; n++) {
        if ((cfg.slot_locked & (1u << n)) == 0u) {
            snprintf(d, sizeof(d), "%d", n);
            add_flag(locked, sizeof(locked), &ln, d);
        }
    }
    if (ln == 0) {
        snprintf(locked, sizeof(locked), "none");
    }

    printf("config zone — decoded (atecc608_config_parse):\n");
    printf("  I2C address (byte 16):    0x%02X (7-bit 0x%02X)\n",
           zone[16], zone[16] >> 1);
    printf("  lock bytes [86:88]:       %02X %02X  (byte 86 data zone, byte 87 config zone; 00 = locked)\n",
           zone[86], zone[87]);
    printf("  SlotLocked (88..89):      %02X %02X  (bit n = 0 -> slot n locked: %s)\n",
           zone[88], zone[89], locked);
    printf("  ChipOptions:              I/O protection %s (key slot %u), KDF AES %s, "
           "ecdh_prot=%u (%s), kdf_prot=%u (%s), POST %s\n",
           cfg.io_prot_en ? "ON" : "off", cfg.io_prot_key,
           cfg.kdf_aes_en ? "on" : "off",
           cfg.ecdh_prot, cfg.ecdh_prot ? "encrypted forced" : "clear ok",
           cfg.kdf_prot, cfg.kdf_prot ? "encrypted forced" : "clear ok",
           cfg.post_en ? "on" : "off");
    if (cfg.count_match_en) {
        printf("  CountMatch:               on (key %u)\n", cfg.count_match_key);
    } else {
        printf("  CountMatch:               off\n");
    }
    printf("  ChipMode:                 i2c-extra %s, TTL %s, watchdog %s, clk-div %u\n",
           cfg.i2c_extra ? "on" : "off", cfg.ttl_en ? "on" : "off",
           cfg.wd_long ? "10 s" : "1.3 s", cfg.clk_div);
    if (cfg.use_lock_en) {
        printf("  UseLock:                  on (key %u)\n", cfg.use_lock_key);
    } else {
        printf("  UseLock:                  off\n");
    }
    printf("  VolKeyPerm:               %s (slot %u)\n",
           cfg.vol_key_perm_en ? "on" : "off", cfg.vol_key_perm_slot);
    if (ATECC608_SB_MODE_OFF == cfg.sb_mode) {
        printf("  SecureBoot:               off\n");
    } else {
        printf("  SecureBoot:               %s (persist %s, rand-nonce %s, "
               "pubkey slot %u, digest slot %u)\n",
               (ATECC608_SB_MODE_FULL_COPY == cfg.sb_mode) ? "full-copy" : "full-store",
               cfg.sb_persist ? "on" : "off", cfg.sb_rand_nonce ? "on" : "off",
               cfg.sb_pubkey_slot, cfg.sb_digest_slot);
    }
    printf("  KDF IV source:            location %u, slot %u\n",
           cfg.kdf_lv_loc, cfg.kdf_lv_slot);
    printf("  UserExtra / UserExtraAdd: 0x%02X / 0x%02X\n",
           cfg.user_extra, cfg.user_extra_add);
    printf("  X509 format:              %02X %02X %02X %02X\n",
           cfg.x509_format[0], cfg.x509_format[1],
           cfg.x509_format[2], cfg.x509_format[3]);
    printf("  counters (decoded):       counter 0 = %lu, counter 1 = %lu\n",
           (unsigned long)cfg.counter[0].value, (unsigned long)cfg.counter[1].value);

    printf("\n  slot  SlotConfig  KeyConfig   decoded (slot policy | key policy)\n");
    for (int n = 0; n <= ATECC608_MAX_DATA_SLOT; n++) {
        print_slot_row(n, zone, &cfg);
    }
}

// --- Phase 4B: the prov command set ------------------------------------------

// Print a 128-byte config zone, 16 bytes per row.
static void print_zone(const char *label, const uint8_t *zone)
{
    printf("%s:\n", label);
    for (int off = 0; off < ATECC608_CONFIG_ZONE_LEN; off += 16) {
        printf("%04X: ", off);
        for (int i = 0; i < 16; i++) {
            printf("%02X ", zone[off + i]);
        }
        printf("\n");
    }
}

// reportIokeyPersistence — the read-only test for "did /io_key.bin survive the
// last reflash?". Prints the volume state (existing = survived, fresh =
// formatted at boot) and the file state (present+valid / present but corrupt /
// missing). No writes. Wired into `prov status`; safe to run after any reflash.
static void reportIokeyPersistence(void)
{
    if (LFS_STATE_NONE == s_lfs_state) {
        printf("littlefs: not mounted at boot (init or mount FAILED) — cannot check %s\n",
               IOKEY_FILE_PATH);
        return;
    }
    printf("littlefs volume: %s\n",
           (LFS_STATE_FRESH == s_lfs_state)
               ? "formatted fresh at boot (first boot or a full-flash erase)"
               : "mounted existing (survived the last reflash)");

    struct lfs_info fi;
    if (0 != pico_lfs_stat(IOKEY_FILE_PATH, &fi)) {
        printf("  %s: MISSING%s\n", IOKEY_FILE_PATH,
               (LFS_STATE_FRESH == s_lfs_state)
                   ? " — expected on a fresh volume"
                   : " — the volume survived but the file is gone");
        printf("  if the chip is provisioned, re-run `prov iokey` and re-record the key.\n");
        return;
    }
    iokey_file_t f;
    int rd = pico_lfs_read_file(IOKEY_FILE_PATH, (uint8_t *)&f, sizeof(f));
    bool ok = (sizeof(f) == (size_t)rd)
           && (IOKEY_FILE_MAGIC == f.magic)
           && (IOKEY_FILE_KEY_LEN == f.len)
           && (iokey_file_crc32((const uint8_t *)&f, offsetof(iokey_file_t, crc32)) == f.crc32);
    if (!ok) {
        printf("  %s: present but CORRUPT (size %d, magic/len/CRC mismatch) — re-run `prov iokey`\n",
               IOKEY_FILE_PATH, rd);
        return;
    }
    printf("  %s: present and valid (%u B key, magic + len + CRC ok)\n", IOKEY_FILE_PATH, f.len);
}

// prov status — read-only: chip state, the current config zone, and a
// byte-by-byte diff vs the planned image (the agreed intent, with byte 16
// patched to the chip's own address, as the prov path does).
static void provStatus(void)
{
    uint8_t zone[ATECC608_CONFIG_ZONE_LEN];
    uint8_t plan[ATECC608_CONFIG_ZONE_LEN];
    uint32_t diff[4] = {0};
    uint32_t counters[2];
    bool locked;
    atecc608_status_t st;

    atecc608_info_t info;
    st = atecc608_info(&info);
    if (ATECC608_OK != st) {
        report_fail("INFO", st);
        return;
    }
    printf("part 0x%02X, silicon revision %u\n", info.part, info.revision);

    uint8_t serial[ATECC608_SERIAL_LEN];
    st = atecc608_serial(serial);
    if (ATECC608_OK != st) {
        report_fail("SERIAL", st);
        return;
    }
    printf("serial: ");
    atecc608_print_hex(serial, sizeof(serial));

    st = atecc608_is_locked(ATECC608_ZONE_CONFIG, &locked);
    if (ATECC608_OK != st) {
        report_fail("IS_LOCKED (config)", st);
        return;
    }
    printf("config zone: %s\n", locked ? "LOCKED" : "unlocked");
    st = atecc608_is_locked(ATECC608_ZONE_DATA, &locked);
    if (ATECC608_OK != st) {
        report_fail("IS_LOCKED (data)", st);
        return;
    }
    printf("data zone:   %s\n", locked ? "LOCKED" : "unlocked");

    for (int i = 0; i < 2; i++) {
        st = atecc608_counter_read((uint8_t)i, &counters[i]);
        if (ATECC608_OK != st) {
            report_fail("COUNTER", st);
            return;
        }
    }
    printf("counter 0 (FIDO2 signature count): %lu\n", (unsigned long)counters[0]);
    printf("counter 1 (fw anti-rollback):      %lu\n", (unsigned long)counters[1]);

    st = atecc608_read_config_zone(zone);
    if (ATECC608_OK != st) {
        report_fail("READ CONFIG ZONE", st);
        return;
    }
    if (!planned_image(zone, plan)) {
        printf("planned image build FAILED (intent rejected by validation)\n");
        return;
    }

    print_zone("config zone (chip)", zone);

    if (atecc608_config_writable_equal(zone, plan, diff)) {
        printf("writable region: matches the planned image\n");
    } else {
        printf("writable region differs from the planned image at bytes:");
        for (int i = 0; i < ATECC608_CONFIG_ZONE_LEN; i++) {
            if (diff[i / 32] & (1u << (i % 32))) {
                printf(" 0x%02X", i);
            }
        }
        printf("\n");
    }
    printf("bytes 0..15: factory (chip keeps its own)\n");
    printf("byte 16: I2C address, preserved by the prov path (chip = 0x%02X)\n", zone[16]);
    printf("bytes 88..89: SlotLocked, preserved by the prov path (chip = %02X %02X)\n",
           zone[88], zone[89]);
    printf("lock bytes [86:88]: %02X %02X (%s)\n", zone[86], zone[87],
           (zone[86] == ATECC608_CONFIG_UNLOCKED &&
            zone[87] == ATECC608_CONFIG_UNLOCKED) ? "unlocked" : "locked/other");
    printf("summary CRC: chip zone %04X  planned image %04X\n",
           atecc608_config_crc16(zone), atecc608_config_crc16(plan));

    reportIokeyPersistence();
}

// The documented factory behavior of the Random command while the config
// zone is unlocked (manual): a repeating 0xFFFF0000.
static bool is_factory_pattern(const uint8_t *r, size_t n)
{
    static const uint8_t pat[4] = { 0xFF, 0xFF, 0x00, 0x00 };
    for (int phase = 0; phase < 4; phase += 2) {
        bool ok = true;
        for (size_t i = 0; i < n; i++) {
            if (r[i] != pat[(i + phase) % 4]) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return true;
        }
    }
    return false;
}

// prov randtest — read-only: two 32-byte chip RNG pulls, annotated with
// whether the factory pattern is present.
static void provRandtest(void)
{
    for (int i = 0; i < 2; i++) {
        uint8_t r[ATECC608_RNG_CHUNK_LEN];
        atecc608_status_t st = atecc608_random(r, sizeof(r));
        if (ATECC608_OK != st) {
            report_fail("RANDOM", st);
            return;
        }
        printf("random #%d: ", i + 1);
        atecc608_print_hex(r, sizeof(r));
        printf("  %s\n", is_factory_pattern(r, sizeof(r))
               ? "0xFFFF0000 factory pattern (expected while the config zone is unlocked)"
               : "no factory pattern");
    }
}

// prov iokey — WRITE (dev flow; re-running re-keys): Pico TRNG -> Write
// slot 14 -> print the key -> save /io_key.bin in littlefs.
// Runs AFTER `prov lock CONFIRM`: the chip refuses data-zone writes until
// the config zone is locked (verified on the bench 2026-10-23). I/O
// protection (io_prot_en) protects the I/O of ECDH/KDF/Verify/SecureBoot,
// not the transport — the chip stays reachable with plain commands after
// the lock. The write is verified by the chip's write ACK only: a
// read-back verify is impossible on the ATECC608 — data slots cannot be
// read while the data zone is unlocked (Microchip's own conformance test
// asserts this), and `prov config` marks slot 14 is_secret. The key is
// verified functionally by an I/O-protected transaction (Phase 7).
static void provIokey(void)
{
    uint8_t key[IOKEY_FILE_KEY_LEN];
    uint8_t zone[ATECC608_CONFIG_ZONE_LEN];
    atecc608_config_intent_t cfg;
    bool locked = false;
    atecc608_status_t st;

    // Gate: only while the config zone is LOCKED — the chip refuses any
    // data-zone write until it is (verified on the bench 2026-10-23).
    // The approved order is `prov config` -> `prov lock CONFIRM` ->
    // `prov iokey`. I/O protection protects command I/O, not the
    // transport, so the chip stays reachable after the lock.
    st = atecc608_is_locked(ATECC608_ZONE_CONFIG, &locked);
    if (ATECC608_OK != st) {
        report_fail("IS_LOCKED (config)", st);
        return;
    }
    if (!locked) {
        printf("config zone is UNLOCKED — the chip refuses data-zone writes\n"
               "until it is locked. Run `prov config`, then\n"
               "`prov lock CONFIRM`, then `prov iokey` again.\n");
        return;
    }
    st = atecc608_is_locked(ATECC608_ZONE_DATA, &locked);
    if (ATECC608_OK != st) {
        report_fail("IS_LOCKED (data)", st);
        return;
    }
    if (locked) {
        printf("data zone is LOCKED — slot %d can no longer be written.\n",
               PROV_IO_KEY_SLOT);
        return;
    }
    // Slot 14 must accept a clear Write in the current config (parsed
    // from the config zone, which is always readable).
    st = atecc608_read_config_zone(zone);
    if (ATECC608_OK != st) {
        report_fail("READ CONFIG ZONE", st);
        return;
    }
    st = atecc608_config_parse(zone, &cfg);
    if (ATECC608_OK != st) {
        report_fail("PARSE CONFIG ZONE", st);
        return;
    }
    if (cfg.key[PROV_IO_KEY_SLOT].private_key
        || cfg.slot[PROV_IO_KEY_SLOT].write_key != 0
        || cfg.slot[PROV_IO_KEY_SLOT].write_config != 0) {
        printf("slot %d does not accept clear writes in the current config —\n"
               "no write issued.\n", PROV_IO_KEY_SLOT);
        return;
    }

    // Pico-side entropy: the chip RNG yields a deterministic factory
    // pattern before the config lock, so the key comes from the RP2350's
    // hardware TRNG (pico_rand uses it by default on RP2350).
    for (int i = 0; i < IOKEY_FILE_KEY_LEN / 4; i++) {
        uint32_t w = get_rand_32();
        memcpy(&key[4 * i], &w, sizeof(w));
    }

    st = atecc608_write_iokey(PROV_IO_KEY_SLOT, key);
    if (ATECC608_OK != st) {
        report_fail("WRITE SLOT 14", st);
        return;
    }
    printf("I/O protection key written to slot %d (write ACKed by the chip).\n",
           PROV_IO_KEY_SLOT);
    printf("NOTE: no read-back verify is possible — data slots are not readable\n"
           "while the data zone is unlocked, and `prov config` marks the slot\n"
           "is_secret. The key is verified functionally by an I/O-protected\n"
           "transaction (Phase 7).\n");
    printf("RECORD THIS — it is the durable backup. A normal uf2 reflash PRESERVES\n"
           "the littlefs volume (it writes only the app region, not flash 0x80000+);\n"
           "only a full-flash erase loses it. Run `prov status` to confirm it survived:\n");
    atecc608_print_hex(key, sizeof(key));

    iokey_file_t f;
    f.magic = IOKEY_FILE_MAGIC;
    f.len   = IOKEY_FILE_KEY_LEN;
    memcpy(f.key, key, sizeof(key));
    f.crc32 = iokey_file_crc32((const uint8_t *)&f, offsetof(iokey_file_t, crc32));
    if (0 != pico_lfs_write_file(IOKEY_FILE_PATH, (const uint8_t *)&f, sizeof(f))) {
        printf("saving %s FAILED — the key is on the chip; re-save later.\n",
               IOKEY_FILE_PATH);
        return;
    }
    iokey_file_t rd;
    if ((sizeof(f) != (size_t)pico_lfs_read_file(IOKEY_FILE_PATH, (uint8_t *)&rd, sizeof(rd)))
        || (0 != memcmp(&f, &rd, sizeof(f)))) {
        printf("saved %s FAILED read-back verify.\n", IOKEY_FILE_PATH);
        return;
    }
    printf("saved to littlefs: %s (read-back verified)\n", IOKEY_FILE_PATH);
}

// prov iokeytest — READ-ONLY functional verification of the I/O-protection
// key in slot 14, against the copy saved in /io_key.bin. The chip's write ACK
// alone cannot prove the key is usable (a read-back verify is impossible —
// data slots are unreadable while the data zone is unlocked, and slot 14 is
// is_secret), so this runs an I/O-protected KDF round-trip:
//   1. read the I/O key from /io_key.bin (magic/len/CRC-32 checked)
//   2. clear KDF (PRF, source=tempkey, target=output)      -> out_clear
//   3. enc   KDF (PRF, source=tempkey, target=output_enc)  -> out_enc, nonce
//   4. atcah_io_decrypt(out_enc, nonce, key-from-file)     (in place)
//   5. PASS iff the clear result == the decrypted enc result, where the
//      clear result is first decrypted too if the chip ENFORCES I/O
//      protection (its clear response carries a nonce — see below).
// It issues no data-zone READ/WRITE and no write/lock — safe to run any time
// after `prov iokey`. Same pattern as cryptoauthlib's own
// kdf_prf_output_encrypted, but the key comes from littlefs instead of a
// hard-coded global.
//
// Bench findings (2026-10-25, after the data-zone lock):
// (1) atcab_nonce is a PASS-THROUGH nonce-LOAD, not random generation — it
//     loads the buffer's CONTENTS into tempkey. This test therefore fills
//     the buffer from the Pico TRNG and loads the SAME buffer before BOTH
//     calls, so the PRF input is identical for both (a prerequisite of the
//     comparison).
// (2) This chip (kdf_prot=1 in ChipOptions) ENFORCES I/O protection on KDF:
//     EVERY target=output KDF returns encrypted data + a 32-B response
//     nonce — the "clear" call was encrypted against the request, which is
//     why the first run FAILED (ciphertext compared with plaintext). The
//     host recomputed the exact keystreams (atcah_io_decrypt is
//     SHA256(io_key || 16-B nonce half) XOR per 32-B block) and verified
//     both responses decrypt with the recorded durable key: the I/O key in
//     slot 14 is FUNCTIONALLY VERIFIED (chip key == file key == record).
//     CONSEQUENCE FOR PHASE 7: every KDF with target=output from this chip
//     must be atcah_io_decrypt'ed with the I/O key before use.
// (3) Diagnostic prints kept (tempkey nonce, clear + its resp nonce, raw
//     enc output, enc resp nonce, and on failure the file key) so any
//     future disagreement is host-reproducible in one run.
// The I/O-key round-trip, shared by `prov iokeytest` (verbose) and
// `selftest` (quiet). True iff the key saved in /io_key.bin matches slot
// 14; on failure detail (if non-NULL) gets the short reason.
//
// verbose: prints the intermediate values (tempkey nonce, clear output +
// its response nonce, raw enc output, enc response nonce, and on failure
// the decrypted KDF + the file key) so any future disagreement is
// host-reproducible in one run (the atcah_io_decrypt keystream is
// SHA256(io_key || 16-B nonce half) XOR per 32-B block).
static bool iokey_roundtrip(bool verbose, char *detail, size_t detail_size)
{
    // 1. Load the saved I/O key.
    uint8_t io_key[IOKEY_FILE_KEY_LEN];
    if (!iokey_file_valid(io_key, detail, detail_size)) {
        if (verbose) {
            printf("cannot load the I/O key: %s — run `prov iokey` first.\n",
                   detail);
        }
        return false;
    }

    // 2-3. ONE random 32-byte nonce, loaded into tempkey before EACH KDF
    // run (atcab_nonce is a pass-through nonce-load — the buffer's CONTENTS
    // are what tempkey gets), so the underlying PRF input is IDENTICAL for
    // the clear and the enc call — a prerequisite of the comparison in step
    // 5.
    uint8_t nonce[32];
    uint8_t msg[16];
    for (int i = 0; i < 16; i++) {
        msg[i] = (uint8_t)i;
    }
    uint8_t out_clear[64];
    uint8_t out_enc[64];
    uint8_t out_nonce[32];
    memset(out_nonce, 0, sizeof(out_nonce));  // stays 0 if the response
    // carried no nonce (64-B response = the call was not encrypted)
    uint8_t clear_nonce[32];
    // Zeroed: the library fills it only if the CLEAR response carries a
    // trailing 32-byte nonce — which it does only if that call was
    // encrypted AGAINST THE REQUEST (I/O protection enforced, not opt-in).
    memset(clear_nonce, 0, sizeof(clear_nonce));
    // PRF, 32-byte source key, 64-byte target, no AEAD processing, 16-byte
    // message (its length lives in bits 24..31 of the details word).
    uint32_t details = KDF_DETAILS_PRF_KEY_LEN_32
                     | KDF_DETAILS_PRF_TARGET_LEN_64
                     | KDF_DETAILS_PRF_AEAD_MODE0
                     | ((uint32_t)sizeof(msg) << 24);
    const uint8_t mode = KDF_MODE_ALG_PRF | KDF_MODE_SOURCE_TEMPKEY;
    ATCA_STATUS atca;

    // Fresh random tempkey input from the Pico TRNG. NOTE (bench 2026-10-25):
    // atcab_nonce is a PASS-THROUGH nonce-LOAD, not random generation — it
    // loads the buffer's CONTENTS into tempkey. The SAME buffer is loaded
    // before BOTH KDF calls, so the PRF input is identical for both.
    for (int i = 0; i < (int)sizeof(nonce) / 4; i++) {
        uint32_t w = get_rand_32();
        memcpy(&nonce[4 * i], &w, sizeof(w));
    }
    atca = atcab_nonce(nonce);
    if (ATCA_SUCCESS != atca) {
        snprintf(detail, detail_size, "NONCE (clear) failed: ATCA_STATUS %d", (int)atca);
        if (verbose) {
            printf("NONCE (clear) failed: ATCA_STATUS %d\n", (int)atca);
        }
        return false;
    }
    if (verbose) {
        printf("tempkey nonce (32 B):  ");
        atecc608_print_hex(nonce, sizeof(nonce));
    }
    atca = atcab_kdf(mode | KDF_MODE_TARGET_OUTPUT, 0x1234, details,
                     msg, out_clear, clear_nonce);
    if (ATCA_SUCCESS != atca) {
        snprintf(detail, detail_size, "clear KDF failed: ATCA_STATUS %d", (int)atca);
        if (verbose) {
            printf("clear KDF failed: ATCA_STATUS %d\n", (int)atca);
        }
        return false;
    }
    // ANY non-zero byte means the library copied a nonce from the response
    // (a random 32-B nonce is all-zero with probability 2^-256; the buffer
    // stays all-zero only when the response carried no nonce).
    bool clear_had_nonce = false;
    for (int i = 0; i < 32; i++) {
        clear_had_nonce |= (0 != clear_nonce[i]);
    }
    if (verbose) {
        printf("clear KDF (64 B):      ");
        atecc608_print_hex(out_clear, sizeof(out_clear));
        printf("clear resp nonce:      %s",
               clear_had_nonce ? "" : "none (64-B response — NOT encrypted)");
        if (clear_had_nonce) {
            printf(" ");
            atecc608_print_hex(clear_nonce, sizeof(clear_nonce));
        }
        printf("\n");
    }

    atca = atcab_nonce(nonce);   // reload the SAME 32 B into tempkey
    if (ATCA_SUCCESS != atca) {
        snprintf(detail, detail_size, "NONCE (enc) failed: ATCA_STATUS %d", (int)atca);
        if (verbose) {
            printf("NONCE (enc) failed: ATCA_STATUS %d\n", (int)atca);
        }
        return false;
    }
    atca = atcab_kdf(mode | KDF_MODE_TARGET_OUTPUT_ENC, 0x1234, details,
                     msg, out_enc, out_nonce);
    if (ATCA_SUCCESS != atca) {
        snprintf(detail, detail_size, "encrypted KDF failed: ATCA_STATUS %d", (int)atca);
        if (verbose) {
            printf("encrypted KDF failed: ATCA_STATUS %d\n", (int)atca);
        }
        return false;
    }
    if (verbose) {
        printf("enc KDF raw (64 B):    ");
        atecc608_print_hex(out_enc, sizeof(out_enc));
        printf("enc resp nonce (32 B): ");
        atecc608_print_hex(out_nonce, sizeof(out_nonce));
    }

    // 4. Decrypt the encrypted output with the saved key (in place).
    atca_io_decrypt_in_out_t dec = {
        .io_key    = io_key,
        .out_nonce = out_nonce,
        .data      = out_enc,
        .data_size = sizeof(out_enc),
    };
    atca = atcah_io_decrypt(&dec);
    if (ATCA_SUCCESS != atca) {
        snprintf(detail, detail_size, "I/O decrypt failed: ATCA_STATUS %d", (int)atca);
        if (verbose) {
            printf("I/O decrypt failed: ATCA_STATUS %d\n", (int)atca);
        }
        return false;
    }

    // 5. Compare the clear result with the decrypted encrypted result.
    // Bench finding (2026-10-25, host-verified against the printed
    // keystreams): with kdf_prot=1 this chip ENFORCES I/O protection —
    // the clear call's output is encrypted too, and its response carries
    // the nonce (clear_had_nonce). Decrypt a copy of the clear output
    // with the SAME saved key before comparing. With an opt-in config
    // (no nonce in the clear response) this reduces to the original
    // direct compare. The tempkey input is identical for both calls, so
    // the underlying PRF output is the same value in both.
    uint8_t ref[64];
    memcpy(ref, out_clear, sizeof(ref));
    if (clear_had_nonce) {
        atca_io_decrypt_in_out_t dec2 = {
            .io_key    = io_key,
            .out_nonce = clear_nonce,
            .data      = ref,
            .data_size = sizeof(ref),
        };
        atca = atcah_io_decrypt(&dec2);
        if (ATCA_SUCCESS != atca) {
            snprintf(detail, detail_size,
                     "I/O decrypt (clear copy) failed: ATCA_STATUS %d", (int)atca);
            if (verbose) {
                printf("I/O decrypt (clear copy) failed: ATCA_STATUS %d\n", (int)atca);
            }
            return false;
        }
    }
    if (0 != memcmp(ref, out_enc, sizeof(ref))) {
        snprintf(detail, detail_size,
                 "decrypted KDF != clear KDF (the I/O key in %s does not match slot %u)",
                 IOKEY_FILE_PATH, (unsigned)PROV_IO_KEY_SLOT);
        if (verbose) {
            printf("I/O key test FAILED: the decrypted KDF does not match the clear\n"
                   "KDF (both decrypted with the saved key when the chip enforces\n"
                   "I/O protection). The printed values let the host side\n"
                   "recompute the exact keystreams (SHA256(io_key || 16-B nonce\n"
                   "half) XOR per 32-B block) and identify which key the chip and\n"
                   "the file each hold — RESUME.md, 2026-10-25 iokeytest recipe.\n"
                   "Do NOT re-key slot 14 before that verdict.\n");
            printf("decrypted KDF (64 B):  ");
            atecc608_print_hex(out_enc, sizeof(out_enc));
            printf("I/O key from %s (32 B): ", IOKEY_FILE_PATH);
            atecc608_print_hex(io_key, sizeof(io_key));
        }
        return false;
    }
    if (verbose) {
        printf("I/O key test PASSED: slot 14 matches %s and the I/O-\n"
               "protection path works end-to-end.\n", IOKEY_FILE_PATH);
        if (clear_had_nonce) {
            printf("NOTE: this chip ENFORCES I/O protection (kdf_prot=1) —\n"
                   "both KDF outputs arrived encrypted; both were decrypted\n"
                   "with the saved key before comparing.\n");
        }
    }
    return true;
}

// prov iokeytest — the verbose diagnostic form of the round-trip: prints
// the chip lock state (context if a KDF is refused) and every intermediate
// value (see iokey_roundtrip).
static void provIokeyTest(void)
{
    bool locked = false;
    atecc608_status_t st;
    st = atecc608_is_locked(ATECC608_ZONE_CONFIG, &locked);
    if (ATECC608_OK != st) {
        report_fail("IS_LOCKED (config)", st);
        return;
    }
    printf("config zone: %s\n", locked ? "LOCKED" : "unlocked");
    st = atecc608_is_locked(ATECC608_ZONE_DATA, &locked);
    if (ATECC608_OK != st) {
        report_fail("IS_LOCKED (data)", st);
        return;
    }
    printf("data zone:   %s\n", locked ? "LOCKED" : "unlocked");

    char detail[128];
    (void)iokey_roundtrip(true, detail, sizeof(detail));
}

// prov iokeyshow — DEV-ONLY diagnostic (a production application must not
// ship this): print the I/O key saved in /io_key.bin (magic/len/CRC-32
// checked) so the operator can compare it against the out-of-band durable
// copy (the console print from `prov iokey`, the dev notes). The I/O key
// is the bus key of the I/O-protected KDF/ECDH paths; exposing it on a
// production console would defeat keeping it secret on the chip.
// READ-ONLY and chip-free: a littlefs read only, no chip commands.
static void provIokeyShow(void)
{
    uint8_t io_key[IOKEY_FILE_KEY_LEN];
    if (!load_io_key_file(io_key)) {
        return;
    }
    printf("I/O key saved in %s (32 B):\n", IOKEY_FILE_PATH);
    atecc608_print_hex(io_key, sizeof(io_key));
    printf("DEV-ONLY print: compare against the out-of-band copy. A\n"
           "production application must not expose this key.\n");
}

// prov config — WRITE (reversible while the zone is unlocked): build the
// agreed intent, provision (unlocked check -> read -> preserve byte 16 and
// SlotLocked 88..89 -> write -> read-back verify), report the result + the
// summary CRC the lock will use. Idempotent: an already-matching chip takes
// no writes.
static void provConfig(void)
{
    atecc608_config_intent_t cfg;
    uint8_t zone[ATECC608_CONFIG_ZONE_LEN];
    uint8_t plan[ATECC608_CONFIG_ZONE_LEN];
    atecc608_status_t st;

    dev_config(&cfg);
    st = atecc608_read_config_zone(zone);
    if (ATECC608_OK != st) {
        report_fail("READ CONFIG ZONE", st);
        return;
    }
    if (!planned_image(zone, plan)) {
        printf("intent rejected by builder validation — nothing written.\n");
        return;
    }
    const bool already = atecc608_config_writable_equal(zone, plan, NULL);
    printf("planned image (chip's byte 16 = 0x%02X, bytes 88..89 = %02X %02X):"
           " summary CRC %04X\n",
           zone[16], zone[88], zone[89], atecc608_config_crc16(plan));
    printf(already
           ? "chip already matches the planned image — no writes (idempotent).\n"
           : "writing the planned image to the config zone...\n");

    st = atecc608_provision_config(&cfg);
    if (ATECC608_OK != st) {
        report_fail("PROVISION", st);
        printf("run `prov status` to inspect the zone's state.\n");
        return;
    }
    st = atecc608_read_config_zone(zone);
    if (ATECC608_OK != st) {
        report_fail("READ CONFIG ZONE (verify)", st);
        return;
    }
    printf("verified: chip zone matches the planned image.\n");
    printf("chip zone summary CRC: %04X  <- the value `prov lock` will use\n",
           atecc608_config_crc16(zone));
}

// The module's confirm gate for `prov lock`: the zone has already been
// verified against the intent at this point; we only decide whether to
// issue the (irreversible) Lock.
struct prov_lock_ctx {
    bool confirmed; // true when the typed token is on the command line
};

static bool provLockConfirm(const char *prompt, void *vctx)
{
    struct prov_lock_ctx *ctx = (struct prov_lock_ctx *)vctx;
    printf("about to: %s\n", prompt);
    if (!ctx->confirmed) {
        printf("NOT locked. To proceed, type the full command:\n\n"
               "    prov lock %s\n", PROV_LOCK_TOKEN);
        return false;
    }
    return true;
}

// prov lock — WRITE, IRREVERSIBLE. Without the token: verifies the zone
// and aborts (no lock). With `CONFIRM`: re-verify -> confirm callback ->
// Lock with the summary CRC of the chip's ACTUAL zone (the builder's CRC
// differs in the factory bytes 0..15).
static void provLock(const char *rest)
{
    struct prov_lock_ctx ctx = {
        .confirmed = (0 == strcmp(rest, PROV_LOCK_TOKEN)),
    };
    uint8_t zone[ATECC608_CONFIG_ZONE_LEN];
    bool locked = false;
    atecc608_status_t st;

    if ((rest[0] != '\0') && !ctx.confirmed) {
        printf("usage: prov lock [CONFIRM]\n");
        return;
    }
    st = atecc608_is_locked(ATECC608_ZONE_CONFIG, &locked);
    if (ATECC608_OK != st) {
        report_fail("IS_LOCKED (config)", st);
        return;
    }
    if (locked) {
        printf("config zone is already LOCKED — nothing to do.\n");
        return;
    }
    st = atecc608_read_config_zone(zone);
    if (ATECC608_OK != st) {
        report_fail("READ CONFIG ZONE", st);
        return;
    }
    printf("chip zone summary CRC: %04X (computed over the chip's actual zone)\n",
           atecc608_config_crc16(zone));

    atecc608_config_intent_t cfg;
    dev_config(&cfg);
    st = atecc608_lock_config_zone(&cfg, provLockConfirm, &ctx);
    if (ATECC608_OK == st) {
        printf("config zone LOCKED (irreversible).\n");
    } else if (ATECC608_ERR_CHIP_STATE == st) {
        // The zone was ruled out as locked above, so this is the
        // typed-confirm abort: nothing was written or locked.
        printf("lock aborted — nothing was written or locked.\n");
    } else {
        report_fail("LOCK", st);
    }
}

// --- Phase 5+: the on-chip ECC key lifecycle (see the top-of-file list) ----

// Parse a slot number (0..15) from the whole argument string; report on
// failure. (A manual parse: the argument is at most two digits.)
static bool parse_slot_arg(const char *text, uint8_t *slot)
{
    uint32_t v = 0;
    int digits = 0;

    while (('0' <= *text) && (*text <= '9')) {
        v = (10u * v) + (uint32_t)(*text - '0');
        text++;
        digits++;
    }
    if ((0 == digits) || (v > ATECC608_MAX_DATA_SLOT) || ('\0' != *text)) {
        printf("expected a slot number 0..15, got \"%s\"\n", text);
        return false;
    }
    *slot = (uint8_t)v;
    return true;
}

// The ECC private key slots of the agreed config (dev_config.h): 1 =
// identity, 3-6 = FIDO2 credential keys (pre-generated), 12 = spare. The
// chip's config check below is authoritative; this allowlist only keeps a
// fat-fingered slot (e.g. the I/O key's 14) out of the command.
static bool is_genkey_slot(uint8_t slot)
{
    return ((1u == slot) || ((3u <= slot) && (slot <= 6u)) || (12u == slot));
}

// prov genkey <slot> — WRITE: generate a fresh ECC P-256 key pair in the
// slot (GenKey mode 0x04; the data zone must be UNLOCKED — a locked CA2
// chip would only recompute the existing public key, so this command
// refuses instead of silently lying). Guards: the slot allowlist (1,
// 3-6, 12) and the chip's actual config (ECC private slot with the
// GenKey bit). Prints the 64-byte public key (re-fetchable any time via
// `prov pubkey <slot>`); the private key never leaves the chip.
static void provGenkey(const char *rest)
{
    uint8_t slot;
    uint8_t pub[ATECC608_PUBKEY_LEN];
    uint8_t zone[ATECC608_CONFIG_ZONE_LEN];
    atecc608_config_intent_t cfg;
    bool locked = false;
    atecc608_status_t st;

    if (!parse_slot_arg(rest, &slot)) {
        printf("usage: prov genkey <slot 0-15>\n");
        return;
    }
    if (!is_genkey_slot(slot)) {
        printf("slot %u is not one of the agreed ECC private key slots\n"
               "(1, 3, 4, 5, 6, 12) — no key generated.\n", (unsigned)slot);
        return;
    }
    st = atecc608_is_locked(ATECC608_ZONE_DATA, &locked);
    if (ATECC608_OK != st) {
        report_fail("IS_LOCKED (data)", st);
        return;
    }
    if (locked) {
        printf("data zone is LOCKED — a fresh key can no longer be generated.\n"
               "(On this CA2 chip, GenKey mode 0x04 on a locked zone would\n"
               "only recompute the existing public key; this command\n"
               "refuses instead of doing that silently.)\n");
        return;
    }
    // The slot must be an ECC private key slot with the GenKey bit in the
    // chip's ACTUAL config (readable even when locked).
    st = atecc608_read_config_zone(zone);
    if (ATECC608_OK != st) {
        report_fail("READ CONFIG ZONE", st);
        return;
    }
    st = atecc608_config_parse(zone, &cfg);
    if (ATECC608_OK != st) {
        report_fail("PARSE CONFIG ZONE", st);
        return;
    }
    if (!cfg.key[slot].private_key || !cfg.slot[slot].gen_key) {
        printf("slot %u is not an ECC private key slot with the GenKey bit\n"
               "in the current config — no key generated.\n", (unsigned)slot);
        return;
    }

    printf("WARNING: if slot %u already holds a key, this REPLACES it and\n"
           "voids everything (e.g. a FIDO2 credential record) bound to the\n"
           "previous public key.\n", (unsigned)slot);
    st = atecc608_genkey(slot, pub);
    if (ATECC608_OK != st) {
        report_fail("GENKEY", st);
        return;
    }
    printf("slot %u: fresh ECC P-256 key pair generated.\n", (unsigned)slot);
    printf("RECORD THIS — the public key (64 B, X || Y big-endian). The\n"
           "private key never leaves the chip. The public key can be\n"
           "re-fetched any time (even after `prov lockdata`) with\n"
           "`prov pubkey %u`.\n", (unsigned)slot);
    atecc608_print_hex(pub, sizeof(pub));
}

// prov pubkey <slot> — READ-ONLY: the 64-byte public key of the ECC
// private key currently in the slot (GenKey mode 0x00 — recomputed from
// the stored private key; works at any time, even with the data zone
// locked). Use it to re-fetch a recorded public key or to verify one
// before `prov lockdata`. (Not `atecc608_read_pubkey`, which reads a
// STORED 72-byte public key from slots 8-15.)
static void provPubkey(const char *rest)
{
    uint8_t slot;
    uint8_t pub[ATECC608_PUBKEY_LEN];
    atecc608_status_t st;

    if (!parse_slot_arg(rest, &slot)) {
        printf("usage: prov pubkey <slot 0-15>\n");
        return;
    }
    st = atecc608_get_pubkey(slot, pub);
    if (ATECC608_OK != st) {
        report_fail("GET PUBKEY", st);
        printf("(the slot must be an ECC private key slot in the current config)\n");
        return;
    }
    printf("slot %u public key (64 B, X || Y big-endian):\n", (unsigned)slot);
    atecc608_print_hex(pub, sizeof(pub));
}

// The module's confirm gate for `prov lockdata` (same pattern as
// provLockConfirm: the command line itself carries the typed confirm).
struct prov_data_lock_ctx {
    bool confirmed;
};

static bool provLockDataConfirm(const char *prompt, void *vctx)
{
    struct prov_data_lock_ctx *ctx = (struct prov_data_lock_ctx *)vctx;
    printf("about to: %s\n", prompt);
    if (!ctx->confirmed) {
        printf("NOT locked. To proceed, type the full command:\n\n"
               "    prov lockdata %s\n", PROV_LOCK_TOKEN);
        return false;
    }
    return true;
}

// prov lockdata [CONFIRM] — WRITE, IRREVERSIBLE: locks the data zone
// (all 16 slots + OTP). Consequences: no more fresh key generation
// (GenKey mode 0x04 needs the zone unlocked), and `prov iokeytest`
// should now PASS (the I/O-protected KDF is gated on this lock).
// Without the token: reports the state and aborts. With CONFIRM: the
// module's guards (config zone locked, data zone unlocked, confirm)
// run, then the lock; the new state is verified by re-reading it.
static void provLockData(const char *rest)
{
    struct prov_data_lock_ctx ctx = {
        .confirmed = (0 == strcmp(rest, PROV_LOCK_TOKEN)),
    };
    bool locked = false;
    atecc608_status_t st;

    if ((rest[0] != '\0') && !ctx.confirmed) {
        printf("usage: prov lockdata [CONFIRM]\n");
        return;
    }
    st = atecc608_is_locked(ATECC608_ZONE_DATA, &locked);
    if (ATECC608_OK != st) {
        report_fail("IS_LOCKED (data)", st);
        return;
    }
    if (locked) {
        printf("data zone is already LOCKED — nothing to do.\n");
        return;
    }
    printf("data zone is UNLOCKED. Re-fetch the public keys of all ECC\n"
           "slots first (`prov pubkey <slot>`): after the lock no fresh\n"
           "keys can be created (existing ones stay re-fetchable).\n");
    st = atecc608_lock_data_zone(provLockDataConfirm, &ctx);
    if (ATECC608_OK == st) {
        st = atecc608_is_locked(ATECC608_ZONE_DATA, &locked);
        if ((ATECC608_OK == st) && locked) {
            printf("data zone LOCKED (irreversible; verified by re-read).\n"
                   "Next: `prov iokeytest` should now PASS (the KDF\n"
                   "target=output is gated on this lock).\n");
        } else {
            printf("the lock command succeeded, but the re-read does NOT show\n"
                   "the data zone locked — investigate before proceeding.\n");
        }
        return;
    }
    if (ATECC608_ERR_CHIP_STATE == st) {
        // Typed-confirm abort (or a guard the pre-checks above could not
        // see, e.g. the config zone being unlocked): nothing was locked.
        printf("lock aborted — nothing was locked.\n");
    } else {
        report_fail("LOCK DATA ZONE", st);
    }
}

// The module's confirm gate for `prov lockslot <slot>`.
struct prov_slot_lock_ctx {
    bool confirmed;
    uint8_t slot;
};

static bool provLockSlotConfirm(const char *prompt, void *vctx)
{
    struct prov_slot_lock_ctx *ctx = (struct prov_slot_lock_ctx *)vctx;
    printf("about to: %s (slot %u)\n", prompt, (unsigned)ctx->slot);
    if (!ctx->confirmed) {
        printf("NOT locked. To proceed, type the full command:\n\n"
               "    prov lockslot %u %s\n", (unsigned)ctx->slot, PROV_LOCK_TOKEN);
        return false;
    }
    return true;
}

// Parse "slot [CONFIRM]": a slot number (0..15) followed by either
// nothing or exactly the CONFIRM token; report usage on anything else.
static bool parse_lockslot_args(const char *text, uint8_t *slot, bool *confirmed)
{
    uint32_t v = 0;
    int digits = 0;

    while (('0' <= *text) && (*text <= '9')) {
        v = (10u * v) + (uint32_t)(*text - '0');
        text++;
        digits++;
    }
    while (' ' == *text) {
        text++;
    }
    if ((0 == digits) || (v > ATECC608_MAX_DATA_SLOT)
        || ((text[0] != '\0') && (0 != strcmp(text, PROV_LOCK_TOKEN)))) {
        printf("usage: prov lockslot <slot 0-15> [CONFIRM]\n");
        return false;
    }
    *slot = (uint8_t)v;
    *confirmed = (0 == strcmp(text, PROV_LOCK_TOKEN));
    return true;
}

// prov lockslot <slot> [CONFIRM] — WRITE, IRREVERSIBLE for that slot:
// locks a single data slot. The chip enforces that the slot is marked
// Lockable in the (locked) config; the pre-checks below only make the
// refusal readable. Production use: slot 14 (the I/O key) — run it only
// AFTER `prov iokeytest` passes, so the key stays re-keyable until it is
// proven.
static void provLockSlot(const char *rest)
{
    struct prov_slot_lock_ctx ctx = { 0 };
    uint8_t zone[ATECC608_CONFIG_ZONE_LEN];
    atecc608_config_intent_t cfg;
    atecc608_status_t st;

    if (!parse_lockslot_args(rest, &ctx.slot, &ctx.confirmed)) {
        return;
    }
    st = atecc608_read_config_zone(zone);
    if (ATECC608_OK != st) {
        report_fail("READ CONFIG ZONE", st);
        return;
    }
    st = atecc608_config_parse(zone, &cfg);
    if (ATECC608_OK != st) {
        report_fail("PARSE CONFIG ZONE", st);
        return;
    }
    // SlotLocked polarity: bit n = 1 -> slot n UNLOCKED, 0 -> locked.
    if ((cfg.slot_locked & (uint16_t)(1u << ctx.slot)) == 0u) {
        printf("slot %u is already individually locked — nothing to do.\n",
               (unsigned)ctx.slot);
        return;
    }
    if (!cfg.key[ctx.slot].lockable) {
        printf("slot %u is not marked Lockable in the current config — the\n"
               "chip will refuse the lock. No command issued.\n",
               (unsigned)ctx.slot);
        return;
    }
    st = atecc608_lock_data_slot(ctx.slot, provLockSlotConfirm, &ctx);
    if (ATECC608_OK == st) {
        // Verify by re-reading the SlotLocked word.
        st = atecc608_read_config_zone(zone);
        if ((ATECC608_OK == st)
            && (ATECC608_OK == atecc608_config_parse(zone, &cfg))
            && ((cfg.slot_locked & (uint16_t)(1u << ctx.slot)) == 0u)) {
            printf("slot %u LOCKED (irreversible; verified by re-reading SlotLocked).\n",
                   (unsigned)ctx.slot);
            if (PROV_IO_KEY_SLOT == ctx.slot) {
                printf("the I/O key slot: it can no longer be re-keyed.\n");
            }
        } else {
            printf("the lock command succeeded, but the re-read does NOT show\n"
                   "slot %u locked — investigate before proceeding.\n",
                   (unsigned)ctx.slot);
        }
        return;
    }
    if (ATECC608_ERR_CHIP_STATE == st) {
        printf("lock aborted — nothing was locked.\n");
    } else {
        report_fail("LOCK SLOT", st);
        if (ATECC608_ERR_EXEC == st) {
            printf("the chip refused: the slot must be marked Lockable in the\n"
                   "config and not already locked.\n");
        }
    }
}

// prov kdf <slot> — READ-ONLY: derive 32 bytes with the Phase 5 KDF wrapper
// (PRF, source = data slot, target = output) — the on-hardware KDF
// round-trip that closes PLAN.md Phase 5 ("at least a KDF round-trip
// validated on hardware"). A FIXED nonce (32 bytes of zero) and a FIXED
// 16-byte message (0x00..0x0F, same as prov iokeytest) make the output
// deterministic: two runs of `prov kdf 7` must print the SAME 32 bytes.
// The I/O key comes from /io_key.bin because this chip enforces I/O
// protection on KDF (kdf_prot=1) — the wrapper decrypts the response in
// place when it carries a nonce. No data-zone reads or writes, no locks —
// safe any time the data zone is locked (the chip's own gate).
static void provKdf(const char *rest)
{
    uint8_t slot;
    uint8_t msg[16];
    uint8_t io_key[IOKEY_FILE_KEY_LEN];
    uint8_t out[ATECC608_KDF_OUT_LEN];
    atecc608_status_t st;

    if (!parse_slot_arg(rest, &slot)) {
        printf("usage: prov kdf <slot 0-15>\n");
        return;
    }
    if (!load_io_key_file(io_key)) {
        return;
    }
    for (int i = 0; i < 16; i++) {
        msg[i] = (uint8_t)i;
    }
    st = atecc608_kdf_prf(slot, NULL, msg, sizeof(msg), io_key, out);
    if (ATECC608_OK != st) {
        report_fail("KDF", st);
        if (ATECC608_ERR_EXEC == st) {
            printf("the chip refused: KDF target=output is unavailable while\n"
                   "the data zone is unlocked, or the slot is not configured\n"
                   "as a key slot.\n");
        }
        return;
    }
    printf("derived value (32 B) from slot %u (fixed zero nonce, msg 00..0F):\n",
           (unsigned)slot);
    atecc608_print_hex(out, sizeof(out));
    printf("run `prov kdf %u` again: identical output = deterministic.\n",
           (unsigned)slot);
}

// --- Phase 7: selftest — the read-only on-hardware validation suite -------
//
// Runs the GENERIC invariants of a chip carrying the agreed config
// (example/common/dev_config.h, fully locked: config zone + data zone +
// slot 14) and prints one [PASS]/[FAIL] line per check plus a final
// verdict. In full mode it then checks the bench-chip goldens (serial,
// the six public keys, the slot-7 KDF value, the config-zone CRC — the
// regression gate); `selftest generic` skips those (a fresh chip during
// bring-up). Strictly READ-ONLY — no chip writes — so it is safe at any
// time, including on production hardware (HARD RULE).

// --- bench-chip goldens (sub-step 7.2; dev-only, console example only) --
//
// Values recorded from the bench chip (serial 01 23 06 40 AE B6 B9 B7
// EE) — the RESUME.md "record of choice" entries. The generic invariants
// above prove a chip carries the AGREED config; the goldens prove it is
// THE recorded bench chip, and `selftest` (full mode) hard-FAILS on a
// mismatch: the regression gate. NOT part of the library.
#define BENCH_CRC16 0xC904u // config zone, fully locked (00 00 / FF BF)
static const uint8_t BENCH_SERIAL[ATECC608_SERIAL_LEN] = {
    0x01, 0x23, 0x06, 0x40, 0xAE, 0xB6, 0xB9, 0xB7, 0xEE,
};
// kdf_prf(slot 7, zero nonce, msg 00..0F) — the vault master derivation.
static const uint8_t BENCH_KDF[ATECC608_KDF_OUT_LEN] = {
    0x6F, 0xFF, 0x7D, 0xD6, 0x41, 0x75, 0x60, 0x3F, 0x83, 0x05, 0xCE, 0xA6, 0x20,
    0xF0, 0xB9, 0x32, 0x57, 0x29, 0x50, 0x26, 0xD9, 0xB4, 0xDF, 0x6B, 0xCC,
    0x8D, 0x6C, 0x9D, 0xC1, 0x31, 0x4C, 0x65,
};
// The six ECC public keys (slots 1, 3, 4, 5, 6, 12), X || Y big-endian,
// as printed by `prov genkey` / `prov pubkey` (GenKey mode 0x00).
static const uint8_t BENCH_PUBKEYS[6][ATECC608_PUBKEY_LEN] = {
    { /* slot 1 — device identity */
      0x1E, 0xE5, 0x07, 0xEC, 0xFC, 0x0D, 0xB2, 0x10, 0x35, 0x54, 0x32, 0xBC,
      0x2E, 0x63, 0xAB, 0x84, 0x36, 0xC3, 0x04, 0xF8, 0xC9, 0x54, 0x73, 0x95,
      0x7F, 0x02, 0xC4, 0xBF, 0x57, 0xA2, 0xC9, 0x4E, 0xDF, 0xB3, 0xA3, 0xA2,
      0x2D, 0x3E, 0x00, 0x8E, 0x89, 0xB8, 0x82, 0xBA, 0x28, 0x9D, 0xC0, 0xE5,
      0x96, 0x2D, 0xBE, 0xF9, 0x90, 0x79, 0x00, 0xDE, 0x22, 0x41, 0x9F, 0xA0,
      0xAC, 0x2D, 0x1A, 0xDB,
    },
    { /* slot 3 — FIDO2 pre-gen 1 */
      0x82, 0xB4, 0x7D, 0x03, 0xD3, 0x11, 0xA5, 0x06, 0xDB, 0xE7, 0x7B, 0x00,
      0xAD, 0x09, 0xBC, 0x31, 0xDC, 0x54, 0xEF, 0xAC, 0x19, 0x0C, 0xCB, 0x12,
      0x48, 0xC3, 0x25, 0x81, 0xCD, 0x33, 0x02, 0xF6, 0xD0, 0xB8, 0xC8, 0x8A,
      0xA9, 0xD8, 0xB3, 0x40, 0x6C, 0x74, 0xFA, 0x4B, 0x76, 0x61, 0x20, 0x5C,
      0xF4, 0x54, 0x05, 0xC1, 0x95, 0xD0, 0xCC, 0x8C, 0x3E, 0xE0, 0x7A, 0x17,
      0xA1, 0x4B, 0x69, 0x00,
    },
    { /* slot 4 — FIDO2 pre-gen 2 */
      0x63, 0x1C, 0xE7, 0x86, 0x3B, 0x57, 0x38, 0xC4, 0xAA, 0xC3, 0xDC, 0xF1,
      0xD7, 0x51, 0x69, 0x45, 0xBA, 0xE5, 0xBE, 0x47, 0x1B, 0xD3, 0x91, 0x9C,
      0x32, 0x36, 0x81, 0x87, 0xA6, 0xD8, 0xBD, 0x14, 0x14, 0xA7, 0x25, 0x76,
      0x9F, 0xFE, 0x6B, 0x96, 0x2B, 0xBF, 0x2D, 0xCB, 0xD6, 0x94, 0xF4, 0x66,
      0x46, 0x2B, 0xE6, 0xA2, 0xEA, 0x75, 0x38, 0x59, 0xEE, 0x00, 0x2D, 0x3E,
      0x0D, 0x83, 0x3C, 0x7E,
    },
    { /* slot 5 — FIDO2 pre-gen 3 */
      0x14, 0xC5, 0x66, 0x85, 0xEF, 0x86, 0xE3, 0x2E, 0x60, 0x20, 0xDC, 0x09,
      0x9C, 0xE1, 0x21, 0x83, 0x2D, 0x0C, 0x95, 0x7C, 0xCE, 0xA0, 0xC8, 0x4B,
      0x7A, 0x52, 0x44, 0x95, 0x89, 0x7D, 0xBF, 0xA7, 0x5F, 0xA0, 0x76, 0x8E,
      0xFC, 0x9B, 0x4B, 0xDD, 0xAF, 0x6D, 0x45, 0xBF, 0xFB, 0xFB, 0x6B, 0xAE,
      0x4B, 0x56, 0x0D, 0x07, 0x1C, 0xAB, 0x38, 0x8C, 0x8E, 0x5B, 0x4F, 0x83,
      0x77, 0x22, 0xB2, 0xB4,
    },
    { /* slot 6 — FIDO2 pre-gen 4 */
      0x23, 0x0A, 0x88, 0x5B, 0x6D, 0x79, 0x44, 0x1A, 0x53, 0xCF, 0x18, 0x3A,
      0xB2, 0xF5, 0xED, 0x3E, 0x8D, 0xDD, 0xD8, 0xF7, 0x7A, 0x6E, 0x0C, 0x92,
      0x81, 0xE8, 0x37, 0x0B, 0x05, 0x53, 0x5B, 0xF0, 0xE6, 0x93, 0x23, 0x8C,
      0x36, 0xAD, 0x9C, 0x9D, 0xBA, 0x9B, 0xAE, 0xE0, 0x7F, 0x25, 0x11, 0x73,
      0x6F, 0xC7, 0xC8, 0x60, 0x46, 0x12, 0xC0, 0x71, 0x3D, 0xEE, 0xE7, 0xD8,
      0x42, 0x0B, 0xFD, 0xEB,
    },
    { /* slot 12 — spare pair */
      0x1F, 0xBB, 0x53, 0x79, 0x05, 0x9B, 0xFD, 0x17, 0x2C, 0x7F, 0x25, 0xA1,
      0x6E, 0xEC, 0x7E, 0xC6, 0xBA, 0xEA, 0x85, 0x5F, 0x69, 0x0D, 0x73, 0xE9,
      0xA0, 0x93, 0xF2, 0xAB, 0x2B, 0x39, 0xDF, 0x92, 0x25, 0x3F, 0x69, 0x9B,
      0x4E, 0xE2, 0x50, 0xBE, 0xAF, 0x24, 0x5C, 0x5A, 0xA7, 0x7E, 0xCA, 0x6A,
      0xEA, 0x9E, 0xBB, 0x6B, 0x1F, 0xFF, 0x7F, 0x3A, 0xEC, 0x43, 0x59, 0x7A,
      0x21, 0x0F, 0x93, 0x63,
    },
};

// The factory RNG pattern: 0xFFFF0000 repeated. The chip's Random command
// returns it while the config zone is unlocked; a provisioned (locked)
// chip must NOT.
static bool factory_rng_pattern(const uint8_t r[32])
{
    static const uint8_t pat[4] = {0xFF, 0xFF, 0x00, 0x00};
    for (int i = 0; i < 32; i++) {
        if (pat[i % 4] != r[i]) {
            return false;
        }
    }
    return true;
}

// One suite check: prints [PASS]/[FAIL] + the short detail, tallies.
typedef struct {
    int passed;
    int failed;
} selftest_t;

static void st_report(selftest_t *st, const char *name, bool ok, const char *detail)
{
    if (ok) {
        st->passed++;
    } else {
        st->failed++;
    }
    printf("[%s] %-28s%s%s\n", ok ? "PASS" : "FAIL", name,
           detail ? ": " : "", detail ? detail : "");
}

// Append a formatted fragment to the running detail string (bounded;
// returns the new length).
static size_t st_addf(char *d, size_t size, size_t n, const char *fmt, ...)
{
    if (n + 1 < size) {
        va_list ap;
        va_start(ap, fmt);
        int w = vsnprintf(d + n, size - n, fmt, ap);
        va_end(ap);
        if (w > 0) {
            n += (size_t)w;
        }
    }
    return n;
}

// selftest — run the read-only on-hardware validation suite (Phase 7).
// Full mode (the default) runs the generic invariants and then the
// bench-chip goldens (the regression gate); `selftest generic` runs the
// invariants only (a fresh chip during bring-up — see docs/BRINGUP.md).
static void commandSelftest(char *cmdLine)
{
    // Optional "generic" sub-mode (invariants only).
    char *rest = cmdLine + strlen("selftest");
    while (' ' == *rest) {
        rest++;
    }
    bool generic = (0 == strncmp(rest, "generic", 9))
                   && ('\0' == rest[9] || ' ' == rest[9]);
    if (generic) {
        rest += 9;
        while (' ' == *rest) {
            rest++;
        }
    }
    if ('\0' != *rest) {
        printf("usage: selftest [generic]\n");
        return;
    }

    selftest_t st = {0, 0};
    char d[112];
    // Function scope: the golden section reuses the zone, the six public
    // keys and the first KDF derivation from the generic checks above.
    static const uint8_t ecc_slots[6] = {1, 3, 4, 5, 6, 12};
    uint8_t zone[ATECC608_CONFIG_ZONE_LEN];
    bool have_zone = false;
    uint8_t pubs[6][ATECC608_PUBKEY_LEN];
    uint8_t k1[ATECC608_KDF_OUT_LEN];
    bool have_k1 = false;

    // (1) probe + info — the wake handshake and part/revision. A dead
    // chip makes every later check meaningless, so the suite aborts.
    atecc608_status_t pst = atecc608_probe();
    if (ATECC608_OK != pst) {
        st_report(&st, "probe + info", false, "chip not responsive (aborting)");
        printf("SELFTEST: %d of %d checks passed — ABORTED, no further checks possible\n",
               st.passed, st.passed + st.failed);
        return;
    }
    atecc608_info_t info = {0, 0};
    atecc608_status_t ist = atecc608_info(&info);
    if (ATECC608_OK != ist || 0x60 != info.part || 5 != info.revision) {
        st_addf(d, sizeof(d), 0, "part 0x%02X rev %u (want part 0x60 rev 5)",
                (unsigned)info.part, (unsigned)info.revision);
        st_report(&st, "probe + info", false, d);
    } else {
        st_report(&st, "probe + info", true, "wake ok, part 0x60 rev 5");
    }

    // (2) chip TRNG: two 32-B fetches, not the factory 0xFFFF0000
    // pattern, not byte-identical to each other.
    uint8_t r1[32];
    uint8_t r2[32];
    atecc608_status_t s1 = atecc608_random(r1, sizeof(r1));
    atecc608_status_t s2 = ATECC608_OK == s1 ? atecc608_random(r2, sizeof(r2)) : s1;
    if (ATECC608_OK != s1 || ATECC608_OK != s2) {
        st_addf(d, sizeof(d), 0, "random call failed: %s",
                atecc608_status_str(ATECC608_OK == s1 ? s2 : s1));
        st_report(&st, "random (TRNG)", false, d);
    } else if (factory_rng_pattern(r1)) {
        st_report(&st, "random (TRNG)", false,
                  "factory 0xFFFF0000 pattern (config zone unlocked?)");
    } else if (0 == memcmp(r1, r2, sizeof(r1))) {
        st_report(&st, "random (TRNG)", false, "two fetches byte-identical");
    } else {
        st_report(&st, "random (TRNG)", true, "32 B, real random, fetches differ");
    }

    // (3) config zone: parses, fully locked (00 00), slot 14 locked
    // (FF BF), the agreed I2C address, and byte-identical to the agreed
    // image over the writable region.
    if (ATECC608_OK != atecc608_read_config_zone(zone)) {
        st_report(&st, "config zone", false, "zone read failed");
    } else {
        have_zone = true;
        atecc608_config_intent_t cfg;
        if (ATECC608_OK != atecc608_config_parse(zone, &cfg)) {
            st_report(&st, "config zone", false, "parse rejected the zone");
        } else {
            bool ok = true;
            size_t n = 0;
            if (0x00 != zone[86] || 0x00 != zone[87]) {
                ok = false;
                n = st_addf(d, sizeof(d), n, "lock bytes %02X %02X (want 00 00); ",
                            zone[86], zone[87]);
            }
            if (0xFF != zone[88] || 0xBF != zone[89]) {
                ok = false;
                n = st_addf(d, sizeof(d), n, "SlotLocked %02X %02X (want FF BF); ",
                            zone[88], zone[89]);
            }
            if (0xC0 != zone[16]) {
                ok = false;
                n = st_addf(d, sizeof(d), n, "I2C byte 0x%02X (want C0); ", zone[16]);
            }
            uint8_t plan[ATECC608_CONFIG_ZONE_LEN];
            uint32_t diff[4] = {0, 0, 0, 0};
            if (!planned_image(zone, plan)) {
                ok = false;
                n = st_addf(d, sizeof(d), n, "planned image build failed");
            } else if (!atecc608_config_writable_equal(zone, plan, diff)) {
                ok = false;
                int first = -1;
                int last = -1;
                for (int i = 0; i < ATECC608_CONFIG_ZONE_LEN; i++) {
                    if (diff[i / 32] & (1u << (i % 32))) {
                        if (first < 0) {
                            first = i;
                        }
                        last = i;
                    }
                }
                n = st_addf(d, sizeof(d), n,
                            "differs from the agreed image at bytes %d..%d", first, last);
            }
            st_report(&st, "config zone", ok,
                      ok ? "locked 00 00, SlotLocked FF BF, I2C C0, zero diff vs agreed image"
                         : d);
        }
    }

    // (4) counters: both read 0 via the counter-read API (nothing has
    // incremented them).
    uint32_t c0 = 0;
    uint32_t c1 = 0;
    atecc608_status_t c0st = atecc608_counter_read(0, &c0);
    atecc608_status_t c1st = ATECC608_OK == c0st ? atecc608_counter_read(1, &c1) : c0st;
    if (ATECC608_OK != c0st || ATECC608_OK != c1st) {
        st_addf(d, sizeof(d), 0, "counter read failed: %s",
                atecc608_status_str(ATECC608_OK == c0st ? c1st : c0st));
        st_report(&st, "counters", false, d);
    } else if (0 != c0 || 0 != c1) {
        st_addf(d, sizeof(d), 0, "counter 0 = %lu, counter 1 = %lu (want 0 / 0)",
                (unsigned long)c0, (unsigned long)c1);
        st_report(&st, "counters", false, d);
    } else {
        st_report(&st, "counters", true, "counter 0 = 0, counter 1 = 0");
    }

    // (5) the six ECC private keys (agreed layout): readable via
    // get_pubkey (mode 0x00 works after the data-zone lock), 64 B,
    // non-zero, pairwise distinct. (The golden section below compares
    // them against the bench chip's recorded keys.)
    {
        bool ok = true;
        for (int i = 0; i < 6 && ok; i++) {
            memset(pubs[i], 0, sizeof(pubs[i]));
            atecc608_status_t gst = atecc608_get_pubkey(ecc_slots[i], pubs[i]);
            if (ATECC608_OK != gst) {
                ok = false;
                st_addf(d, sizeof(d), 0, "slot %u: %s",
                        (unsigned)ecc_slots[i], atecc608_status_str(gst));
            } else {
                bool zero = true;
                for (int b = 0; b < ATECC608_PUBKEY_LEN; b++) {
                    zero = zero && (0 == pubs[i][b]);
                }
                if (zero) {
                    ok = false;
                    st_addf(d, sizeof(d), 0, "slot %u: all-zero public key",
                            (unsigned)ecc_slots[i]);
                } else {
                    for (int j = 0; j < i; j++) {
                        if (0 == memcmp(pubs[i], pubs[j], sizeof(pubs[i]))) {
                            ok = false;
                            st_addf(d, sizeof(d), 0, "slots %u and %u identical",
                                    (unsigned)ecc_slots[i], (unsigned)ecc_slots[j]);
                            break;
                        }
                    }
                }
            }
        }
        st_report(&st, "ecc pubkeys (1,3,4,5,6,12)", ok,
                  ok ? "64 B each, non-zero, pairwise distinct" : d);
    }

    // (6) KDF determinism: two PRF derivations from slot 7 (the vault
    // master in the agreed layout) with the fixed zero nonce and the
    // fixed 00..0F message must be identical. (7.2 adds the bench value.)
    uint8_t io_key[IOKEY_FILE_KEY_LEN];
    bool have_io_key = iokey_file_valid(io_key, d, sizeof(d));
    uint8_t msg[16];
    for (int i = 0; i < 16; i++) {
        msg[i] = (uint8_t)i;
    }
    if (!have_io_key) {
        st_report(&st, "kdf determinism (slot 7)", false, d);
    } else {
        uint8_t k2[ATECC608_KDF_OUT_LEN];
        atecc608_status_t k1st = atecc608_kdf_prf(7, NULL, msg, sizeof(msg), io_key, k1);
        atecc608_status_t k2st = ATECC608_OK == k1st
                                     ? atecc608_kdf_prf(7, NULL, msg, sizeof(msg), io_key, k2)
                                     : k1st;
        if (ATECC608_OK != k1st || ATECC608_OK != k2st) {
            st_addf(d, sizeof(d), 0, "kdf_prf failed: %s",
                    atecc608_status_str(ATECC608_OK == k1st ? k2st : k1st));
            st_report(&st, "kdf determinism (slot 7)", false, d);
        } else if (0 != memcmp(k1, k2, sizeof(k1))) {
            st_report(&st, "kdf determinism (slot 7)", false,
                      "two derivations differ (chip NOT deterministic)");
        } else {
            have_k1 = true;
            st_report(&st, "kdf determinism (slot 7)", true,
                      "two derivations identical (zero nonce, msg 00..0F)");
        }
    }

    // (7) I/O-key round-trip: /io_key.bin matches slot 14 (the shared
    // core of `prov iokeytest`, quiet form).
    char io_d[96];
    bool ok_io = iokey_roundtrip(false, io_d, sizeof(io_d));
    st_report(&st, "io key round-trip", ok_io,
              ok_io ? "clear vs I/O-protected KDF match (slot 14 == /io_key.bin)" : io_d);

    // (8) littlefs: the volume mounted at boot and /io_key.bin intact
    // (magic, len, CRC-32).
    if (LFS_STATE_NONE == s_lfs_state) {
        st_report(&st, "littlefs + /io_key.bin", false, "volume not mounted at boot");
    } else if (!have_io_key) {
        st_report(&st, "littlefs + /io_key.bin", false, d);
    } else {
        st_report(&st, "littlefs + /io_key.bin", true,
                  LFS_STATE_FRESH == s_lfs_state
                      ? "volume fresh, /io_key.bin valid (magic, len, CRC-32)"
                      : "volume survived the last reflash, /io_key.bin valid");
    }

    // --- bench-chip goldens (full mode only) ------------------------------
    // The checks above prove the chip carries the AGREED config; the
    // goldens prove it is THE recorded bench chip. A mismatch hard-FAILs:
    // this is the regression gate (PLAN.md, Phase 7).
    if (!generic) {
        // G1 — the recorded factory serial.
        uint8_t sn[ATECC608_SERIAL_LEN];
        if (ATECC608_OK != atecc608_serial(sn)) {
            st_report(&st, "golden: serial (bench)", false, "serial read failed");
        } else if (0 != memcmp(sn, BENCH_SERIAL, sizeof(sn))) {
            st_addf(d, sizeof(d), 0, "serial %02X %02X %02X %02X … (bench %02X %02X %02X %02X …)",
                    sn[0], sn[1], sn[2], sn[3],
                    BENCH_SERIAL[0], BENCH_SERIAL[1], BENCH_SERIAL[2], BENCH_SERIAL[3]);
            st_report(&st, "golden: serial (bench)", false, d);
        } else {
            st_report(&st, "golden: serial (bench)", true,
                      "matches the bench record (01 23 06 40 …)");
        }

        // G2 — the six recorded ECC public keys (a failed generic read
        // leaves that slot zeroed and shows up as a mismatch here).
        bool ok = true;
        size_t n = 0;
        for (int i = 0; i < 6; i++) {
            if (0 != memcmp(pubs[i], BENCH_PUBKEYS[i], ATECC608_PUBKEY_LEN)) {
                ok = false;
                n = st_addf(d, sizeof(d), n, "%s%u", 0 == n ? "" : ", ",
                            (unsigned)ecc_slots[i]);
            }
        }
        st_report(&st, "golden: ecc pubkeys (bench)", ok,
                  ok ? "all six match the bench record" : d);

        // G3 — the recorded slot-7 KDF derivation value.
        if (!have_k1) {
            st_report(&st, "golden: kdf value (bench)", false,
                      have_io_key ? "derivation failed (see above)" : d);
        } else if (0 != memcmp(k1, BENCH_KDF, sizeof(k1))) {
            int first = 0;
            while (first < ATECC608_KDF_OUT_LEN && k1[first] == BENCH_KDF[first]) {
                first++;
            }
            st_addf(d, sizeof(d), 0,
                    "differs from the bench value (first diff at byte %d)", first);
            st_report(&st, "golden: kdf value (bench)", false, d);
        } else {
            st_report(&st, "golden: kdf value (bench)", true,
                      "matches the bench value (6F FF 7D D6 …)");
        }

        // G4 — the recorded config-zone CRC (the fully-locked zone).
        if (!have_zone) {
            st_report(&st, "golden: config CRC (bench)", false,
                      "zone read failed (see above)");
        } else {
            uint16_t crc = atecc608_config_crc16(zone);
            if (BENCH_CRC16 != crc) {
                st_addf(d, sizeof(d), 0, "CRC %04X (bench %04X)",
                        (unsigned)crc, (unsigned)BENCH_CRC16);
                st_report(&st, "golden: config CRC (bench)", false, d);
            } else {
                st_report(&st, "golden: config CRC (bench)", true,
                          "C904 — matches the bench record");
            }
        }
    }

    const int total = st.passed + st.failed;
    if (0 == st.failed) {
        printf("SELFTEST: %d/%d checks PASSED%s\n", total, total,
               generic ? " (generic mode — bench goldens not run)" : "");
    } else {
        printf("SELFTEST: %d of %d checks FAILED (see the [FAIL] lines)\n",
               st.failed, total);
    }
}

// Consume the whole word w at the start of *pline (it must be followed by
// a space or end-of-line); advance past it and any following spaces.
static bool take_word(char **pline, const char *w)
{
    char *line = *pline;
    const size_t n = strlen(w);
    if ((0 != strncmp(line, w, n)) || ((line[n] != '\0') && (line[n] != ' '))) {
        return false;
    }
    line += n;
    while (' ' == *line) {
        line++;
    }
    *pline = line;
    return true;
}

static void commandProv(char *cmdLine)
{
    char *rest = cmdLine + strlen("prov");
    while (' ' == *rest) {
        rest++;
    }
    if (take_word(&rest, "status")) {
        provStatus();
    } else if (take_word(&rest, "randtest")) {
        provRandtest();
    } else if (take_word(&rest, "iokey")) {
        provIokey();
    } else if (take_word(&rest, "iokeytest")) {
        provIokeyTest();
    } else if (take_word(&rest, "iokeyshow")) {
        provIokeyShow();
    } else if (take_word(&rest, "config")) {
        provConfig();
    } else if (take_word(&rest, "lock")) {
        provLock(rest);
    } else if (take_word(&rest, "lockdata")) {
        provLockData(rest);
    } else if (take_word(&rest, "lockslot")) {
        provLockSlot(rest);
    } else if (take_word(&rest, "genkey")) {
        provGenkey(rest);
    } else if (take_word(&rest, "pubkey")) {
        provPubkey(rest);
    } else if (take_word(&rest, "kdf")) {
        provKdf(rest);
    } else {
        printf("usage: prov status | prov randtest | prov iokey | prov iokeytest"
               " | prov iokeyshow | prov config | prov lock [CONFIRM] | prov genkey <slot>"
               " | prov pubkey <slot> | prov kdf <slot> | prov lockdata [CONFIRM]"
               " | prov lockslot <slot> [CONFIRM]\n");
    }
}

static void commandUnknown(char *cmdLine)
{
    printf("Unknown command. Try 'help'.\n");
}

// Command table; the entry with a NULL name is the "unknown command" handler.
static struct command_t commands[] = {
    {NULL, commandUnknown},
    {"help", commandHelp},
    {"bootrom", commandBootrom},
    {"probe", commandProbe},
    {"diag", commandDiag},
    {"random", commandRandom},
    {"info", commandInfo},
    {"serial", commandSerial},
    {"lock", commandLock},
    {"config", commandConfig},
    {"selftest", commandSelftest},
    {"prov", commandProv},
};

// core1 entry point: the command handlers (and their littlefs writes) run
// on this core. Both cores must be initialized as flash lockout "victims"
// so that a core inside flash_safe_execute() can stop the other one
// during program/erase — required whenever multicore_launch_core1() is
// used (SDK: pico/flash.h). Without it, flash_safe_execute() on the
// calling core returns PICO_ERROR_NOT_PERMITTED, which surfaces as
// LFS_ERR_IO from littlefs: every flash-backed write from the console
// (e.g. `prov iokey` saving /io_key.bin) fails while reads still work.
static void core1_main(void)
{
    flash_safe_execute_core_init();
    commandProcessor();
}

int main(void) {
    initPicoStdio();

    // See core1_main: make core0 a flash lockout victim too. Called before
    // multicore_launch_core1() so core1's first flash_safe_execute() finds
    // core0 ready (the boot-time littlefs format below works even without
    // it — core1 is not running yet — but keep the standard order).
    flash_safe_execute_core_init();

    atecc608_status_t st = atecc608_init(&s_cfg);
    if (ATECC608_OK == st) {
        printf("pico-atecc608 ready: ATECC608 on I2C0 GP20/GP21 @ 0x%02X, %lu Hz.\n",
               s_cfg.addr, (unsigned long)s_cfg.baud);
    } else {
        printf("ATECC608 init failed: %s (ATCA_STATUS %d)\n",
               atecc608_status_str(st), (int)atecc608_last_error());
    }

    // Pico-side persistence (littlefs, flash @ 0x80000): /io_key.bin for
    // now; /vault.db and /fido2.db later (see example/README.md).
    if (0 == pico_lfs_init(NULL)) {
        // Mount the existing volume first; a failure means the volume is
        // fresh (first boot, or a full-flash erase) and pico_lfs_mount()
        // formats it. A normal uf2 reflash does NOT reach this branch — the
        // app region and the littlefs volume (flash 0x80000+) are disjoint, so
        // the existing volume mounts and /io_key.bin survives.
        if (0 != pico_lfs_mount_existing()) {
            printf("littlefs: no formatted volume — formatting (one-time; can take a while)...\n");
            if (0 != pico_lfs_mount()) {
                printf("littlefs mount FAILED — %s persistence unavailable.\n", IOKEY_FILE_PATH);
            } else {
                s_lfs_state = LFS_STATE_FRESH;
                printf("littlefs: fresh volume formatted.\n");
            }
        } else {
            s_lfs_state = LFS_STATE_EXISTING;
        }
        if (pico_lfs_is_mounted()) {
            struct lfs_info fi;
            if (0 != pico_lfs_stat(IOKEY_FILE_PATH, &fi)) {
                printf("WARNING: %s not found (first boot, or a full-flash erase — a\n"
                       "         normal uf2 reflash preserves the volume). If the chip is\n"
                       "         already provisioned, re-run `prov iokey` and re-record the key.\n",
                       IOKEY_FILE_PATH);
            }
        }
    } else {
        printf("littlefs init FAILED — %s persistence unavailable.\n", IOKEY_FILE_PATH);
    }

    // The command processor (core1) blocks on a semaphore, so it must be
    // initialized before the core is launched.
    initCommandProcessor(commands, sizeof(commands) / sizeof(commands[0]));
    multicore_launch_core1(core1_main);
    picoConsole();
}

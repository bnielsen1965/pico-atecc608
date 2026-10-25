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
//   prov config    - WRITE: agreed intent -> config zone (byte 16 +
//                    SlotLocked 88..89 preserved), read-back verified;
//                    idempotent
//   prov lock      - WRITE, IRREVERSIBLE: verify zone vs intent -> typed
//                    confirm -> Lock with the summary CRC
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
#include "atecc608/atecc608_prov.h"
#include "dev_config.h"
// The I/O-key functional test (prov iokeytest) uses the raw KDF command and
// the host-side I/O decrypt. The module API has no KDF wrapper yet (Phase 5
// is "on demand"), so this example reaches into cryptoauthlib directly —
// fine here because it is a diagnostic, not a library feature.
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

#define PROV_IOKEY_PATH   "/io_key.bin"
#define PROV_IOKEY_LEN    32
#define PROV_IOKEY_MAGIC  0x494F4B31u  // 'I''O''K''1'
#define PROV_LOCK_TOKEN   "CONFIRM"
#define PROV_IO_KEY_SLOT  14

// /io_key.bin: magic, length, key, and a CRC-32 over all preceding bytes.
typedef struct {
    uint32_t magic;
    uint32_t len;
    uint8_t  key[PROV_IOKEY_LEN];
    uint32_t crc32;
} iokey_file_t;

// littlefs volume state, recorded at boot in main(). Distinguishes a volume
// that SURVIVED the last reflash (an existing volume mounted) from one that
// had to be formatted (first boot, or a full-flash erase). A normal uf2 reflash
// writes only the app region (flash 0x0..~0x19000) and never touches the
// littlefs volume (flash offset 0x80000), so the volume — and /io_key.bin —
// normally survive; only a full-flash erase (or an app that grows past
// 0x80000) loses them.
enum { LFS_STATE_NONE = 0, LFS_STATE_EXISTING = 1, LFS_STATE_FRESH = 2 };
static int s_lfs_state = LFS_STATE_NONE;

// Standard reflected CRC-32 (poly 0xEDB88320, init/xorout 0xFFFFFFFF).
static uint32_t crc32_buf(const uint8_t *buf, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int)(crc & 1u)));
        }
    }
    return crc ^ 0xFFFFFFFFu;
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
    printf("prov status   - chip state + config zone + diff + /io_key.bin persistence\n");
    printf("prov randtest - chip RNG x2 (0xFFFF0000 pattern while unlocked)\n");
    printf("prov iokey    - Pico TRNG -> slot 14 (after prov lock) -> print -> save\n");
    printf("prov iokeytest- verify slot 14's I/O key via an I/O-protected KDF\n");
    printf("                (read-only; uses the key saved in /io_key.bin)\n");
    printf("prov config   - write the agreed config zone (idempotent)\n");
    printf("prov lock     - LOCK the config zone (IRREVERSIBLE; add CONFIRM)\n");
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
               PROV_IOKEY_PATH);
        return;
    }
    printf("littlefs volume: %s\n",
           (LFS_STATE_FRESH == s_lfs_state)
               ? "formatted fresh at boot (first boot or a full-flash erase)"
               : "mounted existing (survived the last reflash)");

    struct lfs_info fi;
    if (0 != pico_lfs_stat(PROV_IOKEY_PATH, &fi)) {
        printf("  %s: MISSING%s\n", PROV_IOKEY_PATH,
               (LFS_STATE_FRESH == s_lfs_state)
                   ? " — expected on a fresh volume"
                   : " — the volume survived but the file is gone");
        printf("  if the chip is provisioned, re-run `prov iokey` and re-record the key.\n");
        return;
    }
    iokey_file_t f;
    int rd = pico_lfs_read_file(PROV_IOKEY_PATH, (uint8_t *)&f, sizeof(f));
    bool ok = (sizeof(f) == (size_t)rd)
           && (PROV_IOKEY_MAGIC == f.magic)
           && (PROV_IOKEY_LEN == f.len)
           && (crc32_buf((const uint8_t *)&f, offsetof(iokey_file_t, crc32)) == f.crc32);
    if (!ok) {
        printf("  %s: present but CORRUPT (size %d, magic/len/CRC mismatch) — re-run `prov iokey`\n",
               PROV_IOKEY_PATH, rd);
        return;
    }
    printf("  %s: present and valid (%u B key, magic + len + CRC ok)\n", PROV_IOKEY_PATH, f.len);
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
    uint8_t key[PROV_IOKEY_LEN];
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
    for (int i = 0; i < PROV_IOKEY_LEN / 4; i++) {
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
    f.magic = PROV_IOKEY_MAGIC;
    f.len   = PROV_IOKEY_LEN;
    memcpy(f.key, key, sizeof(key));
    f.crc32 = crc32_buf((const uint8_t *)&f, offsetof(iokey_file_t, crc32));
    if (0 != pico_lfs_write_file(PROV_IOKEY_PATH, (const uint8_t *)&f, sizeof(f))) {
        printf("saving %s FAILED — the key is on the chip; re-save later.\n",
               PROV_IOKEY_PATH);
        return;
    }
    iokey_file_t rd;
    if ((sizeof(f) != (size_t)pico_lfs_read_file(PROV_IOKEY_PATH, (uint8_t *)&rd, sizeof(rd)))
        || (0 != memcmp(&f, &rd, sizeof(f)))) {
        printf("saved %s FAILED read-back verify.\n", PROV_IOKEY_PATH);
        return;
    }
    printf("saved to littlefs: %s (read-back verified)\n", PROV_IOKEY_PATH);
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
//   5. PASS iff out_clear == the decrypted out_enc: the key in slot 14
//      (chip) matches the saved key, and I/O protection works end-to-end.
// It issues no data-zone READ/WRITE and no write/lock — safe to run any time
// after `prov iokey`. Same pattern as cryptoauthlib's own
// kdf_prf_output_encrypted, but the key comes from littlefs instead of a
// hard-coded global. CAVEAT: that test runs against a config with the data
// zone LOCKED; if this chip's KDF (target=output) is also gated on the data
// zone / key lock, the KDF call fails and we print the exact ATCA_STATUS so
// that case is distinguishable from a key mismatch.
static void provIokeyTest(void)
{
    // 1. Load the saved I/O key.
    iokey_file_t f;
    int rd = pico_lfs_read_file(PROV_IOKEY_PATH, (uint8_t *)&f, sizeof(f));
    if ((int)sizeof(f) != rd
        || PROV_IOKEY_MAGIC != f.magic
        || PROV_IOKEY_LEN != f.len) {
        printf("cannot load the I/O key: %s is missing or corrupt — run\n"
               "`prov iokey` first.\n", PROV_IOKEY_PATH);
        return;
    }
    if (crc32_buf((const uint8_t *)&f, offsetof(iokey_file_t, crc32)) != f.crc32) {
        printf("cannot load the I/O key: %s CRC-32 mismatch — run\n"
               "`prov iokey` first.\n", PROV_IOKEY_PATH);
        return;
    }

    // Chip lock state, printed for context if a KDF below is refused (see the
    // data-zone/key-lock caveat in the failure message). I/O protection is
    // active only with the config zone locked; the data zone and slot 14's
    // individual lock are the states cryptoauthlib's own I/O-protected KDF
    // test keeps locked.
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
    }

    // 2-3. A fixed, deterministic input shared by both KDF runs: a 32-byte
    // nonce (the PRF source, loaded into tempkey) and a 16-byte message.
    uint8_t nonce[32];
    for (int i = 0; i < 32; i++) {
        nonce[i] = (uint8_t)i;
    }
    uint8_t msg[16];
    for (int i = 0; i < 16; i++) {
        msg[i] = (uint8_t)i;
    }
    uint8_t out_clear[64];
    uint8_t out_enc[64];
    uint8_t out_nonce[32];
    // PRF, 32-byte source key, 64-byte target, no AEAD processing, 16-byte
    // message (its length lives in bits 24..31 of the details word).
    uint32_t details = KDF_DETAILS_PRF_KEY_LEN_32
                     | KDF_DETAILS_PRF_TARGET_LEN_64
                     | KDF_DETAILS_PRF_AEAD_MODE0
                     | ((uint32_t)sizeof(msg) << 24);
    const uint8_t mode = KDF_MODE_ALG_PRF | KDF_MODE_SOURCE_TEMPKEY;
    ATCA_STATUS atca;

    atca = atcab_nonce(nonce);
    if (ATCA_SUCCESS != atca) {
        printf("NONCE (clear) failed: ATCA_STATUS %d\n", (int)atca);
        return;
    }
    atca = atcab_kdf(mode | KDF_MODE_TARGET_OUTPUT, 0x1234, details,
                     msg, out_clear, NULL);
    if (ATCA_SUCCESS != atca) {
        printf("clear KDF failed: ATCA_STATUS %d\n", (int)atca);
        printf("if ATCA_STATUS is -12 (execution error), the KDF is likely\n"
               "gated on the data-zone/key lock: cryptoauthlib's own\n"
               "I/O-protected KDF test runs against a data-zone-LOCKED config.\n"
               "The key is still on the chip — re-test after locking the data\n"
               "zone (or slot 14). This is NOT a key mismatch.\n");
        return;
    }

    atca = atcab_nonce(nonce);
    if (ATCA_SUCCESS != atca) {
        printf("NONCE (enc) failed: ATCA_STATUS %d\n", (int)atca);
        return;
    }
    atca = atcab_kdf(mode | KDF_MODE_TARGET_OUTPUT_ENC, 0x1234, details,
                     msg, out_enc, out_nonce);
    if (ATCA_SUCCESS != atca) {
        printf("encrypted KDF failed: ATCA_STATUS %d\n", (int)atca);
        printf("(same data-zone/key-lock caveat as above if this is -12)\n");
        return;
    }

    // 4. Decrypt the encrypted output with the saved key (in place).
    atca_io_decrypt_in_out_t dec = {
        .io_key    = f.key,
        .out_nonce = out_nonce,
        .data      = out_enc,
        .data_size = sizeof(out_enc),
    };
    atca = atcah_io_decrypt(&dec);
    if (ATCA_SUCCESS != atca) {
        printf("I/O decrypt failed: ATCA_STATUS %d\n", (int)atca);
        return;
    }

    // 5. Compare the clear result with the decrypted encrypted result.
    if (0 == memcmp(out_clear, out_enc, sizeof(out_clear))) {
        printf("I/O key test PASSED: slot 14 matches %s and the I/O-\n"
               "protection path works (clear KDF == decrypted KDF).\n", PROV_IOKEY_PATH);
        printf("clear KDF (64 B): ");
        atecc608_print_hex(out_clear, sizeof(out_clear));
    } else {
        printf("I/O key test FAILED: the decrypted KDF does not match the clear\n"
               "KDF — the key in slot 14 does NOT match %s.\n", PROV_IOKEY_PATH);
        printf("clear KDF:     ");
        atecc608_print_hex(out_clear, sizeof(out_clear));
        printf("decrypted KDF: ");
        atecc608_print_hex(out_enc, sizeof(out_enc));
        printf("re-run `prov iokey` to re-key slot 14 (safe: the data zone is\n"
               "still unlocked).\n");
    }
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
    } else if (take_word(&rest, "config")) {
        provConfig();
    } else if (take_word(&rest, "lock")) {
        provLock(rest);
    } else {
        printf("usage: prov status | prov randtest | prov iokey | prov iokeytest"
               " | prov config | prov lock [CONFIRM]\n");
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
                printf("littlefs mount FAILED — %s persistence unavailable.\n", PROV_IOKEY_PATH);
            } else {
                s_lfs_state = LFS_STATE_FRESH;
                printf("littlefs: fresh volume formatted.\n");
            }
        } else {
            s_lfs_state = LFS_STATE_EXISTING;
        }
        if (pico_lfs_is_mounted()) {
            struct lfs_info fi;
            if (0 != pico_lfs_stat(PROV_IOKEY_PATH, &fi)) {
                printf("WARNING: %s not found (first boot, or a full-flash erase — a\n"
                       "         normal uf2 reflash preserves the volume). If the chip is\n"
                       "         already provisioned, re-run `prov iokey` and re-record the key.\n",
                       PROV_IOKEY_PATH);
            }
        }
    } else {
        printf("littlefs init FAILED — %s persistence unavailable.\n", PROV_IOKEY_PATH);
    }

    // The command processor (core1) blocks on a semaphore, so it must be
    // initialized before the core is launched.
    initCommandProcessor(commands, sizeof(commands) / sizeof(commands[0]));
    multicore_launch_core1(core1_main);
    picoConsole();
}

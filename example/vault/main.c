/*
 * vault - a PIN-gated password store demo built on the ATECC608
 * (example/README.md "vault" scenario). It demonstrates the chip's role
 * in a password store; it is not a full password manager.
 *
 * Wiring (same as the console example):
 *   I2C0  GP20 (SDA), GP21 (SCL)  -> ATECC608C SDA/SCL (pull-ups to 3V3)
 *   UART0 GP0  (TX),  GP1 (RX)    -> USB-serial console
 *   USB   flashing / optional CDC console
 *
 * Division of labour (agreed design):
 *   chip = key master, not a bulk cipher. The master key in data slot 7
 *          is secret and never leaves the chip. Each unlock is a KDF
 *          (PRF mode) with the fixed (zero) TempKey nonce, so the derived
 *          key is identical for every attempt at the same salt+PIN:
 *              derived = PRF(slot 7, salt || PIN)
 *          where salt comes from the entry (chip RNG, at add time). With
 *          kdf_prot=1 the chip returns the derived key I/O-encrypted
 *          (slot 14 key); the module decrypts it in transit, so the key
 *          never appears in clear on the bus.
 *   Pico = bulk cipher: AES-256-GCM over the password (vault_gcm.c —
 *          software, host-verified against NIST GCM vectors; this
 *          pico-sdk fork has no hardware_crypto module, and the ATECC608
 *          performs no AES at all).
 *
 * A wrong PIN derives a wrong key, so the GCM auth tag fails and `get`
 * can only report "wrong PIN or corrupted entry" — the two are
 * deliberately not distinguished. The entry name is bound as GCM AAD, so
 * ciphertexts cannot be swapped between entries or renamed.
 *
 * Entry layout: one littlefs file per entry, /v_<name>. Upstream
 * pico-littlefs has no mkdir, so entries sit flat at the volume root
 * next to /io_key.bin. Fixed 96-byte record:
 *   u32     magic   'VAU1'
 *   u8[16]  salt    chip RNG at add time (not secret)
 *   u8[12]  nonce   GCM IV, chip RNG at add time (not secret)
 *   u32     pt_len  password length
 *   u8[40]  ct      GCM ciphertext (first pt_len bytes valid)
 *   u8[16]  tag     GCM auth tag
 *   u32     crc32   standard reflected CRC-32 over all preceding bytes
 *
 * Startup contract (example/README.md): the chip must already be
 * provisioned per docs/BRINGUP.md — config and data zones LOCKED (a KDF
 * with target=output is gated on the data-zone lock) and /io_key.bin
 * present (written by the console app's `prov iokey`). If anything is
 * missing, this app says what is missing and where to get it; it does
 * NOT provision the chip itself — the console example is the provisioner.
 *
 * Note: the reference chip's slot 7 holds all-zero factory content
 * (the data zone is locked, so it never gets re-keyed). The demo works
 * with it as-is; a real deployment provisions a random master into slot 7
 * during bring-up, before the data-zone lock.
 *
 * Demo caveats:
 *   - the console echoes what you type: the PIN and password are visible
 *     on the serial console;
 *   - `get` prints the password to the console. That is the point of
 *     the demo.
 *
 * Commands:
 *   help                          - this list
 *   probe                         - chip presence check (wake handshake)
 *   bootrom                       - reset into BOOTSEL mode (USB bootloader)
 *   list                          - list stored entries
 *   add <name> <pin> <password>   - encrypt + store; replaces an existing
 *                                   entry (fresh salt/nonce each time)
 *   get <name> <pin>              - decrypt + print the password
 *   dump <name>                   - show the RAW stored entry (no PIN):
 *                                   the 96 flash bytes as text, non-
 *                                   printable as '?' — a plaintext leak
 *                                   would stand out as readable text
 *   rm <name>                     - delete the entry
 *
 * Limits: name 1..16 chars from [A-Za-z0-9._-]; PIN 1..24 ASCII;
 * password 1..40 ASCII (no spaces — the command line is one buffer).
 */

#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/flash.h"
#include "pico/bootrom.h"
#include "hardware/gpio.h"
#include "pico-command-line.h"
#include "pico_littlefs.h"

#include "atecc608/atecc608.h"
#include "atecc608/atecc608_crypto.h"
#include "iokey_file.h"
#include "vault_gcm.h"

// Same bench wiring as the console example (see its header).
#define I2C_BUS     i2c0
#define I2C_SDA_PIN 20
#define I2C_SCL_PIN 21

static atecc608_cfg_t s_cfg = {
    .i2c     = I2C_BUS,
    .sda_pin = I2C_SDA_PIN,
    .scl_pin = I2C_SCL_PIN,
    .addr    = ATECC608_ADDR_ADR_LOW,
    .baud    = ATECC608_FAST_BAUD_HZ,
};

// --- vault geometry ----------------------------------------------------------

// KDF master: data slot 7 (secret; never leaves the chip). The reference
// chip's slot 7 is all-zero factory content — see the header note.
#define VAULT_MASTER_SLOT 7

#define VAULT_SALT_LEN    16
#define VAULT_NONCE_LEN   12              // == VAULT_GCM_NONCE_LEN
#define VAULT_NAME_MAX    16
#define VAULT_PIN_MAX     24              // KDF msg = salt || PIN (40 B) <= 128
#define VAULT_PASS_MAX    40
#define VAULT_MAGIC       0x31554156u     // 'V''A''U''1'
#define VAULT_FILE_PREFIX "v_"

// One fixed-size littlefs file per entry (96 bytes).
typedef struct {
    uint32_t magic;
    uint8_t  salt[VAULT_SALT_LEN];
    uint8_t  nonce[VAULT_NONCE_LEN];
    uint32_t pt_len;
    uint8_t  ct[VAULT_PASS_MAX];
    uint8_t  tag[VAULT_GCM_TAG_LEN];
    uint32_t crc32;                       // over all preceding bytes
} vault_entry_t;

// Startup-contract state, recorded in main().
static bool    s_chip_present  = false;
static bool    s_zones_locked  = false;
static bool    s_io_key_loaded = false;
static uint8_t s_io_key[IOKEY_FILE_KEY_LEN];

// --- helpers -------------------------------------------------------------------

static void entry_path(const char *name, char *path, size_t path_size)
{
    snprintf(path, path_size, "/%s%s", VAULT_FILE_PREFIX, name);
}

static bool valid_name(const char *name)
{
    size_t n = strlen(name);
    if ((n < 1) || (n > VAULT_NAME_MAX)) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || (c == '.') || (c == '_') || (c == '-'))) {
            return false;
        }
    }
    return true;
}

// Split rest (modified in place) into at most max space-separated tokens;
// returns the number found (leading/multiple spaces tolerated).
static int split_words(char *rest, int max, char **tok)
{
    int n = 0;
    while (*rest && (n < max)) {
        while (*rest == ' ') {
            rest++;
        }
        if (!*rest) {
            break;
        }
        tok[n++] = rest;
        while (*rest && (*rest != ' ')) {
            rest++;
        }
        if (*rest) {
            *rest++ = '\0';
        }
    }
    return n;
}

// The startup contract: chip present, config+data zones locked (the KDF
// target=output gate), and the I/O key loaded. Prints what is missing and
// where to get it; never provisions.
static bool vault_ready(void)
{
    if (!s_chip_present) {
        printf("ATECC608 not found on the bus (see `probe`) — nothing to do.\n");
        return false;
    }
    if (!s_zones_locked) {
        printf("chip not provisioned (config/data zones not locked) — flash the\n"
               "       console app and run the docs/BRINGUP.md sequence first.\n");
        return false;
    }
    if (!s_io_key_loaded) {
        printf("I/O key missing — flash the console app and run `prov iokey` first.\n");
        return false;
    }
    return true;
}

// derived = PRF(slot 7, zero nonce, salt || PIN); I/O-encrypted in transit
// and decrypted by the module (kdf_prot=1).
static bool vault_derive_key(const uint8_t salt[VAULT_SALT_LEN],
                             const char *pin, size_t pin_len,
                             uint8_t key[VAULT_GCM_KEY_LEN])
{
    uint8_t msg[VAULT_SALT_LEN + VAULT_PIN_MAX];
    memcpy(msg, salt, VAULT_SALT_LEN);
    memcpy(msg + VAULT_SALT_LEN, pin, pin_len);
    atecc608_status_t st = atecc608_kdf_prf(VAULT_MASTER_SLOT, NULL, msg,
                                            (uint8_t)(VAULT_SALT_LEN + pin_len),
                                            s_io_key, key);
    if (ATECC608_OK != st) {
        printf("KDF failed: %s (ATCA_STATUS %d)\n",
               atecc608_status_str(st), (int)atecc608_last_error());
        return false;
    }
    return true;
}

// --- commands --------------------------------------------------------------------

static void commandHelp(char *cmdLine)
{
    (void)cmdLine;
    printf("vault: ATECC608 PIN-gated password store demo (I2C0 GP20/GP21 @ 0x%02X)\n",
           s_cfg.addr);
    printf("help  - display this message\n");
    printf("probe - chip presence check (wake handshake)\n");
    printf("bootrom - reset into BOOTSEL mode (USB bootloader)\n");
    printf("list  - list stored entries\n");
    printf("add <name> <pin> <password> - encrypt + store (replaces an entry)\n");
    printf("get <name> <pin> - decrypt + print the password\n");
    printf("dump <name> - show the raw stored entry ('?' = non-printable byte)\n");
    printf("rm <name> - delete the entry\n");
    printf("note: input is echoed, and get prints the password — that is the demo.\n");
}

static void commandUnknown(char *cmdLine)
{
    (void)cmdLine;
    printf("Unknown command. Try 'help'.\n");
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

// pico_lfs_list callback: print the vault entries.
static int list_cb(const pico_lfs_entry_t *entry, void *user)
{
    int *count = (int *)user;
    if ((!entry->is_dir) &&
        (0 == strncmp(entry->name, VAULT_FILE_PREFIX, strlen(VAULT_FILE_PREFIX)))) {
        printf("  %s\n", entry->name + strlen(VAULT_FILE_PREFIX));
        (*count)++;
    }
    return 0;  // continue
}

static void commandList(char *cmdLine)
{
    (void)cmdLine;
    if (!pico_lfs_is_mounted()) {
        printf("littlefs not mounted — cannot list\n");
        return;
    }
    int count = 0;
    if (0 != pico_lfs_list("/", list_cb, &count)) {
        printf("listing failed\n");
        return;
    }
    if (0 == count) {
        printf("(no entries)\n");
    }
}

static void commandAdd(char *cmdLine)
{
    char *tok[3];
    if (3 != split_words(cmdLine + strlen("add"), 3, tok)) {
        printf("usage: add <name> <pin> <password>\n"
               "  name 1..%d [A-Za-z0-9._-]; PIN 1..%d chars; password 1..%d chars (no spaces)\n",
               VAULT_NAME_MAX, VAULT_PIN_MAX, VAULT_PASS_MAX);
        return;
    }
    const char *name = tok[0];
    const char *pin  = tok[1];
    const char *pass = tok[2];
    if (!valid_name(name)) {
        printf("name must be 1..%d chars from [A-Za-z0-9._-]\n", VAULT_NAME_MAX);
        return;
    }
    size_t pin_len = strlen(pin);
    if ((pin_len < 1) || (pin_len > VAULT_PIN_MAX)) {
        printf("PIN must be 1..%d chars\n", VAULT_PIN_MAX);
        return;
    }
    size_t pass_len = strlen(pass);
    if ((pass_len < 1) || (pass_len > VAULT_PASS_MAX)) {
        printf("password must be 1..%d chars (no spaces)\n", VAULT_PASS_MAX);
        return;
    }
    if (!vault_ready()) {
        return;
    }

    // Fresh salt + nonce from the chip RNG (one call covers both).
    uint8_t rand[VAULT_SALT_LEN + VAULT_NONCE_LEN];
    atecc608_status_t st = atecc608_random(rand, sizeof(rand));
    if (ATECC608_OK != st) {
        printf("RNG failed: %s (ATCA_STATUS %d)\n",
               atecc608_status_str(st), (int)atecc608_last_error());
        return;
    }

    vault_entry_t e;
    memset(&e, 0, sizeof(e));
    e.magic  = VAULT_MAGIC;
    memcpy(e.salt, rand, VAULT_SALT_LEN);
    memcpy(e.nonce, rand + VAULT_SALT_LEN, VAULT_NONCE_LEN);
    e.pt_len = (uint32_t)pass_len;

    uint8_t key[VAULT_GCM_KEY_LEN];
    if (!vault_derive_key(e.salt, pin, pin_len, key)) {
        return;
    }

    // The name is bound as GCM AAD: the ciphertext cannot be swapped
    // between entries or renamed.
    if (!vault_gcm_encrypt(key, e.nonce, (const uint8_t *)name, strlen(name),
                           (const uint8_t *)pass, pass_len,
                           e.ct, sizeof(e.ct), e.tag)) {
        printf("GCM encrypt failed (size error) — should not happen.\n");
        return;
    }
    e.crc32 = iokey_file_crc32((const uint8_t *)&e, offsetof(vault_entry_t, crc32));

    char path[2 + VAULT_NAME_MAX + 1];
    entry_path(name, path, sizeof(path));
    if (0 != pico_lfs_write_file(path, (const uint8_t *)&e, sizeof(e))) {
        printf("failed to write %s\n", path);
        return;
    }
    printf("stored '%s' (%u B password, fresh salt/nonce)\n", name, (unsigned)pass_len);
}

static void commandGet(char *cmdLine)
{
    char *tok[2];
    if (2 != split_words(cmdLine + strlen("get"), 2, tok)) {
        printf("usage: get <name> <pin>\n");
        return;
    }
    const char *name = tok[0];
    const char *pin  = tok[1];
    if (!valid_name(name)) {
        printf("name must be 1..%d chars from [A-Za-z0-9._-]\n", VAULT_NAME_MAX);
        return;
    }
    size_t pin_len = strlen(pin);
    if ((pin_len < 1) || (pin_len > VAULT_PIN_MAX)) {
        printf("PIN must be 1..%d chars\n", VAULT_PIN_MAX);
        return;
    }
    if (!vault_ready()) {
        return;
    }

    char path[2 + VAULT_NAME_MAX + 1];
    entry_path(name, path, sizeof(path));
    vault_entry_t e;
    int rd = pico_lfs_read_file(path, (uint8_t *)&e, sizeof(e));
    if ((int)sizeof(e) != rd) {
        printf("no entry named '%s'\n", name);
        return;
    }
    // The CRC pre-check separates storage corruption from a wrong PIN
    // (which the GCM tag check alone cannot).
    if ((VAULT_MAGIC != e.magic) || (e.pt_len > VAULT_PASS_MAX) ||
        (iokey_file_crc32((const uint8_t *)&e, offsetof(vault_entry_t, crc32)) != e.crc32)) {
        printf("entry '%s' is corrupt (magic/length/CRC mismatch) — `rm` it and re-add\n",
               name);
        return;
    }

    uint8_t key[VAULT_GCM_KEY_LEN];
    if (!vault_derive_key(e.salt, pin, pin_len, key)) {
        return;
    }

    char pass[VAULT_PASS_MAX + 1];
    if (!vault_gcm_decrypt(key, e.nonce, (const uint8_t *)name, strlen(name),
                           e.ct, e.pt_len, e.tag, (uint8_t *)pass, sizeof(pass))) {
        // Wrong PIN and entry corruption are deliberately not distinguished.
        printf("wrong PIN or corrupted entry '%s'\n", name);
        return;
    }
    pass[e.pt_len] = '\0';
    printf("%s\n", pass);
}

// One byte as a console character: printable ASCII as-is, anything else
// as '?'. The point of `dump` is visual: the password is GCM-encrypted
// in the ct field, so a 96-byte entry full of '?'-ish bytes is exactly
// right — any plaintext leak would stand out as readable text.
static char dump_char(uint8_t b)
{
    return ((b >= 0x20) && (b <= 0x7e)) ? (char)b : '?';
}

// READ-ONLY: print the raw stored entry as it sits in flash (no PIN,
// no chip access — a littlefs read). Demonstrates that the password is
// not stored in the clear.
static void commandDump(char *cmdLine)
{
    char *tok[1];
    if (1 != split_words(cmdLine + strlen("dump"), 1, tok)) {
        printf("usage: dump <name>\n");
        return;
    }
    const char *name = tok[0];
    if (!valid_name(name)) {
        printf("name must be 1..%d chars from [A-Za-z0-9._-]\n", VAULT_NAME_MAX);
        return;
    }
    if (!pico_lfs_is_mounted()) {
        printf("littlefs not mounted — cannot read\n");
        return;
    }
    char path[2 + VAULT_NAME_MAX + 1];
    entry_path(name, path, sizeof(path));
    uint8_t raw[sizeof(vault_entry_t)];
    if ((int)sizeof(raw) != pico_lfs_read_file(path, raw, sizeof(raw))) {
        printf("no entry named '%s'\n", name);
        return;
    }
    printf("raw entry %s (%u B) as stored in flash — non-printable bytes as '?':\n",
           path, (unsigned)sizeof(raw));
    printf("layout: [0:4] magic | [4:20] salt | [20:32] nonce | [32:36] pt_len\n"
           "        [36:76] ct (the password, GCM-encrypted) | [76:92] tag | [92:96] crc32\n");
    for (size_t off = 0; off < sizeof(raw); off += 16) {
        printf("  %02u: ", (unsigned)off);
        for (size_t i = 0; i < 16; i++) {
            printf("%c", dump_char(raw[off + i]));
        }
        printf("\n");
    }
    // Record summary: the dump above is the raw bytes; this says whether
    // the record parses (same checks `get` uses before the tag check).
    vault_entry_t *e = (vault_entry_t *)raw;
    if ((VAULT_MAGIC == e->magic) && (e->pt_len <= VAULT_PASS_MAX) &&
        (iokey_file_crc32(raw, offsetof(vault_entry_t, crc32)) == e->crc32)) {
        printf("record: magic OK, pt_len %u, CRC OK — the password text must NOT appear above\n",
               (unsigned)e->pt_len);
    } else {
        printf("record: CORRUPT (magic/length/CRC mismatch) — `rm` it and re-add\n");
    }
}

static void commandRm(char *cmdLine)
{
    char *tok[1];
    if (1 != split_words(cmdLine + strlen("rm"), 1, tok)) {
        printf("usage: rm <name>\n");
        return;
    }
    const char *name = tok[0];
    if (!valid_name(name)) {
        printf("name must be 1..%d chars from [A-Za-z0-9._-]\n", VAULT_NAME_MAX);
        return;
    }
    if (!pico_lfs_is_mounted()) {
        printf("littlefs not mounted — cannot remove\n");
        return;
    }
    char path[2 + VAULT_NAME_MAX + 1];
    entry_path(name, path, sizeof(path));
    if (0 != pico_lfs_remove(path)) {
        printf("no entry named '%s'\n", name);
        return;
    }
    printf("removed '%s'\n", name);
}

// Command table; the entry with a NULL name is the "unknown command" handler.
static struct command_t commands[] = {
    {NULL, commandUnknown},
    {"help", commandHelp},
    {"probe", commandProbe},
    {"bootrom", commandBootrom},
    {"list", commandList},
    {"add", commandAdd},
    {"get", commandGet},
    {"dump", commandDump},
    {"rm", commandRm},
};

// core1 entry point: the command handlers (and their littlefs writes) run
// on this core. Both cores must be initialized as flash lockout "victims"
// so that a core inside flash_safe_execute() can stop the other one
// during program/erase — same requirement as the console example.
static void core1_main(void)
{
    flash_safe_execute_core_init();
    commandProcessor();
}

int main(void)
{
    initPicoStdio();

    // core0 is the "victor" side of flash_safe_execute() — initialize it
    // before multicore_launch_core1() (see core1_main).
    flash_safe_execute_core_init();

    // Startup contract: chip present + provisioned. This app does NOT
    // provision — the console example is the provisioner.
    atecc608_status_t st = atecc608_init(&s_cfg);
    if (ATECC608_OK == st) {
        st = atecc608_probe();
        s_chip_present = (ATECC608_OK == st);
        if (s_chip_present) {
            printf("pico-atecc608 vault: ATECC608 on I2C0 GP20/GP21 @ 0x%02X, %lu Hz.\n",
                   s_cfg.addr, (unsigned long)s_cfg.baud);
        } else {
            printf("ATECC608 not found @ 0x%02X: %s (ATCA_STATUS %d)\n",
                   s_cfg.addr, atecc608_status_str(st), (int)atecc608_last_error());
        }
    } else {
        printf("ATECC608 init failed: %s (ATCA_STATUS %d) — check I2C wiring.\n",
               atecc608_status_str(st), (int)atecc608_last_error());
    }

    if (s_chip_present) {
        bool cfg_locked  = false;
        bool data_locked = false;
        if ((ATECC608_OK == atecc608_is_locked(ATECC608_ZONE_CONFIG, &cfg_locked)) &&
            (ATECC608_OK == atecc608_is_locked(ATECC608_ZONE_DATA, &data_locked))) {
            s_zones_locked = cfg_locked && data_locked;
            printf("zones: config %s, data %s%s\n",
                   cfg_locked ? "locked" : "unlocked",
                   data_locked ? "locked" : "unlocked",
                   s_zones_locked ? "" : " — not provisioned");
        }
    }

    // Pico-side persistence (littlefs, flash @ 0x80000), shared with the
    // console app: /io_key.bin (written by the console) and the /v_<name>
    // entry files survive console <-> vault reflashes; only a full-flash
    // erase wipes them.
    if (0 == pico_lfs_init(NULL)) {
        if (0 != pico_lfs_mount_existing()) {
            printf("littlefs: no formatted volume — formatting (one-time; can take a while)...\n");
            if (0 != pico_lfs_mount()) {
                printf("littlefs mount FAILED — entry persistence unavailable.\n");
            } else {
                printf("littlefs: fresh volume formatted.\n");
            }
        }
        if (pico_lfs_is_mounted()) {
            iokey_file_t f;
            int rd = pico_lfs_read_file(IOKEY_FILE_PATH, (uint8_t *)&f, sizeof(f));
            if ((int)sizeof(f) != rd) {
                printf("WARNING: %s not found (first boot, or a full-flash erase). Flash the\n"
                       "         console app and run `prov iokey` to restore it.\n",
                       IOKEY_FILE_PATH);
            } else if (!iokey_file_check(&f, s_io_key, NULL, 0)) {
                printf("WARNING: %s is corrupt — flash the console app and re-run `prov iokey`.\n",
                       IOKEY_FILE_PATH);
            } else {
                s_io_key_loaded = true;
            }
        }
    } else {
        printf("littlefs init FAILED — entry persistence unavailable.\n");
    }

    printf("vault ready (demo) — type `help`. Note: input is echoed on this console.\n");

    // The command processor (core1) blocks on a semaphore, so initialize
    // it before the core is launched.
    initCommandProcessor(commands, sizeof(commands) / sizeof(commands[0]));
    multicore_launch_core1(core1_main);
    picoConsole();
}

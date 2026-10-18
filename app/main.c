// pico-atecc608
//
// Raspberry Pi Pico 2 (RP2350) + Microchip ATECC608C crypto co-processor.
//
// Wiring:
//   I2C0  GP20 (SDA), GP21 (SCL)  -> ATECC608C SDA/SCL  (needs pull-ups to 3V3)
//   UART0 GP0  (TX),  GP1 (RX)    -> USB-serial console
//   USB   flashing / optional CDC console
//
// Phase 3: the console exercises the module's curated atecc608_* API
// (read-only operations) and must produce the same results as the Phase 1
// standalone driver. Phase 6 adds the config read-back demo.
//
// Console commands (basic smoke tests only - no slots are programmed):
//   help     - list commands
//   bootrom  - reset into BOOTSEL mode (USB bootloader)
//   probe    - atecc608_probe: wake handshake
//   random   - atecc608_random: 32 bytes of chip-generated randomness
//   info     - atecc608_info: part id + silicon revision
//   serial   - atecc608_serial: 9-byte factory serial
//   lock     - atecc608_is_locked: config/data zone lock status
//   diag     - raw I2C bus diagnostics (levels, general call, wake read)

#include <stdio.h>

#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/bootrom.h"
#include "hardware/gpio.h"
#include "pico-command-line.h"

#include "atecc608/atecc608.h"

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
}

static void commandBootrom(char *cmdLine)
{
    (void)cmdLine;
    printf("Rebooting into BOOTSEL mode... (watch for the RPI-RP2 drive)\n");
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
};

int main(void) {
    initPicoStdio();

    atecc608_status_t st = atecc608_init(&s_cfg);
    if (ATECC608_OK == st) {
        printf("pico-atecc608 ready: ATECC608 on I2C0 GP20/GP21 @ 0x%02X, %lu Hz.\n",
               s_cfg.addr, (unsigned long)s_cfg.baud);
    } else {
        printf("ATECC608 init failed: %s (ATCA_STATUS %d)\n",
               atecc608_status_str(st), (int)atecc608_last_error());
    }

    // The command processor (core1) blocks on a semaphore, so it must be
    // initialized before the core is launched.
    initCommandProcessor(commands, sizeof(commands) / sizeof(commands[0]));
    multicore_launch_core1(commandProcessor);
    picoConsole();
}

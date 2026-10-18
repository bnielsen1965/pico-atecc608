// pico-atecc608
//
// Raspberry Pi Pico 2 (RP2350) + Microchip ATECC608C crypto co-processor.
//
// Wiring:
//   I2C0  GP20 (SDA), GP21 (SCL)  -> ATECC608C SDA/SCL  (needs pull-ups to 3V3)
//   UART0 GP0  (TX),  GP1 (RX)    -> USB-serial console
//   USB   flashing / optional CDC console
//
// Phase 2: the console runs read-only operations through cryptoauthlib
// (atcab_*) and must match the Phase 1 standalone driver's outputs.
// Phase 6 rewires it to the module's atecc608_* API.
//
// Console commands (basic smoke tests only - no slots are programmed):
//   help     - list commands
//   bootrom  - reset into BOOTSEL mode (USB bootloader)
//   probe    - wake handshake through cryptoauthlib (atcab_wakeup)
//   random   - atcab_random: 32 bytes of chip-generated randomness
//   info     - atcab_info: silicon revision
//   serial   - atcab_read_config_zone: config block 0 (factory serial)
//   lock     - atcab_is_locked: config/data zone lock status
//   diag     - raw I2C bus diagnostics (levels, general call, wake read)

#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/bootrom.h"
#include "hardware/gpio.h"
#include "pico-command-line.h"

#include "cryptoauthlib.h"
#include "atecc608.h"

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

// Short text for the ATCA_STATUS codes the read-only commands can hit.
static const char *atca_status_str(ATCA_STATUS status)
{
    switch (status) {
    case ATCA_SUCCESS:            return "ok";
    case ATCA_WAKE_FAILED:        return "wake handshake failed (chip asleep / absent?)";
    case ATCA_RX_FAIL:            return "I2C receive failed (NACK / timeout)";
    case ATCA_RX_NO_RESPONSE:     return "no response from device";
    case ATCA_COMM_FAIL:          return "I2C communication failed";
    case ATCA_STATUS_SELFTEST_ERROR: return "chip POST self-test failure";
    case ATCA_EXECUTION_ERROR:    return "chip could not execute the command";
    case ATCA_GEN_FAIL:           return "general failure";
    default:                      return "error";
    }
}

static void report_fail(const char *op, ATCA_STATUS status)
{
    printf("%s failed: %s (%d)\n", op, atca_status_str(status), (int)status);
}

static void commandHelp(char *cmdLine)
{
    (void)cmdLine;
    printf("pico-atecc608: Pico 2 + ATECC608C over I2C0 (GP20/GP21)\n");
    printf("help    - display this message\n");
    printf("bootrom - reset into BOOTSEL mode (USB bootloader)\n");
    printf("probe   - wake handshake through cryptoauthlib (atcab_wakeup)\n");
    printf("diag    - raw I2C bus diagnostics (levels, wake handshake bytes)\n");
    printf("random  - atcab_random (32 random bytes from the chip)\n");
    printf("info    - atcab_info (silicon revision)\n");
    printf("serial  - atcab_read_config_zone, block 0 (factory serial)\n");
    printf("lock    - atcab_is_locked (config / data zone)\n");
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
    ATCA_STATUS status = atcab_wakeup();
    if (ATCA_SUCCESS == status) {
        printf("ATECC608 found at I2C address 0x%02X (wake handshake ok)\n", s_cfg.addr);
    } else {
        printf("ATECC608 not found @ 0x%02X: %s\n", s_cfg.addr, atca_status_str(status));
    }
}

static void commandRandom(char *cmdLine)
{
    (void)cmdLine;
    uint8_t rand[32];
    ATCA_STATUS status = atcab_random(rand);
    if (ATCA_SUCCESS != status) {
        report_fail("RANDOM", status);
        return;
    }
    printf("32 random bytes from ATECC608 @ 0x%02X:\n", s_cfg.addr);
    atecc608_print_hex(rand, sizeof(rand));
}

static void commandInfo(char *cmdLine)
{
    (void)cmdLine;
    uint8_t info[4];
    ATCA_STATUS status = atcab_info(info);
    if (ATCA_SUCCESS != status) {
        report_fail("INFO", status);
        return;
    }
    // Per cryptoauthlib: info[2] is the part id, info[3] the silicon
    // revision. Part 0x60 with revision > 2 is the 608 B/C family.
    const char *model = "unknown";
    if (info[2] == 0x60) {
        model = (info[3] > 0x02) ? "ATECC608 (B/C)" : "ATECC608A";
    } else if (info[2] == 0x50) {
        model = "ATECC508A";
    }
    printf("ATECC @ 0x%02X info: %02X %02X %02X %02X  (%s, revision %u)\n",
           s_cfg.addr, info[0], info[1], info[2], info[3], model, info[3]);
}

static void commandSerial(char *cmdLine)
{
    (void)cmdLine;
    uint8_t config[128];
    ATCA_STATUS status = atcab_read_config_zone(config);
    if (ATCA_SUCCESS != status) {
        report_fail("READ config zone", status);
        return;
    }
    printf("Config block 0 @ 0x%02X:\n", s_cfg.addr);
    atecc608_print_hex(config, 32);
    // The 9-byte factory serial number lives in bytes [0:4] and [8:13].
    uint8_t serial[9];
    memcpy(&serial[0], &config[0], 4);
    memcpy(&serial[4], &config[8], 5);
    printf("Serial: ");
    atecc608_print_hex(serial, sizeof(serial));
}

static void commandLock(char *cmdLine)
{
    (void)cmdLine;
    bool config_locked = false;
    bool data_locked = false;
    ATCA_STATUS status;

    status = atcab_is_locked(LOCK_ZONE_CONFIG, &config_locked);
    if (ATCA_SUCCESS != status) {
        report_fail("IS_LOCKED (config)", status);
        return;
    }
    // Note: atcab_is_locked takes the LOCK_ZONE_* zone ids (0x00 config,
    // 0x01 data), not the ATCA_ZONE_* command zone ids (0x00 config, 0x02
    // data) — the two enums differ for the data zone.
    status = atcab_is_locked(LOCK_ZONE_DATA, &data_locked);
    if (ATCA_SUCCESS != status) {
        report_fail("IS_LOCKED (data)", status);
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

    ATCA_STATUS status = atecc608_init(&s_cfg);
    if (ATCA_SUCCESS == status) {
        printf("pico-atecc608 ready: ATECC608 on I2C0 GP20/GP21 @ 0x%02X, %lu Hz.\n",
               s_cfg.addr, (unsigned long)s_cfg.baud);
    } else {
        printf("ATECC608 init failed: %s (%d)\n", atca_status_str(status), (int)status);
    }

    // The command processor (core1) blocks on a semaphore, so it must be
    // initialized before the core is launched.
    initCommandProcessor(commands, sizeof(commands) / sizeof(commands[0]));
    multicore_launch_core1(commandProcessor);
    picoConsole();
}

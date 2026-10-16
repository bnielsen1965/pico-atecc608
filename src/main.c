// pico-atecc608
//
// Raspberry Pi Pico 2 (RP2350) + Microchip ATECC608B crypto co-processor.
//
// Wiring:
//   I2C0  GP20 (SDA), GP21 (SCL)  -> ATECC608B SDA/SCL  (needs pull-ups to 3V3)
//   UART0 GP0  (TX),  GP1 (RX)    -> USB-serial console
//   USB   flashing / optional CDC console
//
// Console commands (basic smoke tests only - no slots are programmed):
//   help     - list commands
//   bootrom  - reset into BOOTSEL mode (USB bootloader)
//   probe    - wake handshake at 0x60 / 0x61 to locate the ATECC608
//   random   - RANDOM command: read 32 bytes of chip-generated randomness
//   info     - INFO command: silicon revision
//   serial   - READ command: config block 0 (contains the factory serial)

#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/bootrom.h"
#include "hardware/gpio.h"
#include "pico-command-line.h"
#include "atecc608.h"

#define I2C_BUS     i2c0
#define I2C_SDA_PIN 20
#define I2C_SCL_PIN 21

static atecc608_t atecc;

static void commandHelp(char *cmdLine) {
    (void)cmdLine;
    printf("pico-atecc608: Pico 2 + ATECC608B over I2C0 (GP20/GP21)\n");
    printf("help    - display this message\n");
    printf("bootrom - reset into BOOTSEL mode (USB bootloader)\n");
    printf("probe   - scan I2C0 for the ATECC608 (0x60/0x61)\n");
    printf("random  - RANDOM command (32 random bytes from the chip)\n");
    printf("info    - INFO command (silicon revision)\n");
    printf("serial  - READ config block 0 (factory serial number)\n");
}

static void commandBootrom(char *cmdLine) {
    (void)cmdLine;
    printf("Rebooting into BOOTSEL mode... (watch for the RPI-RP2 drive)\n");
    // Give the console a moment to flush the message out the UART.
    sleep_ms(200);
    rom_reset_usb_boot(0, 0);
}

static void commandProbe(char *cmdLine) {
    (void)cmdLine;
    if (atecc608_probe(&atecc, I2C_BUS)) {
        printf("ATECC608 found at I2C address 0x%02X (wake handshake ok)\n", atecc.addr);
    } else {
        printf("ATECC608 not found (tried 0x%02X and 0x%02X)\n",
               ATECC608_ADDR_ADR_LOW, ATECC608_ADDR_ADR_HIGH);
    }
}

static void commandRandom(char *cmdLine) {
    (void)cmdLine;
    uint8_t rand[32];
    int rc;
    if (!atecc.found) {
        commandProbe(cmdLine);
        return;
    }
    rc = atecc608_random(&atecc, rand);
    if (rc != ATECC608_OK) {
        printf("RANDOM failed: %s\n", atecc608_result_str(rc));
        return;
    }
    printf("32 random bytes from ATECC608 @ 0x%02X:\n", atecc.addr);
    atecc608_print_hex(rand, sizeof(rand));
}

static void commandInfo(char *cmdLine) {
    (void)cmdLine;
    uint8_t info[4];
    int rc;
    if (!atecc.found) {
        commandProbe(cmdLine);
        return;
    }
    rc = atecc608_info(&atecc, info);
    if (rc == ATECC608_ERR_CHIP) {
        printf("INFO failed: chip error status 0x%02X\n", atecc.chip_status);
        return;
    }
    if (rc != ATECC608_OK) {
        printf("INFO failed: %s\n", atecc608_result_str(rc));
        return;
    }
    printf("ATECC608 @ 0x%02X revision: %02X %02X %02X %02X",
           atecc.addr, info[0], info[1], info[2], info[3]);
    // ATECC608B silicon answers 00 00 60 03 (02 on ATECC608A).
    if (info[0] == 0x00 && info[1] == 0x00 && info[2] == 0x60) {
        printf("  (%s, revision %u)", info[3] == 0x03 ? "ATECC608B" : "ATECC608A", info[3]);
    }
    printf("\n");
}

static void commandSerial(char *cmdLine) {
    (void)cmdLine;
    uint8_t config[32];
    int rc;
    if (!atecc.found) {
        commandProbe(cmdLine);
        return;
    }
    rc = atecc608_read_config_block0(&atecc, config);
    if (rc == ATECC608_ERR_CHIP) {
        printf("READ failed: chip error status 0x%02X\n", atecc.chip_status);
        return;
    }
    if (rc != ATECC608_OK) {
        printf("READ failed: %s\n", atecc608_result_str(rc));
        return;
    }
    printf("Config block 0 @ 0x%02X:\n", atecc.addr);
    atecc608_print_hex(config, sizeof(config));
    // The 9-byte factory serial number lives in bytes [0:3] and [8:12].
    uint8_t serial[9];
    memcpy(&serial[0], &config[0], 4);
    memcpy(&serial[4], &config[8], 5);
    printf("Serial: ");
    atecc608_print_hex(serial, sizeof(serial));
}

static void commandUnknown(char *cmdLine) {
    printf("Unknown command. Try 'help'.\n");
}

// Command table; the entry with a NULL name is the "unknown command" handler.
static struct command_t commands[] = {
    {NULL, commandUnknown},
    {"help", commandHelp},
    {"bootrom", commandBootrom},
    {"probe", commandProbe},
    {"random", commandRandom},
    {"info", commandInfo},
    {"serial", commandSerial},
};

int main(void) {
    // I2C0 on GP20 (SDA) / GP21 (SCL).
    i2c_init(I2C_BUS, ATECC608_NORMAL_BAUD_HZ);
    gpio_set_function(I2C_SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(I2C_SCL_PIN, GPIO_FUNC_I2C);
    // The ATECC608 I2C lines need pull-ups to 3V3 (4.7k typical); enable the
    // on-chip pull-ups as a fallback in case the board does not have them.
    gpio_pull_up(I2C_SDA_PIN);
    gpio_pull_up(I2C_SCL_PIN);

    initPicoStdio();
    printf("pico-atecc608 ready.\n");
    if (atecc608_probe(&atecc, I2C_BUS)) {
        printf("ATECC608 found at I2C address 0x%02X\n", atecc.addr);
    } else {
        printf("ATECC608 not found - check wiring. Use 'probe' to rescan.\n");
    }

    // The command processor (core1) blocks on a semaphore, so it must be
    // initialized before the core is launched.
    initCommandProcessor(commands, sizeof(commands) / sizeof(commands[0]));
    multicore_launch_core1(commandProcessor);
    picoConsole();
}

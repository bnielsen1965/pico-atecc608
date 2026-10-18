// RP2350 I2C HAL for Microchip cryptoauthlib v3.8.0 (modern, non-legacy
// ATCAHAL_t interface).
//
// Wire protocol (verified against the standalone Phase 1 driver on
// hardware): the I/O token is the FIRST DATA BYTE of each write
// transaction, not part of the address:
//
//   command:  S [addr|W] 03 count opcode param1 param2 data crc_lo crc_hi P
//   read tok: S [addr|W] 00 P          (chip NACKs while a command runs)
//   read:     S [addr|R] count data crc_lo crc_hi P
//   idle:     S [addr|W] 02 P
//   sleep:    S [addr|W] 01 P
//   wake:     S 00 NACK P  (I2C general call at 100 kHz, then read 4 bytes)
//
// Wake design (settled 2026-10-18): the library's non-legacy I2C wake path
// (calib_wakeup_i2c) first asks the HAL for ATCA_HAL_CHANGE_BAUD; when the
// HAL returns ATCA_UNIMPLEMENTED, the library routes the whole handshake
// through hal_i2c_control(ATCA_HAL_CONTROL_WAKE). That is where our wake
// lives: 100 kHz general-call pulse, cfg->wake_delay wait, 4-byte response
// read, restore baud, and the library's own hal_check_wake() validation.
//
// pico-sdk has no zero-length I2C write, so the general call is expressed
// as a 1-byte write to address 0x00: the chip NACKs the address byte and
// the I2C controller aborts (HSTXABORT -> STOP) before the dummy byte is
// clocked. On the wire this is S 0x00 NACK P — byte-identical to the
// true 0-byte general call the library's SAM reference HAL issues.

#include "hal_rp2350.h"

#include <string.h>

#include "pico/stdlib.h"
#include "hardware/gpio.h"

#include "cryptoauthlib.h"

// Per-transaction I2C timeout. The SDK's plain blocking calls spin forever
// on a stuck bus (SDA held low), which would hang the boot-time probe.
#define RP2350_I2C_TIMEOUT_US 10000u

// The wake pulse is specified at standard speed (100 kHz); normal command
// traffic runs at cfg->baud (fast mode).
#define RP2350_WAKE_BAUD_HZ   100000u

// I/O tokens (first data byte of the write transaction).
#define RP2350_TOKEN_READ    0x00u
#define RP2350_TOKEN_SLEEP   0x01u
#define RP2350_TOKEN_IDLE    0x02u
#define RP2350_TOKEN_COMMAND 0x03u

// The chip NACKs the 0x00 general-call address, so this byte is never
// clocked; it only exists because pico-sdk's i2c_write* rejects
// zero-length writes.
static const uint8_t s_general_call_dummy = 0x00;


// ---------------------------------------------------------------------------
// Stuck-bus recovery (moved from the Phase 1 console app)
// ---------------------------------------------------------------------------

void hal_rp2350_bus_recover(const hal_rp2350_ctx_t *ctx)
{
    i2c_inst_t *bus = ctx->i2c;

    if (gpio_get(ctx->sda_pin)) {
        return;  // bus idle, nothing to recover
    }

    bus->hw->enable = 0;

    for (size_t i = 0; i < 2; i++) {
        uint pin = (i == 0) ? ctx->sda_pin : ctx->scl_pin;
        gpio_set_function(pin, GPIO_FUNC_SIO);
        gpio_pull_up(pin);
        gpio_put(pin, 1);
        gpio_set_dir(pin, GPIO_OUT);
    }

    for (int i = 0; i < 9; i++) {
        gpio_put(ctx->scl_pin, 0);
        sleep_us(10);
        gpio_put(ctx->scl_pin, 1);
        sleep_us(10);
        if (gpio_get(ctx->sda_pin)) {
            break;  // SDA released, slave is no longer holding the bus
        }
    }

    // STOP condition: SDA low -> high while SCL is high.
    gpio_put(ctx->scl_pin, 1);
    gpio_put(ctx->sda_pin, 0);
    sleep_us(10);
    gpio_put(ctx->sda_pin, 1);
    sleep_us(10);

    gpio_set_function(ctx->sda_pin, GPIO_FUNC_I2C);
    gpio_set_function(ctx->scl_pin, GPIO_FUNC_I2C);
    bus->hw->enable = 1;
}


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static const hal_rp2350_ctx_t *hal_ctx(ATCAIface iface)
{
    return (const hal_rp2350_ctx_t *)iface->hal_data;
}

// Single-byte I/O token write: S [addr|W] [token] P.
static ATCA_STATUS send_token(const hal_rp2350_ctx_t *ctx, uint8_t dev_addr8, uint8_t token)
{
    if (i2c_write_timeout_us(ctx->i2c, (size_t)dev_addr8 >> 1, &token, 1, true,
                             RP2350_I2C_TIMEOUT_US) != 1) {
        // ATCA_COMM_FAIL, matching the reference I2C HALs' failure status.
        return ATCA_COMM_FAIL;
    }
    return ATCA_SUCCESS;
}

// Full-handshake fallback attempts after the first one fails. The read NACKs
// both when the chip was already awake (no wake response pending — harmless,
// the subsequent command send will succeed) and when the wake pulse was
// missed or the chip needs more time (harmful — the command send will NACK).
// The two cases are indistinguishable on the wire, so re-issue a few complete
// handshakes (fresh pulse + full settle delay), mirroring calib_wakeup_i2c,
// which retries the whole handshake rx_retries times when the HAL implements
// CHANGE_BAUD.
#define RP2350_WAKE_FALLBACK_ATTEMPTS 3u

// One wake-handshake attempt: general-call pulse, settle for tWHI + tWLO,
// read the 4-byte wake response. Returns true when the read succeeded; the
// packet content is validated by the caller via hal_check_wake.
static bool wake_attempt(const hal_rp2350_ctx_t *ctx, uint8_t dev_addr8,
                         uint32_t wake_delay_us, int read_retries,
                         uint8_t response[4])
{
    // General call: S 0x00 NACK P. The NACK is expected — the SDA dip is
    // the wake pulse — so the write status is intentionally ignored.
    (void)i2c_write_timeout_us(ctx->i2c, 0, &s_general_call_dummy, 1, true,
                               RP2350_I2C_TIMEOUT_US);

    // Settle: tWHI + tWLO (wake_delay; 1500 us for the ATECC608, the
    // library's own default).
    hal_delay_us(wake_delay_us);

    // Read the 4-byte wake response. If the response window is missed the
    // chip NACKs the read, so retry a few times.
    while (read_retries-- > 0) {
        if (i2c_read_timeout_us(ctx->i2c, (size_t)dev_addr8 >> 1, response,
                                4u, true, RP2350_I2C_TIMEOUT_US) == 4) {
            return true;
        }
    }

    return false;
}

// Wake handshake: 100 kHz general-call pulse, wait tWHI + tWLO, then read
// the 4-byte wake response (count, status 0x11 "woken up", CRC).
static ATCA_STATUS hal_rp2350_wake(ATCAIfaceCfg *cfg, const hal_rp2350_ctx_t *ctx)
{
    uint8_t dev_addr8 = ATCA_IFACECFG_I2C_ADDRESS(cfg);
    uint32_t baud = ATCA_IFACECFG_I2C_BAUD(cfg);
    uint8_t response[4] = { 0 };
    bool got_response = false;

    // 1. The wake pulse is specified at 100 kHz.
    if (baud != RP2350_WAKE_BAUD_HZ) {
        i2c_set_baudrate(ctx->i2c, RP2350_WAKE_BAUD_HZ);
    }

    // 2. First handshake: pulse, settle, read (with fast read retries).
    got_response = wake_attempt(ctx, dev_addr8, cfg->wake_delay,
                                cfg->rx_retries, response);

    // 3. If the read NACKed, re-issue complete handshakes in case the pulse
    //    was missed (see RP2350_WAKE_FALLBACK_ATTEMPTS).
    for (uint32_t attempt = 0;
         !got_response && (attempt < RP2350_WAKE_FALLBACK_ATTEMPTS);
         attempt++) {
        got_response = wake_attempt(ctx, dev_addr8, cfg->wake_delay, 1, response);
    }

    // 4. Restore the normal traffic baud.
    if (baud != RP2350_WAKE_BAUD_HZ) {
        i2c_set_baudrate(ctx->i2c, baud);
    }

    // 5. The library validates the packet (04 11 33 43, and it also detects
    //    the POST self-test-fail packet 04 07 C4 40).
    return hal_check_wake(response, (int)sizeof(response));
}


// ---------------------------------------------------------------------------
// atca_hal I2C interface (implemented for the ATCAHAL_t table in atca_hal.c)
// ---------------------------------------------------------------------------

ATCA_STATUS hal_i2c_init(ATCAIface iface, ATCAIfaceCfg *cfg)
{
    const hal_rp2350_ctx_t *ctx = cfg->cfg_data;

    if ((NULL == iface) || (NULL == ctx) || (NULL == ctx->i2c) || (0 == ctx->baud)) {
        return ATCA_BAD_PARAM;
    }

    // The HAL owns the peripheral's lifetime: initialized here, deinitialized
    // in hal_i2c_release.
    i2c_init(ctx->i2c, ctx->baud);
    gpio_set_function(ctx->sda_pin, GPIO_FUNC_I2C);
    gpio_set_function(ctx->scl_pin, GPIO_FUNC_I2C);
    // The ATECC608 I2C lines need pull-ups to 3V3 (4.7k typical); enable the
    // on-chip pull-ups as a fallback in case the board does not have them.
    gpio_pull_up(ctx->sda_pin);
    gpio_pull_up(ctx->scl_pin);
    // A chip (or a previous firmware that died mid-transaction) may be
    // holding SDA low; recover before the first transaction.
    hal_rp2350_bus_recover(ctx);

    iface->hal_data = (void *)ctx;
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    (void)iface;
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    const hal_rp2350_ctx_t *ctx = hal_ctx(iface);

    if ((NULL == cfg) || (NULL == ctx)) {
        return ATCA_BAD_PARAM;
    }

    uint8_t dev_addr8 = ATCA_IFACECFG_I2C_ADDRESS(cfg);

    if (0u == dev_addr8) {
        // I2C general call (wake pulse): S 0x00 NACK P. The NACK aborts
        // before the dummy byte is clocked. Callers discard this status —
        // the NACK is the point.
        (void)i2c_write_timeout_us(ctx->i2c, 0, &s_general_call_dummy, 1, true,
                                   RP2350_I2C_TIMEOUT_US);
        return ATCA_SUCCESS;
    }

    if ((txlength > 0) && (NULL == txdata)) {
        return ATCA_BAD_PARAM;
    }
    if (txlength > (int)CA_MAX_PACKET_SIZE) {
        return ATCA_BAD_PARAM;
    }

    // One I2C write transaction: S [addr|W] [word_address] [data...] P.
    // For a command, word_address is the 0x03 command token and data is the
    // command packet (count, opcode, params, data, CRC). For the read
    // token, idle and sleep, data is empty.
    uint8_t frame[1 + CA_MAX_PACKET_SIZE];
    frame[0] = word_address;
    if (txlength > 0) {
        memcpy(&frame[1], txdata, (size_t)txlength);
    }

    int rc = i2c_write_timeout_us(ctx->i2c, (size_t)dev_addr8 >> 1, frame,
                                  (size_t)txlength + 1u, true, RP2350_I2C_TIMEOUT_US);
    if (rc != (int)((size_t)txlength + 1u)) {
        // NACK (chip asleep / busy / absent) or bus timeout. ATCA_COMM_FAIL
        // matches the reference I2C HALs; the iface layer treats any
        // non-success here the same way.
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength)
{
    const hal_rp2350_ctx_t *ctx = hal_ctx(iface);

    if ((NULL == ctx) || (NULL == rxdata) || (NULL == rxlength)) {
        return ATCA_BAD_PARAM;
    }

    // One I2C read transaction: S [addr|R] [data...] P. word_address is the
    // 8-bit device address; the read I/O token was already sent by the
    // preceding zero-length hal_i2c_send.
    int rc = i2c_read_timeout_us(ctx->i2c, (size_t)word_address >> 1, rxdata,
                                 *rxlength, true, RP2350_I2C_TIMEOUT_US);
    if (rc != (int)*rxlength) {
        // NACK (chip still executing) or bus timeout; the caller polls.
        // ATCA_COMM_FAIL matches the reference I2C HALs.
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_control(ATCAIface iface, uint8_t option, void *param, size_t paramlen)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    const hal_rp2350_ctx_t *ctx = hal_ctx(iface);

    if ((NULL == cfg) || (NULL == ctx)) {
        return ATCA_BAD_PARAM;
    }
    (void)param;
    (void)paramlen;

    switch (option) {
    case ATCA_HAL_CONTROL_WAKE:
        return hal_rp2350_wake(cfg, ctx);
    case ATCA_HAL_CONTROL_IDLE:
        return send_token(ctx, ATCA_IFACECFG_I2C_ADDRESS(cfg), RP2350_TOKEN_IDLE);
    case ATCA_HAL_CONTROL_SLEEP:
        return send_token(ctx, ATCA_IFACECFG_I2C_ADDRESS(cfg), RP2350_TOKEN_SLEEP);
    default:
        // ATCA_HAL_CHANGE_BAUD: intentionally unimplemented. The wake
        // handshake does its own 100 kHz dip/restore inside the WAKE case,
        // and calib_wakeup_i2c routes wake through ATCA_HAL_CONTROL_WAKE
        // when CHANGE_BAUD is ATCA_UNIMPLEMENTED.
        // ATCA_HAL_CONTROL_RESET / SELECT / DESELECT / DIRECTION /
        // FLUSH_BUFFER: no bus-level equivalent on plain I2C; the iface
        // layer accepts ATCA_UNIMPLEMENTED for SELECT/DESELECT.
        return ATCA_UNIMPLEMENTED;
    }
}

ATCA_STATUS hal_i2c_release(void *hal_data)
{
    const hal_rp2350_ctx_t *ctx = hal_data;

    if (NULL != ctx) {
        i2c_deinit(ctx->i2c);
    }

    return ATCA_SUCCESS;
}


// ---------------------------------------------------------------------------
// Delay API (implemented at the HAL level per atca_hal.h)
// ---------------------------------------------------------------------------

void hal_delay_ms(uint32_t delay)
{
    sleep_ms(delay);
}

void hal_delay_us(uint32_t delay)
{
    sleep_us(delay);
}

// Note: the core's atca_delay_ms/atca_delay_us calls are mapped to these by
// macros in the generated atca_config.h — do not define them here.

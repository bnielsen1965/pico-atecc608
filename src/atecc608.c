#include "atecc608.h"

#include <stdio.h>

#include "cryptoauthlib.h"
#include "hal_rp2350.h"

// The HAL context and interface configuration live in module storage so
// they outlive the caller's stack frame: cryptoauthlib retains the
// ATCAIfaceCfg (and its cfg_data pointer) for the whole session.
static hal_rp2350_ctx_t s_hal_ctx;
static ATCAIfaceCfg s_iface_cfg;

ATCA_STATUS atecc608_init(const atecc608_cfg_t *cfg)
{
    if ((NULL == cfg) || (NULL == cfg->i2c) || (0 == cfg->baud)) {
        return ATCA_BAD_PARAM;
    }

    // atcab_release() is a no-op when nothing is initialized; call it
    // unconditionally so re-init is safe.
    (void)atcab_release();

    s_hal_ctx.i2c = cfg->i2c;
    s_hal_ctx.sda_pin = cfg->sda_pin;
    s_hal_ctx.scl_pin = cfg->scl_pin;
    s_hal_ctx.baud = cfg->baud;

    s_iface_cfg = (ATCAIfaceCfg) {
        .iface_type = ATCA_I2C_IFACE,
        .devtype    = ATECC608,
        .atcai2c = {
            .address = (uint8_t)(cfg->addr << 1), // 8-bit form; I2C LSB is 0
            .bus     = 0,                         // logical bus (unused; the HAL uses cfg_data)
            .baud    = cfg->baud,
        },
        .wake_delay = 1500, // tWHI + tWLO for the ATECC608 (the library's own default)
        .rx_retries = 20,   // library default
        .cfg_data   = &s_hal_ctx,
    };

    return atcab_init(&s_iface_cfg);
}

void atecc608_deinit(void)
{
    (void)atcab_release();
}

void atecc608_print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02X%s", data[i],
               (i + 1 == len) ? "\n" : ((i % 8 == 7) ? "  " : " "));
    }
}

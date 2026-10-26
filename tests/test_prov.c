// Host unit tests for the ATECC608 guarded provisioning API (Phase 4A),
// driven through the real cryptoauthlib atcab_*/calib layers against the
// mock chip (tests/mock_chip.c) — no Pico, no physical device.

#include <stdio.h>
#include <string.h>

#include "atecc608/atecc608_prov.h"
#include "cryptoauthlib.h"
#include "mock_chip.h"

#include "test_golden.h"

// --- tiny harness ---------------------------------------------------------------

static int s_checks = 0;
static int s_failures = 0;

#define CHECK(cond) do { \
    s_checks++; \
    if (!(cond)) { \
        s_failures++; \
        printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
    } \
} while (0)

// --- shared state -----------------------------------------------------------------

static mock_chip_t s_chip;
static ATCAIfaceCfg s_cfg;

static int s_confirm_calls;
static bool s_confirm_result = true;

static bool confirm_hook(const char *prompt, void *ctx)
{
    (void)prompt;
    (void)ctx;
    s_confirm_calls++;
    return s_confirm_result;
}

// Fresh factory chip + initialized atcab layer. Mirrors atecc608_init's
// ATCAIfaceCfg (same interface fields), but cfg_data points at the mock chip
// instead of the RP2350 HAL context.
static void setup(void)
{
    mock_chip_reset(&s_chip);
    s_confirm_calls = 0;
    s_confirm_result = true;

    s_cfg = (ATCAIfaceCfg) {
        .iface_type = ATCA_I2C_IFACE,
        .devtype    = ATECC608,
        .atcai2c    = { .address = 0xC0, .bus = 0, .baud = 400000 },
        .wake_delay = 1500,
        .rx_retries = 20,
        .cfg_data   = &s_chip,
    };
    CHECK(ATCA_SUCCESS == atcab_release());
    CHECK(ATCA_SUCCESS == atcab_init(&s_cfg));
}

// --- tests ---------------------------------------------------------------------------

static void t_wake(void)
{
    uint8_t zone[ATECC608_CONFIG_ZONE_LEN];

    printf("t_wake\n");
    setup();

    // atcab_init issues no chip commands; the first real command wakes.
    // (The exact number of wake handshakes per command is a library
    // implementation detail — some calib wrappers wake more than once — so
    // only assert that at least one happened and the chip is now awake.)
    CHECK(!s_chip.awake);
    CHECK(0u == s_chip.wakes);

    CHECK(ATCA_SUCCESS == atcab_read_config_zone(zone));
    CHECK(s_chip.awake);
    CHECK(s_chip.wakes >= 1u);

    // Factory identification bytes come back intact.
    CHECK(0x01u == zone[0]);
    CHECK(0x23u == zone[1]);
    CHECK(0x06u == zone[2]);
    CHECK(0x40u == zone[3]);
    CHECK(0xC0u == zone[16]);  // I2C address, 8-bit form
    CHECK(ATECC608_CONFIG_UNLOCKED == zone[86]);
    CHECK(ATECC608_CONFIG_UNLOCKED == zone[87]);
}

static void t_provision_default(void)
{
    atecc608_config_intent_t cfg;

    printf("t_provision_default\n");
    setup();
    atecc608_config_default(&cfg);

    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));
    // The factory zone differs from the safe default only in the KeyConfig
    // words (factory 0x0000 vs 0x001C NON_ECC): exactly one write pass.
    CHECK(13u == s_chip.writes_config);
    CHECK(0x1Cu == s_chip.config[96]);
    CHECK(0xC0u == s_chip.config[16]);  // address preserved

    // Idempotent: the second pass must not write anything.
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));
    CHECK(13u == s_chip.writes_config);
}

static void t_provision_golden(void)
{
    atecc608_config_intent_t cfg;

    printf("t_provision_golden\n");
    setup();
    fill_golden_config(&cfg);

    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));
    CHECK(13u == s_chip.writes_config);  // one atcab_write_config_zone

    // Spot-check the written bytes straight from the mock memory.
    CHECK(0x51u == s_chip.config[18]);
    CHECK(0x12u == s_chip.config[19]);
    CHECK(0x07u == s_chip.config[52]);   // counter 0 = 5 (dual encoding)
    CHECK(0xA5u == s_chip.config[84]);   // one-shot UserExtra
    CHECK(0xC4u == s_chip.config[85]);   // one-shot UserExtraAdd
    CHECK(0xC0u == s_chip.config[16]);   // factory I2C address preserved
    CHECK(ATECC608_CONFIG_UNLOCKED == s_chip.config[86]);
    CHECK(ATECC608_CONFIG_UNLOCKED == s_chip.config[87]);

    // Idempotent: second pass is a no-op.
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));
    CHECK(13u == s_chip.writes_config);
}

static void t_provision_guarded(void)
{
    atecc608_config_intent_t cfg;
    uint32_t v;

    printf("t_provision_guarded\n");
    setup();
    fill_golden_config(&cfg);

    // Invalid intent: rejected before touching the chip.
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_provision_config(NULL));
    cfg.counter[0].value = ATECC608_COUNTER_MAX + 1u;
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_provision_config(&cfg));
    cfg.counter[0].value = 5u;
    CHECK(0u == s_chip.writes_config);

    // Locked config zone: refused, no writes.
    s_chip.config[87] = 0x00;  // what the Lock command does
    CHECK(ATECC608_ERR_CHIP_STATE == atecc608_provision_config(&cfg));
    CHECK(0u == s_chip.writes_config);

    // One-shot UserExtra: changing byte 84 after it was set once fails on
    // the chip, surfaces as ERR_EXEC, and leaves the byte unchanged.
    mock_chip_reset(&s_chip);
    CHECK(ATCA_SUCCESS == atcab_init(&s_cfg));
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));
    CHECK(0xA5u == s_chip.config[84]);

    cfg.user_extra = 0x11u;
    CHECK(ATECC608_ERR_EXEC == atecc608_provision_config(&cfg));
    CHECK(0xA5u == s_chip.config[84]);      // one-shot value kept
    CHECK(0x51u == s_chip.config[18]);      // rest of the zone untouched

    // Absent chip: every operation fails at the transport level.
    s_chip.present = false;
    CHECK(ATECC608_ERR_COMM == atecc608_provision_config(&cfg));
    CHECK(ATECC608_ERR_COMM == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));
    CHECK(0u == s_confirm_calls);           // never reached the confirm
    CHECK(ATECC608_ERR_COMM == atecc608_counter_read(0, &v));
}

static void t_lock_config_zone(void)
{
    atecc608_config_intent_t cfg;

    printf("t_lock_config_zone\n");
    setup();
    fill_golden_config(&cfg);
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));

    // Refused without confirm: nothing changes.
    s_confirm_result = false;
    CHECK(ATECC608_ERR_CHIP_STATE == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));
    CHECK(1u == s_confirm_calls);
    CHECK(ATECC608_CONFIG_UNLOCKED == s_chip.config[87]);
    s_confirm_result = true;

    // Drift between provision and lock: re-verification fails BEFORE the
    // confirm (a corrupted zone cannot be locked).
    s_chip.config[18] ^= 0x01u;
    CHECK(ATECC608_ERR_EXEC == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));
    CHECK(1u == s_confirm_calls);
    s_chip.config[18] ^= 0x01u;  // restore

    // Clean path: confirmed, CRC-verified lock, zone locked.
    CHECK(ATECC608_OK == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));
    CHECK(2u == s_confirm_calls);
    CHECK(0x00u == s_chip.config[87]);

    // Already locked: refused before the confirm, no chip command.
    CHECK(ATECC608_ERR_CHIP_STATE == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));
    CHECK(2u == s_confirm_calls);

    // NULL confirm: rejected without any chip access.
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_lock_config_zone(&cfg, NULL, NULL));
}

static void t_lock_data_zone(void)
{
    atecc608_config_intent_t cfg;
    uint8_t data[ATECC608_DATA_SLOT_LEN];
    uint8_t readback[ATECC608_DATA_SLOT_LEN];

    printf("t_lock_data_zone\n");
    setup();
    fill_golden_config(&cfg);

    // The data zone cannot be locked before the config zone.
    CHECK(ATECC608_ERR_CHIP_STATE == atecc608_lock_data_zone(confirm_hook, NULL));
    CHECK(0u == s_confirm_calls);

    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));
    CHECK(ATECC608_OK == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));
    CHECK(0x00u == s_chip.config[87]);

    // Refused without confirm. (The refused attempt still consumes the
    // confirm call: the confirm comes after the state checks, right
    // before the irreversible command.)
    s_confirm_result = false;
    CHECK(ATECC608_ERR_CHIP_STATE == atecc608_lock_data_zone(confirm_hook, NULL));
    CHECK(2u == s_confirm_calls);
    CHECK(ATECC608_CONFIG_UNLOCKED == s_chip.config[86]);
    s_confirm_result = true;

    // Lock it.
    CHECK(ATECC608_OK == atecc608_lock_data_zone(confirm_hook, NULL));
    CHECK(3u == s_confirm_calls);
    CHECK(0x00u == s_chip.config[86]);

    // After the lock: plain slots stay WRITABLE — the data-zone lock
    // switches the zone to policy enforcement (reads become possible,
    // 4-byte word writes are allowed); only individual slot locks freeze
    // contents (Microchip's write_upper_slots expects the 32-byte write to
    // succeed "for both locked and unlocked case"). Plain slots are
    // readable; secret slots (slot 15 in the golden intent) are not.
    // (Slots 0 and 3 are key slots and not readable from the data zone at
    // all.)
    memset(data, 0x5Au, sizeof(data));
    CHECK(ATCA_SUCCESS ==
          atcab_write_zone(ATCA_ZONE_DATA, 1, 0, 0, data, ATECC608_DATA_SLOT_LEN));
    CHECK(ATCA_SUCCESS ==
          atcab_read_zone(ATCA_ZONE_DATA, 1, 0, 0, readback, ATECC608_DATA_SLOT_LEN));
    CHECK(0 == memcmp(readback, data, sizeof(data)));
    CHECK(ATCA_EXECUTION_ERROR ==
          atcab_read_zone(ATCA_ZONE_DATA, 15, 0, 0, readback, ATECC608_DATA_SLOT_LEN));

    // Re-lock: refused (already locked), before the confirm.
    CHECK(ATECC608_ERR_CHIP_STATE == atecc608_lock_data_zone(confirm_hook, NULL));
    CHECK(3u == s_confirm_calls);
}

static void t_lock_data_slot(void)
{
    atecc608_config_intent_t cfg;

    printf("t_lock_data_slot\n");
    setup();

    atecc608_config_default(&cfg);
    cfg.key[4].lockable = true;
    cfg.key[15].lockable = true;
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));

    // SlotLocked polarity: bit n = 1 -> unlocked, 0 -> locked (factory
    // 0xFFFF = nothing locked; the Lock command clears the bit).
    // Slot not marked lockable: the chip rejects it.
    CHECK(ATECC608_ERR_EXEC == atecc608_lock_data_slot(3, confirm_hook, NULL));
    CHECK(0xFFu == s_chip.config[88]);
    CHECK(0xFFu == s_chip.config[89]);

    // Refused without confirm: nothing changes.
    s_confirm_result = false;
    CHECK(ATECC608_ERR_CHIP_STATE == atecc608_lock_data_slot(4, confirm_hook, NULL));
    CHECK(0xFFu == s_chip.config[88]);
    CHECK(0xFFu == s_chip.config[89]);
    s_confirm_result = true;

    // Lockable slot: OK (bit 15 of the SlotLocked word is cleared).
    CHECK(ATECC608_OK == atecc608_lock_data_slot(15, confirm_hook, NULL));
    CHECK((s_chip.config[89] & 0x80u) == 0u);

    // Re-locking the same slot: the chip rejects it.
    CHECK(ATECC608_ERR_EXEC == atecc608_lock_data_slot(15, confirm_hook, NULL));

    // With the config zone locked (the precondition for any data-zone
    // write), a 32-byte write to the individually locked slot is
    // rejected by the chip (atca_tests_write.c write_upper_slots skips
    // such slots: "Slot is locked and can't be written to").
    CHECK(ATECC608_OK == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));
    {
        uint8_t data[ATECC608_DATA_SLOT_LEN];
        memset(data, 0x5Au, sizeof(data));
        CHECK(ATCA_EXECUTION_ERROR ==
              atcab_write_zone(ATCA_ZONE_DATA, 15, 0, 0, data, ATECC608_DATA_SLOT_LEN));
    }

    // Out-of-range slot: rejected without any chip command.
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_lock_data_slot(16, confirm_hook, NULL));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_lock_data_slot(0, NULL, NULL));
}

static void t_genkey(void)
{
    atecc608_config_intent_t cfg;
    uint8_t pub[ATECC608_PUBKEY_LEN];

    printf("t_genkey\n");
    setup();
    fill_golden_config(&cfg);
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));

    // Golden slot 0: ECC private with GenKey permitted. The mock returns a
    // deterministic fake key: pub[i] = slot*7 + i*3 + 1.
    CHECK(ATECC608_OK == atecc608_genkey(0, pub));
    CHECK(0x01u == pub[0]);
    CHECK(0x04u == pub[1]);
    CHECK(0x07u == pub[2]);

    // Slot 1 is not a private key slot: the chip rejects it.
    CHECK(ATECC608_ERR_EXEC == atecc608_genkey(1, pub));

    // Invalid arguments.
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_genkey(0, NULL));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_genkey(16, pub));
}

static void t_get_pubkey(void)
{
    atecc608_config_intent_t cfg;
    uint8_t pub[ATECC608_PUBKEY_LEN];
    uint8_t pub2[ATECC608_PUBKEY_LEN];

    printf("t_get_pubkey\n");
    setup();
    fill_golden_config(&cfg);
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));

    // Golden slot 0: ECC private. The public key is never stored in a
    // data slot; mode 0x00 recomputes it from the stored private key.
    CHECK(ATECC608_OK == atecc608_get_pubkey(0, pub));
    CHECK(0x01u == pub[0]);  // mock: pub[i] = slot*7 + i*3 + 1
    CHECK(0x04u == pub[1]);
    CHECK(0x07u == pub[2]);

    // Consistency: mode 0x00 "recomputes" exactly the key that mode 0x04
    // just generated for the same slot.
    CHECK(ATECC608_OK == atecc608_genkey(0, pub2));
    CHECK(0 == memcmp(pub, pub2, sizeof(pub)));

    // The point of mode 0x00: it keeps working after the data-zone lock,
    // when mode 0x04 is gone.
    CHECK(ATECC608_OK == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));
    CHECK(ATECC608_OK == atecc608_lock_data_zone(confirm_hook, NULL));
    CHECK(ATECC608_OK == atecc608_get_pubkey(0, pub2));
    CHECK(0 == memcmp(pub, pub2, sizeof(pub)));
    // ...and mode 0x04 is really refused once the data zone is locked.
    CHECK(ATECC608_ERR_EXEC == atecc608_genkey(0, pub2));

    // Slot 1 is not a private key slot: the chip rejects it.
    CHECK(ATECC608_ERR_EXEC == atecc608_get_pubkey(1, pub));

    // Invalid arguments: rejected before any chip command.
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_get_pubkey(0, NULL));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_get_pubkey(16, pub));
}

static void t_iokey(void)
{
    atecc608_config_intent_t cfg;
    uint8_t key[ATECC608_DATA_SLOT_LEN];
    uint8_t readback[ATECC608_DATA_SLOT_LEN];

    printf("t_iokey\n");
    setup();

    // Real chip behavior (verified on the bench; Microchip's own
    // conformance test atca_tests_read.c asserts it): data slots cannot
    // be read while the data zone is unlocked. A read-back verify of the
    // I/O key write is therefore impossible at any point in the flow;
    // the write is confirmed by the chip's OK response only.
    CHECK(ATCA_EXECUTION_ERROR ==
          atcab_read_zone(ATCA_ZONE_DATA, 14, 0, 0, readback, ATECC608_DATA_SLOT_LEN));

    // Real chip behavior (verified on the bench 2026-10-23: a 32-byte
    // Write to a plain factory slot returns ATCA_EXECUTION_ERROR): the
    // data zone cannot be WRITTEN until the config zone is locked — all
    // of Microchip's data-write conformance tests run with the config
    // zone locked. The prov layer refuses before reaching the chip; the
    // chip refuses the raw write as well.
    for (size_t i = 0; i < sizeof(key); i++) {
        key[i] = (uint8_t)(0xA0u + i);
    }
    CHECK(ATECC608_ERR_CHIP_STATE == atecc608_write_iokey(14, key));
    CHECK(ATCA_EXECUTION_ERROR ==
          atcab_write_zone(ATCA_ZONE_DATA, 14, 0, 0, key, ATECC608_DATA_SLOT_LEN));

    // The approved 4B order: provision the config zone, lock it
    // (irreversible), THEN write the I/O key.
    atecc608_config_default(&cfg);
    cfg.slot[14].is_secret = true;   // the dev intent marks slot 14 secret
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));
    CHECK(ATECC608_OK == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));

    // Now the write is permitted: the chip's OK commits it and the slot
    // holds the key. Still unreadable (data zone unlocked).
    CHECK(ATECC608_OK == atecc608_write_iokey(14, key));
    CHECK(0 == memcmp(&s_chip.data[14 * ATECC608_DATA_SLOT_LEN], key, sizeof(key)));
    CHECK(ATCA_EXECUTION_ERROR ==
          atcab_read_zone(ATCA_ZONE_DATA, 14, 0, 0, readback, ATECC608_DATA_SLOT_LEN));

    // Re-keying after the config zone lock: is_secret blocks reads, not
    // writes; the data zone is still unlocked.
    for (size_t i = 0; i < sizeof(key); i++) {
        key[i] = (uint8_t)(0x30u + i);
    }
    CHECK(ATECC608_OK == atecc608_write_iokey(14, key));
    CHECK(0 == memcmp(&s_chip.data[14 * ATECC608_DATA_SLOT_LEN], key, sizeof(key)));

    // Invalid arguments: rejected before any chip command.
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_write_iokey(16, key));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_write_iokey(14, NULL));

    // Slots that do not accept a clear write in the LOCKED config:
    // refused before the write (the config zone is readable even when
    // locked). Slot 14 is plain in this intent, so it still works.
    setup();
    atecc608_config_default(&cfg);
    cfg.slot[5].is_secret    = true;
    cfg.slot[5].write_config = 7;  // writing slot 5 requires key 7
    cfg.key[0].private_key   = true;
    cfg.key[0].key_type      = ATECC608_KEY_TYPE_ECC;
    cfg.slot[0].is_secret    = true;
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));
    CHECK(ATECC608_OK == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));
    CHECK(ATECC608_ERR_CHIP_STATE == atecc608_write_iokey(5, key));  // write_config
    CHECK(ATECC608_ERR_CHIP_STATE == atecc608_write_iokey(0, key));  // private key
    CHECK(ATECC608_OK == atecc608_write_iokey(14, key));

    // Data zone locked: refused (our flow never locks the data zone; the
    // guard stays conservative).
    setup();
    fill_golden_config(&cfg);
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));
    CHECK(ATECC608_OK == atecc608_lock_config_zone(&cfg, confirm_hook, NULL));
    CHECK(ATECC608_OK == atecc608_lock_data_zone(confirm_hook, NULL));
    CHECK(ATECC608_ERR_CHIP_STATE == atecc608_write_iokey(14, key));
}

static void t_counters(void)
{
    atecc608_config_intent_t cfg;
    uint32_t v;

    printf("t_counters\n");
    setup();
    fill_golden_config(&cfg);
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));

    // Golden: counter 0 = 5, counter 1 = 0.
    CHECK(ATECC608_OK == atecc608_counter_read(0, &v));
    CHECK(5u == v);
    CHECK(ATECC608_OK == atecc608_counter_read(1, &v));
    CHECK(0u == v);

    // Increment is gated by confirm.
    s_confirm_result = false;
    CHECK(ATECC608_ERR_CHIP_STATE == atecc608_counter_increment(0, &v, confirm_hook, NULL));
    CHECK(ATECC608_OK == atecc608_counter_read(0, &v));
    CHECK(5u == v);  // unchanged
    s_confirm_result = true;

    CHECK(ATECC608_OK == atecc608_counter_increment(0, &v, confirm_hook, NULL));
    CHECK(6u == v);
    CHECK(ATECC608_OK == atecc608_counter_read(0, &v));
    CHECK(6u == v);

    // Out-of-range id: rejected without any chip command.
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_counter_read(2, &v));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_counter_read(0, NULL));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_counter_increment(2, &v, confirm_hook, NULL));
    CHECK(ATECC608_ERR_BAD_PARAM == atecc608_counter_increment(0, NULL, confirm_hook, NULL));
}

static void t_counter_max(void)
{
    atecc608_config_intent_t cfg;
    uint32_t v;

    printf("t_counter_max\n");
    setup();
    atecc608_config_default(&cfg);
    cfg.counter[0].value = ATECC608_COUNTER_MAX;
    CHECK(ATECC608_OK == atecc608_provision_config(&cfg));

    CHECK(ATECC608_OK == atecc608_counter_read(0, &v));
    CHECK(ATECC608_COUNTER_MAX == v);

    // One past the max: the chip rejects the increment.
    CHECK(ATECC608_ERR_EXEC == atecc608_counter_increment(0, &v, confirm_hook, NULL));
    CHECK(ATECC608_OK == atecc608_counter_read(0, &v));
    CHECK(ATECC608_COUNTER_MAX == v);  // unchanged
}

// --- main ------------------------------------------------------------------------------

int main(void)
{
    t_wake();
    t_provision_default();
    t_provision_golden();
    t_provision_guarded();
    t_lock_config_zone();
    t_lock_data_zone();
    t_lock_data_slot();
    t_genkey();
    t_get_pubkey();
    t_iokey();
    t_counters();
    t_counter_max();

    printf("%s: %d checks, %d failures\n",
           (s_failures == 0) ? "PASS" : "FAIL", s_checks, s_failures);
    return (s_failures == 0) ? 0 : 1;
}

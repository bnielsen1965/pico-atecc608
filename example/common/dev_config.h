// The development config for the on-bench ATECC608 (see example/README.md
// for the full rationale).
//
// Shared by the two consumers that must always encode the SAME image:
//   - example/console/main.c       (prov status/config/lock on the Pico)
//   - example/tools/dump_devconfig.c (the host byte-plan dump)
//
// Principle: lock the layout, keep the contents open.

#pragma once

#include "atecc608/atecc608_config.h"

// Encode the agreed 4B config as a build intent.
static void dev_config(atecc608_config_intent_t *c)
{
    atecc608_config_default(c);

    // --- Slot table -------------------------------------------------------
    // ECC public key slots: key_type ECC, pub_info (usable to verify), no
    // access key. SlotConfig stays all-clear.
    //   0  = firmware validation (primary), lockable
    //   2  = device identity public, not lockable
    //   11 = second firmware key, lockable
    //   13 = spare pair public, not lockable
    for (int i = 0; i <= 15; i++) {
        if (i == 0 || i == 2 || i == 11 || i == 13) {
            c->key[i].key_type = ATECC608_KEY_TYPE_ECC;
            c->key[i].pub_info = true;
        }
    }
    c->key[0].lockable  = true;
    c->key[11].lockable = true;

    // ECC private key slots (distinct SlotConfig layout): is_secret is
    // mandatory, gen_key=1 so slots can be re-bound after a DB loss.
    //   1  = device identity: sign external + ECDH
    //   3-6 = FIDO2 credentials: sign external (asserts sign the
    //         challenge digest computed on the Pico)
    //   12 = spare pair: ECDH / second identity
    for (int i = 0; i <= 15; i++) {
        if (i == 1 || (i >= 3 && i <= 6) || i == 12) {
            c->key[i].key_type    = ATECC608_KEY_TYPE_ECC;
            c->key[i].private_key = true;
            c->key[i].pub_info    = true;
            c->slot[i].is_secret  = true;
            c->slot[i].ext_sig    = true;
            c->slot[i].gen_key    = true;
        }
    }
    c->slot[1].ecdh  = true;
    c->slot[12].ecdh = true;

    // Non-ECC unreadable secret slots (key_type NON_ECC is the default):
    // is_secret = no clear reads at all; KDF/sign stay internal.
    //   7-10 = password-store master + spare compartments, lockable
    //   14   = I/O protection key, LOCKABLE:
    //          contents stay re-writable in development (lost copy =
    //          re-key); production hardening slot-locks it after the
    //          recorded copy is verified, closing the bus-attacker
    //          re-key hole.
    //   15   = plain data spare (all clear)
    for (int i = 7; i <= 10; i++) {
        c->slot[i].is_secret = true;
        c->key[i].lockable   = true;
    }
    c->slot[14].is_secret = true;
    c->key[14].lockable   = true;

    // --- Counters ----------------------------------------------------------
    // 0 = FIDO2 signature count (CTAP global), 1 = firmware
    // anti-rollback. Both start at the factory value (0).
    // (Defaults are already 0; stated here for the plan's completeness.)

    // --- ChipOptions: I/O protection ON from the start ----------------------
    c->io_prot_en  = true;
    c->io_prot_key = 14;
    c->kdf_aes_en  = true; // required for KDF (library ATECC608 KDF test)
    c->ecdh_prot   = 1;    // ECDH output encrypted on the bus
    c->kdf_prot    = 1;    // KDF output encrypted on the bus

    // Everything else stays at the safe defaults: use_lock_en=false,
    // secure boot off, no volatile key permission, no CountMatch,
    // counters 0, slot_locked 0, x509 0.
}

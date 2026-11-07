// fido_button.h
//
// A debounced button state machine — the user-presence touch input of
// the FIDO2 app. Pure C, no Pico dependency, so the logic is
// host-tested in tests/test_button.c.
//
// A mechanical switch bounces: the contacts make and break dozens of
// times over ~10-50 ms before settling. A press only counts once the
// raw level has stayed stable for FIDO_BUTTON_DEBOUNCE_MS — any change
// in level restarts the window. The machine is edge-triggered: it
// fires exactly once per release->press transition, so a held button
// is a single touch (the "touch the key" semantics the CTAP layer
// expects: one touch is consumed by the pending transaction).
//
// The app calls fido_button_tick() once per main-loop iteration (the
// 1 ms card tick) with the raw "is the button pressed" level. The
// button is OPTIONAL hardware: with no button wired, the pin (pulled
// up, wired to GND through the switch) reads released forever and the
// machine never fires.

#pragma once

#include <stdbool.h>
#include <stdint.h>

// The raw level must be stable this long before an edge is accepted.
// Tactile switches settle well inside this; the CTAP UP wait is in
// seconds, so the delay is invisible to the user.
#define FIDO_BUTTON_DEBOUNCE_MS 30u

typedef struct {
    bool     stable;    // the debounced level (false = released at boot)
    bool     raw;       // the last raw sample seen
    uint32_t since_ms;  // when the current raw run started
} fido_button_t;

void fido_button_init(fido_button_t *b);

// One sample at time now_ms (milliseconds, monotonic). Returns true
// exactly once, on a debounced press edge (release -> press); release
// edges and everything else return false.
bool fido_button_tick(fido_button_t *b, bool pressed, uint32_t now_ms);

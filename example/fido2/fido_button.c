// fido_button.c — see fido_button.h.

#include "fido_button.h"

void fido_button_init(fido_button_t *b)
{
    b->stable   = false;   // released at boot
    b->raw      = false;
    b->since_ms = 0;
}

bool fido_button_tick(fido_button_t *b, bool pressed, uint32_t now_ms)
{
    if (pressed != b->raw) {
        // The raw level changed (or this is the first sample): restart
        // the stability window. Bounce is exactly this — a run of
        // level changes — and it can never produce an edge on its own.
        b->raw      = pressed;
        b->since_ms = now_ms;
        return false;
    }
    if (pressed == b->stable) {
        return false;   // settled at the current level: no edge
    }
    // The raw level has differed from the debounced level since
    // since_ms. Unsigned subtraction: a ms-timer wraparound is correct.
    if (now_ms - b->since_ms < FIDO_BUTTON_DEBOUNCE_MS) {
        return false;   // still inside the stability window
    }
    b->stable = pressed;
    return pressed;     // true only for the press edge
}

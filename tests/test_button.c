// Host unit tests for the fido2 example's debounced button state
// machine (example/fido2/fido_button.c) — pure C, no Pico.
//
// Covers: the clean press edge (firing exactly at the debounce
// boundary, not one sample before), the boundary itself (29 ms of
// press is not a press, 30 ms is), bounce (a run of level changes can
// never fire on its own; the edge lands debounce-ms after the level
// SETTLES), release (no edge, the machine returns to released),
// double-press (two edges), a held button (exactly one edge), a
// button already held at the first sample, and the ms-timer
// wraparound.

#include <stdio.h>
#include <stdint.h>

#include "fido_button.h"

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

// --- the tests --------------------------------------------------------------------

static void t_init(void)
{
    fido_button_t b;
    fido_button_init(&b);
    // Released at boot: released samples are a no-op forever.
    for (uint32_t t = 0; t < 100; t++) {
        CHECK(false == fido_button_tick(&b, false, t));
    }
}

// A clean press: the first pressed sample starts the window, the edge
// fires on the sample where now - since == FIDO_BUTTON_DEBOUNCE_MS —
// and on no sample before it.
static void t_press(void)
{
    fido_button_t b;
    fido_button_init(&b);
    for (uint32_t t = 0; t <= 100; t++) {
        const bool edge = fido_button_tick(&b, true, t);
        if (t < FIDO_BUTTON_DEBOUNCE_MS) {
            CHECK(false == edge);
        } else if (t == FIDO_BUTTON_DEBOUNCE_MS) {
            CHECK(true == edge);
        } else {
            CHECK(false == edge);   // held: no re-fire
        }
    }
}

// The boundary, from both sides: a press that lasts 29 ms (then
// released) never fires; one that lasts 30 ms fires exactly once.
static void t_boundary(void)
{
    fido_button_t b;
    fido_button_init(&b);
    for (uint32_t t = 0; t < 29; t++) {
        CHECK(false == fido_button_tick(&b, true, t));
    }
    // Release at t=29: the press run was 29 samples long — no edge.
    CHECK(false == fido_button_tick(&b, false, 29));
    for (uint32_t t = 30; t < 70; t++) {
        CHECK(false == fido_button_tick(&b, false, t));
    }
    // A second press held for exactly 30 ms.
    for (uint32_t t = 70; t < 100; t++) {
        const bool edge = fido_button_tick(&b, true, t);
        CHECK((100 == t) == edge);
    }
}

// Bounce: the raw level flips true/false/true/... for 10 ms, then
// settles at pressed. No edge may land inside the bounce, and the
// edge lands exactly FIDO_BUTTON_DEBOUNCE_MS after the settle — not
// after the first contact.
static void t_bounce(void)
{
    fido_button_t b;
    fido_button_init(&b);
    // t=0..9: bounce (glitch every other sample, ending RELEASED at
    // t=9 so the pressed run starts exactly at the settle), settle
    // pressed at t=10.
    for (uint32_t t = 0; t <= 10; t++) {
        const bool raw = (t < 10) ? ((t % 2) == 0) : true;
        CHECK(false == fido_button_tick(&b, raw, t));
    }
    // t=11..39: inside the post-settle window.
    for (uint32_t t = 11; t < 10 + FIDO_BUTTON_DEBOUNCE_MS; t++) {
        CHECK(false == fido_button_tick(&b, true, t));
    }
    // t=10+30: the single edge.
    CHECK(true == fido_button_tick(&b, true, 10 + FIDO_BUTTON_DEBOUNCE_MS));
    // t=41..: held, no re-fire.
    for (uint32_t t = 11 + FIDO_BUTTON_DEBOUNCE_MS; t < 200; t++) {
        CHECK(false == fido_button_tick(&b, true, t));
    }
}

// Release: no edge on the way down (the machine only fires on press),
// and the machine is released again after the window.
static void t_release(void)
{
    fido_button_t b;
    fido_button_init(&b);
    // A clean press + hold...
    for (uint32_t t = 0; t < FIDO_BUTTON_DEBOUNCE_MS; t++) {
        CHECK(false == fido_button_tick(&b, true, t));
    }
    CHECK(true == fido_button_tick(&b, true, FIDO_BUTTON_DEBOUNCE_MS));
    // ...released at t=50: the release edge is NOT reported...
    CHECK(false == fido_button_tick(&b, false, 50));
    // ...the release settles at t=80 (30 ms of released samples)...
    for (uint32_t t = 51; t < 100; t++) {
        CHECK(false == fido_button_tick(&b, false, t));
    }
    // ...and a fresh press at t=100 fires again at t=130.
    for (uint32_t t = 100; t <= 130; t++) {
        const bool edge = fido_button_tick(&b, true, t);
        CHECK((130u == t) == edge);
    }
}

// Double-press: two clean presses give exactly two edges, in order.
static void t_double(void)
{
    fido_button_t b;
    fido_button_init(&b);
    int edges = 0;
    for (uint32_t t = 0; t < 300; t++) {
        // press 1: t=10..40, release: t=80.., press 2: t=120..150.
        const bool raw = ((10 <= t) && (t < 80)) || ((120 <= t) && (t < 200));
        if (fido_button_tick(&b, raw, t)) {
            edges++;
        }
    }
    CHECK(2 == edges);
}

// A held button is ONE touch: a 10-second press fires exactly once.
static void t_hold(void)
{
    fido_button_t b;
    fido_button_init(&b);
    int edges = 0;
    for (uint32_t t = 0; t < 10000; t++) {
        if (fido_button_tick(&b, true, t)) {
            edges++;
        }
    }
    CHECK(1 == edges);
}

// The button is already held at the first sample: the window starts
// at that sample and the edge lands FIDO_BUTTON_DEBOUNCE_MS later.
static void t_held_at_boot(void)
{
    fido_button_t b;
    fido_button_init(&b);
    for (uint32_t t = 0; t <= 50; t++) {
        const bool edge = fido_button_tick(&b, true, t);
        CHECK((FIDO_BUTTON_DEBOUNCE_MS == t) == edge);
    }
}

// The ms timer wraps at 2^32 (~497 days): a press straddling the
// wrap debounces correctly — the unsigned difference is what matters.
static void t_wraparound(void)
{
    fido_button_t b;
    fido_button_init(&b);
    const uint32_t base = 0xFFFFFFF0u;   // 16 ms before the wrap
    CHECK(false == fido_button_tick(&b, false, base));
    for (uint32_t i = 1; i <= 0x2Au; i++) {   // 42 samples past base
        const uint32_t now = base + i;       // wraps at i=16
        const bool edge = fido_button_tick(&b, true, now);
        // The run started at base+1 (first pressed sample); the edge
        // lands when now - (base+1) == 30, i.e. i == 31.
        CHECK((31u == i) == edge);
    }
}

int main(void)
{
    t_init();
    t_press();
    t_boundary();
    t_bounce();
    t_release();
    t_double();
    t_hold();
    t_held_at_boot();
    t_wraparound();

    printf("%s: %d checks, %d failures\n",
           (s_failures == 0) ? "PASS" : "FAIL", s_checks, s_failures);
    return (s_failures == 0) ? 0 : 1;
}

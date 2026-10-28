// tusb_config.h — TinyUSB configuration for the fido2 app: a device-mode,
// single-HID-interface security key. Mirrors pico_stdio_usb's tusb_config.h
// (same fork, same RP2040/RP2350 DCD), minus the CDC class — the USB
// interface here is the FIDO HID interface only.

#pragma once

// NOTE: no LIB_TINYUSB_HOST/DEVICE guard around these definitions (the
// pico_stdio_usb config has one). This app links the MARKED tinyusb_device
// target, which defines LIB_TINYUSB_DEVICE=1 in the app's own
// translation units to tell pico_stdio_usb that the app owns the USB
// stack — guarding on it here would silently drop the whole config
// (TinyUSB then builds with no device class and tud_task() vanishes).
// The marked target also disables pico_stdio_usb's default-descriptor,
// auto-init, and background-task behavior, which is exactly what a
// self-driven TinyUSB app wants.

#define CFG_TUSB_RHPORT0_MODE   (OPT_MODE_DEVICE)

// One HID instance (the FIDO interface).
#define CFG_TUD_HID             1

// OUT endpoint transfer buffer. MUST stay 64 — the FIDO HID reports are
// exactly 64 bytes, and the RP2040 DCD arms the OUT transfer with this
// size: a 64-byte arm carries the hardware LAST bit, so one full 64-byte
// host packet completes the transfer (dcd_rp2040's bufctrl_prepare16 sets
// LAST only when the remaining length is zero at arm time). A larger
// buffer would arm WITHOUT LAST and wait for a second packet that never
// comes, stalling every 64-byte host report until the next write.
// (A 65-byte SET_REPORT control write is rejected at 64 by TinyUSB's own
// hid_device.c guard — the same limit real FIDO hosts never exceed,
// because they deliver 64-byte reports.)
#define CFG_TUD_HID_EP_BUFSIZE  64

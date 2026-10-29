// fido_desc_probe.c — raw-USB ground truth for the FIDO key's descriptor
// requests.
//
// The kernel's usbhid probe (drivers/hid/usbhid/hid-core.c,
// usbhid_parse, kernel 7.2) does, in order:
//   1. (config extra descriptor, no live transfer)
//   2. SET_IDLE (class/interface, wValue=0, len 0) — the kernel
//      ignores its result. Request code is 0x0A: Linux's uapi hid.h
//      (and TinyUSB's hidd) number the SET_* HID requests
//      0x09/0x0A/0x0B, not the USB-IF table's 0x02/0x04/0x06 — the
//      kernel sends 0x0A, and a 0x04 is STALLed by a conformant
//      hidd.
//   3. GET_DESCRIPTOR(0x2200) — a STANDARD request (rt=0x81, interface
//      recipient), wLength = wReportLength (34), retried up to 4x while
//      the answer is short
//
// This tool replays those exact requests (plus a reference GET with a big
// wLength) over raw libusb and prints the raw results — descriptor-level
// ground truth for the control path (the kernel-side check is: dmesg
// shows usbhid binding without error, and /dev/hidraw0 appears).
//
// Build:  gcc -o fido_desc_probe fido_desc_probe.c $(pkg-config --cflags --libs libusb-1.0)
// Run:    sudo ./fido_desc_probe

#include <libusb-1.0/libusb.h>
#include <stdio.h>
#include <string.h>

#define VID 0x2e8a
#define PID 0x000b

static unsigned char s_buf[4096];

static void dump(const char *what, int n)
{
    if (n < 0) {
        printf("%-28s FAILED: %s\n", what, libusb_error_name(n));
        return;
    }
    printf("%-28s n=%d\n", what, n);
    for (int j = 0; j < n; j++)
        printf("  %02x%s", s_buf[j], (j + 1) % 16 == 0 ? "\n" : "");
    if (n % 16)
        printf("\n");
}

int main(void)
{
    struct libusb_context *ctx = NULL;
    struct libusb_device **list = NULL;
    if (libusb_init(&ctx) != 0) {
        fprintf(stderr, "libusb_init failed\n");
        return 1;
    }
    ssize_t cnt = libusb_get_device_list(ctx, &list);
    if (cnt < 0) {
        fprintf(stderr, "get_device_list: %s\n",
                libusb_strerror((int)cnt));
        return 1;
    }

    for (ssize_t i = 0; i < cnt; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) != 0)
            continue;
        if (dd.idVendor != VID || dd.idProduct != PID)
            continue;

        printf("found %04x:%04x on bus %d device %d\n",
               dd.idVendor, dd.idProduct,
               libusb_get_bus_number(list[i]),
               libusb_get_device_address(list[i]));

        struct libusb_device_handle *h = NULL;
        int rc = libusb_open(list[i], &h);
        if (rc != 0) {
            fprintf(stderr, "open: %s\n", libusb_error_name(rc));
            return 1;
        }

        // The kernel's usbhid now binds this interface (the -22 is
        // fixed), and while a kernel driver is attached, usbfs blocks
        // our transfers with EIO (LIBUSB_ERROR_IO). Detach it for the
        // probe, restore it afterwards. (Pre-fix, usbhid had failed to
        // bind, so there was nothing to detach — which is why this
        // worked before.)
        int ifnum = 0;
        int had_kdrv = 0;
        if (libusb_kernel_driver_active(h, ifnum) > 0) {
            had_kdrv = 1;
            rc = libusb_detach_kernel_driver(h, ifnum);
            if (rc != 0) {
                fprintf(stderr, "detach_kernel_driver: %s\n",
                        libusb_error_name(rc));
                return 1;
            }
            printf("detached kernel driver (usbhid) from interface 0\n");
        }

        // Same requests, same order as the kernel's usbhid_parse.
        // (2) SET_IDLE, report 0, idle 0. Linux's hid.h (and TinyUSB)
        // number SET_IDLE = 0x0A, not the USB-IF table's 0x04.
        int n = libusb_control_transfer(h, 0x21, 0x0A, 0x0000, 0,
                                        NULL, 0, 5000);
        printf("SET_IDLE                     n=%d (%s)\n", n,
               n < 0 ? libusb_error_name(n) : "ok");

        // (3) GET_DESCRIPTOR(REPORT), wLength = 34, exactly as the
        // kernel: rt=0x81 (STANDARD, interface recipient) — NOT 0xA1
        // (class). GET_DESCRIPTOR is a standard request; a class-typed
        // GET_DESCRIPTOR is STALLed by a conformant device (and by
        // TinyUSB's hidd), which is what this probe's first version hit.
        memset(s_buf, 0, sizeof s_buf);
        n = libusb_control_transfer(h, 0x81, 0x06, 0x2200, 0,
                                    s_buf, 34, 5000);
        dump("GET_DESC(REPORT) len=34", n);

        // Reference: ask for a lot, see what length the device commits to
        memset(s_buf, 0, sizeof s_buf);
        n = libusb_control_transfer(h, 0x81, 0x06, 0x2200, 0,
                                    s_buf, sizeof s_buf, 5000);
        dump("GET_DESC(REPORT) len=4096", n);

        // GET_DESCRIPTOR(HID class desc) for completeness
        memset(s_buf, 0, sizeof s_buf);
        n = libusb_control_transfer(h, 0x81, 0x06, 0x2100, 0,
                                    s_buf, 9, 5000);
        dump("GET_DESC(HID) len=9", n);

        if (had_kdrv)
            libusb_attach_kernel_driver(h, ifnum);

        libusb_close(h);
        libusb_free_device_list(list, 1);
        libusb_exit(ctx);
        return 0;
    }

    fprintf(stderr, "device %04x:%04x not found\n", VID, PID);
    libusb_free_device_list(list, 1);
    libusb_exit(ctx);
    return 1;
}

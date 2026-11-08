# bench/

Bench tools for the Pico ATECC608 FIDO2 key. Both target the
key's USB/HID interface on the Linux bench machine (Fedora, kernel 7.2).

## fido_desc_probe (C, libusb-1.0)

Raw-USB ground truth for the descriptor control path. Replays the
kernel's `usbhid` probe — SET_IDLE (request code 0x0A: Linux's
`uapi/linux/hid.h` and TinyUSB number the SET_* HID requests
0x09/0x0A/0x0B, not the USB-IF table's 0x02/0x04/0x06) followed by
GET_DESCRIPTOR (standard, rt=0x81) for the report and HID descriptors —
and prints the raw bytes. This is the tool that verified the usbhid
-22 fix (the `0x22` report-descriptor type in `fido_hid.c`). It detaches
the kernel driver from interface 0 first (so it can talk raw) and
reattaches it on exit.

    # build (bench machine)
    gcc -o fido_desc_probe fido_desc_probe.c $(pkg-config --cflags --libs libusb-1.0)

    # run (root: detaches the kernel driver + opens the device)
    sudo ./fido_desc_probe

Expected (provisioned or not): `GET_DESC(REPORT) len=34` → the
34-byte FIDO U2F report descriptor, `GET_DESC(HID) len=9` →
`09 21 11 01 00 01 22 22 00`.

## fido_probe.py (Python 3, stdlib only — no pyusb/hidapi)

CTAPHID transport check over `/dev/hidraw` (the real-host path):
INIT (channel allocation) + PING echo + WINK (LED). The app answers
nothing until the ATECC608 is provisioned (config locked + identity key
in slot 2), so this only passes after provisioning with the console app.

    sudo python3 fido_probe.py

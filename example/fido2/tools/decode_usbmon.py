#!/usr/bin/env python3
"""decode_usbmon.py — decode a usbmon pcap into a CTAPHID timeline.

Usage: decode_usbmon.py <capture.usb>

Parses the raw pcap + usbmon URB records directly (tshark's USB field
extraction is unreliable for this format), filters to the HID interrupt
endpoints, reassembles CTAPHID messages (INIT / CBOR / PING / keep-alive /
continuations), and prints a per-direction timeline. The makeCredential
response is hex-dumped so it can be inspected byte-for-byte.
"""
import struct
import sys

# CTAPHID command bytes (low 7 bits; response has 0x80 set).
CMD = {
    0x01: "PING", 0x02: "KEEPALIVE(spec2.0)", 0x03: "MSG", 0x04: "LOCK",
    0x06: "INIT", 0x07: "VERSION", 0x08: "WINK", 0x10: "CBOR",
    0x11: "CANCEL", 0x3B: "KEEPALIVE(2.3)", 0x3F: "ERROR",
}


def cmd_name(b: int) -> str:
    return CMD.get(b & 0x7F, f"?0x{b & 0x7F:02x}")


def parse_pcap(path):
    """Yield (ts_sec, ts_usec, payload_bytes) for each pcap record."""
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        bo = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        bo = ">"
    else:
        raise SystemExit(f"not a pcap (magic={magic.hex()})")
    off = 24  # global header
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, orig = struct.unpack_from(bo + "IIII", data, off)
        off += 16
        if incl == 0 or off + incl > len(data):
            break
        yield ts_sec, ts_usec, data[off:off + incl]
        off += incl


def main():
    path = sys.argv[1]
    rows = []
    for ts_sec, ts_usec, payload in parse_pcap(path):
        # usbmon_urb: id(4) kernel_ts(8) type(1) status(4) sequence(4)
        #   socketno(1) interface(1) endpoint(1) type_flags(1) start_frame(4)
        #   error_code(4) number(2) babble(2) xferaddr(4) xferlen(4)
        #   mapping_len(4)  => data starts at 53
        if len(payload) < 53:
            continue
        # usbmon_urb field offsets: type@13(1), status@14(4), sequence@18(4),
        # socketno@22(1), interface@23(1), endpoint@24(1), type_flags@25(1),
        # start_frame@26(4), error_code@30(4), number@34(2), babble@36(2),
        # xferaddr@38(4), xferlen@45(4), mapping_len@49(4) => data @ 53
        urb_type = payload[13]
        endpoint = payload[24]
        xferlen = struct.unpack_from("i", payload, 45)[0]
        if urb_type != 0:  # only URBs, not EVENT/FILTER
            continue
        d = payload[53:53 + max(0, xferlen)]
        rows.append((ts_sec, ts_usec, endpoint, xferlen, d))

    # Group by endpoint; IN = endpoint & 0x80.
    print(f"{'#':>3} {'t(s)':>10} {'ep':>4} {'len':>4}  data(<=64B)")
    print("-" * 70)
    for i, (ts_sec, ts_usec, ep, xlen, d) in enumerate(rows):
        t = ts_sec % 1000 + ts_usec / 1e6
        print(f"{i:>3} {t:>10.6f} {ep:#04x} {xlen:>4}  {d[:64].hex(' ')}")


if __name__ == "__main__":
    main()

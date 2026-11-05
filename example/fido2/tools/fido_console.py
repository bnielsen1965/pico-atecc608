#!/usr/bin/env python3
"""Send a console command to the FIDO2 Pico over UART0 and print the reply.

Usage: fido_console.py <command> [port] [read_ms]
  command : 'up' | 'wipe' | any line the firmware console accepts
  port    : default /dev/ttyUSB0
  read_ms : how long to listen for the reply (default 3000)

The firmware (fido_hid.c console_tick) accumulates chars until CR/LF and
strcmp()s the line to 'up' / 'wipe' (exact — no trailing spaces). We send the
command + '\n' and read the reply. Note: 'wipe' does a littlefs flash write,
which pauses all cores briefly, so allow a few seconds for the reply.
"""
import sys
import time
import serial


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    port = sys.argv[2] if len(sys.argv) > 2 else "/dev/ttyUSB0"
    read_ms = int(sys.argv[3]) if len(sys.argv) > 3 else 3000

    with serial.Serial(port, 115200, timeout=0.5) as s:
        time.sleep(0.1)
        s.reset_input_buffer()
        s.write((cmd + "\n").encode())
        s.flush()
        print(f"sent: {cmd!r} to {port}", file=sys.stderr)
        buf = b""
        deadline = time.time() + read_ms / 1000.0
        while time.time() < deadline:
            data = s.read(256)
            if data:
                buf += data
            time.sleep(0.02)
        sys.stdout.write(buf.decode(errors="replace"))
        if not buf:
            print("(no reply)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

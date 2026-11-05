#!/usr/bin/env python3
"""fd_watch.py — log which processes hold /dev/hidraw* open.

Usage: fd_watch.py [DUR_S] [OUT_LOG]
Default: 600 s -> /tmp/opencode/hidraw_fd_watch.log (appended).

Only the browser should be opening the key during a round; anything
else (e.g. a stale terminal, the agent) pollutes the round.
"""
import glob
import os
import sys
import time

DUR_S = int(sys.argv[1]) if len(sys.argv) > 1 else 600
OUT = sys.argv[2] if len(sys.argv) > 2 else '/tmp/opencode/hidraw_fd_watch.log'


def scan():
    found = {}
    for fd in glob.glob('/proc/[0-9]*/fd/*'):
        try:
            tgt = os.readlink(fd)
        except OSError:
            continue
        if tgt.startswith('/dev/hidraw'):
            pid = fd.split('/')[2]
            try:
                comm = open(f'/proc/{pid}/comm').read().strip()
            except OSError:
                comm = '?'
            found.setdefault((pid, comm), set()).add(tgt)
    return found


def main():
    out = open(OUT, 'a')
    out.write(f'== fd_watch start {time.strftime("%F %T")} ({DUR_S} s) ==\n')
    out.flush()
    prev = None
    t0 = time.time()
    while time.time() - t0 < DUR_S:
        cur = scan()
        if cur != prev:
            ts = time.strftime('%H:%M:%S')
            if cur:
                for (pid, comm), nodes in sorted(cur.items()):
                    out.write(f'{ts} pid={pid} {comm} -> {sorted(nodes)}\n')
            else:
                out.write(f'{ts} (no hidraw holders)\n')
            out.flush()
            prev = cur
        time.sleep(1)
    out.write(f'== fd_watch end {time.strftime("%F %T")} ==\n')
    out.close()


if __name__ == '__main__':
    main()

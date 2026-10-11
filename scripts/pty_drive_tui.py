#!/usr/bin/env python3
"""Drive bitwarden-tui under a PTY and send keystrokes for debug reproduction."""

from __future__ import annotations

import os
import pty
import select
import struct
import fcntl
import termios
import time
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BIN = os.path.join(
    os.environ.get(
        "CARGO_TARGET_DIR",
        os.path.join(ROOT, "target"),
    ),
    "debug",
    "bitwarden-tui",
)
# Prefer workspace cargo target; fall back to sandbox cache path discovery via cargo
def find_bin() -> str:
    candidates = [
        os.path.join(ROOT, "target", "debug", "bitwarden-tui"),
        BIN,
    ]
    # Also check common cargo target env
    target = os.environ.get("CARGO_TARGET_DIR")
    if target:
        candidates.insert(0, os.path.join(target, "debug", "bitwarden-tui"))
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return candidates[0]


def set_winsize(fd: int, rows: int = 40, cols: int = 120) -> None:
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def main() -> int:
    os.environ["DEBUG_RUN_ID"] = os.environ.get("DEBUG_RUN_ID", "pty-drive")
    os.environ.setdefault("RUST_LOG", "off")

    bin_path = find_bin()
    if not os.path.isfile(bin_path):
        print(f"binary missing: {bin_path}", file=sys.stderr)
        print("Run: cargo build -p vault-tui", file=sys.stderr)
        return 2

    argv = [bin_path, "--mock", "--server", "http://127.0.0.1:8080"]
    print(f"spawning: {' '.join(argv)}", flush=True)

    pid, master = pty.fork()
    if pid == 0:
        # child
        os.chdir(ROOT)
        os.execv(bin_path, argv)

    set_winsize(master, 40, 120)
    time.sleep(0.8)  # let UI draw + app_start log

    # Sequence: type into server (append 'X'), Tab, type email, Tab, type password, Esc quit
    # Clear server field first with many backspaces then type a short marker
    seq = []
    seq.append(b"\x7f" * 40)  # backspace clear
    seq.append(b"http://test.local")
    seq.append(b"\t")  # tab to email
    seq.append(b"user@test.local")
    seq.append(b"\t")  # tab to password
    seq.append(b"secret123")
    seq.append(b"\x1b")  # Esc quit

    for chunk in seq:
        os.write(master, chunk)
        # drain output
        end = time.time() + 0.15
        while time.time() < end:
            r, _, _ = select.select([master], [], [], 0.05)
            if not r:
                break
            try:
                os.read(master, 4096)
            except OSError:
                break
        time.sleep(0.05)

    time.sleep(0.5)

    # Force kill if still alive
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass

    print("pty drive finished", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

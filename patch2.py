#!/usr/bin/env python3
"""
patch_tcon.py - apply boot-handshake patches to both Samsung TCON SoCs
                via two OpenOCD instances, then resume them in order.

Assumes two OpenOCD instances are already running, e.g.:

    ./openocd -f tcon_m.cfg      # tcl_port 6666  (MASTER)
    ./openocd -f tcon_s.cfg      # tcl_port 6667  (SLAVE)

Usage:
    ./patch_tcon.py                 # patch both, verify, resume S then M
    ./patch_tcon.py --dry-run       # connect + read only, change nothing
    ./patch_tcon.py --diag          # read diagnostic registers and exit
    ./patch_tcon.py --no-resume     # patch + verify but leave both halted
"""

import argparse
import socket
import sys
import time

# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------

TARGETS = [
    # (label, tcl_port)
    ("MASTER", 6666),
    ("SLAVE", 6667),
]

# Resume order: slave first so it is listening before the master transmits.
RESUME_ORDER = ["SLAVE", "MASTER"]
RESUME_GAP_S = 0.05

# --------------------------------------------------------------------------
# Patch table  (address, halfword value, description)
#
# All values are 16-bit little-endian Thumb.
#   0xBF00 = NOP
#   0xE003 = b 0x2788  (unconditional branch, replaces cbnz)
# --------------------------------------------------------------------------

PATCHES = [
    (0x000029E6, 0xBF00, "NOP cbnz r4  - ignore struct[0]"),
    (0x000029E8, 0xBF00, "NOP cbnz r5  - ignore CFG/MS, take handshake path"),
    (0x000029FE, 0xBF00, "NOP bl 0x640c lo - no eMMC blanking on SPI fail"),
    (0x00002A00, 0xBF00, "NOP bl 0x640c hi"),
    (0x00002A02, 0xBF00, "NOP bl 0x2a20 lo - no reset on SPI fail"),
    (0x00002A04, 0xBF00, "NOP bl 0x2a20 hi"),
    (0x0000277E, 0xE003, "cbnz -> b     - GPIO5 timeout safety net"),
]

# Expected original values, used to detect "already patched" or "wrong build".
ORIGINALS = {
    0x0000277E: 0xB918,  # cbnz r0, 0x2788
}

# --------------------------------------------------------------------------
# Diagnostic registers
# --------------------------------------------------------------------------

DIAGS = [
    (0x5830017C, "syscon cfg/status (b14=multichip, b15=slave, b28=BUS_RELHI)"),
    (0x40100094, "scan start selector (==10 -> struct[0]=0)"),
    (0x200016B4, "config struct +0 (scan start index)"),
    (0x200016B8, "config struct +4 (selected CFG/MS)"),
    (0x40130018, "GPIO port 0 input (bit 5 = handshake in)"),
    (0x40131018, "GPIO port 1 input (bit 4 = GPIO 20 ready out)"),
]


class OpenOCD:
    """Minimal client for OpenOCD's TCL RPC (commands/replies end with 0x1a)."""

    TERM = b"\x1a"

    def __init__(self, host, port, timeout=10.0):
        self.addr = (host, port)
        self.sock = socket.create_connection(self.addr, timeout=timeout)
        self.sock.settimeout(timeout)

    def cmd(self, command):
        self.sock.sendall(command.encode() + self.TERM)
        buf = b""
        while not buf.endswith(self.TERM):
            chunk = self.sock.recv(8192)
            if not chunk:
                raise ConnectionError(f"connection closed by {self.addr}")
            buf += chunk
        return buf[: -len(self.TERM)].decode("utf-8", "replace").strip()

    def read16(self, addr):
        out = self.cmd(f"read_memory 0x{addr:08x} 16 1")
        return self._parse_first(out, addr)

    def read32(self, addr):
        out = self.cmd(f"read_memory 0x{addr:08x} 32 1")
        return self._parse_first(out, addr)

    def write16(self, addr, value):
        self.cmd(f"write_memory 0x{addr:08x} 16 {{0x{value:04x}}}")

    @staticmethod
    def _parse_first(out, addr):
        tokens = out.replace(",", " ").split()
        for tok in tokens:
            try:
                return int(tok, 0)
            except ValueError:
                continue
        raise ValueError(f"could not parse read at 0x{addr:08x}: {out!r}")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def connect_all():
    conns = {}
    for label, port in TARGETS:
        try:
            conns[label] = OpenOCD("localhost", port)
            print(f"[{label}] connected on tcl port {port}")
        except OSError as exc:
            print(f"[{label}] FAILED to connect on port {port}: {exc}")
            for c in conns.values():
                c.close()
            sys.exit(1)
    return conns


def halt(label, ocd):
    ocd.cmd("halt")
    state = ocd.cmd("targets")
    print(f"[{label}] halted")
    return state


def show_diags(label, ocd):
    print(f"[{label}] diagnostics:")
    for addr, desc in DIAGS:
        try:
            val = ocd.read32(addr)
            print(f"    0x{addr:08x} = 0x{val:08x}   {desc}")
        except Exception as exc:
            print(f"    0x{addr:08x} = <error: {exc}>")


def check_originals(label, ocd):
    """Warn if the code doesn't look like the build we analysed."""
    ok = True
    for addr, expected in ORIGINALS.items():
        got = ocd.read16(addr)
        patched = dict((a, v) for a, v, _ in PATCHES).get(addr)
        if got == expected:
            print(f"[{label}] 0x{addr:08x} = 0x{got:04x} (original, as expected)")
        elif got == patched:
            print(f"[{label}] 0x{addr:08x} = 0x{got:04x} (already patched)")
        else:
            print(
                f"[{label}] WARNING 0x{addr:08x} = 0x{got:04x}, "
                f"expected 0x{expected:04x} or 0x{patched:04x}"
            )
            ok = False
    return ok


def apply_patches(label, ocd, dry_run=False):
    print(f"[{label}] applying {len(PATCHES)} patches"
          f"{' (DRY RUN)' if dry_run else ''}")
    if not dry_run:
        for addr, val, _ in PATCHES:
            ocd.write16(addr, val)

    all_ok = True
    for addr, val, desc in PATCHES:
        got = ocd.read16(addr)
        good = (got == val)
        all_ok &= good
        flag = "ok " if good else "BAD"
        print(f"    [{flag}] 0x{addr:08x} = 0x{got:04x} "
              f"(want 0x{val:04x})  {desc}")
    return all_ok


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="read and verify only, write nothing")
    ap.add_argument("--diag", action="store_true",
                    help="halt, dump diagnostic registers, exit (no writes)")
    ap.add_argument("--no-resume", action="store_true",
                    help="patch and verify but leave targets halted")
    args = ap.parse_args()

    conns = connect_all()

    try:
        for label, _ in TARGETS:
            halt(label, conns[label])

        if args.diag:
            for label, _ in TARGETS:
                show_diags(label, conns[label])
            print("\nDiagnostics only - targets left halted, nothing written.")
            return 0

        for label, _ in TARGETS:
            check_originals(label, conns[label])

        results = {}
        for label, _ in TARGETS:
            results[label] = apply_patches(label, conns[label], args.dry_run)

        for label, _ in TARGETS:
            show_diags(label, conns[label])

        if not all(results.values()):
            print("\nVERIFY FAILED - not resuming. "
                  "Targets left halted so you can investigate.")
            return 1

        if args.dry_run:
            print("\nDry run complete - nothing written, targets left halted.")
            return 0

        if args.no_resume:
            print("\nPatched and verified. Targets left halted (--no-resume).")
            return 0

        print(f"\nResuming in order: {' -> '.join(RESUME_ORDER)}")
        for label in RESUME_ORDER:
            conns[label].cmd("resume")
            print(f"[{label}] resumed")
            time.sleep(RESUME_GAP_S)

        print("\nDone. Watch both UARTs.")
        print("  Success  : no 'Boot GPIO CNT Over', boot proceeds to "
              "'chB vref' / 'makersheet bank'")
        print("  Partial  : 'Boot GPIO CNT Over' prints but no 'system reset!'")
        return 0

    finally:
        for c in conns.values():
            c.close()


if __name__ == "__main__":
    sys.exit(main())

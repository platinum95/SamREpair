#!/usr/bin/env python3
"""
tcon_bulkdump.py - host-side driver for a read-only bulk dump of the TCON
eMMC user area on the REPLACEMENT board, both SoCs in parallel, over SWD.

Python standard library only. Talks to the two OpenOCD instances over their
TCL RPC ports (master 6666, slave 6667). It sources tconutils.tcl,
tcondump.tcl, pnidprobe.tcl and tconbulk.tcl into each instance, then drives
tconbulk.tcl's primitives. Bulk data crosses SWD via dump_image, which writes
files on the OpenOCD host, so THIS SCRIPT MUST RUN ON THE SAME MACHINE AS
OPENOCD. Use absolute paths without spaces for --new and --tmp.

Output layout, per chip, understood by tcon_diffdump.py:
    <new>/<chip>/user_swd.bin      offset-aligned image (byte N = eMMC byte N)
    <new>/<chip>/journal.txt       D/U/B/X progress lines (see tcon_regions)
    <new>/<chip>/bad_sectors.txt   unreadable sectors, zero-filled in the image

Subcommands (run in the order the procedure gives):
    clockcheck   step adapter speed up while both SoCs run; cmp ITCM vs running.bin
    prepare      halt both, arm guards, reset_to_scan (master then slave), begin both
    pnid         read the ten panel-ID sites, print old vs new
    verify       correctness checks against running.bin and known tags
    speedtest    per-sector vs bulk read timing + full-dump estimate
    dump         the dump itself (parallel, resumable, self-checking)
    state        print tcon_bulk_state for both SoCs
    survey       sample the rest of the user area (optional)
    stop         halt both SoCs and leave them halted (for recovery)

Options common to every subcommand: --speed KHZ sets `adapter speed` on both
instances at connect and prints what the probe actually applied (clockcheck
recommends a value; an OpenOCD restart resets it to the .cfg's 4000).
TCON_RPC_PORTS="master=P,slave=Q" overrides the RPC ports (test_sim.py only).
--regions accepts region names, 0xA-0xB ranges, 'all' (the old-board data
map, the default) or 'full' (the whole user area; use with --skip-blank).

Safety (from the dossier): halt both SoCs or neither; the 0x640C blanking guard
and the 0x6C8C/0x6D50 eMMC-write guards stay armed; never resume after eMMC work
(power cycle instead); no eMMC writes at all. On any TCONERR the driver halts
both SoCs and tells you to power cycle.
"""

import argparse
import collections
import os
import re
import socket
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from tcon_regions import (DUMP_REGIONS, PNID_SITES, SECTOR,  # noqa: E402
                          merge_intervals, parse_regions, subtract_intervals)

DEFAULT_NEW = os.path.normpath(os.path.join(HERE, "..", "emmc_dumps",
                                            "emmc_dumps", "new_board"))
DEFAULT_OLD = os.path.normpath(os.path.join(HERE, "..", "emmc_dumps",
                                            "emmc_dumps", "old_board"))
RUNNING_BIN = os.path.join(HERE, "running.bin")

TCL_FILES = ["tconutils.tcl", "tcondump.tcl", "pnidprobe.tcl", "tconbulk.tcl"]


def _chip_ports():
    """chip name -> TCL RPC port. TCON_RPC_PORTS="master=16666,slave=16667"
    overrides the real ports (test_sim.py uses this so the simulator can never
    share ports with the real OpenOCD instances)."""
    ports = {"master": 6666, "slave": 6667}
    for item in filter(None, (s.strip() for s in
                              os.environ.get("TCON_RPC_PORTS", "").split(","))):
        name, _, port = item.partition("=")
        if name not in ports or not port.isdigit():
            raise SystemExit(f"bad TCON_RPC_PORTS entry {item!r}")
        ports[name] = int(port)
    return ports


CHIPS = _chip_ports()

RPC_TERM = b"\x1a"

# eMMC read function and staging, mirrored from the .tcl for host-side maths
FN_EMMC_READ = 0x00006A98
STAGE = 0x20220000
CHUNK = 0x10000                 # 64 KiB, == tconbulk staging size
ITCM_LEN = 0x60000             # running.bin length
# running.bin is only valid for the part of ITCM that BL1 loads from the eMMC:
# 0x0-0x3C800. Beyond that, live ITCM 0x3C800-0x40000 is never loaded
# (uninitialised, differs per chip and per boot), and the eMMC FW body past
# 0x3C800 does not match running.bin either. Only compare this range.
FW_LOADED_END = 0x3C800
CLOCK_REF_SPEED = 1000          # kHz, reference dumps for clockcheck


# ---------------------------------------------------------------------------
# TCL RPC transport
# ---------------------------------------------------------------------------
class TconError(Exception):
    """A TCONERR reply from tcon_rpc, or a transport/protocol failure."""


class Rpc:
    """One connection to an OpenOCD TCL RPC port.

    OpenOCD's TCL RPC frames every command and every reply with a trailing
    0x1a. It returns only the command's *return value*; echo output is
    dropped, though log lines can interleave into the reply, so we key off
    tcon_rpc's leading TCONOK / TCONERR token and ignore anything before it.
    """

    def __init__(self, name, port, host="127.0.0.1", timeout=60.0):
        self.name = name
        self.port = port
        self.timeout = timeout
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def _raw(self, cmd, timeout=None):
        """Send one command, return the raw reply string (no 0x1a)."""
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            self.sock.sendall(cmd.encode("utf-8", "replace") + RPC_TERM)
            while RPC_TERM not in self.buf:
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise TconError(f"{self.name}: RPC connection closed")
                self.buf += chunk
        finally:
            if timeout is not None:
                self.sock.settimeout(self.timeout)
        line, _, self.buf = self.buf.partition(RPC_TERM)
        return line.decode("utf-8", "replace")

    def rpc(self, cmd, timeout=None):
        """Run `tcon_rpc <cmd>`; return the payload, raise TconError on TCONERR.

        The reply is `TCONOK ...` or `TCONERR ...`. Interleaved log lines are
        tolerated by scanning for the last TCONOK/TCONERR token.
        """
        reply = self._raw("tcon_rpc " + cmd, timeout=timeout)
        idx_ok = reply.rfind("TCONOK")
        idx_err = reply.rfind("TCONERR")
        idx = max(idx_ok, idx_err)
        if idx < 0:
            raise TconError(f"{self.name}: unframed reply to {cmd!r}: {reply!r}")
        token = reply[idx:]
        if token.startswith("TCONERR"):
            raise TconError(f"{self.name}: {token[len('TCONERR '):].strip()}"
                            f"  (cmd: {cmd})")
        return token[len("TCONOK "):].strip()

    def bare(self, cmd, timeout=None):
        """Run a command WITHOUT tcon_rpc (for cmds that must run before
        tconbulk.tcl is sourced, and for state-free things like dump_image
        that we want to time separately). Returns the trailing token."""
        reply = self._raw(cmd, timeout=timeout)
        # the return value is emitted after any interleaved logs -> last line
        lines = [ln for ln in reply.splitlines() if ln.strip() != ""]
        return (lines[-1].strip() if lines else "")

    # -- typed helpers -----------------------------------------------------
    def source_files(self, files_dir):
        for fn in TCL_FILES:
            path = os.path.join(files_dir, fn)
            if not os.path.exists(path):
                raise TconError(f"missing {path}")
            # the reply is catch's return code (0 = success); the message, if
            # any, is fetched separately. Appending "; set __e__" here would
            # make the reply the sourced file's last result instead.
            rc = self.bare("catch {source {%s}} __e__" % path)
            if rc.strip() != "0":
                msg = self.bare("set __e__")
                raise TconError(f"{self.name}: source {fn} failed: {msg}")
        # tcon_rpc exists now; confirm the key procs are defined
        got = self.rpc("info commands tcon_bulk_begin")
        if "tcon_bulk_begin" not in got:
            raise TconError(f"{self.name}: tconbulk.tcl did not define its procs")

    def read_words(self, addr, width, count):
        """read_memory over RPC -> list of ints."""
        out = self.rpc(f"read_memory 0x{addr:08x} {width} {count}")
        return [int(x, 0) for x in out.split()] if out else []

    def read_bytes(self, addr, n):
        return bytes(self.read_words(addr, 8, n))

    def ascii_at(self, addr, n):
        return "".join(chr(c) if 0x20 <= c < 0x7F else "."
                       for c in self.read_bytes(addr, n))


# ---------------------------------------------------------------------------
# parse tcon_bulk_read's "rc=0x0 canary=1 ms=NN" reply
# ---------------------------------------------------------------------------
def parse_read(reply):
    d = {}
    for tok in reply.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            try:
                d[k] = int(v, 0)
            except ValueError:
                d[k] = v
    return d


def read_ok(reply):
    # A good read overwrites the planted tail canary with real eMMC data, so
    # tcon_bulk_read reports canary=0. canary=1 means the last word was NOT
    # overwritten (a short / failed read), which is a failure.
    d = parse_read(reply)
    return d.get("rc") == 0 and d.get("canary") == 0


# ---------------------------------------------------------------------------
# host-side output file + journal per chip
# ---------------------------------------------------------------------------
class Journal:
    def __init__(self, chipdir):
        self.chipdir = chipdir
        os.makedirs(chipdir, exist_ok=True)
        self.jpath = os.path.join(chipdir, "journal.txt")
        self.bpath = os.path.join(chipdir, "bad_sectors.txt")
        self.imgpath = os.path.join(chipdir, "user_swd.bin")
        self.jf = open(self.jpath, "a", buffering=1)   # line-buffered
        # image file: keep existing data on resume, else create
        mode = "r+b" if os.path.exists(self.imgpath) else "wb"
        self.img = open(self.imgpath, mode)
        self.recent = []           # (addr, len) of the last few D chunks
        self._lock = threading.Lock()

    def write_image(self, off, data):
        with self._lock:
            self.img.seek(off)
            self.img.write(data)
            self.img.flush()

    def fill_image(self, off, length, word):
        """Fill [off, off+length) with the 32-bit `word` little-endian."""
        pat = (word & 0xFFFFFFFF).to_bytes(4, "little") * (length // 4)
        self.write_image(off, pat)

    def log(self, line):
        with self._lock:
            self.jf.write(line + "\n")
            self.jf.flush()

    def logD(self, addr, length, window):
        self.log(f"D 0x{addr:08x} 0x{length:x}")
        self.recent.append((addr, length))
        if len(self.recent) > window:
            self.recent.pop(0)

    def logU(self, addr, length, fill):
        self.log(f"U 0x{addr:08x} 0x{length:x} 0x{fill:08x}")

    def logB(self, addr, length, nbad):
        self.log(f"B 0x{addr:08x} 0x{length:x} {nbad}")

    def logX(self, addr, length):
        self.log(f"X 0x{addr:08x} 0x{length:x}")

    def add_bad(self, sector):
        with self._lock:
            with open(self.bpath, "a") as f:
                f.write(f"0x{sector:08x}\n")

    def close(self):
        try:
            self.jf.close()
            self.img.close()
        except OSError:
            pass


def load_covered(chipdir):
    """Covered intervals from an existing journal (for resume)."""
    from tcon_regions import load_journal
    covered, bad = load_journal(chipdir)
    return covered, bad


def chunked(intervals, chunk):
    """Split (a,b) intervals into <= chunk, sector-aligned pieces."""
    for a, b in intervals:
        cur = a
        while cur < b:
            n = min(chunk, b - cur)
            yield cur, n
            cur += n


# ---------------------------------------------------------------------------
# connection / prepare / state
# ---------------------------------------------------------------------------
def set_speed(rpc, khz):
    """Set the adapter speed and return what OpenOCD reports it actually
    applied (the probe may clamp or round), or None if it can't be parsed."""
    for cmd in (f"adapter speed {khz}", "adapter speed"):
        m = re.search(r"(\d+)\s*kHz", rpc._raw(cmd, timeout=15))
        if m:
            return int(m.group(1))
    return None


def connect(name, files_dir, timeout=60.0, speed=None):
    rpc = Rpc(name, CHIPS[name], timeout=timeout)
    rpc.source_files(files_dir)
    if speed:
        actual = set_speed(rpc, speed)
        shown = f"{actual} kHz" if actual is not None else "unknown"
        print(f"[{name}] adapter speed requested {speed} kHz, applied {shown}")
    return rpc


def connect_all(chips, files_dir, timeout=60.0, speed=None):
    return {c: connect(c, files_dir, timeout, speed) for c in chips}


def cmd_state(args):
    conns = connect_all(args.chips, args.files, speed=args.speed)
    try:
        for c in args.chips:
            print(f"[{c}] {conns[c].rpc('tcon_bulk_state')}")
    finally:
        for c in conns.values():
            c.close()


def cmd_stop(args):
    """Halt both SoCs and leave them halted. Guards get re-armed."""
    conns = connect_all(args.chips, args.files, speed=args.speed)
    try:
        for c in args.chips:
            try:
                print(f"[{c}] {conns[c].rpc('tcon_bulk_halt_and_guard')}")
            except TconError as e:
                print(f"[{c}] halt/guard error: {e}")
        print("\nBoth SoCs halted with guards armed. Power cycle when done; "
              "do NOT resume.")
    finally:
        for c in conns.values():
            c.close()


def cmd_prepare(args):
    """Halt both, arm guards on both, reset_to_scan master then slave, begin
    both. Order is the dossier's: never leave one running while the other is
    halted for longer than necessary."""
    conns = connect_all(args.chips, args.files, speed=args.speed)
    try:
        # 1) halt + guard both, back to back
        for c in args.chips:
            print(f"[{c}] halt+guard: {conns[c].rpc('tcon_bulk_halt_and_guard')}")
        # 2) reset_to_scan master, then slave
        for c in args.chips:
            print(f"[{c}] reset_to_scan: "
                  f"{conns[c].rpc('tcon_bulk_reset_to_scan', timeout=90)}")
        # 3) begin both
        for c in args.chips:
            print(f"[{c}] begin: "
                  f"{conns[c].rpc(f'tcon_bulk_begin 0x{STAGE:08x} 0x{CHUNK:x}')}")
        print("\nPrepared. Both SoCs halted at the post-scan point, guards + "
              "trap armed, staging probed.")
    except TconError as e:
        print(f"\nTCONERR during prepare: {e}", file=sys.stderr)
        emergency_stop(conns, args.chips)
        sys.exit(2)
    finally:
        for c in conns.values():
            c.close()


def emergency_stop(conns, chips):
    """On any TCONERR: stop both SoCs, ensure halted, tell the user to power
    cycle. Uses bare halt (tcon_rpc may itself be the thing that failed), on a
    FRESH connection per chip: after a socket timeout the old connection's
    buffer may still hold the late reply to an earlier command, which would
    then be misread as the reply to halt / curstate."""
    print("\n!!! Stopping BOTH SoCs and halting them. DO NOT RESUME. !!!",
          file=sys.stderr)
    for c in chips:
        fresh = None
        try:
            fresh = Rpc(c, CHIPS[c], timeout=15)
        except OSError as e:
            print(f"[{c}] fresh RPC connection failed ({e}); "
                  f"falling back to the existing one", file=sys.stderr)
        r = fresh or conns.get(c)
        try:
            if r is None:
                raise TconError("no connection")
            try:
                r.bare("halt", timeout=15)
            except Exception as e:  # noqa: BLE001 - best effort
                print(f"[{c}] halt attempt: {e}", file=sys.stderr)
            try:
                st = r.bare("[target current] curstate", timeout=15)
                print(f"[{c}] curstate = {st}", file=sys.stderr)
            except Exception as e:  # noqa: BLE001
                print(f"[{c}] curstate: {e}", file=sys.stderr)
        except TconError as e:
            print(f"[{c}] could not reach OpenOCD: {e}", file=sys.stderr)
        finally:
            if fresh:
                fresh.close()
    print("\n>>> POWER CYCLE the board at the wall before doing anything else. "
          "<<<", file=sys.stderr)


# ---------------------------------------------------------------------------
# SWD clock check (both SoCs RUNNING - no halt)
# ---------------------------------------------------------------------------
def cmd_clockcheck(args):
    """Each speed must reproduce a REFERENCE dump of ITCM 0x0-0x60000 taken
    from the same chip at CLOCK_REF_SPEED (two reference dumps that agree).
    running.bin is only used as a sanity check on the loaded firmware range
    0x0-FW_LOADED_END: live ITCM past that is uninitialised and would make
    every speed "FAIL" if compared against running.bin."""
    if not os.path.exists(RUNNING_BIN):
        sys.exit(f"missing {RUNNING_BIN}")
    with open(RUNNING_BIN, "rb") as f:
        fw = f.read()
    if len(fw) != ITCM_LEN:
        sys.exit(f"running.bin is {len(fw)} bytes, expected 0x{ITCM_LEN:x}")

    tmp = ensure_tmp(args.tmp)
    speeds = args.speeds or [4000, 6000, 8000, 10000, 12000, 15000,
                             20000, 25000, 30000, 40000]
    conns = connect_all(args.chips, args.files)   # --speed is ignored here
    passing = {c: [] for c in args.chips}
    tested = []            # requested speeds actually tested (no duplicates)
    seen = {}              # applied speeds per chip -> first requested speed
    refs = {}
    try:
        # reference: two identical dumps per chip at a slow speed
        print(f"Reference dumps at {CLOCK_REF_SPEED} kHz (both SoCs RUNNING):")
        for c in args.chips:
            set_speed(conns[c], CLOCK_REF_SPEED)
            r1 = dump_itcm(conns[c], c, tmp, "ref1", CLOCK_REF_SPEED)
            r2 = dump_itcm(conns[c], c, tmp, "ref2", CLOCK_REF_SPEED)
            if r1 != r2:
                ndiff = sum(x != y for x, y in zip(r1, r2)) + abs(len(r1) - len(r2))
                print(f"  [{c}] two reference dumps differ ({ndiff} bytes): ITCM "
                      f"is not stable, or the link is bad even at "
                      f"{CLOCK_REF_SPEED} kHz. Check wiring; do not proceed.")
                conns[c].bare("adapter speed 4000")
                return
            fwok = (r1[:FW_LOADED_END] == fw[:FW_LOADED_END])
            print(f"  [{c}] reference stable; loaded FW 0x0-0x{FW_LOADED_END:x} "
                  f"{'matches' if fwok else 'DOES NOT match'} running.bin")
            if not fwok:
                print(f"  [{c}] not the expected Apr-2023 firmware - do not "
                      f"proceed.")
                conns[c].bare("adapter speed 4000")
                return
            refs[c] = r1

        print("\nSWD clock check (each speed vs that chip's reference, "
              "ITCM 0x0-0x%x):" % ITCM_LEN)
        print(f"{'request':>8} {'applied':>9}  "
              + "  ".join(f"{c:>8}" for c in args.chips))
        for spd in speeds:
            row = {}
            applied = tuple(set_speed(conns[c], spd) for c in args.chips)
            shown = "/".join("?" if a is None else str(a) for a in applied)
            if None not in applied and applied in seen:
                # the probe clamped or rounded to a speed already tested
                print(f"{spd:>8} {shown:>9}  same as {seen[applied]} kHz, "
                      f"skipped")
                continue
            seen[applied] = spd
            tested.append(spd)
            for c in args.chips:
                try:
                    ok = (dump_itcm(conns[c], c, tmp, str(spd), spd) == refs[c])
                except Exception as e:  # noqa: BLE001
                    row[c] = f"ERR:{str(e)[:12]}"
                    continue
                row[c] = "pass" if ok else "FAIL"
                if ok:
                    passing[c].append(spd)
            print(f"{spd:>8} {shown:>9}  "
                  + "  ".join(f"{row.get(c, '?'):>8}" for c in args.chips))
        # reset to the safe default
        for c in args.chips:
            conns[c].bare("adapter speed 4000")

        # recommend: highest speed that passed CONTIGUOUSLY on all chips, with
        # a margin (one step below, or 0.75x)
        common = None
        for c in args.chips:
            contig = contiguous_from_start(tested, passing[c])
            common = set(contig) if common is None else (common & set(contig))
        common = sorted(common or [])
        print()
        if not common:
            print("No speed passed on all chips (even 4000). Check wiring; do "
                  "not proceed.")
            return
        top = common[-1]
        # margin: prefer one tested step below the top, else 75% of top
        if len(common) >= 2:
            rec = common[-2]
        else:
            rec = int(top * 0.75)
        print(f"Highest speed passing on all chips: {top} kHz")
        print(f"Recommended (with margin): {rec} kHz")
        print(f"Adapter speed reset to 4000. Pass --speed {rec} to every later "
              f"command (applied at connect; an OpenOCD restart resets it).")
    finally:
        for c in conns.values():
            c.close()


def dump_itcm(rpc, chip, tmp, tag, khz):
    """dump_image ITCM 0x0-0x60000 to a scratch file, return its bytes."""
    out = os.path.join(tmp, f"itcm_{chip}_{tag}.bin")
    try:
        rpc.bare(f"dump_image {{{out}}} 0x0 0x{ITCM_LEN:x}",
                 timeout=max(30, ITCM_LEN // max(1, khz) + 20))
        with open(out, "rb") as f:
            return f.read()
    finally:
        try:
            os.remove(out)
        except OSError:
            pass


def contiguous_from_start(speeds, passed):
    """Longest run of `speeds` (ascending) that all passed, from the lowest."""
    ps = set(passed)
    out = []
    for s in sorted(speeds):
        if s in ps:
            out.append(s)
        else:
            break
    return out


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
def cmd_verify(args):
    if not os.path.exists(RUNNING_BIN):
        sys.exit(f"missing {RUNNING_BIN}")
    with open(RUNNING_BIN, "rb") as f:
        ref = f.read()
    tmp = ensure_tmp(args.tmp)
    conns = connect_all(args.chips, args.files, speed=args.speed)
    ok_all = True
    try:
        for c in args.chips:
            print(f"\n=== verify [{c}] ===")
            try:
                ok_all &= verify_one(conns[c], c, ref, tmp)
            except TconError as e:
                print(f"  TCONERR: {e}")
                emergency_stop(conns, args.chips)
                sys.exit(2)
    finally:
        for c in conns.values():
            c.close()
    if not ok_all:
        print("\nVERIFY FAILED - do not start the dump.")
        sys.exit(1)
    print("\nAll verify checks passed.")


def verify_one(rpc, chip, ref, tmp):
    ok = True

    # 1) bulk-read the eMMC FW#1 body and cmp running.bin over the part BL1
    #    actually loads (0x0-FW_LOADED_END; past that the eMMC image and
    #    running.bin legitimately differ). Read in 64 KiB chunks.
    print(f"  [1] FW#1 body 0x200..0x{0x200 + FW_LOADED_END:x} vs running.bin "
          f"... ", end="")
    ref = ref[:FW_LOADED_END]
    body = bytearray()
    for off in range(0, FW_LOADED_END, CHUNK):
        n = min(CHUNK, FW_LOADED_END - off)
        r = rpc.rpc(f"tcon_bulk_read 0x{0x200 + off:08x} 0x{n:x} 0x0")
        if not read_ok(r):
            print(f"read failed ({r})")
            return False
        out = os.path.join(tmp, f"verify_{chip}.bin")
        rpc.rpc(f"tcon_bulk_dump {{{out}}} 0x{n:x} 0x{STAGE:08x}")
        with open(out, "rb") as f:
            body += f.read()
    match = (bytes(body) == ref)
    print("MATCH" if match else "MISMATCH")
    ok &= match

    # 2) bulk vs per-sector at 0x04400000 and 0x80000000 must match.
    for addr in (0x04400000, 0x80000000):
        print(f"  [2] bulk vs per-sector at 0x{addr:08x} ... ", end="")
        span = 0x2000    # 16 sectors
        # bulk: one multi-sector read
        r = rpc.rpc(f"tcon_bulk_read 0x{addr:08x} 0x{span:x} 0x0")
        if not read_ok(r):
            print(f"bulk read failed ({r})"); ok = False; continue
        fa = os.path.join(tmp, f"bulk_{chip}.bin")
        rpc.rpc(f"tcon_bulk_dump {{{fa}}} 0x{span:x} 0x{STAGE:08x}")
        with open(fa, "rb") as f:
            bulk = f.read()
        # per-sector: one 512-byte read per sector back into staging
        for i in range(span // SECTOR):
            rr = rpc.rpc(f"tcon_bulk_read 0x{addr + i*SECTOR:08x} 0x200 "
                         f"0x{i*SECTOR:x}")
            if not read_ok(rr):
                print(f"per-sector read failed at +{i} ({rr})"); ok = False
                break
        else:
            fb = os.path.join(tmp, f"persec_{chip}.bin")
            rpc.rpc(f"tcon_bulk_dump {{{fb}}} 0x{span:x} 0x{STAGE:08x}")
            with open(fb, "rb") as f:
                persec = f.read()
            same = (bulk == persec)
            print("MATCH" if same else "MISMATCH")
            ok &= same

    # 2b) the bulk path passes flag 0xABCD; cross-check 4 sectors against the
    #     ORIGINAL per-sector path (tcondump's tcon_emmc_read_to: tcon_call,
    #     flag 0, USB-busy wait included), then re-join the bulk session:
    #     tcon_call removes the return trap when it finishes.
    addr, span = 0x04400000, 0x800
    print(f"  [2b] bulk vs original flag-0 reads at 0x{addr:08x} ... ", end="")
    r = rpc.rpc(f"tcon_bulk_read 0x{addr:08x} 0x{span:x} 0x0")
    if not read_ok(r):
        print(f"bulk read failed ({r})")
        return False
    fa = os.path.join(tmp, f"bulk2b_{chip}.bin")
    rpc.rpc(f"tcon_bulk_dump {{{fa}}} 0x{span:x} 0x{STAGE:08x}")
    with open(fa, "rb") as f:
        bulk = f.read()
    for i in range(span // SECTOR):
        rpc.rpc(f"tcon_emmc_read_to 0x{addr + i*SECTOR:08x} "
                f"0x{STAGE + 0x8000 + i*SECTOR:08x}")
    rpc.rpc(f"tcon_bulk_begin 0x{STAGE:08x} 0x{CHUNK:x}")
    fb = os.path.join(tmp, f"flag0_{chip}.bin")
    rpc.rpc(f"tcon_bulk_dump {{{fb}}} 0x{span:x} 0x{STAGE + 0x8000:08x}")
    with open(fb, "rb") as f:
        flag0 = f.read()
    same = (bulk == flag0)
    print("MATCH" if same else "MISMATCH")
    ok &= same

    # 3) tags at +4: "PFT\0" @ 0x7F000000, "LOG\0" @ 0x80000000
    for addr, tag in ((0x7F000000, b"PFT\0"), (0x80000000, b"LOG\0")):
        print(f"  [3] tag at 0x{addr:08x}+4 ... ", end="")
        r = rpc.rpc(f"tcon_bulk_read 0x{addr:08x} 0x200 0x0")
        if not read_ok(r):
            print(f"read failed ({r})"); ok = False; continue
        got = bytes(rpc.read_words(STAGE + 4, 8, 4))
        good = (got == tag)
        shown = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in got)
        print(f"'{shown}' {'OK' if good else 'expected ' + repr(tag)}")
        ok &= good

    # 4) uniform self-test
    print("  [4] uniform self-test ... ", end="")
    st = rpc.rpc("tcon_bulk_uniform_selftest")
    d = dict(tok.split("=", 1) for tok in st.split() if "=" in tok)
    good = (d.get("zero") == "1" and d.get("last") == "0"
            and d.get("ff") == "1" and d.get("mid") == "0")
    print(("PASS" if good else "FAIL") + f"  ({st})")
    ok &= good
    return ok


# ---------------------------------------------------------------------------
# speed test
# ---------------------------------------------------------------------------
def cmd_speedtest(args):
    tmp = ensure_tmp(args.tmp)
    conns = connect_all(args.chips, args.files, speed=args.speed)
    try:
        for c in args.chips:
            print(f"\n=== speedtest [{c}] ===")
            try:
                speedtest_one(conns[c], c, tmp, args)
            except TconError as e:
                print(f"  TCONERR: {e}")
                emergency_stop(conns, args.chips)
                sys.exit(2)
    finally:
        for c in conns.values():
            c.close()


def speedtest_one(rpc, chip, tmp, args):
    addr = args.speedtest_addr
    # per-sector: CHUNK/512 individual 512-byte reads
    nsec = CHUNK // SECTOR
    t0 = time.time()
    for i in range(nsec):
        rpc.rpc(f"tcon_bulk_read 0x{addr + i*SECTOR:08x} 0x200 0x{i*SECTOR:x}")
    t_persec = time.time() - t0

    # bulk: one CHUNK read + dump_image to host
    t0 = time.time()
    rpc.rpc(f"tcon_bulk_read 0x{addr:08x} 0x{CHUNK:x} 0x0")
    t_read = time.time() - t0
    out = os.path.join(tmp, f"speed_{chip}.bin")
    t0 = time.time()
    rpc.rpc(f"tcon_bulk_dump {{{out}}} 0x{CHUNK:x} 0x{STAGE:08x}")
    t_dump = time.time() - t0
    try:
        os.remove(out)
    except OSError:
        pass

    t_bulk = t_read + t_dump
    kib = CHUNK / 1024.0
    print(f"  per-sector 64 KiB: {t_persec*1000:8.0f} ms "
          f"({kib/t_persec:7.1f} KiB/s)")
    print(f"  bulk read  64 KiB: {t_read*1000:8.0f} ms "
          f"({kib/t_read:7.1f} KiB/s)")
    print(f"  bulk dump  64 KiB: {t_dump*1000:8.0f} ms "
          f"({kib/t_dump:7.1f} KiB/s)")
    print(f"  bulk total 64 KiB: {t_bulk*1000:8.0f} ms "
          f"({kib/t_bulk:7.1f} KiB/s)  speedup x{t_persec/t_bulk:.1f}")

    total = sum(b - a for _, a, b in parse_regions(args.regions))
    est = total / CHUNK * t_bulk
    print(f"  full dump ~{total/2**20:.0f} MB per chip: "
          f"~{est/60:.1f} min at this rate "
          f"(both chips in parallel -> wall time ~= the slower chip)")


# ---------------------------------------------------------------------------
# the dump
# ---------------------------------------------------------------------------
class Aborted(Exception):
    pass


def cmd_dump(args):
    tmp = ensure_tmp(args.tmp)
    regions = parse_regions(args.regions)
    conns = connect_all(args.chips, args.files, timeout=120,
                        speed=args.speed)
    abort = threading.Event()
    reason = {}

    workers = {}
    for c in args.chips:
        chipdir = os.path.join(args.new, c)
        jr = Journal(chipdir)
        workers[c] = (jr, threading.Thread(
            target=dump_worker,
            args=(conns[c], c, jr, regions, tmp, args, abort, reason),
            name=f"dump-{c}", daemon=True))

    for _, (_, th) in workers.items():
        th.start()
    try:
        for c in args.chips:
            workers[c][1].join()
    except KeyboardInterrupt:
        print("\nCtrl-C: aborting, halting both SoCs ...", file=sys.stderr)
        abort.set()
        for c in args.chips:
            workers[c][1].join(timeout=60)
        emergency_stop(conns, args.chips)
        for c in args.chips:
            workers[c][0].close()
        for c in conns.values():
            c.close()
        sys.exit(130)

    for c in args.chips:
        workers[c][0].close()

    # never report "complete" on the workers' word alone: the journal must
    # cover every requested region
    incomplete = {}
    region_iv = [(a, b) for _, a, b in regions]
    for c in args.chips:
        covered, _ = load_covered(os.path.join(args.new, c))
        missing = subtract_intervals(region_iv, covered)
        if missing:
            incomplete[c] = missing
    if incomplete and not abort.is_set():
        for c, missing in incomplete.items():
            print(f"[{c}] INCOMPLETE: {sum(b - a for a, b in missing) / 2**20:.1f} "
                  f"MB not covered, first 0x{missing[0][0]:08x}-0x{missing[0][1]:08x}",
                  file=sys.stderr)
        for c in conns.values():
            c.close()
        print("\nDump INCOMPLETE although no chip reported a stop. Both SoCs "
              "are still halted; re-run the same command to resume.",
              file=sys.stderr)
        sys.exit(3)

    if abort.is_set():
        print(f"\nDump aborted: {reason}", file=sys.stderr)
        emergency_stop(conns, args.chips)
        for c in conns.values():
            c.close()
        sys.exit(2)

    for c in conns.values():
        c.close()
    print("\nDump complete on all chips. Power off at the wall before closing "
          "OpenOCD, then run tcon_diffdump.py.")


def fmt_dur(sec):
    sec = int(round(sec))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else (f"{m}m{s:02d}s" if m else f"{s}s")


class Progress:
    """Transfer rate and ETA for one chip's dump: the average since this run
    started, and a recent rate over roughly the last `window` seconds (which
    tracks changes, e.g. --skip-blank racing through empty space)."""

    def __init__(self, total, window=60.0):
        self.total = total
        self.window = window
        self.t0 = time.time()
        self.done = 0
        self.samples = collections.deque([(self.t0, 0)])

    def add(self, n):
        self.done += n
        now = time.time()
        self.samples.append((now, self.done))
        # keep the newest sample that is older than the window as the base
        while len(self.samples) > 2 and now - self.samples[1][0] > self.window:
            self.samples.popleft()

    def rates(self):
        now = time.time()
        avg = self.done / (now - self.t0) if now > self.t0 else 0.0
        t_old, d_old = self.samples[0]
        recent = (self.done - d_old) / (now - t_old) if now > t_old else avg
        return avg, recent

    def elapsed(self):
        return time.time() - self.t0

    def line(self):
        avg, recent = self.rates()
        left = max(0, self.total - self.done)
        pct = 100.0 * self.done / self.total if self.total else 100.0

        def eta(rate):
            if left == 0:
                return "0s"
            if rate <= 0:
                return "?"
            t = left / rate
            return f"{fmt_dur(t)} (~{time.strftime('%H:%M', time.localtime(time.time() + t))})"

        return (f"{self.done / 2**20:.0f}/{self.total / 2**20:.0f} MB "
                f"({pct:.1f}%)  avg {avg / 1024:.0f} KiB/s, recent "
                f"{recent / 1024:.0f} KiB/s  left {left / 2**20:.0f} MB  "
                f"ETA {eta(recent)} at recent rate, {eta(avg)} at avg")


def dump_worker(rpc, chip, jr, regions, tmp, args, abort, reason):
    try:
        region_iv = [(a, b) for _, a, b in regions]
        covered, bad = load_covered(jr.chipdir)
        todo = subtract_intervals(region_iv, covered)
        todo_bytes = sum(b - a for a, b in todo)
        done_bytes = sum(b - a for a, b in region_iv) - todo_bytes
        print(f"[{chip}] resume: {done_bytes/2**20:.0f} MB already covered, "
              f"{todo_bytes/2**20:.0f} MB to go")

        out = os.path.join(tmp, f"chunk_{chip}.bin")
        prog = Progress(todo_bytes)
        n_since_report = 0
        t_report = time.time()
        chunk_index = 0

        for addr, length in chunked(todo, CHUNK):
            if abort.is_set():
                raise Aborted("peer chip aborted")

            chunk_index += 1
            do_recheck = (args.recheck_every > 0
                          and chunk_index % args.recheck_every == 0)

            if do_recheck:
                data = read_chunk_twice(rpc, chip, addr, length, out, jr,
                                        args, abort, reason)
                # None means EITHER a blank/bad chunk that was accepted (U / B
                # already journaled: carry on) OR a failed check that set the
                # abort (stop). Only the abort flag tells them apart.
                if data is None and abort.is_set():
                    return
            else:
                data = read_chunk(rpc, chip, addr, length, out, jr, args)

            if data is not None:      # None == handled as blank (U) or bad-only
                jr.write_image(addr, data)
                jr.logD(addr, length, args.recheck_window)

            prog.add(length)
            n_since_report += length
            now = time.time()
            if (n_since_report >= args.report_every
                    or (args.report_secs > 0
                        and now - t_report >= args.report_secs)):
                print(f"[{chip}] 0x{addr + length:08x}  {prog.line()}")
                n_since_report = 0
                t_report = now
        avg, _ = prog.rates()
        print(f"[{chip}] region set complete: {prog.done / 2**20:.0f} MB in "
              f"{fmt_dur(prog.elapsed())} (avg {avg / 1024:.0f} KiB/s).")
    except (TconError, Aborted) as e:
        if not abort.is_set():
            reason[chip] = str(e)
        abort.set()
        print(f"[{chip}] STOP: {e}", file=sys.stderr)


def read_chunk(rpc, chip, addr, length, out, jr, args):
    """Read one chunk. Returns bytes to write, or None if it was recorded as
    a blank (U) chunk or fully handled as bad."""
    r = rpc.rpc(f"tcon_bulk_read 0x{addr:08x} 0x{length:x} 0x0")
    if not read_ok(r):
        # retry a few times, then per-sector fallback
        for _ in range(args.retries):
            r = rpc.rpc(f"tcon_bulk_read 0x{addr:08x} 0x{length:x} 0x0")
            if read_ok(r):
                break
        else:
            return persector_fallback(rpc, chip, addr, length, out, jr, args)

    if args.skip_blank:
        u = rpc.rpc(f"tcon_bulk_uniform 0x{length:x} 0x0")
        du = dict(tok.split("=", 1) for tok in u.split() if "=" in tok)
        if du.get("hr") == "1":
            print(f"[{chip}] note: helper routine at 0x2021C000 had been "
                  f"overwritten and was rewritten (before 0x{addr:08x})",
                  file=sys.stderr)
        if du.get("uni") == "1":
            fill = int(du.get("w0", "0x0"), 0)
            jr.fill_image(addr, length, fill)
            jr.logU(addr, length, fill)
            return None

    rpc.rpc(f"tcon_bulk_dump {{{out}}} 0x{length:x} 0x{STAGE:08x}")
    with open(out, "rb") as f:
        return f.read()


def read_chunk_twice(rpc, chip, addr, length, out, jr, args, abort, reason):
    """Transfer the same chunk twice and compare. On a mismatch, invalidate
    the recent chunks with X lines and stop. Returns the verified bytes, or
    None if a mismatch triggered an abort."""
    a = read_chunk(rpc, chip, addr, length, out, jr, args)
    if a is None:
        # blank/bad chunk: nothing byte-exact to double-check, accept it
        return None
    out2 = out + ".2"
    b = None
    for _ in range(1 + max(0, args.retries)):
        b = read_chunk_raw(rpc, addr, length, out2, args)
        if b is not None:
            break
    if b is None:
        # the check itself could not complete: nothing says earlier data is
        # bad, so no X lines - but stop rather than dump unchecked
        print(f"[{chip}] double-read check: second read of 0x{addr:08x} "
              f"failed {1 + max(0, args.retries)} time(s) - stopping",
              file=sys.stderr)
        reason[chip] = f"double-read check: second read failed at 0x{addr:08x}"
        abort.set()
        return None
    if a == b:
        return a
    # mismatch: invalidate this chunk + the recent window
    print(f"[{chip}] SWD double-read MISMATCH at 0x{addr:08x} - invalidating "
          f"recent chunks and stopping", file=sys.stderr)
    jr.logX(addr, length)
    for ra, rl in jr.recent:
        jr.logX(ra, rl)
    reason[chip] = f"double-read mismatch at 0x{addr:08x}"
    abort.set()
    return None


def read_chunk_raw(rpc, addr, length, out, args):
    """A plain re-read to file for the double-check (no U/bad handling)."""
    r = rpc.rpc(f"tcon_bulk_read 0x{addr:08x} 0x{length:x} 0x0")
    if not read_ok(r):
        return None
    rpc.rpc(f"tcon_bulk_dump {{{out}}} 0x{length:x} 0x{STAGE:08x}")
    with open(out, "rb") as f:
        return f.read()


def persector_fallback(rpc, chip, addr, length, out, jr, args):
    """Read a chunk sector by sector. Unreadable sectors are zero-filled,
    logged to bad_sectors.txt, and the chunk gets a B journal line. Returns
    the assembled bytes (with zeros for bad sectors)."""
    nsec = length // SECTOR
    zero_words = "{" + " ".join(["0"] * (SECTOR // 4)) + "}"
    nbad = 0
    for i in range(nsec):
        sec = addr + i * SECTOR
        off = i * SECTOR
        good = False
        for _ in range(max(1, args.retries)):
            rr = rpc.rpc(f"tcon_bulk_read 0x{sec:08x} 0x200 0x{off:x}")
            if read_ok(rr):
                good = True
                break
        if not good:
            nbad += 1
            jr.add_bad(sec)
            rpc.rpc(f"write_memory 0x{STAGE + off:08x} 32 {zero_words}")
            print(f"[{chip}] bad sector 0x{sec:08x} (zero-filled)",
                  file=sys.stderr)
    rpc.rpc(f"tcon_bulk_dump {{{out}}} 0x{length:x} 0x{STAGE:08x}")
    with open(out, "rb") as f:
        data = f.read()
    jr.write_image(addr, data)
    jr.logB(addr, length, nbad)
    return None    # already written + logged


# ---------------------------------------------------------------------------
# panel-ID check
# ---------------------------------------------------------------------------
def cmd_pnid(args):
    conns = connect_all(args.chips, args.files, speed=args.speed)
    try:
        for c in args.chips:
            print(f"\n=== panel-ID sites [{c}] (old | new) ===")
            oldimg = os.path.join(args.old, c, args.old_image)
            fo = open(oldimg, "rb") if os.path.exists(oldimg) else None
            try:
                for sector, off, desc in PNID_SITES:
                    r = conns[c].rpc(f"tcon_bulk_read 0x{sector:08x} 0x200 0x0")
                    if not read_ok(r):
                        print(f"  0x{sector + off:08x} {desc:<22} READ FAILED "
                              f"({r})")
                        continue
                    new = conns[c].ascii_at(STAGE + off, 10)
                    if fo:
                        fo.seek(sector + off)
                        ob = fo.read(10)
                        old = "".join(chr(b) if 0x20 <= b < 0x7F else "."
                                      for b in ob)
                    else:
                        old = "(no old image)"
                    flag = "" if old == new else "  <-- DIFFERS"
                    print(f"  0x{sector + off:08x} {desc:<22} {old} | {new}{flag}")
            finally:
                if fo:
                    fo.close()
    except TconError as e:
        print(f"  TCONERR: {e}")
        emergency_stop(conns, args.chips)
        sys.exit(2)
    finally:
        for c in conns.values():
            c.close()


# ---------------------------------------------------------------------------
# survey (optional) - sample one sector every --stride bytes across the user
# area and note which look non-blank, to spot data outside the known regions.
# ---------------------------------------------------------------------------
def cmd_survey(args):
    from tcon_regions import CAPACITY
    conns = connect_all(args.chips, args.files, speed=args.speed)
    stride = args.stride
    try:
        for c in args.chips:
            print(f"\n=== survey [{c}] (one sector every 0x{stride:x}) ===")
            addr = 0
            nonblank = []
            while addr < CAPACITY:
                try:
                    r = conns[c].rpc(f"tcon_bulk_read 0x{addr:08x} 0x200 0x0")
                except TconError as e:
                    print(f"  0x{addr:08x} error {e}")
                    addr += stride
                    continue
                if read_ok(r):
                    u = conns[c].rpc("tcon_bulk_uniform 0x200 0x0")
                    du = dict(t.split("=", 1) for t in u.split() if "=" in t)
                    if du.get("uni") != "1":
                        head = conns[c].ascii_at(STAGE, 16)
                        nonblank.append((addr, head))
                addr += stride
            print(f"  {len(nonblank)} non-blank sample(s):")
            for a, head in nonblank[:args.show]:
                print(f"    0x{a:08x}  '{head}'")
            if len(nonblank) > args.show:
                print(f"    ... {len(nonblank) - args.show} more")
    except TconError as e:
        print(f"  TCONERR: {e}")
        emergency_stop(conns, args.chips)
        sys.exit(2)
    finally:
        for c in conns.values():
            c.close()


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------
def ensure_tmp(path):
    path = os.path.abspath(path)
    if " " in path:
        sys.exit(f"--tmp must not contain spaces: {path!r}")
    os.makedirs(path, exist_ok=True)
    return path


def add_common(ap):
    ap.add_argument("--files", default=HERE,
                    help="directory holding the .tcl files (default %(default)s)")
    ap.add_argument("--chips", type=lambda s: [x.strip() for x in s.split(",")],
                    default=["master", "slave"],
                    help="chips to act on (default master,slave)")
    ap.add_argument("--tmp", default=os.path.join(HERE, "bulk_tmp"),
                    help="scratch dir for dump_image files (absolute, no spaces)")
    ap.add_argument("--speed", type=int, default=None, metavar="KHZ",
                    help="set 'adapter speed' on both instances at connect "
                         "(from clockcheck's recommendation); default: leave "
                         "OpenOCD's current speed. clockcheck ignores it.")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("clockcheck", help="step SWD speed while running")
    add_common(p)
    p.add_argument("--speeds", type=lambda s: [int(x) for x in s.split(",")],
                   default=None, help="comma list of kHz to try")
    p.set_defaults(func=cmd_clockcheck)

    p = sub.add_parser("prepare", help="halt+guard+reset_to_scan+begin both")
    add_common(p)
    p.set_defaults(func=cmd_prepare)

    p = sub.add_parser("verify", help="correctness checks before dumping")
    add_common(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("speedtest", help="per-sector vs bulk timing + estimate")
    add_common(p)
    p.add_argument("--speedtest-addr", type=lambda s: int(s, 0),
                   default=0x04400000)
    p.add_argument("--regions", default="all")
    p.set_defaults(func=cmd_speedtest)

    p = sub.add_parser("dump", help="the dump (parallel, resumable)")
    add_common(p)
    p.add_argument("--new", default=DEFAULT_NEW, help="new_board output dir")
    p.add_argument("--regions", default="all",
                   help="region names / ranges from tcon_regions.py")
    p.add_argument("--retries", type=int, default=3,
                   help="bulk-read retries before per-sector fallback")
    p.add_argument("--recheck-every", type=int, default=64,
                   help="double-transfer every N chunks (0 = never)")
    p.add_argument("--recheck-window", type=int, default=8,
                   help="chunks to invalidate on a double-read mismatch")
    p.add_argument("--skip-blank", action="store_true",
                   help="don't transfer chunks that are one repeated word")
    p.add_argument("--report-every", type=lambda s: int(s, 0),
                   default=0x1000000, help="progress line every N bytes")
    p.add_argument("--report-secs", type=float, default=30,
                   help="also a progress line at least every N seconds "
                        "(0 = bytes only; default %(default)s)")
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("pnid", help="read the ten panel-ID sites, old vs new")
    add_common(p)
    p.add_argument("--old", default=DEFAULT_OLD)
    p.add_argument("--old-image", default="user_a.bin")
    p.set_defaults(func=cmd_pnid)

    p = sub.add_parser("survey", help="sample the rest of the user area")
    add_common(p)
    p.add_argument("--stride", type=lambda s: int(s, 0), default=0x1000000)
    p.add_argument("--show", type=int, default=40)
    p.set_defaults(func=cmd_survey)

    p = sub.add_parser("state", help="print tcon_bulk_state for both")
    add_common(p)
    p.set_defaults(func=cmd_state)

    p = sub.add_parser("stop", help="halt both SoCs and leave them halted")
    add_common(p)
    p.set_defaults(func=cmd_stop)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

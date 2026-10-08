#!/usr/bin/env python3
"""
tcon_copycal.py - copy the original board's calibration onto the replacement
board over SWD, both SoCs in parallel (master -> master, slave -> slave).
Plan: AgentInfo/calibration_copy_plan.md; procedure: section "Calibration
copy" in AgentInfo/swd_bulk_dump_procedure.md.

THIS WRITES TO THE eMMC (subcommand `write` only, after a typed WRITE).

Input: the frozen packs from tcon_copyplan.py, per chip under --plan:
manifest.tsv, src.bin (old data), bak.bin (backup). The pack hashes are
checked against the manifest before anything connects.

Subcommands:
  dryrun   read-only: pre-read every chunk and classify it against the packs;
           measured speed and an ETA for the write
  write    the copy (resumable from the journal)
  verify   read-only: every chunk must equal the target data
  state    tcon_bulk_state for both SoCs + journal progress
  gapcheck offline: judge a `tcon_bulkdump.py dump --skip-blank` journal of
           the never-read gaps (only U lines with fill 0x00000000 pass)

Per chunk (32 KiB; staging A = 0x20220000 source, B = 0x20228000 read-back):
  1. pre-read into B: == before-data -> go on; == target -> journal W, skip;
     neither -> STOP (unless the journal has S without W: an interrupted
     write, or the chunk is named in --rewrite)
  2. journal S; load_image the target data into A
  3. FUN_00006DD4 write (tconwrite.tcl: only 0x6C8C lifted), rc must be 0
  4. read-back into B == target -> journal W; else rewrite (3 attempts in
     all), then STOP
Phase 1 goes in ascending order with the panel-ID chunks last; phase 2
(LOG) ascending. Any STOP halts both SoCs over fresh connections.

--source old (default) copies the old data; --source backup rolls back to
the backup, with its own journal. A write session retires the other
direction's journal (renamed), since its W lines no longer hold.

--allow-valid-header: work on a board whose FW#1 header is restored (plan
section 4). Not with --entry loop. verify then reports mismatches in chunks
with a known runtime writer as "runtime-updated" instead of failing.

Exit status: 0 done, 1 refused / verify or dry run found problems (targets
untouched), 2 STOP (both SoCs halted: power cycle), 130 Ctrl-C.
"""

import argparse
import hashlib
import os
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tcon_bulkdump as drv  # noqa: E402
import tcon_copyplan as cp  # noqa: E402
import tcon_fixheader as fix  # noqa: E402
from tcon_regions import load_journal, parse_regions, subtract_intervals  # noqa: E402

WRITE_TCL = "tconwrite.tcl"
CHUNK = cp.CHUNK                 # 0x8000
OFF_A = 0x0                      # source / write buffer
OFF_B = 0x8000                   # pre-read / read-back
ATTEMPTS = 3                     # write + read-back attempts per chunk
JOURNALS = {"old": "journal.txt", "backup": "journal_backup.txt"}


# ---------------------------------------------------------------------------
# packs
# ---------------------------------------------------------------------------
class Packs:
    """One chip's manifest + packs. `after` is what the chunk must become,
    `before` what it holds before the copy, for the chosen --source."""

    def __init__(self, plan_dir, chip, source):
        self.chip = chip
        self.dir = os.path.join(plan_dir, chip)
        self.meta, self.entries = cp.load_manifest(self.dir)
        if self.meta.get("chip") != chip:
            raise SystemExit(f"{self.dir}: manifest is for chip "
                             f"{self.meta.get('chip')!r}, not {chip!r}")
        self.by_addr = {e.addr: e for e in self.entries}
        self.fs = open(os.path.join(self.dir, "src.bin"), "rb")
        self.fb = open(os.path.join(self.dir, "bak.bin"), "rb")
        self.source = source
        self.pnid = self.meta["pnid"]

    def verify(self):
        """Sizes, whole-file and per-chunk SHA-256 against the manifest, and
        every entry's region/phase against the copy table. -> problems."""
        probs = []
        for e in self.entries:
            region, phase = cp.group_of(e.addr)
            if (region, phase) != (e.region, e.phase):
                probs.append(f"0x{e.addr:08x}: region/phase {e.region}/{e.phase} "
                             f"is not the copy table's {region}/{phase}")
        for name, f, col in (("src", self.fs, "sha_src"), ("bak", self.fb, "sha_bak")):
            want = int(self.meta.get(f"{name}_size", "-1"))
            size = os.fstat(f.fileno()).st_size
            if size != want or size != len(self.entries) * CHUNK:
                probs.append(f"{name}.bin is {size} bytes, manifest says {want}")
                continue
            whole = hashlib.sha256()
            f.seek(0)
            bad = 0
            for e in self.entries:
                d = f.read(CHUNK)
                whole.update(d)
                if hashlib.sha256(d).hexdigest() != getattr(e, col):
                    bad += 1
                    if bad <= 3:
                        probs.append(f"{name}.bin chunk {e.idx} (0x{e.addr:08x}) "
                                     f"hash mismatch")
            if bad > 3:
                probs.append(f"{name}.bin: {bad} chunk hash mismatches in all")
            if whole.hexdigest() != self.meta.get(f"{name}_sha256"):
                probs.append(f"{name}.bin SHA-256 {whole.hexdigest()[:16]}... does "
                             f"not match the manifest")
        return probs

    def _read(self, f, e, col):
        f.seek(e.idx * CHUNK)
        d = f.read(CHUNK)
        if hashlib.sha256(d).hexdigest() != getattr(e, col):
            raise drv.TconError(f"{self.chip}: pack data for 0x{e.addr:08x} no "
                                f"longer matches the manifest - STOP")
        return d

    def after(self, e):
        return (self._read(self.fs, e, "sha_src") if self.source == "old"
                else self._read(self.fb, e, "sha_bak"))

    def before(self, e):
        return (self._read(self.fb, e, "sha_bak") if self.source == "old"
                else self._read(self.fs, e, "sha_src"))

    def pnid_want(self, src, bak):
        """(before, after) panel-ID strings for one site."""
        return (bak, src) if self.source == "old" else (src, bak)

    def close(self):
        self.fs.close()
        self.fb.close()


def ordered(entries, phase):
    """The write order: phase 1 ascending with the panel-ID chunks last, then
    phase 2 (LOG) ascending."""
    sel = [e for e in entries if phase == "all" or e.phase == int(phase)]
    p1 = [e for e in sel if e.phase == 1]
    return ([e for e in p1 if "pnid" not in e.flags.split(",")]
            + [e for e in p1 if "pnid" in e.flags.split(",")]
            + [e for e in sel if e.phase == 2])


# ---------------------------------------------------------------------------
# journal
# ---------------------------------------------------------------------------
class CopyJournal:
    """S addr len   = about to write; W addr len = verified on the eMMC.
    Flushed per line; S lines are also fsync'd before the write starts."""

    def __init__(self, chipdir, source):
        self.path = os.path.join(chipdir, JOURNALS[source])
        self.S, self.W = set(), set()
        if os.path.exists(self.path):
            with open(self.path) as f:
                for line in f:
                    p = line.split()
                    if len(p) >= 2 and p[0] in ("S", "W"):
                        (self.S if p[0] == "S" else self.W).add(int(p[1], 0))
        self.f = None
        self._lock = threading.Lock()

    @property
    def pending(self):
        return self.S - self.W

    def is_pending(self, addr):
        return addr in self.S and addr not in self.W

    def log(self, line, sync=False):
        with self._lock:
            if self.f is None:
                self.f = open(self.path, "a", buffering=1)
            self.f.write(line + "\n")
            self.f.flush()
            if sync:
                os.fsync(self.f.fileno())

    def logS(self, addr):
        self.S.add(addr)
        self.log(f"S 0x{addr:08x} 0x{CHUNK:x}", sync=True)

    def logW(self, addr, note=""):
        self.W.add(addr)
        self.log(f"W 0x{addr:08x} 0x{CHUNK:x}" + (f" {note}" if note else ""))

    def close(self):
        if self.f:
            self.f.close()


def retire_other(chipdir, source):
    """A write in one direction invalidates the other direction's W lines."""
    other = [s for s in JOURNALS if s != source][0]
    path = os.path.join(chipdir, JOURNALS[other])
    if os.path.exists(path) and os.path.getsize(path):
        dst = f"{path}.retired-{time.strftime('%Y%m%d-%H%M%S')}"
        os.replace(path, dst)
        return dst
    return None


# ---------------------------------------------------------------------------
# target helpers
# ---------------------------------------------------------------------------
def source_write(rpc, files_dir):
    path = os.path.join(files_dir, WRITE_TCL)
    if not os.path.exists(path):
        raise drv.TconError(f"missing {path}")
    rc = rpc.bare("catch {source {%s}} __e__" % path)
    if rc.strip() != "0":
        raise drv.TconError(f"{rpc.name}: source {WRITE_TCL} failed: "
                            f"{rpc.bare('set __e__')}")
    if "tcon_write_call" not in rpc.rpc("info commands tcon_write_call"):
        raise drv.TconError(f"{rpc.name}: {WRITE_TCL} did not define its procs")


def read_chunk(rpc, chip, addr, path, retries):
    """Bulk-read one chunk into half B and return its bytes."""
    r = ""
    for _ in range(1 + retries):
        r = rpc.rpc(f"tcon_bulk_read 0x{addr:08x} 0x{CHUNK:x} 0x{OFF_B:x}")
        if drv.read_ok(r):
            break
    else:
        raise drv.TconError(f"{chip}: read of 0x{addr:08x} failed {1 + retries} "
                            f"time(s) ({r}) - STOP")
    rpc.rpc(f"tcon_bulk_dump {{{path}}} 0x{CHUNK:x} 0x{drv.STAGE + OFF_B:08x}")
    with open(path, "rb") as f:
        d = f.read()
    if len(d) != CHUNK:
        raise drv.TconError(f"{chip}: dump_image gave {len(d)} bytes - STOP")
    return d


def pnid_check(rpc, chip, packs, jr, strict, tmp, rewrite=()):
    """Read the ten panel-ID sites. strict: every site must read the target
    ID (verify / after a complete write). Otherwise consistent with the
    journal: W -> target, S without W (or --rewrite) -> either, else the
    before ID. -> (ok, lines)"""
    ok, lines = True, []
    for site, src, bak, desc in packs.pnid:
        sec = site & ~0x1FF
        r = rpc.rpc(f"tcon_bulk_read 0x{sec:08x} 0x200 0x{OFF_B:x}")
        if not drv.read_ok(r):
            raise drv.TconError(f"{chip}: panel-ID read 0x{sec:08x} failed ({r})")
        got = rpc.ascii_at(drv.STAGE + OFF_B + site - sec, 10)
        before, after = packs.pnid_want(src, bak)
        chunk = site & ~(CHUNK - 1)
        if strict or chunk in jr.W:
            want = {after}
        elif jr.is_pending(chunk) or chunk in rewrite:
            want = {before, after}
        else:
            want = {before}
        good = got in want
        ok &= good
        lines.append(f"  [{chip}] 0x{site:08x} {desc:<22} {got}"
                     + ("" if good else f"   <-- expected {' or '.join(sorted(want))}"))
    return ok, lines


# ---------------------------------------------------------------------------
# session setup shared by dryrun / write / verify
# ---------------------------------------------------------------------------
def load_packs(args):
    packs = {c: Packs(args.plan, c, args.source) for c in args.chips}
    print("Checking the packs against the manifests ...")
    probs = []
    for c, p in packs.items():
        t0 = time.time()
        pr = p.verify()
        probs += [f"{c}: {x}" for x in pr]
        print(f"  [{c}] {len(p.entries)} chunks, "
              f"{'OK' if not pr else 'PROBLEMS'} ({time.time() - t0:.1f}s)")
    if probs:
        print("\nREFUSED: pack check failed; nothing was connected or touched.")
        for x in probs:
            print(f"  - {x}")
        sys.exit(1)
    return packs


def open_session(args, packs):
    """Connect, source the write file, enter, begin, panel-ID check.
    -> (conns, journals, begin replies). Exits on any refusal."""
    conns = drv.connect_all(args.chips, args.files, timeout=120, speed=args.speed)
    journals = {c: CopyJournal(packs[c].dir, args.source) for c in args.chips}
    try:
        for c in args.chips:
            fix.source_fix(conns[c], args.files)
            source_write(conns[c], args.files)
        fix.enter(conns, args.chips, args.entry)
    except drv.TconError as e:
        print(f"\nTCONERR during entry: {e}", file=sys.stderr)
        drv.emergency_stop(conns, args.chips)
        sys.exit(2)

    begins = {}
    try:
        for c in args.chips:
            begins[c] = conns[c].rpc(
                f"tcon_write_begin {int(args.allow_valid_header)} "
                f"0x{drv.STAGE:08x} 0x{drv.CHUNK:x}", timeout=90)
            print(f"[{c}] begin: {begins[c]}")
    except drv.TconError as e:
        print(f"\nREFUSED at the begin check: {e}", file=sys.stderr)
        drv.emergency_stop(conns, args.chips)
        sys.exit(1)

    strict = args.cmd == "verify"
    allok = True
    print("\nPanel-ID sites" + (" (must all read the target ID):" if strict
                                 else " (consistent with the journal):"))
    try:
        for c in args.chips:
            ok, lines = pnid_check(conns[c], c, packs[c], journals[c], strict,
                                   args.tmp, getattr(args, "rewrite", ()))
            allok &= ok
            print("\n".join(lines))
    except drv.TconError as e:
        print(f"\nTCONERR: {e}", file=sys.stderr)
        drv.emergency_stop(conns, args.chips)
        sys.exit(2)
    if not allok and not strict:
        print("\nREFUSED: the panel-ID sites don't match the journal. Both SoCs "
              "left halted: power cycle at the wall, do not resume.")
        close_all(conns, journals)
        sys.exit(1)
    return conns, journals, begins, allok


def close_all(conns, journals=None):
    for c in conns.values():
        c.close()
    for j in (journals or {}).values():
        j.close()


def run_parallel(args, conns, target, extra):
    """One worker thread per chip; any error on one stops both."""
    abort = threading.Event()
    reason = {}
    threads = {c: threading.Thread(target=target, name=f"copy-{c}",
                                   args=(c, abort, reason) + extra, daemon=True)
               for c in args.chips}
    for t in threads.values():
        t.start()
    try:
        for t in threads.values():
            t.join()
    except KeyboardInterrupt:
        print("\nCtrl-C: stopping after the current chunk, halting both SoCs ...",
              file=sys.stderr)
        abort.set()
        for t in threads.values():
            t.join(timeout=120)
        drv.emergency_stop(conns, args.chips)
        sys.exit(130)
    return abort.is_set(), reason


def worker_guard(fn):
    """Run a worker body; turn TconError / Aborted into the shared abort."""
    def run(chip, abort, reason, *extra):
        try:
            fn(chip, abort, reason, *extra)
        except (drv.TconError, drv.Aborted) as e:
            if not abort.is_set() or not isinstance(e, drv.Aborted):
                reason.setdefault(chip, str(e))
            abort.set()
            print(f"[{chip}] STOP: {e}", file=sys.stderr, flush=True)
    return run


def reporter(chip, prog, args):
    state = {"t": time.time(), "n": 0, "eta_done": False}

    def tick(nchunks):
        now = time.time()
        if not state["eta_done"] and nchunks >= 20:
            state["eta_done"] = True
            print(f"[{chip}] measured after {nchunks} chunks: {prog.line()}",
                  flush=True)
            state["t"] = now
        elif args.report_secs > 0 and now - state["t"] >= args.report_secs:
            print(f"[{chip}] {prog.line()}", flush=True)
            state["t"] = now
    return tick


def stamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# dryrun
# ---------------------------------------------------------------------------
def cmd_dryrun(args):
    packs = load_packs(args)
    conns, journals, begins, _ = open_session(args, packs)
    tmp = drv.ensure_tmp(args.tmp)
    results = {c: {"before": 0, "after": 0, "pending": 0, "problems": [],
                   "secs": 0.0, "n": 0} for c in args.chips}

    @worker_guard
    def work(chip, abort, reason):
        p, jr, res = packs[chip], journals[chip], results[chip]
        todo = ordered(p.entries, args.phase)
        if args.limit:
            todo = todo[:args.limit]
        path = os.path.join(tmp, f"cc_{chip}_pre.bin")
        prog = drv.Progress(len(todo) * CHUNK)
        tick = reporter(chip, prog, args)
        t0 = time.time()
        for i, e in enumerate(todo):
            if abort.is_set():
                raise drv.Aborted("peer chip stopped")
            pre = read_chunk(conns[chip], chip, e.addr, path, args.retries)
            if pre == p.after(e):
                kind = "after"
            elif pre == p.before(e):
                kind = "before"
                if e.addr in jr.W:
                    res["problems"].append(f"0x{e.addr:08x} journaled W but holds "
                                           f"the pre-copy data")
            elif jr.is_pending(e.addr):
                kind = "pending"
            else:
                kind = None
                res["problems"].append(f"0x{e.addr:08x} ({e.region}) matches "
                                       f"neither image")
            if kind:
                res[kind] += 1
            res["n"] += 1
            prog.add(CHUNK)
            tick(i + 1)
        res["secs"] = time.time() - t0

    aborted, reason = run_parallel(args, conns, work, ())
    if aborted:
        print(f"\nDry run stopped: {reason}", file=sys.stderr)
        drv.emergency_stop(conns, args.chips)
        close_all(conns, journals)
        sys.exit(2)

    bad = False
    print(f"\nDry run ({'source ' + args.source}, phase {args.phase}"
          + (f", limit {args.limit}" if args.limit else "") + "):")
    for c in args.chips:
        r = results[c]
        rate = r["n"] * CHUNK / r["secs"] if r["secs"] else 0
        to_write = r["before"] + r["pending"]
        # a write moves each chunk three times (pre-read, load, read-back)
        eta = to_write * CHUNK * 3 / rate if rate else 0
        print(f"  [{c}] {r['n']} chunks read in {drv.fmt_dur(r['secs'])} "
              f"({rate / 1024:.0f} KiB/s): {r['before']} to write, {r['after']} "
              f"already hold the target data, {r['pending']} interrupted (S without "
              f"W), {len(r['problems'])} problem(s)")
        print(f"  [{c}] write estimate at this rate: ~{drv.fmt_dur(eta)} of "
              f"transfer for {to_write} chunks (x3 transfers each), plus eMMC "
              f"write time and per-chunk overhead")
        for x in r["problems"][:20]:
            print(f"      - {x}")
        if len(r["problems"]) > 20:
            print(f"      ... {len(r['problems']) - 20} more")
        bad |= bool(r["problems"])
    close_all(conns, journals)
    print("\nNothing was written. Both SoCs are halted at the scan point "
          "(staging 0x20220000 / 0x10000, so `tcon_bulkdump.py dump` can run in "
          "this session). Power off at the wall when done; do not resume.")
    if bad:
        print("\nDRY RUN FOUND PROBLEMS - do not write until they are understood.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------
def copy_chunk(rpc, chip, p, jr, e, tmp, args, stats, rewrite):
    """The per-chunk algorithm. Returns 'skip' or 'written'."""
    after, before = p.after(e), p.before(e)
    pre_path = os.path.join(tmp, f"cc_{chip}_pre.bin")
    src_path = os.path.join(tmp, f"cc_{chip}_src.bin")
    pending = jr.is_pending(e.addr) or e.addr in rewrite

    pre = read_chunk(rpc, chip, e.addr, pre_path, args.retries)
    if pre == after:
        jr.logW(e.addr, "already")
        return "skip"
    if pre != before and not pending:
        keep = os.path.join(tmp, f"stop_{chip}_{e.addr:08x}.bin")
        with open(keep, "wb") as f:
            f.write(pre)
        raise drv.TconError(
            f"{chip}: pre-read of 0x{e.addr:08x} ({e.region}) matches neither the "
            f"data to be overwritten nor the target (saved to {keep}) - STOP")
    if pre != before:
        print(f"[{chip}] 0x{e.addr:08x}: "
              + ("interrupted earlier (S without W)" if jr.is_pending(e.addr)
                 else "named in --rewrite")
              + ", rewriting", flush=True)

    jr.logS(e.addr)
    with open(src_path, "wb") as f:
        f.write(after)
    w0, wl = struct.unpack_from("<I", after, 0)[0], struct.unpack_from("<I", after, CHUNK - 4)[0]
    for attempt in range(1, ATTEMPTS + 1):
        rpc.rpc(f"tcon_write_load {{{src_path}}} 0x{OFF_A:x} 0x{CHUNK:x} "
                f"0x{w0:08x} 0x{wl:08x}", timeout=120)
        r = rpc.rpc(f"tcon_write_call 0x{e.addr:08x} 0x{CHUNK:x} 0x{OFF_A:x}",
                    timeout=120)
        rc = drv.parse_read(r).get("rc")
        if rc != 0:
            raise drv.TconError(f"{chip}: write 0x{e.addr:08x} returned {r} - STOP")
        back = read_chunk(rpc, chip, e.addr, pre_path, args.retries)
        if back == after:
            jr.logW(e.addr, f"attempt={attempt}" if attempt > 1 else "")
            return "written"
        stats["retries"] += 1
        ndiff = sum(x != y for x, y in zip(back, after))
        print(f"[{chip}] 0x{e.addr:08x}: read-back differs from the target in "
              f"{ndiff} byte(s) after attempt {attempt}/{ATTEMPTS}"
              + (", retrying" if attempt < ATTEMPTS else ""), flush=True)
    raise drv.TconError(f"{chip}: 0x{e.addr:08x} still differs after {ATTEMPTS} "
                        f"write attempts - STOP")


def cmd_write(args):
    packs = load_packs(args)
    rewrite = set()
    for a in args.rewrite:
        for c in args.chips:
            if a not in packs[c].by_addr:
                sys.exit(f"--rewrite 0x{a:08x} is not a chunk in {c}'s manifest")
        rewrite.add(a)
    args.rewrite = rewrite
    conns, journals, begins, _ = open_session(args, packs)
    tmp = drv.ensure_tmp(args.tmp)

    todo = {}
    print()
    for c in args.chips:
        jr = journals[c]
        sel = ordered(packs[c].entries, args.phase)
        todo[c] = [e for e in sel if e.addr not in jr.W or e.addr in rewrite]
        print(f"[{c}] source {args.source}, phase {args.phase}: {len(sel)} chunks, "
              f"{len(sel) - len(todo[c])} already written per the journal, "
              f"{len(todo[c])} to check/write"
              + (f" (limit {args.limit} writes)" if args.limit else "")
              + (f", {len(jr.pending)} interrupted" if jr.pending else ""))
    if not any(todo.values()):
        print("\nNothing to do. Both SoCs left halted: power cycle at the wall, "
              "do not resume.")
        close_all(conns, journals)
        return

    hdr = {c: dict(t.split("=", 1) for t in begins[c].split() if "=" in t)
           for c in args.chips}
    if not args.yes:
        if args.allow_valid_header:
            print("\n--allow-valid-header: FW#1 header state "
                  + ", ".join(f"{c} fw1={hdr[c].get('fw1')} cfg={hdr[c].get('cfg')}"
                              for c in args.chips)
                  + ". Halt both or neither; the 0x640C guard now protects a "
                    "valid header.")
            if input("Type VALID HEADER to continue: ").strip() != "VALID HEADER":
                print("Not confirmed; nothing written. Both SoCs left halted.")
                close_all(conns, journals)
                return
        what = "ROLL BACK to the backup" if args.source == "backup" else \
            "copy the old board's data"
        if input(f"\n{what} on {', '.join(args.chips)} (phase {args.phase}). "
                 f"Type WRITE to confirm: ").strip() != "WRITE":
            print("Not confirmed; nothing written. Both SoCs left halted.")
            close_all(conns, journals)
            return

    for c in args.chips:
        gone = retire_other(packs[c].dir, args.source)
        if gone:
            print(f"[{c}] the other direction's journal is superseded -> {gone}")
            journals[c].log(f"# retired {gone}")
        journals[c].log(
            f"# session {stamp()} cmd=write source={args.source} phase={args.phase} "
            f"limit={args.limit or 0} entry={args.entry} "
            f"allow_valid_header={int(args.allow_valid_header)} "
            f"fw1={hdr[c].get('fw1')} fw2={hdr[c].get('fw2')} cfg={hdr[c].get('cfg')} "
            f"ccr={hdr[c].get('ccr')} rewrite={','.join(f'0x{a:08x}' for a in sorted(rewrite)) or '-'}")

    stats = {c: {"written": 0, "skipped": 0, "retries": 0, "secs": 0.0}
             for c in args.chips}

    @worker_guard
    def work(chip, abort, reason):
        p, jr, st = packs[chip], journals[chip], stats[chip]
        prog = drv.Progress(len(todo[chip]) * CHUNK)
        tick = reporter(chip, prog, args)
        t0 = time.time()
        for i, e in enumerate(todo[chip]):
            if abort.is_set():
                raise drv.Aborted("peer chip stopped")
            if args.limit and st["written"] >= args.limit:
                break
            r = copy_chunk(conns[chip], chip, p, jr, e, tmp, args, st, rewrite)
            st["written" if r == "written" else "skipped"] += 1
            prog.add(CHUNK)
            tick(i + 1)
            st["secs"] = time.time() - t0
        st["secs"] = time.time() - t0

    aborted, reason = run_parallel(args, conns, work, ())
    for c in args.chips:
        s = stats[c]
        print(f"[{c}] written {s['written']}, already there {s['skipped']}, "
              f"retries {s['retries']}, {drv.fmt_dur(s['secs'])}"
              + (f" ({s['written'] * CHUNK * 3 / s['secs'] / 1024:.0f} KiB/s over SWD)"
                 if s["secs"] and s["written"] else ""))
    if aborted:
        print(f"\nWrite STOPPED: {reason}", file=sys.stderr)
        drv.emergency_stop(conns, args.chips)
        close_all(conns, journals)
        print("After the power cycle, rerun with --entry loop: the journal "
              "resumes, and a chunk left S without W is rewritten.",
              file=sys.stderr)
        sys.exit(2)

    done = {c: all(e.addr in journals[c].W for e in packs[c].entries)
            for c in args.chips}
    print("\nPanel-ID sites now:")
    try:
        for c in args.chips:
            ok, lines = pnid_check(conns[c], c, packs[c], journals[c], done[c], tmp)
            print("\n".join(lines))
    except drv.TconError as e:
        print(f"TCONERR: {e}", file=sys.stderr)
        drv.emergency_stop(conns, args.chips)
        close_all(conns, journals)
        sys.exit(2)
    close_all(conns, journals)
    for c in args.chips:
        left = sum(e.addr not in journals[c].W for e in packs[c].entries)
        print(f"[{c}] " + ("copy complete (every chunk W)" if not left
                           else f"{left} chunk(s) still to write"))
    print("\nBoth SoCs left HALTED. Power off at the wall; do NOT resume.")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
def cmd_verify(args):
    packs = load_packs(args)
    conns, journals, begins, pn_ok = open_session(args, packs)
    tmp = drv.ensure_tmp(args.tmp)
    res = {c: {"ok": 0, "runtime": [], "bad": []} for c in args.chips}

    @worker_guard
    def work(chip, abort, reason):
        p, r = packs[chip], res[chip]
        todo = ordered(p.entries, args.phase)
        path = os.path.join(tmp, f"cc_{chip}_ver.bin")
        prog = drv.Progress(len(todo) * CHUNK)
        tick = reporter(chip, prog, args)
        for i, e in enumerate(todo):
            if abort.is_set():
                raise drv.Aborted("peer chip stopped")
            got = read_chunk(conns[chip], chip, e.addr, path, args.retries)
            if got == p.after(e):
                r["ok"] += 1
            elif args.allow_valid_header and "rt" in e.flags.split(","):
                r["runtime"].append(e)
            else:
                r["bad"].append(e)
                with open(os.path.join(tmp, f"mismatch_{chip}_{e.addr:08x}.bin"),
                          "wb") as f:
                    f.write(got)
            prog.add(CHUNK)
            tick(i + 1)

    aborted, reason = run_parallel(args, conns, work, ())
    if aborted:
        print(f"\nVerify stopped: {reason}", file=sys.stderr)
        drv.emergency_stop(conns, args.chips)
        close_all(conns, journals)
        sys.exit(2)
    close_all(conns, journals)

    failed = not pn_ok
    print(f"\nVerify (target = {'old data' if args.source == 'old' else 'backup'}, "
          f"phase {args.phase}):")
    for c in args.chips:
        r = res[c]
        print(f"  [{c}] {r['ok']} match, {len(r['runtime'])} runtime-updated, "
              f"{len(r['bad'])} MISMATCH")
        if r["runtime"]:
            regions = sorted({e.region for e in r["runtime"]})
            print(f"      runtime-updated (known runtime writer; exempt with "
                  f"--allow-valid-header): {', '.join(regions)}")
        for e in r["bad"][:20]:
            print(f"      MISMATCH 0x{e.addr:08x} {e.region}  "
                  f"(saved mismatch_{c}_{e.addr:08x}.bin in --tmp)")
        if len(r["bad"]) > 20:
            print(f"      ... {len(r['bad']) - 20} more")
        failed |= bool(r["bad"])
    if not pn_ok:
        print("  panel-ID sites: NOT all the target ID (see above)")
    print("\nNothing was written. Both SoCs left halted: power off at the wall, "
          "do not resume.")
    if failed:
        print("\nVERIFY FAILED.")
        sys.exit(1)
    print("\nVERIFY PASSED.")


# ---------------------------------------------------------------------------
# state / gapcheck
# ---------------------------------------------------------------------------
def cmd_state(args):
    for c in args.chips:
        d = os.path.join(args.plan, c)
        try:
            _, entries = cp.load_manifest(d)
        except OSError as e:
            print(f"[{c}] no manifest ({e})")
            continue
        for src in JOURNALS:
            jr = CopyJournal(d, src)
            if not (jr.S or jr.W):
                continue
            per = {ph: (sum(e.addr in jr.W for e in entries if e.phase == ph),
                        sum(e.phase == ph for e in entries)) for ph in (1, 2)}
            print(f"[{c}] journal {JOURNALS[src]}: phase 1 {per[1][0]}/{per[1][1]}, "
                  f"phase 2 {per[2][0]}/{per[2][1]} written"
                  + (f", interrupted: {', '.join(f'0x{a:08x}' for a in sorted(jr.pending))}"
                     if jr.pending else ""))
    conns = drv.connect_all(args.chips, args.files, speed=args.speed)
    try:
        for c in args.chips:
            print(f"[{c}] {conns[c].rpc('tcon_bulk_state')}")
    finally:
        close_all(conns)


def gapcheck_dir(chipdir, regions):
    """-> (problems, n_U, missing intervals) for one chip's dump journal."""
    probs, n_u = [], 0
    jp = os.path.join(chipdir, "journal.txt")
    if os.path.exists(jp):
        with open(jp) as f:
            for line in f:
                p = line.split()
                if not p or p[0].startswith("#"):
                    continue
                if p[0] == "U" and len(p) >= 4 and int(p[3], 0) == 0:
                    n_u += 1
                elif p[0] == "U":
                    probs.append(f"U {p[1]} {p[2]} fill {p[3]} (not zero: differs "
                                 f"from the old board's blank)")
                else:
                    probs.append(" ".join(p) + {"D": " (data)", "B": " (bad sectors)",
                                                "X": " (invalidated)"}.get(p[0], ""))
    covered, _ = load_journal(chipdir)
    missing = subtract_intervals([(a, b) for _, a, b in regions], covered)
    return probs, n_u, missing


def cmd_gapcheck(args):
    regions = parse_regions(args.regions)
    bad = False
    for c in args.chips:
        probs, n_u, missing = gapcheck_dir(os.path.join(args.new, c), regions)
        verdict = "OK" if not probs and not missing else "FLAGGED"
        print(f"[{c}] {n_u} blank (U 0x00000000) chunk(s), {len(probs)} flagged, "
              f"{sum(b - a for a, b in missing) / 2**20:.1f} MiB not covered: {verdict}")
        for x in probs[:30]:
            print(f"    {x}")
        if len(probs) > 30:
            print(f"    ... {len(probs) - 30} more")
        for a, b in missing[:5]:
            print(f"    not covered: 0x{a:08x}-0x{b:08x}")
        bad |= verdict != "OK"
    if bad:
        print("\nGAP CHECK FLAGGED: the replacement board holds data (or the dump "
              "is incomplete) outside the write set. Stop and review before "
              "writing.")
        sys.exit(1)
    print("\nGap check OK: only zero-filled blank chunks.")


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def session(p, writes=False):
        drv.add_common(p)
        p.add_argument("--plan", default=cp.DEFAULT_OUT,
                       help="pack directory from tcon_copyplan.py (default %(default)s)")
        p.add_argument("--entry", choices=["loop", "reset", "none"], required=True,
                       help="loop: wait for the boot loop's scan point (fresh "
                            "power cycle); reset: halt both + reset_to_scan; "
                            "none: both already halted at 0x29c2 / 0x414")
        p.add_argument("--source", choices=["old", "backup"], default="old",
                       help="old = copy the old board's data (default); "
                            "backup = roll back to the replacement board's backup")
        p.add_argument("--phase", choices=["1", "2", "all"], default="all")
        p.add_argument("--allow-valid-header", action="store_true",
                       help="accept a FW#1 header identical to FW#2's and cfg=0 "
                            "(plan section 4); not with --entry loop")
        p.add_argument("--retries", type=int, default=3,
                       help="re-reads of a chunk whose read fails (default 3)")
        p.add_argument("--report-secs", type=float, default=30,
                       help="progress line every N seconds (default %(default)s)")
        if writes:
            p.add_argument("--limit", type=int, default=0,
                           help="stop after N chunks written per chip (0 = no limit)")
            p.add_argument("--rewrite", type=lambda s: [int(x, 0) for x in s.split(",")],
                           default=[], metavar="ADDR,...",
                           help="chunks to rewrite even if the pre-read matches "
                                "neither image (after a failed verify, confirmed "
                                "by hand)")
            p.add_argument("--yes", action="store_true",
                           help="skip the typed confirmations (tests only)")

    p = sub.add_parser("dryrun", help="read-only pre-read of the write set")
    session(p)
    p.add_argument("--limit", type=int, default=0, help="read only the first N chunks")
    p.set_defaults(func=cmd_dryrun)

    p = sub.add_parser("write", help="the copy (WRITES the eMMC)")
    session(p, writes=True)
    p.set_defaults(func=cmd_write)

    p = sub.add_parser("verify", help="read-only: every chunk == target")
    session(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("state", help="SoC state + journal progress")
    drv.add_common(p)
    p.add_argument("--plan", default=cp.DEFAULT_OUT)
    p.set_defaults(func=cmd_state)

    p = sub.add_parser("gapcheck", help="judge a --skip-blank dump of the gaps (offline)")
    p.add_argument("--new", required=True, help="the dump's --new directory")
    p.add_argument("--chips", type=lambda s: [x.strip() for x in s.split(",")],
                   default=["master", "slave"])
    p.add_argument("--regions", default="gap0,gap1,gap2",
                   help="what the dump must cover (default %(default)s)")
    p.set_defaults(func=cmd_gapcheck)

    args = ap.parse_args()
    if getattr(args, "allow_valid_header", False) and args.entry == "loop":
        sys.exit("REFUSED: --allow-valid-header cannot be used with --entry loop: "
                 "a board with a valid header doesn't loop (use --entry reset or "
                 "none). Nothing was connected.")
    args.func(args)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
tcon_diffdump.py - diff new (replacement-board) eMMC dumps against the old
board's external dumps, region by region, per chip, and list the differing
byte ranges.

Inputs, per chip (master, slave):
  old   <old>/<chip>/user_a.bin           full user area, from the reader
  new   <new>/<chip>/user_swd.bin         offset-aligned image: byte N of the
                                          file is eMMC byte N (sparse is fine)
        <new>/<chip>/journal.txt          optional; if present, only ranges it
                                          marks as read are compared (format in
                                          tcon_regions.load_journal)
        <new>/<chip>/bad_sectors.txt      optional; excluded and listed

Without a journal, the regions given by --regions (default: every dump
region in tcon_regions.py) are compared, clipped to the new file's size.

Outputs, in --out (default <new>/diff):
  diff_<chip>.tsv      start, end, length, label - one line per differing range
  summary.txt          the per-label table printed to stdout

Ranges closer than --merge-gap bytes are merged (default 16), so random-looking
calibration data isn't split by bytes that match by chance. Use 0 for exact.

Needs numpy.
"""

import argparse
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from tcon_regions import (LABELS, PNID_SITES, SECTOR, label_segments,  # noqa: E402
                          load_journal, merge_intervals, parse_regions,
                          subtract_intervals)

BLOCK = 8 << 20
DEFAULT_OLD = os.path.normpath(os.path.join(HERE, "..", "emmc_dumps", "emmc_dumps", "old_board"))
DEFAULT_NEW = os.path.normpath(os.path.join(HERE, "..", "emmc_dumps", "emmc_dumps", "new_board"))


class RangeBuilder:
    """Collects differing offsets into [start, end) ranges, merging gaps <= gap."""

    def __init__(self, gap):
        self.gap = gap
        self.cur = None
        self.out = []
        self.nbytes = 0

    def feed(self, idx):
        if idx.size == 0:
            return
        self.nbytes += int(idx.size)
        brk = np.flatnonzero(np.diff(idx) > self.gap + 1)
        starts = idx[np.r_[0, brk + 1]]
        ends = idx[np.r_[brk, idx.size - 1]] + 1
        s0, e0 = int(starts[0]), int(ends[0])
        if self.cur is not None and s0 - self.cur[1] <= self.gap:
            self.cur[1] = e0
        else:
            self.close()
            self.cur = [s0, e0]
        if starts.size > 1:
            self.close()
            self.out.extend(zip(starts[1:-1].tolist(), ends[1:-1].tolist()))
            self.cur = [int(starts[-1]), int(ends[-1])]

    def close(self):
        if self.cur is not None:
            self.out.append(tuple(self.cur))
            self.cur = None


def read_at(f, off, n):
    f.seek(off)
    d = f.read(n)
    if len(d) < n:
        d += b"\0" * (n - len(d))
    return np.frombuffer(d, dtype=np.uint8)


def compare_segment(fo, fn, a, b, gap):
    rb = RangeBuilder(gap)
    for off in range(a, b, BLOCK):
        n = min(BLOCK, b - off)
        x = read_at(fo, off, n)
        y = read_at(fn, off, n)
        rb.feed(np.flatnonzero(x != y).astype(np.int64) + off)
    rb.close()
    return rb


def ascii_at(f, off, n):
    f.seek(off)
    return "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in f.read(n))


def coverage_for(newdir, img, regions):
    covered, bad = load_journal(newdir)
    size = os.path.getsize(img)
    wanted = [(a, min(b, size)) for _, a, b in regions if a < size]
    # key on the journal FILE, not on whether it still covers anything: a
    # journal whose chunks were all invalidated (X lines) must compare
    # nothing, not fall back to comparing whole regions of undumped zeros
    if os.path.exists(os.path.join(newdir, "journal.txt")):
        covered = [(max(a, wa), min(b, wb)) for a, b in covered for wa, wb in wanted
                   if max(a, wa) < min(b, wb)]
        source = "journal"
    else:
        covered = wanted
        source = "regions (no journal)"
    covered = merge_intervals(covered)
    if bad:
        covered = subtract_intervals(covered, [(s, s + SECTOR) for s in bad])
    missing = subtract_intervals([(a, b) for _, a, b in regions], covered)
    missing = subtract_intervals(missing, [(s, s + SECTOR) for s in bad])
    return covered, bad, missing, source


def diff_chip(chip, args, out_lines):
    def emit(s=""):
        print(s)
        out_lines.append(s)

    olddir = os.path.join(args.old, chip)
    newdir = os.path.join(args.new, chip)
    old_img = os.path.join(olddir, args.old_image)
    new_img = os.path.join(newdir, args.new_image)
    for p in (old_img, new_img):
        if not os.path.exists(p):
            emit(f"[{chip}] missing {p} - skipped")
            return

    regions = parse_regions(args.regions)
    covered, bad, missing, source = coverage_for(newdir, new_img, regions)
    total = sum(b - a for a, b in covered)
    emit(f"=== {chip}: {new_img}")
    emit(f"    vs {old_img}")
    emit(f"    coverage from {source}: {total / 2**20:.1f} MB compared, "
         f"{len(bad)} bad sector(s) excluded")
    if missing:
        emit(f"    NOT compared ({sum(b - a for a, b in missing) / 2**20:.1f} MB, not dumped yet):")
        for a, b in missing[:args.show]:
            emit(f"      0x{a:08x}-0x{b:08x}")
        if len(missing) > args.show:
            emit(f"      ... {len(missing) - args.show} more")

    rows = []
    all_ranges = []
    with open(old_img, "rb") as fo, open(new_img, "rb") as fn:
        for ca, cb in covered:
            for a, b, label in label_segments(ca, cb):
                rb = compare_segment(fo, fn, a, b, args.merge_gap)
                rows.append((a, b, label, rb.nbytes, len(rb.out)))
                all_ranges.extend((s, e, label) for s, e in rb.out)

        # collapse per label for the table (a label can span several segments)
        table = {}
        for a, b, label, nd, nr in rows:
            t = table.setdefault((label, _label_start(a)), [a, b, 0, 0, 0])
            t[0] = min(t[0], a)
            t[1] = max(t[1], b)
            t[2] += b - a
            t[3] += nd
            t[4] += nr
        emit("")
        emit(f"    {'label':<28} {'range':<23} {'compared':>10} {'differ':>12} {'ranges':>7}  verdict")
        for (label, _), (a, b, comp, nd, nr) in sorted(table.items(), key=lambda kv: kv[1][0]):
            verdict = "identical" if nd == 0 else f"DIFFERS ({100.0 * nd / comp:.3g}%)"
            emit(f"    {label:<28} 0x{a:08x}-0x{b:08x} {comp / 2**20:>8.2f}MB {nd:>12,} {nr:>7}  {verdict}")

        emit("")
        emit(f"    panel-ID sites (old | new):")
        for sec, off, desc in PNID_SITES:
            inside = any(a <= sec + off and sec + off + 10 <= b for a, b in covered)
            new_s = ascii_at(fn, sec + off, 10) if inside else "(not dumped)"
            emit(f"      0x{sec + off:08x} {desc:<22} {ascii_at(fo, sec + off, 10)} | {new_s}")

        if args.check_ab:
            ab = os.path.join(olddir, "user_b.bin")
            if os.path.exists(ab):
                n_ab = 0
                with open(ab, "rb") as fb:
                    for ca, cb in covered:
                        n_ab += compare_segment(fo, fb, ca, cb, 0).nbytes
                emit(f"    old user_a vs user_b over the compared ranges: {n_ab:,} bytes differ")

    os.makedirs(args.out, exist_ok=True)
    tsv = os.path.join(args.out, f"diff_{chip}.tsv")
    with open(tsv, "w") as f:
        f.write("start\tend\tlength\tlabel\n")
        for s, e, label in all_ranges:
            f.write(f"0x{s:08x}\t0x{e:08x}\t{e - s}\t{label}\n")
    if bad:
        with open(os.path.join(args.out, f"bad_{chip}.txt"), "w") as f:
            f.writelines(f"0x{s:08x}\n" for s in bad)
    emit(f"    {len(all_ranges)} differing range(s) -> {tsv}")
    for s, e, label in all_ranges[:args.show]:
        emit(f"      0x{s:08x}-0x{e:08x} {e - s:>10}  {label}")
    if len(all_ranges) > args.show:
        emit(f"      ... {len(all_ranges) - args.show} more in the TSV")
    emit("")


def _label_start(a):
    # key helper so repeated labels ("gap") at different places stay separate
    for la, lb, _ in LABELS:
        if la <= a < lb:
            return la
    return a


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--old", default=DEFAULT_OLD, help="old-board dump dir (default %(default)s)")
    ap.add_argument("--new", default=DEFAULT_NEW, help="new-board dump dir (default %(default)s)")
    ap.add_argument("--old-image", default="user_a.bin")
    ap.add_argument("--new-image", default="user_swd.bin")
    ap.add_argument("--chips", default="master,slave")
    ap.add_argument("--regions", default="all",
                    help="region names from tcon_regions.py and/or 0xA-0xB ranges, comma separated")
    ap.add_argument("--merge-gap", type=int, default=16)
    ap.add_argument("--show", type=int, default=30, help="ranges to print per chip")
    ap.add_argument("--check-ab", action="store_true",
                    help="also check the old user_a.bin against user_b.bin over the same ranges")
    ap.add_argument("--out", default=None, help="output dir (default <new>/diff)")
    args = ap.parse_args()
    args.out = args.out or os.path.join(args.new, "diff")

    lines = []
    for chip in args.chips.split(","):
        diff_chip(chip.strip(), args, lines)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "summary.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()

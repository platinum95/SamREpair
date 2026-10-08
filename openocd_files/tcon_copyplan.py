#!/usr/bin/env python3
"""
tcon_copyplan.py - build the frozen calibration-copy packs, offline.

Plan: AgentInfo/calibration_copy_plan.md (sections 2-4). Python standard
library only. Nothing here talks to OpenOCD or the board.

For each chip it compares the original board's external image
(<old>/<chip>/user_a.bin) with the replacement board's SWD backup
(<new>/<chip>/user_swd.bin, over what its journal.txt covers), in 32 KiB
chunks, and writes, under <out>/<chip>/:

    manifest.tsv   one line per differing chunk: index, address, length,
                   phase, region, flags, SHA-256 of the old data (src) and
                   of the backup (bak). '#' lines carry the metadata the
                   driver checks (pack sizes and hashes, panel-ID sites).
    src.bin        the old data of every chunk, in manifest order
    bak.bin        the backup data of every chunk, in manifest order

Chunk i sits at offset i * 0x8000 in both packs. tcon_copycal.py needs only
these files, not the 3.9 GB images.

It refuses to write anything unless every offline check passes:
  - the backup journal covers the whole 'all' region set, with no bad sectors;
  - the old image reads the real panel ID at all ten panel-ID sites;
  - every differing chunk lies in a region the plan copies (never FW,
    makersheets, blobs, ISC_ST or the gaps);
  - every 512-byte sector in the write set that passes the header checksum
    (sum of all 128 words == 0xFFFFFFFF) on the new board also passes it on
    the old board;
  - the old LOG's current header (the higher index) points at a non-blank
    sector, and everything after it up to 0x94000000 is blank;
  - the old image is blank everywhere the backup does not cover;
  - user_a.bin == user_b.bin over the write set (if user_b.bin exists).

Existing packs are never overwritten while a copy journal sits next to them;
without a journal, --force is needed.
"""

import argparse
import array
import collections
import hashlib
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from tcon_regions import (DUMP_REGIONS, LABELS, PNID_SITES,  # noqa: E402
                          SECTOR, load_journal, merge_intervals,
                          subtract_intervals)

DUMPS = os.path.normpath(os.path.join(HERE, "..", "emmc_dumps", "emmc_dumps"))
DEFAULT_OLD = os.path.join(DUMPS, "old_board")
DEFAULT_NEW = os.path.join(DUMPS, "new_board")
DEFAULT_OUT = os.path.join(DUMPS, "copy_plan")

CHUNK = 0x8000                  # 32 KiB: the largest firmware write is 0x9400
OLD_PID = b"1HND0V7S0B"         # the real panel (sticker, EEPROM)
MANIFEST_VERSION = 1
MANIFEST_COLS = ["idx", "addr", "len", "phase", "region", "flags",
                 "sha_src", "sha_bak"]

# What the plan copies (section 2), as (region, start, end, phase). Anything
# that differs outside these is a refusal. 'block groups (pre bank A)'
# includes the 'between block groups' label, which is identical anyway.
COPY_GROUPS = [
    ("ISC_AGE",                   0x00FF0000, 0x02980000, 1),
    ("LCC",                       0x04400000, 0x04500000, 1),
    ("iRUN",                      0x04500000, 0x04580000, 1),
    ("GCM + MCU_OVER",            0x04580000, 0x04800000, 1),
    ("VRR",                       0x04800000, 0x05000000, 1),
    ("panel-ID records",          0x05000000, 0x050F0000, 1),
    ("~25 x 1.1MB blocks",        0x050F0000, 0x0C100000, 1),
    ("12 x 4.3MB blocks",         0x0C310000, 0x152A0000, 1),
    ("block groups (pre bank A)", 0x152A0000, 0x22000000, 1),
    ("bank A",                    0x22000000, 0x23000000, 1),
    ("block groups (post bank A)", 0x23000000, 0x2FBC0000, 1),
    ("bank B",                    0x32000000, 0x33000000, 1),
    ("PFT",                       0x7F000000, 0x80000000, 1),
    ("LOG",                       0x80000000, 0x94000000, 2),
]

# Chunks with a known runtime writer (plan section 1): after a full boot the
# firmware may legitimately change them, so `verify --allow-valid-header`
# reports them as "runtime-updated" instead of failing. Whole regions, plus
# the chunks holding these addresses.
RT_REGIONS = ("ISC_AGE", "LOG")
RT_ADDRS = (0x04600000,         # MCU_OVER (0x4D04)
            0x05000C00,         # counter table (0x3253C)
            0x7F300000)         # PFT +0x300000 (0x301A8)

# LOG layout (plan section 1)
LOG_BASE = 0x80000000
LOG_HDRS = (0x80000000, 0x80000200)
LOG_ENTRIES = 0x80004000
LOG_END = 0x94000000

BLOCK = 0x100000
ZERO = bytes(BLOCK)


# ---------------------------------------------------------------------------
# small helpers, shared with tcon_copycal.py
# ---------------------------------------------------------------------------
def group_of(addr):
    for name, a, b, phase in COPY_GROUPS:
        if a <= addr < b:
            return name, phase
    return None, None


def label_of(addr):
    for a, b, name in LABELS:
        if a <= addr < b:
            return name
    return "?"


def chunk_flags(addr, region):
    f = []
    if any(addr <= s + off < addr + CHUNK for s, off, _ in PNID_SITES):
        f.append("pnid")
    if region in RT_REGIONS or any(addr <= a < addr + CHUNK for a in RT_ADDRS):
        f.append("rt")
    return ",".join(f) or "-"


def is_blank(b):
    return b == ZERO[:len(b)] if len(b) <= BLOCK else b.count(0) == len(b)


def hdr_ok(sector):
    """The header checksum from the LOG header builder (0x5608):
    word0 = 0xFFFFFFFF - sum(words 1..127), i.e. all 128 words sum to
    0xFFFFFFFF (mod 2^32)."""
    return (sum(struct.unpack("<128I", sector)) & 0xFFFFFFFF) == 0xFFFFFFFF


def passing_sectors(data):
    """Offsets of the sectors in `data` that pass hdr_ok."""
    a = array.array("I", data)
    if sys.byteorder != "little":
        a.byteswap()
    return [i * SECTOR for i in range(len(data) // SECTOR)
            if (sum(a[i * 128:(i + 1) * 128]) & 0xFFFFFFFF) == 0xFFFFFFFF]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def pid_str(b):
    return "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in b)


class Image:
    """Read-only access to an offset-aligned image; reads past EOF are
    zero (the SWD backup is sparse and shorter than the user area)."""

    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.size = os.path.getsize(path)

    def read(self, off, n):
        self.f.seek(off)
        d = self.f.read(n)
        return d + bytes(n - len(d)) if len(d) < n else d

    def close(self):
        self.f.close()


Entry = collections.namedtuple("Entry", MANIFEST_COLS)


def load_manifest(chipdir):
    """-> (meta dict, [Entry]). meta holds the '# key value...' lines; the
    'pnid' lines are collected into meta['pnid'] as (site, src, bak, desc)."""
    meta = {"pnid": []}
    entries = []
    with open(os.path.join(chipdir, "manifest.tsv")) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#"):
                p = line[1:].strip().split(None, 1)
                if not p:
                    continue
                if p[0] == "pnid":
                    site, src, bak, desc = p[1].split(None, 3)
                    meta["pnid"].append((int(site, 0), src.split("=", 1)[1],
                                         bak.split("=", 1)[1], desc))
                else:
                    meta[p[0]] = p[1] if len(p) > 1 else ""
                continue
            p = line.split("\t")
            if p[0] == "idx":
                if p != MANIFEST_COLS:
                    raise ValueError(f"unexpected manifest columns {p}")
                continue
            entries.append(Entry(int(p[0]), int(p[1], 0), int(p[2], 0),
                                 int(p[3]), p[4], p[5], p[6], p[7]))
    if int(meta.get("version", "0")) != MANIFEST_VERSION:
        raise ValueError(f"manifest version {meta.get('version')} "
                         f"!= {MANIFEST_VERSION}")
    for i, e in enumerate(entries):
        if e.idx != i or e.len != CHUNK or e.addr % CHUNK:
            raise ValueError(f"manifest line {i} malformed: {e}")
    return meta, entries


# ---------------------------------------------------------------------------
# the checks
# ---------------------------------------------------------------------------
class Checks:
    def __init__(self, out):
        self.out = out
        self.failed = []

    def __call__(self, name, ok, detail=""):
        if not ok:
            self.failed.append(name)
        self.out(f"  [{'PASS' if ok else 'FAIL'}] {name}"
                 + (f": {detail}" if detail else ""))
        return ok


def log_state(img):
    """The two LOG headers -> dict, or a string saying why they're unusable."""
    hdrs = []
    for a in LOG_HDRS:
        s = img.read(a, SECTOR)
        hdrs.append({"addr": a, "tag": s[4:8], "idx": struct.unpack_from("<I", s, 8)[0],
                     "ctr": struct.unpack_from("<I", s, 0x18)[0], "ok": hdr_ok(s)})
    cur = 0 if hdrs[0]["idx"] > hdrs[1]["idx"] else 1
    last = LOG_ENTRIES + (hdrs[cur]["idx"] - 1) * SECTOR
    return {"hdrs": hdrs, "cur": cur, "idx": hdrs[cur]["idx"],
            "ctr": hdrs[cur]["ctr"], "last": last}


def check_log(img, chk, chip):
    ls = log_state(img)
    h0, h1 = ls["hdrs"]
    chk(f"{chip}: old LOG headers tagged 'LOG' and checksummed",
        all(h["tag"] == b"LOG\0" and h["ok"] for h in ls["hdrs"]),
        f"hdr0 tag={h0['tag']!r} ok={h0['ok']}, hdr1 tag={h1['tag']!r} ok={h1['ok']}")
    if h0["idx"] == h1["idx"]:
        chk(f"{chip}: old LOG header indices differ", False,
            f"both 0x{h0['idx']:x}")
        return ls
    last = ls["last"]
    if not (ls["idx"] >= 1 and LOG_ENTRIES <= last < LOG_END):
        chk(f"{chip}: old LOG index in range", False,
            f"index 0x{ls['idx']:x} -> 0x{last:08x}")
        return ls
    chk(f"{chip}: old LOG current header is header {ls['cur']} "
        f"(index 0x{ls['idx']:x}, other 0x{ls['hdrs'][1 - ls['cur']]['idx']:x}) "
        f"-> last entry 0x{last:08x} is non-blank",
        not is_blank(img.read(last, SECTOR)))
    # everything after the last entry up to LOG_END must be blank
    first_data = None
    a = last + SECTOR
    while a < LOG_END:
        n = min(BLOCK - (a % BLOCK), LOG_END - a)
        d = img.read(a, n)
        if not is_blank(d):
            off = next(i for i in range(0, n, SECTOR)
                       if not is_blank(d[i:i + SECTOR]))
            first_data = a + off
            break
        a += n
    chk(f"{chip}: old LOG blank from 0x{last + SECTOR:08x} to 0x{LOG_END:08x}",
        first_data is None,
        "" if first_data is None else f"data at 0x{first_data:08x}")
    return ls


def scan_chip(chip, args, out):
    """Run every check for one chip and find the write set. Returns
    (entries, info, failed_check_names). Nothing is written."""
    chk = Checks(out)
    old_path = os.path.join(args.old, chip, args.old_image)
    oldb_path = os.path.join(args.old, chip, "user_b.bin")
    new_dir = os.path.join(args.new, chip)
    new_path = os.path.join(new_dir, "user_swd.bin")
    out(f"\n=== {chip} ===")
    out(f"  old    {old_path}")
    out(f"  backup {new_path}")
    for p in (old_path, new_path):
        if not os.path.exists(p):
            chk(f"{chip}: {p} exists", False)
            return [], {}, chk.failed

    old, new = Image(old_path), Image(new_path)
    oldb = Image(oldb_path) if os.path.exists(oldb_path) else None
    info = {"old": old_path, "new": new_path, "old_size": old.size,
            "new_size": new.size}
    try:
        # -- the backup: complete for the 'all' set, no bad sectors ----------
        covered, bad = load_journal(new_dir)
        allset = merge_intervals([(a, b) for _, a, b in DUMP_REGIONS])
        missing = subtract_intervals(allset, covered)
        chk(f"{chip}: backup journal covers the 'all' region set",
            not missing, (f"{len(missing)} gap(s), first 0x{missing[0][0]:08x}-"
                          f"0x{missing[0][1]:08x}") if missing else "")
        chk(f"{chip}: backup has no bad sectors", not bad,
            f"{len(bad)} bad" if bad else "")
        with open(os.path.join(new_dir, "journal.txt")) as f:
            kinds = collections.Counter(ln.split()[0] for ln in f
                                        if ln.strip() and not ln.startswith("#"))
        chk(f"{chip}: backup journal has only D lines",
            set(kinds) <= {"D"}, dict(kinds))
        cov_end = max((b for _, b in covered), default=0)
        chk(f"{chip}: backup image spans its journal",
            new.size >= cov_end, f"size 0x{new.size:x}, journal to 0x{cov_end:x}")
        info["covered"] = sum(b - a for a, b in covered)

        # -- panel-ID sites ----------------------------------------------------
        pn = []
        for sec, off, desc in PNID_SITES:
            pn.append((sec + off, old.read(sec + off, 10), new.read(sec + off, 10), desc))
        bad_pid = [f"0x{s:08x}={pid_str(o)}" for s, o, _, _ in pn if o != args.old_pid]
        chk(f"{chip}: old image reads {args.old_pid.decode()} at all "
            f"{len(PNID_SITES)} panel-ID sites", not bad_pid, ", ".join(bad_pid))
        newpids = collections.Counter(pid_str(n) for _, _, n, _ in pn)
        out("  (backup panel-ID sites: "
            + ", ".join(f"{k} x{v}" for k, v in newpids.items()) + ")")
        info["pnid"] = pn

        # -- compare over the covered ranges, 1 MiB at a time ----------------
        entries = []
        stray = []
        for ca, cb in covered:
            for a in range(ca, cb, BLOCK):
                n = min(BLOCK, cb - a)
                do, dn = old.read(a, n), new.read(a, n)
                if do == dn:
                    continue
                for c in range(a, a + n, CHUNK):
                    o, w = c - a, min(CHUNK, a + n - c)
                    if do[o:o + w] == dn[o:o + w]:
                        continue
                    region, phase = group_of(c)
                    if region is None or w != CHUNK or c % CHUNK:
                        stray.append(c)
                        continue
                    entries.append((c, region, phase))
        chk(f"{chip}: every differing chunk lies in a copied region",
            not stray, (f"{len(stray)} outside, first 0x{stray[0]:08x} "
                        f"({label_of(stray[0])})") if stray else "")

        # -- header checksum rule over the write set ---------------------------
        n_new = n_old = 0
        broken = []
        per_region = collections.Counter()
        ab_diff = []
        for c, region, _ in entries:
            do, dn = old.read(c, CHUNK), new.read(c, CHUNK)
            pn_new = set(passing_sectors(dn))
            pn_old = set(passing_sectors(do))
            n_new += len(pn_new)
            n_old += len(pn_old)
            per_region[region] += len(pn_new)
            broken += [c + s for s in sorted(pn_new - pn_old)]
            if oldb is not None and oldb.read(c, CHUNK) != do:
                ab_diff.append(c)
        chk(f"{chip}: every sector passing the header checksum on the backup "
            f"also passes on the old image", not broken,
            (f"{len(broken)} fail on old, first " + ", ".join(
                f"0x{b:08x} ({label_of(b)})" for b in broken[:4])) if broken
            else f"{n_new} pass on backup, {n_old} on old")
        info["hdr_regions"] = per_region
        if oldb is None:
            out(f"  [skip] {chip}: no user_b.bin, old image not cross-checked")
        else:
            chk(f"{chip}: old user_a == user_b over the write set",
                not ab_diff, f"{len(ab_diff)} chunks differ" if ab_diff else "")

        # -- LOG ---------------------------------------------------------------
        info["log_old"] = check_log(old, chk, chip)
        info["log_new"] = log_state(new)

        # -- old image blank where the backup doesn't reach ------------------
        outside = subtract_intervals([(0, old.size)], covered)
        found = []
        for a, b in outside:
            for x in range(a, b, BLOCK):
                n = min(BLOCK, b - x)
                if not is_blank(old.read(x, n)):
                    found.append(x)
                    if len(found) >= 8:
                        break
            if len(found) >= 8:
                break
        chk(f"{chip}: old image blank outside the backup's coverage "
            f"({sum(b - a for a, b in outside) / 2**20:.0f} MiB)",
            not found, ("data at " + ", ".join(f"0x{x:08x}" for x in found))
            if found else "")
        return entries, info, chk.failed
    finally:
        old.close()
        new.close()
        if oldb:
            oldb.close()


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------
def summary(results, out):
    chips = list(results)
    counts = {c: collections.Counter(r for _, r, _ in results[c][0]) for c in chips}
    out("\n=== write set (32 KiB chunks) ===")
    out(f"  {'region':<28}" + "".join(f"{c:>9}" for c in chips)
        + f"{'MiB':>9}  {'hdr-ok sectors':>14}")
    tot = {c: collections.Counter() for c in chips}
    for phase in (1, 2):
        for name, a, b, ph in COPY_GROUPS:
            if ph != phase:
                continue
            n = [counts[c][name] for c in chips]
            for c in chips:
                tot[c][phase] += counts[c][name]
            hdr = "/".join(str(results[c][1].get("hdr_regions", {}).get(name, 0))
                           for c in chips)
            out(f"  {name:<28}" + "".join(f"{x:>9,}" for x in n)
                + f"{sum(n) * CHUNK / 2**20 / len(chips):>9.1f}  {hdr:>14}")
        label = "Phase 1 subtotal (calibration)" if phase == 1 else "Phase 2 (LOG)"
        n = [tot[c][phase] for c in chips]
        out(f"  {label:<28}" + "".join(f"{x:>9,}" for x in n)
            + f"{sum(n) * CHUNK / 2**20 / len(chips):>9.1f}")
    n = [tot[c][1] + tot[c][2] for c in chips]
    out(f"  {'Total':<28}" + "".join(f"{x:>9,}" for x in n)
        + f"{sum(n) * CHUNK / 2**20 / len(chips):>9.1f}")
    out("  (MiB = mean per chip; hdr-ok = sectors passing the header checksum "
        "on the backup, " + "/".join(chips) + ")")
    flagged = {c: collections.Counter() for c in chips}
    for c in chips:
        for addr, region, _ in results[c][0]:
            for f in chunk_flags(addr, region).split(","):
                flagged[c][f] += 1
    out("  panel-ID chunks (written last in phase 1): "
        + ", ".join(f"{c} {flagged[c]['pnid']}" for c in chips))
    out("  runtime-writer chunks ('rt', exempt in verify --allow-valid-header): "
        + ", ".join(f"{c} {flagged[c]['rt']}" for c in chips))

    out("\n=== LOG headers (index at +8, counter at +0x18) ===")
    for c in chips:
        info = results[c][1]
        for tag in ("log_old", "log_new"):
            ls = info.get(tag)
            if not ls:
                continue
            h0, h1 = ls["hdrs"]
            out(f"  {c:<7} {tag[4:]:<4} hdr0 0x{h0['idx']:x}  hdr1 0x{h1['idx']:x}  "
                f"current hdr{ls['cur']}  counter 0x{ls['ctr']:x}  "
                f"last entry 0x{ls['last']:08x}")


def write_packs(chip, entries, info, outdir, out):
    """Write the packs to .tmp names, then the manifest, then rename all."""
    os.makedirs(outdir, exist_ok=True)
    final = {k: os.path.join(outdir, f) for k, f in
             (("src", "src.bin"), ("bak", "bak.bin"), ("man", "manifest.tsv"))}
    tmp = {k: v + ".tmp" for k, v in final.items()}
    old, new = Image(info["old"]), Image(info["new"])
    hs, hb = hashlib.sha256(), hashlib.sha256()
    lines = []
    try:
        with open(tmp["src"], "wb") as fs, open(tmp["bak"], "wb") as fb:
            for i, (addr, region, phase) in enumerate(entries):
                ds, db = old.read(addr, CHUNK), new.read(addr, CHUNK)
                fs.write(ds)
                fb.write(db)
                hs.update(ds)
                hb.update(db)
                lines.append(f"{i}\t0x{addr:08x}\t0x{CHUNK:x}\t{phase}\t{region}\t"
                             f"{chunk_flags(addr, region)}\t{sha(ds)}\t{sha(db)}")
    finally:
        old.close()
        new.close()
    n1 = sum(1 for _, _, p in entries if p == 1)
    lo, ln = info["log_old"], info["log_new"]
    meta = [
        "# tcon_copyplan manifest",
        f"# version {MANIFEST_VERSION}",
        f"# chip {chip}",
        f"# created {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# chunk 0x{CHUNK:x}",
        f"# chunks {len(entries)}",
        f"# phase1 {n1}",
        f"# phase2 {len(entries) - n1}",
        f"# old {info['old']} {info['old_size']}",
        f"# new {info['new']} {info['new_size']}",
        f"# src_size {len(entries) * CHUNK}",
        f"# src_sha256 {hs.hexdigest()}",
        f"# bak_size {len(entries) * CHUNK}",
        f"# bak_sha256 {hb.hexdigest()}",
        f"# log_old hdr{lo['cur']} index 0x{lo['idx']:x} last 0x{lo['last']:08x} counter 0x{lo['ctr']:x}",
        f"# log_new hdr{ln['cur']} index 0x{ln['idx']:x} last 0x{ln['last']:08x} counter 0x{ln['ctr']:x}",
    ]
    for site, o, n, desc in info["pnid"]:
        meta.append(f"# pnid 0x{site:08x} src={pid_str(o)} bak={pid_str(n)} {desc}")
    with open(tmp["man"], "w") as f:
        f.write("\n".join(meta) + "\n" + "\t".join(MANIFEST_COLS) + "\n"
                + "\n".join(lines) + ("\n" if lines else ""))
    for k in ("src", "bak", "man"):
        os.replace(tmp[k], final[k])
    out(f"  [{chip}] {outdir}: {len(entries)} chunks, "
        f"src.bin sha256 {hs.hexdigest()[:16]}, bak.bin sha256 {hb.hexdigest()[:16]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--old", default=DEFAULT_OLD, help="old-board dump dir (default %(default)s)")
    ap.add_argument("--new", default=DEFAULT_NEW, help="new-board backup dir (default %(default)s)")
    ap.add_argument("--out", default=DEFAULT_OUT, help="pack output dir (default %(default)s)")
    ap.add_argument("--old-image", default="user_a.bin")
    ap.add_argument("--chips", default="master,slave")
    ap.add_argument("--old-pid", default=OLD_PID.decode(),
                    help="panel ID the old image must carry (default %(default)s)")
    ap.add_argument("--check-only", action="store_true",
                    help="run the checks and print the summary; write no packs")
    ap.add_argument("--force", action="store_true",
                    help="replace existing packs (never while a copy journal exists)")
    args = ap.parse_args()
    args.old_pid = args.old_pid.encode()
    chips = [c.strip() for c in args.chips.split(",") if c.strip()]

    lines = []

    def out(s=""):
        print(s, flush=True)
        lines.append(s)

    out("tcon_copyplan: offline checks")
    results, failed = {}, []
    for c in chips:
        entries, info, bad = scan_chip(c, args, out)
        results[c] = (entries, info)
        failed += bad
    summary(results, out)

    if failed:
        out(f"\nREFUSED: {len(failed)} check(s) failed; no packs written.")
        for f in failed:
            out(f"  - {f}")
        sys.exit(1)
    out("\nAll offline checks passed.")
    if args.check_only:
        out("--check-only: no packs written.")
        return

    for c in chips:
        d = os.path.join(args.out, c)
        journals = [j for j in ("journal.txt", "journal_backup.txt")
                    if os.path.exists(os.path.join(d, j))]
        if journals:
            sys.exit(f"REFUSED: {d} holds {', '.join(journals)} - a copy has "
                     f"started from these packs; they stay frozen.")
        if os.path.exists(os.path.join(d, "manifest.tsv")) and not args.force:
            sys.exit(f"REFUSED: {d}/manifest.tsv exists (use --force to replace "
                     f"packs no copy has used yet)")
    out("\nWriting packs:")
    for c in chips:
        write_packs(c, results[c][0], results[c][1], os.path.join(args.out, c), out)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "summary.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    out(f"Summary saved to {os.path.join(args.out, 'summary.txt')}")


if __name__ == "__main__":
    main()

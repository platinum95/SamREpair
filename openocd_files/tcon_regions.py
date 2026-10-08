"""
tcon_regions.py - eMMC region tables and dump-journal parsing shared by
tcon_bulkdump.py and tcon_diffdump.py.

Offsets are eMMC user-area byte addresses. Labels come from dossier sections
7 and 12 (old-board survey); boundaries of the calibration groups are
approximate and only used to annotate diff output.
"""

import os

SECTOR = 0x200
CAPACITY = 0xE9000000          # 3,909,091,328 bytes, KLM4G1FETE user area

# What tcon_bulkdump.py dumps, in this order: the small, interesting regions
# first, the bulk calibration groups next, the logs last. Every boundary is
# 64 KiB aligned.
#
#   head    FW#1/FW#2, makersheets, blobs, ISC_ST, LCC/iRUN/GCM/VRR and the
#           panel-ID records (old-board data runs through 0x050F0000)
#   bankA   16 MB A bank, panel ID at +0xFE30
#   bankB   16 MB B bank - outside 0x0-0x2FBC0000 but holds a panel-ID site
#           (0x3200FE30); old-board data 0x32000000-0x32970000
#   PFT     0x7F000000 (data at +0 and +0x300000 on the old board)
#   main    rest of 0x0-0x2FBC0000 (old board: 0x050F0000-0x18A90000 and
#           0x1BF30000-0x2FBC0000, empty 0x18A90000-0x1BF30000)
#   LOG     old-board data ends 0x93F10000; dumped to 0x94000000 for margin
DUMP_REGIONS = [
    ("head",  0x00000000, 0x05100000),
    ("bankA", 0x22000000, 0x23000000),
    ("bankB", 0x32000000, 0x33000000),
    ("PFT",   0x7F000000, 0x80000000),
    ("main",  0x05100000, 0x22000000),
    ("main2", 0x23000000, 0x2FBC0000),
    ("LOG",   0x80000000, 0x94000000),
]

# Annotation table for diff output. Contiguous from 0 to CAPACITY.
LABELS = [
    (0x00000000, 0x00000200, "FW#1 header"),
    (0x00000200, 0x00060000, "FW#1 body"),
    (0x00060000, 0x000B0000, "makersheet bank a"),
    (0x000B0000, 0x001C0000, "cfg0 blob A"),
    (0x001C0000, 0x001D0000, "gap"),
    (0x001D0000, 0x002E0000, "cfg0 blob B"),
    (0x002E0000, 0x003F0000, "cfg0 blob C"),
    (0x003F0000, 0x00500000, "cfg0 blob D"),
    (0x00500000, 0x00500200, "FW#2 header"),
    (0x00500200, 0x00560000, "FW#2 body"),
    (0x00560000, 0x005B0000, "makersheet bank b"),
    (0x005B0000, 0x006C0000, "cfg1 blob A"),
    (0x006C0000, 0x006D0000, "gap"),
    (0x006D0000, 0x007E0000, "cfg1 blob B"),
    (0x007E0000, 0x008F0000, "cfg1 blob C"),
    (0x008F0000, 0x00A00000, "cfg1 blob D"),
    (0x00A00000, 0x00FF0000, "gap"),
    (0x00FF0000, 0x02980000, "4 x ~2.9MB blocks"),
    (0x02980000, 0x03000000, "gap"),
    (0x03000000, 0x03800000, "ISC_ST copy 1"),
    (0x03800000, 0x04000000, "ISC_ST copy 2"),
    (0x04000000, 0x04400000, "gap"),
    (0x04400000, 0x04500000, "LCC"),
    (0x04500000, 0x04580000, "iRUN"),
    (0x04580000, 0x04800000, "GCM"),
    (0x04800000, 0x05000000, "VRR"),
    (0x05000000, 0x050F0000, "panel-ID records"),
    (0x050F0000, 0x0C100000, "~25 x 1.1MB blocks"),
    (0x0C100000, 0x0C310000, "gap"),
    (0x0C310000, 0x152A0000, "12 x 4.3MB blocks"),
    (0x152A0000, 0x15AF0000, "between block groups"),
    (0x15AF0000, 0x22000000, "block groups (pre bank A)"),
    (0x22000000, 0x23000000, "bank A"),
    (0x23000000, 0x2FBC0000, "block groups (post bank A)"),
    (0x2FBC0000, 0x32000000, "gap"),
    (0x32000000, 0x33000000, "bank B"),
    (0x33000000, 0x7F000000, "gap"),
    (0x7F000000, 0x80000000, "PFT"),
    (0x80000000, 0x93F10000, "LOG"),
    (0x93F10000, CAPACITY,   "gap (after LOG)"),
]

# {sector, id offset inside it, description} - same as pnidprobe.tcl
PNID_SITES = [
    (0x04400000, 0x028, "LCC"),
    (0x04500000, 0x028, "iRUN"),
    (0x04502000, 0x028, "iRUN +0x2000"),
    (0x04580000, 0x028, "GCM"),
    (0x04580200, 0x028, "GCM +0x200"),
    (0x04800000, 0x028, "VRR"),
    (0x05000800, 0x020, "0x5000000 rec +0x800"),
    (0x05000A00, 0x020, "0x5000000 rec +0xA00"),
    (0x2200FE00, 0x030, "bank A (QMC490EA02)"),
    (0x3200FE00, 0x030, "bank B (QMC490EA02)"),
]


def gap_regions():
    """Everything in the user area NOT covered by DUMP_REGIONS, as
    ("gapN", a, b). On the old board these are empty, but the replacement
    board may hold data there that the old-board map would miss."""
    holes = subtract_intervals([(0, CAPACITY)],
                               [(a, b) for _, a, b in DUMP_REGIONS])
    return [(f"gap{i}", a, b) for i, (a, b) in enumerate(holes)]


def parse_regions(spec):
    """'head,bankB' or '0x7F000000-0x7F100000' (comma separated, mixable).
    'all' = DUMP_REGIONS (the old-board data map); 'full' = the whole user
    area: DUMP_REGIONS first, then every gap (use with --skip-blank)."""
    if not spec or spec == "all":
        return list(DUMP_REGIONS)
    if spec == "full":
        return list(DUMP_REGIONS) + gap_regions()
    names = {n: (n, a, b) for n, a, b in DUMP_REGIONS + gap_regions()}
    out = []
    for item in spec.split(","):
        item = item.strip()
        if item in names:
            out.append(names[item])
        elif "-" in item:
            a, b = (int(x, 0) for x in item.split("-", 1))
            if a % SECTOR or b % SECTOR or not 0 <= a < b <= CAPACITY:
                raise ValueError(f"bad range {item}: must be 512-byte aligned, "
                                 f"inside the {CAPACITY:#x}-byte user area")
            out.append((item, a, b))
        else:
            raise ValueError(f"unknown region {item!r}; known: {', '.join(names)}")
    return out


def merge_intervals(iv):
    out = []
    for a, b in sorted(iv):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [tuple(x) for x in out]


def subtract_intervals(iv, holes):
    """iv minus holes; both lists of (a, b)."""
    out = []
    holes = merge_intervals(holes)
    for a, b in merge_intervals(iv):
        cur = a
        for ha, hb in holes:
            if hb <= cur or ha >= b:
                continue
            if ha > cur:
                out.append((cur, ha))
            cur = max(cur, hb)
        if cur < b:
            out.append((cur, b))
    return out


def load_journal(dirpath):
    """
    Read <dirpath>/journal.txt and bad_sectors.txt written by tcon_bulkdump.py.

    Journal lines:  D addr len          data transferred
                    U addr len fill     uniform chunk, filled with 'fill' word
                    B addr len nbad     some sectors unreadable (bad_sectors.txt)
                    X addr len          invalidated (SWD check failed later)
    Returns (covered intervals, bad sector list).
    """
    covered = []
    jpath = os.path.join(dirpath, "journal.txt")
    if os.path.exists(jpath):
        with open(jpath) as f:
            for line in f:
                p = line.split()
                if not p or p[0].startswith("#"):
                    continue
                kind, a, n = p[0], int(p[1], 0), int(p[2], 0)
                if kind in ("D", "U", "B"):
                    covered.append((a, a + n))
                elif kind == "X":
                    covered = subtract_intervals(covered, [(a, a + n)])
                covered = merge_intervals(covered) if len(covered) > 4096 else covered
    bad = []
    bpath = os.path.join(dirpath, "bad_sectors.txt")
    if os.path.exists(bpath):
        with open(bpath) as f:
            for line in f:
                p = line.split()
                if p and not p[0].startswith("#"):
                    bad.append(int(p[0], 0))
    return merge_intervals(covered), sorted(set(bad))


def label_segments(a, b):
    """Split [a, b) at LABELS boundaries -> [(a, b, label), ...]."""
    out = []
    for la, lb, name in LABELS:
        s, e = max(a, la), min(b, lb)
        if s < e:
            out.append((s, e, name))
    return out

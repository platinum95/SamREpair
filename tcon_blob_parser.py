#!/usr/bin/env python3
"""
Samsung Odyssey G9 T-CON -- config-blob record parser

Parses the "AP_*" named sub-blob manifest table (reverse-engineered from
running.bin) and scans a config blob's record area, inside your eMMC dump,
for named records such as AP_ISC4.1 / AP_SA_ISC4.3 (candidate demura /
calibration tables) and AP_EXCO.

--------------------------------------------------------------------------
IMPORTANT CORRECTION vs. the earlier chat analysis
--------------------------------------------------------------------------
The manifest-driven record loader (FUN_00038C6C -> FUN_000028D0 ->
FUN_0000297A) resolves blob addresses using the SAME address function used
by the "B/C/D" validator (FUN_000037DC), i.e. {0x1D0000, 0x2E0000, 0x3F0000}
for cfg0 / +0x500000 for cfg1. That means the AP_ISC4.1 / AP_EXCO / etc.
records live inside blob B/C/D -- the GENERIC, triple-redundant blob group
that you already confirmed is byte-identical between your original board
and an unrelated replacement.

That means these specific records are almost certainly NOT your per-panel
demura data (identical content across two different physical panels can't
encode panel-specific correction). Blob A (0x0B0000 / 0x5B0000) is the one
validated alone (FUN_000037C4) and the one that actually differs between
boards -- it's still the best candidate for genuinely panel-specific data,
but I have NOT confirmed it uses this same named-record format (only one
code path into the record loader was traced, and it only ever resolves to
B/C/D addresses).

Recommended use of this script:
  1. Run `scan --bank B` (or C/D) first -- you should get hits for
     AP_ISC4.1 / AP_SA_ISC4.3 / AP_EXCO etc. This is just a sanity check
     that the parsing logic is right, on data known to be generic.
  2. Run `scan --bank A` -- if it also finds named records, great, you can
     directly diff blob A's per-name payloads against the generic B copy
     to isolate what's actually panel-specific. If it finds nothing, blob
     A uses a different internal layout and needs fresh RE work (start by
     hex-diffing blob A between your two boards' dumps -- the byte ranges
     that differ are your panel-specific data, regardless of format).

--------------------------------------------------------------------------
Reverse-engineering notes (from Ghidra analysis of running.bin)
--------------------------------------------------------------------------
Manifest table:  ITCM 0x0003A704, 16 entries x 0x1C (28) bytes:
    +0x00  u32  name string pointer (into ITCM rodata)
    +0x04  u32  RAM destination address, region 1
    +0x08  u32  max size (bytes), region 1
    +0x0C  u32  RAM destination address, region 2
    +0x10  u32  max size (bytes), region 2
    +0x14  8 bytes  not fully decoded (looks like a couple of u16 IDs)

Decoded manifest entries of interest (name -> dest1/size1, dest2/size2):
    AP_ISC4.1     0x2000E07E /  220B    0x2000E15A / 7038B
    AP_SA_ISC4.3  0x2024A4A6 /  512B    0x20240000 / 42150B
    AP_EXCO       0x2000C058 /  558B    0x20207B60 / 4608B

Blob layout (per handoff doc + FUN_00004EAC / FUN_00004F98):
    blob = 0x200-byte header + 0x10FE00-byte payload
    payload = array of up to (0x10FE00 / 0x200) = 2174 records
    each record on-disk is 512 (0x200) bytes; only the first 0x1B8
    (440) bytes are meaningful (per FUN_00004AEC)
    record byte 0x00-0x0F (16 bytes) = NUL-terminated ASCII name,
    matched via strcmp (FUN_00000510) against the manifest table

The exact byte offsets of the "source eMMC address" / "length" fields
*within* a record (beyond the 16-byte name) were NOT confirmed against
disassembly of FUN_00003E14's stack-argument layout -- treat those as
unknown. This script surfaces the raw record bytes plus a search for the
manifest's already-known size values (e.g. 7038, 42150, 4608) so you can
pin down those fields empirically by inspection.

--------------------------------------------------------------------------
Usage
--------------------------------------------------------------------------
  # Dump the manifest table straight from the firmware image (ground truth,
  # doesn't need your eMMC dump):
  python3 tcon_blob_parser.py manifest running.bin

  # Scan a blob bank in your eMMC dump for named AP_* records:
  python3 tcon_blob_parser.py scan emmc_dump.bin --cfg 0 --bank B

  # Same, but dump the full 512-byte hex of every match:
  python3 tcon_blob_parser.py scan emmc_dump.bin --cfg 0 --bank A -v

  # Once you've located a source offset by hand, pull the raw bytes out:
  python3 tcon_blob_parser.py extract emmc_dump.bin 0x1D0200 0x1B8 --out record.bin
"""

import argparse
import struct

MANIFEST_TABLE_ADDR = 0x0003A704
MANIFEST_ENTRY_SIZE = 0x1C
MANIFEST_ENTRY_COUNT = 16

RECORD_SIZE_ON_DISK = 0x200      # 512 bytes per record slot in eMMC
RECORD_USEFUL_BYTES = 0x1B8      # 440 bytes actually copied out by firmware
RECORD_NAME_LEN = 16             # first 16 bytes = NUL-terminated name

BLOB_HEADER_SIZE = 0x200
BLOB_PAYLOAD_SIZE = 0x10FE00
BLOB_TOTAL_SIZE = BLOB_HEADER_SIZE + BLOB_PAYLOAD_SIZE   # 0x110000
MAX_RECORDS = BLOB_PAYLOAD_SIZE // RECORD_SIZE_ON_DISK   # 2174

# eMMC layout from the handoff doc
CFG0_BLOBS = {"A": 0x0B0000, "B": 0x1D0000, "C": 0x2E0000, "D": 0x3F0000}
CFG1_BLOBS = {"A": 0x5B0000, "B": 0x6D0000, "C": 0x7E0000, "D": 0x8F0000}

# Known manifest entries decoded by hand from running.bin (used as a
# cross-check / fallback even without --firmware)
KNOWN_MANIFEST = {
    "AP_ISC4.1":    dict(dest1=0x2000E07E, size1=220,   dest2=0x2000E15A, size2=7038),
    "AP_SA_ISC4.3": dict(dest1=0x2024A4A6, size1=512,   dest2=0x20240000, size2=42150),
    "AP_EXCO":      dict(dest1=0x2000C058, size1=558,   dest2=0x20207B60, size2=4608),
}


def read_cstr(data: bytes, offset: int, maxlen: int) -> str:
    chunk = data[offset:offset + maxlen]
    nul = chunk.find(b"\x00")
    if nul != -1:
        chunk = chunk[:nul]
    try:
        return chunk.decode("ascii")
    except UnicodeDecodeError:
        return ""


def is_probable_name(raw16: bytes) -> bool:
    """Heuristic: looks like 'AP_XXXX\\0...\\0' -- printable prefix, a NUL,
    then only NUL padding to the end of the 16-byte field."""
    nul = raw16.find(b"\x00")
    if nul <= 0:
        return False
    prefix = raw16[:nul]
    if not all(32 <= b < 127 for b in prefix):
        return False
    return all(b == 0 for b in raw16[nul:])


def parse_manifest_table(fw_data: bytes, base_addr: int = 0):
    """Parse the 16-entry AP_* manifest table out of a firmware image
    (running.bin), where fw_data[0] corresponds to ITCM address
    `base_addr` (normally 0)."""
    entries = []
    table_off = MANIFEST_TABLE_ADDR - base_addr
    for i in range(MANIFEST_ENTRY_COUNT):
        off = table_off + i * MANIFEST_ENTRY_SIZE
        raw = fw_data[off:off + MANIFEST_ENTRY_SIZE]
        if len(raw) < MANIFEST_ENTRY_SIZE:
            break
        tag_ptr, dest1, size1, dest2, size2 = struct.unpack_from("<IIIII", raw, 0)
        tail = raw[0x14:0x1C]
        name_off = tag_ptr - base_addr
        name = (read_cstr(fw_data, name_off, 32)
                if 0 <= name_off < len(fw_data) else "<out of range>")
        entries.append(dict(
            index=i, name=name, tag_ptr=tag_ptr,
            dest1=dest1, size1=size1, dest2=dest2, size2=size2,
            tail=tail.hex(),
        ))
    return entries


def decode_type7(rec: bytes):
    """Decode a type-7 record (confirmed field layout, cross-checked against
    real EXCO_LUT1_S0 / LUT2 / LUT3 / 05_ISC_0 / EXCO_PARA1 bytes):

        +0x24  u32  base_addr   -- eMMC base address for this record's data
        +0xF0  u32  chunk_count -- 0 if this record uses the single-blob
                                    path (FUN_00003B54) instead of the
                                    chunked path
        +0xF4  chunk_count x u32  source offsets, added to base_addr
        +0x134 chunk_count x u32  destination RAM offsets
        +0x174 chunk_count x u32  chunk lengths (bytes)

    When chunk_count == 0, this script does not yet decode the single-blob
    (FUN_00003B54) path -- +0x28/+0x2C looked like a flag/size pair on
    EXCO_PARA1 but that's unconfirmed, so it's surfaced as raw hex only.
    """
    if len(rec) < 0x28:
        return None
    base_addr = struct.unpack_from("<I", rec, 0x24)[0]
    count = struct.unpack_from("<I", rec, 0xF0)[0]
    result = dict(base_addr=base_addr, count=count, chunks=[])
    if count == 0:
        return result
    src_end, dst_end, len_end = 0xF4 + count * 4, 0x134 + count * 4, 0x174 + count * 4
    if max(src_end, dst_end, len_end) > len(rec):
        result["count"] = 0
        result["note"] = "declared chunk_count overruns the 0x1B8-byte record -- not decoded"
        return result
    src_offs = struct.unpack_from(f"<{count}I", rec, 0xF4)
    dst_offs = struct.unpack_from(f"<{count}I", rec, 0x134)
    lens = struct.unpack_from(f"<{count}I", rec, 0x174)
    for i in range(count):
        result["chunks"].append(dict(
            eMMC_addr=base_addr + src_offs[i], dest_ram_offset=dst_offs[i], length=lens[i]))
    return result


def scan_blob_records(emmc_data: bytes, blob_base: int, max_records: int = MAX_RECORDS):
    """Walk every 512-byte record slot in a blob's payload and yield the
    ones that look like a named 'AP_*' / other record."""
    payload_base = blob_base + BLOB_HEADER_SIZE
    found = []
    for idx in range(max_records):
        rec_off = payload_base + idx * RECORD_SIZE_ON_DISK
        rec = emmc_data[rec_off:rec_off + RECORD_USEFUL_BYTES]
        if len(rec) < RECORD_USEFUL_BYTES:
            break
        name16 = rec[0:RECORD_NAME_LEN]
        if not is_probable_name(name16):
            continue
        name = read_cstr(rec, 0, RECORD_NAME_LEN)
        rtype = struct.unpack_from("<I", rec, 0x20)[0] if len(rec) >= 0x24 else None
        entry = dict(index=idx, eMMC_offset=rec_off, name=name, type=rtype, raw=rec)
        if rtype == 7:
            entry["type7"] = decode_type7(rec)
        found.append(entry)
    return found


def search_size_hint(rec: bytes, size_values):
    """Search a record's raw bytes for any of the given known sizes, as a
    little-endian u32 or u16, to help locate the length field by hand."""
    hits = []
    for val in size_values:
        for width, fmt in ((4, "<I"), (2, "<H")):
            needle = struct.pack(fmt, val)
            start = 0
            while True:
                pos = rec.find(needle, start)
                if pos == -1:
                    break
                hits.append((val, width, pos))
                start = pos + 1
    return hits


def hexdump(data: bytes, base_addr: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base_addr + i:08X}  {hexpart:<{width * 3}}  {asciipart}")
    return "\n".join(lines)


def cmd_manifest(args):
    with open(args.firmware, "rb") as f:
        fw_data = f.read()
    entries = parse_manifest_table(fw_data, args.fw_base)
    print(f"{'idx':<4} {'name':<16} {'tag_ptr':<10} {'dest1':<10} {'size1':<8} "
          f"{'dest2':<10} {'size2':<8} tail")
    for e in entries:
        print(f"{e['index']:<4} {e['name']:<16} 0x{e['tag_ptr']:08X} "
              f"0x{e['dest1']:08X} {e['size1']:<8} "
              f"0x{e['dest2']:08X} {e['size2']:<8} {e['tail']}")


def cmd_scan(args):
    with open(args.emmc, "rb") as f:
        emmc_data = f.read()

    blob_map = CFG0_BLOBS if args.cfg == 0 else CFG1_BLOBS
    blob_base = args.blob_base if args.blob_base is not None else blob_map[args.bank]

    print(f"Scanning cfg{args.cfg} blob {args.bank} at eMMC 0x{blob_base:06X} "
          f"(payload starts 0x{blob_base + BLOB_HEADER_SIZE:06X}) ...")
    if args.bank == "A":
        print("  [note] blob A is the one NOT confirmed to use this record "
              "format -- it's still the best candidate for genuinely "
              "panel-specific data, so a scan finding nothing here is a "
              "real (informative) possible outcome, not necessarily a bug.")

    if blob_base + BLOB_TOTAL_SIZE > len(emmc_data):
        print(f"  [!] dump is only {len(emmc_data)} (0x{len(emmc_data):X}) bytes -- "
              f"this blob needs up to 0x{blob_base + BLOB_TOTAL_SIZE:X}. "
              f"Results may be truncated / incomplete.")

    found = scan_blob_records(emmc_data, blob_base)
    if not found:
        print("  No named records found in the scanned range.")
        return

    print(f"  Found {len(found)} named record(s).")
    for rec in found:
        print(f"\n--- record #{rec['index']}  eMMC offset 0x{rec['eMMC_offset']:06X}  "
              f"name='{rec['name']}'  type={rec['type']}")
        if rec["type"] == 7 and rec.get("type7"):
            t7 = rec["type7"]
            print(f"    base_addr=0x{t7['base_addr']:08X}  chunk_count={t7['count']}")
            if t7.get("note"):
                print(f"    [!] {t7['note']}")
            for i, c in enumerate(t7["chunks"]):
                print(f"      chunk {i}: eMMC 0x{c['eMMC_addr']:08X}  "
                      f"-> RAM +0x{c['dest_ram_offset']:04X}  len {c['length']}")
            if t7["chunks"]:
                lo = min(c["eMMC_addr"] for c in t7["chunks"])
                hi = max(c["eMMC_addr"] + c["length"] for c in t7["chunks"])
                print(f"      span: eMMC 0x{lo:08X} - 0x{hi:08X}  ({hi - lo} bytes) "
                      f"-- likely outside your dump if this dump is < ~1.5GB")
        manifest = KNOWN_MANIFEST.get(rec["name"])
        if manifest:
            sizes = [manifest["size1"], manifest["size2"]]
            print(f"    manifest says: dest1=0x{manifest['dest1']:08X} size1={manifest['size1']}"
                  f"   dest2=0x{manifest['dest2']:08X} size2={manifest['size2']}")
            hits = search_size_hint(rec["raw"], sizes)
            if hits:
                print("    size-value hits inside this record (candidate length fields):")
                for val, width, pos in hits:
                    print(f"      value {val} as {'u32' if width == 4 else 'u16'} "
                          f"at record offset 0x{pos:02X}")
            else:
                print("    (none of the known sizes appear verbatim -- the length "
                      "field may be encoded differently, e.g. in 512-byte sectors "
                      "rather than bytes, or this record's regions weren't the "
                      "ones actually used)")
        if args.verbose:
            print(hexdump(rec["raw"], base_addr=0))


def cmd_extract(args):
    """Dump raw eMMC bytes at an arbitrary offset/length -- e.g. once you've
    located a record's embedded source address by hand, use this to pull
    out the actual bulk payload for inspection."""
    with open(args.emmc, "rb") as f:
        f.seek(args.offset)
        data = f.read(args.length)
    if args.out:
        with open(args.out, "wb") as f:
            f.write(data)
        print(f"Wrote {len(data)} bytes from 0x{args.offset:X} to {args.out}")
    else:
        print(hexdump(data, base_addr=args.offset))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("manifest", help="Dump the AP_* manifest table from a firmware image")
    p1.add_argument("firmware", help="path to running.bin (or equivalent ITCM dump)")
    p1.add_argument("--fw-base", type=lambda x: int(x, 0), default=0,
                     help="ITCM address that firmware[0] corresponds to (default 0)")
    p1.set_defaults(func=cmd_manifest)

    p2 = sub.add_parser("scan", help="Scan a config blob's records for named AP_* entries")
    p2.add_argument("emmc", help="path to the eMMC dump")
    p2.add_argument("--cfg", type=int, choices=[0, 1], default=0,
                     help="cfg0 (master, default) or cfg1 (slave)")
    p2.add_argument("--bank", choices=["A", "B", "C", "D"], default="A",
                     help="which blob bank to scan (default A -- the "
                          "panel-specific one; try B/C/D first as a sanity "
                          "check, see script docstring)")
    p2.add_argument("--blob-base", type=lambda x: int(x, 0), default=None,
                     help="override: explicit eMMC byte offset of the blob header")
    p2.add_argument("-v", "--verbose", action="store_true",
                     help="print full hex dump of every matched record")
    p2.set_defaults(func=cmd_scan)

    p3 = sub.add_parser("extract", help="Dump raw bytes from the eMMC image at a given offset")
    p3.add_argument("emmc", help="path to the eMMC dump")
    p3.add_argument("offset", type=lambda x: int(x, 0), help="byte offset (e.g. 0x1D0200)")
    p3.add_argument("length", type=lambda x: int(x, 0), help="number of bytes to dump/extract")
    p3.add_argument("--out", help="write raw bytes to this file instead of hex-dumping")
    p3.set_defaults(func=cmd_extract)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

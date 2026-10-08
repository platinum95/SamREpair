#!/usr/bin/env python3
"""
tcon_fixheader.py - restore a blanked FW#1 header (eMMC 0x0) from FW#2's
header (eMMC 0x500000) on both SoCs: the verified procedure from dossier
section 5, driven over the TCL RPC ports, with extra checks.

THIS WRITES TO THE eMMC: one 512-byte sector at 0x0 per SoC, and only with
--write plus a typed confirmation. Without --write it is a dry run: it does
every check and reports what it would write.

It refuses to write on ANY chip unless, on EVERY chip:
  - FW#1 header is all zeros (the blanked state) - or already identical to
    FW#2's, in which case that chip is skipped;
  - FW#2 header has the Apr-2023 magic, type (+0x1F8), checksum (+0x1FC) and
    version string;
  - FW#1 body == FW#2 body over 0x200+0x60000 (so FW#2's header, checksum
    included, is valid for FW#1's body);
  - FW#1 body == running.bin over the loaded range 0x0-0x3C800.

Getting both SoCs to the post-scan halt (0x29C2), --entry:
  loop   (default) the dossier's proven method for a blanked board: per chip,
         tcon_halt_at_scan waits for the firmware's own boot loop to reach
         the scan breakpoint. No blanking guard during entry: the header is
         already blank, so a blanking pass writes zeros over zeros.
  reset  the dump driver's prepare path (halt + guards, reset_to_scan).
  none   both are already halted at 0x29C2 / 0x414 (e.g. after `prepare`).

Afterwards both SoCs are left HALTED. Power cycle at the wall; do not resume.
Expect on the UART: "BL1 EMMC FW#1 core0,1" and "FW 0, CFG/MS 0".

Pre-write copies of both headers are saved to <out>/<chip>/ for the record.
"""

import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tcon_bulkdump as drv  # noqa: E402

FIX_TCL = "tconfix.tcl"
FW1_BODY = 0x200
FW2_BODY = 0x500200
BODY_LEN = 0x60000
DEFAULT_OUT = os.path.normpath(os.path.join(HERE, "..", "emmc_dumps",
                                            "emmc_dumps", "header_fix"))


def source_fix(rpc, files_dir):
    path = os.path.join(files_dir, FIX_TCL)
    if not os.path.exists(path):
        raise drv.TconError(f"missing {path}")
    rc = rpc.bare("catch {source {%s}} __e__" % path)
    if rc.strip() != "0":
        raise drv.TconError(f"{rpc.name}: source {FIX_TCL} failed: "
                            f"{rpc.bare('set __e__')}")
    if "tcon_fix_header_write" not in rpc.rpc("info commands tcon_fix_header_write"):
        raise drv.TconError(f"{rpc.name}: {FIX_TCL} did not define its procs")


def enter(conns, chips, entry):
    if entry == "none":
        return
    if entry == "loop":
        # proven in dossier section 5 on a blank-looping board. Guards left in
        # the FPB by an earlier session (they survive OpenOCD restarts, not
        # power cycles) would stop the loop at 0x640C instead of the scan
        # point; on an already-blank header they protect nothing, so clear
        # them first. tcon_bulk_begin re-arms all of them once halted.
        # A SoC that is already halted was stopped by an earlier session:
        # resuming it from wherever it sits is not the boot loop. Refuse.
        for c in chips:
            st = conns[c].rpc("tcon_bulk_curstate")
            if st == "halted":
                raise drv.TconError(
                    f"{c} is already halted (an earlier session?). --entry loop "
                    f"needs both SoCs running their boot loop: power cycle "
                    f"first, or use --entry none if both are halted at "
                    f"0x29c2 / 0x414 ('tcon_bulkdump.py state' shows pc)")
        for c in chips:
            conns[c].rpc("halt")
            for g in ("0x0000640C", "0x00006C8C", "0x00006D50"):
                conns[c].rpc(f"tcon_rbp_quiet {g}")
            print(f"[{c}] waiting for the boot loop to reach the scan point ...")
            conns[c].rpc("tcon_halt_at_scan", timeout=90)
            print(f"[{c}] halted at 0x29c2")
    elif entry == "reset":
        for c in chips:
            print(f"[{c}] halt+guard: {conns[c].rpc('tcon_bulk_halt_and_guard')}")
        for c in chips:
            print(f"[{c}] reset_to_scan: "
                  f"{conns[c].rpc('tcon_bulk_reset_to_scan', timeout=90)}")


def read_region(rpc, chip, addr, length, tmp):
    """Bulk-read [addr, addr+length) via the staging buffer -> bytes."""
    out = os.path.join(tmp, f"fix_{chip}.bin")
    data = bytearray()
    for off in range(0, length, drv.CHUNK):
        n = min(drv.CHUNK, length - off)
        r = rpc.rpc(f"tcon_bulk_read 0x{addr + off:08x} 0x{n:x} 0x0")
        if not drv.read_ok(r):
            raise drv.TconError(f"{chip}: read 0x{addr + off:08x} failed ({r})")
        rpc.rpc(f"tcon_bulk_dump {{{out}}} 0x{n:x} 0x{drv.STAGE:08x}")
        with open(out, "rb") as f:
            data += f.read()
    try:
        os.remove(out)
    except OSError:
        pass
    return bytes(data)


def check_chip(rpc, chip, fw, tmp, outdir):
    """All checks for one chip. Returns (state, problems)."""
    problems = []
    rpc.rpc(f"tcon_bulk_begin 0x{drv.STAGE:08x} 0x{drv.CHUNK:x}")

    print(f"[{chip}] reading FW#1 and FW#2 bodies ...")
    b1 = read_region(rpc, chip, FW1_BODY, BODY_LEN, tmp)
    b2 = read_region(rpc, chip, FW2_BODY, BODY_LEN, tmp)
    if b1 != b2:
        n = sum(x != y for x, y in zip(b1, b2))
        problems.append(f"FW#1 body != FW#2 body ({n} bytes differ)")
    if b1[:drv.FW_LOADED_END] != fw[:drv.FW_LOADED_END]:
        problems.append("FW#1 body != running.bin over 0x0-0x3C800")

    st = rpc.rpc("tcon_fix_header_check")
    print(f"[{chip}] headers: {st}")
    d = dict(t.split("=", 1) for t in st.split() if "=" in t)
    if d.get("fw2") != "ok":
        problems.append(f"FW#2 header not as expected ({d.get('fw2')})")
    if d.get("fw1") == "other":
        problems.append("FW#1 header is neither blank nor FW#2's - inspect it")

    # record both headers as read, before any write
    os.makedirs(os.path.join(outdir, chip), exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for name, addr in (("fw1_header", drv.STAGE + 0x200),
                       ("fw2_header", drv.STAGE)):
        path = os.path.join(outdir, chip, f"{name}_{stamp}.bin")
        rpc.rpc(f"tcon_bulk_dump {{{path}}} 0x200 0x{addr:08x}")
    return d.get("fw1"), problems


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    drv.add_common(ap)
    ap.add_argument("--entry", choices=["loop", "reset", "none"], default="loop",
                    help="how to reach the post-scan halt (default: loop)")
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help="where pre-write header copies go (default %(default)s)")
    ap.add_argument("--write", action="store_true",
                    help="actually write (default: dry run)")
    ap.add_argument("--yes", action="store_true",
                    help="skip the typed confirmation (tests only)")
    args = ap.parse_args()

    with open(drv.RUNNING_BIN, "rb") as f:
        fw = f.read()
    tmp = drv.ensure_tmp(args.tmp)
    outdir = os.path.abspath(args.out)

    conns = drv.connect_all(args.chips, args.files, speed=args.speed)
    try:
        for c in args.chips:
            source_fix(conns[c], args.files)
        enter(conns, args.chips, args.entry)

        states, bad = {}, {}
        for c in args.chips:
            states[c], bad[c] = check_chip(conns[c], c, fw, tmp, outdir)

        print()
        for c in args.chips:
            verdict = ("already restored - skip" if states[c] == "same"
                       else "needs restore" if states[c] == "zero" else "?")
            print(f"[{c}] {verdict}" + ("" if not bad[c]
                                        else "; PROBLEMS: " + "; ".join(bad[c])))
        if any(bad.values()):
            print("\nRefusing to write on any chip. Both SoCs left halted: power "
                  "cycle at the wall, do not resume.")
            sys.exit(1)

        todo = [c for c in args.chips if states[c] == "zero"]
        if not todo:
            print("\nNothing to write. Both SoCs left halted: power cycle at the "
                  "wall, do not resume.")
            return
        if not args.write:
            print(f"\nDRY RUN: would write FW#2's header to eMMC 0x0 on: "
                  f"{', '.join(todo)}. Re-run with --write to do it (the SoCs "
                  f"are halted at the scan point; --entry none reuses that).")
            return

        if not args.yes:
            ans = input(f"\nWrite FW#2's header over eMMC 0x0 on "
                        f"{', '.join(todo)}? Type WRITE to confirm: ")
            if ans.strip() != "WRITE":
                print("Not confirmed; nothing written. Both SoCs left halted.")
                return

        for c in todo:
            r = conns[c].rpc("tcon_fix_header_write", timeout=90)
            print(f"[{c}] {r}")
            if "REARM-FAILED" in r:
                print(f"[{c}] WARNING: write guards could not be re-armed. "
                      f"The write itself verified; do not do anything else on "
                      f"this SoC before power cycling.")
        print("\nHeader restored and verified on: " + ", ".join(todo))
        print("Both SoCs left HALTED. Power cycle at the wall now; do NOT resume.")
        print('Expect on the UART: "BL1 EMMC FW#1 core0,1" and "FW 0, CFG/MS 0".')
    except drv.TconError as e:
        print(f"\nTCONERR: {e}", file=sys.stderr)
        drv.emergency_stop(conns, args.chips)
        sys.exit(2)
    finally:
        for c in conns.values():
            c.close()


if __name__ == "__main__":
    main()

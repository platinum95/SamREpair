#!/usr/bin/env python3
"""
test_sim.py - end-to-end test of tconbulk.tcl and tcon_bulkdump.py against a
SIMULATED target, no hardware.

It launches two headless OpenOCD instances (the bundled binary) with
`adapter driver dummy`, each sourcing sim_target.tcl (which shadows the target
primitives with Tcl procs and models a fake eMMC/ITCM/FPB) followed by the four
real .tcl files.

The simulator runs on its OWN ports (TCL RPC 16666 / 16667, via the driver's
TCON_RPC_PORTS override), never the real 6666 / 6667. It refuses to start if
those ports are already in use, and refuses to run any check against an
instance that doesn't have sim_target.tcl loaded, so it can't drive the real
board even if OpenOCD is connected to it. Then it:

  * exercises tconbulk.tcl's primitives and its failure paths directly over the
    TCL RPC port (guard missing, wait_halt timeout, sp mismatch, wrong return
    pc, blanking-guard hit on reset), and
  * runs every tcon_bulkdump.py subcommand end to end (clockcheck, prepare,
    pnid, verify, speedtest, and several dump variants: normal, skip-blank,
    bad-sector fallback, double-read mismatch abort, and a TCONERR abort),
    checking exit codes, journals and the power-cycle handling.

Standard library only. Run from the openocd_files directory:
    python3 test_sim.py
Exit status is 0 iff every check passed.
"""

import argparse
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# The simulator gets its OWN ports, never the real OpenOCD ones (6666/6667):
# set before importing the driver, and inherited by every driver subprocess.
SIM_PORTS = "master=16666,slave=16667"
os.environ["TCON_RPC_PORTS"] = SIM_PORTS

import tcon_bulkdump as drv  # noqa: E402
from tcon_regions import PNID_SITES  # noqa: E402

OPENOCD = os.path.join(HERE, "openocd")
RUNNING = os.path.join(HERE, "running.bin")
NEW_PID = b"1HNC0J270B"           # the "wrong" ID the sim board reports
EMMC_SIZE = 0x80002000            # sparse; covers the LOG tag site

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({detail})" if detail else ""))
    return ok


# ---------------------------------------------------------------------------
# build a fake eMMC backing file
# ---------------------------------------------------------------------------
FW_LOADED_END = 0x3C800           # as on the real board / the driver


def build_itcm(path):
    """Simulated live ITCM, as measured on the replacement board: running.bin
    except 0x3C800-0x40000, which BL1 never loads (random, per chip/boot)."""
    with open(RUNNING, "rb") as f:
        itcm = bytearray(f.read())
    itcm[FW_LOADED_END:0x40000] = os.urandom(0x40000 - FW_LOADED_END)
    with open(path, "wb") as f:
        f.write(itcm)


def fw2_header():
    """A FW#2 header with the fields tconfix.tcl checks (dossier section 5)."""
    h = bytearray(0x200)
    h[0:4] = bytes.fromhex("5a5aa5a5")
    h[0x40:0x47] = b"230423A"
    h[0x80:0x93] = b"04-23-2023 14:06:48"
    h[0x1F8:0x1FC] = struct.pack("<I", 0xF1000042)
    h[0x1FC:0x200] = struct.pack("<I", 0x2CD4C603)
    return bytes(h)


def build_emmc(path):
    with open(RUNNING, "rb") as f:
        running = f.read()
    with open(path, "wb") as f:
        f.truncate(EMMC_SIZE)
        # FW#1 body: running.bin over the loaded range only; past 0x3C800 the
        # real eMMC image differs from running.bin, so the sim does too.
        # FW#2 body is identical to FW#1's (as on the real boards). FW#1's
        # header is left blank (zeros); FW#2's is the Apr-2023 header.
        body = running[:FW_LOADED_END] + os.urandom(len(running) - FW_LOADED_END)
        f.seek(0x200)
        f.write(body)
        f.seek(0x500000)
        f.write(fw2_header())
        f.write(body)
        for sector, off, _desc in PNID_SITES:   # panel-ID at every site
            f.seek(sector + off)
            f.write(NEW_PID)
        f.seek(0x7F000004)
        f.write(b"PFT\0")
        f.seek(0x80000004)
        f.write(b"LOG\0")
        # a non-blank marker at the verify[2] site
        f.seek(0x04400000)
        f.write(b"LCC\0" + struct.pack("<I", 0x12345678))


# ---------------------------------------------------------------------------
# launch / stop OpenOCD
# ---------------------------------------------------------------------------
def wait_port(port, timeout=15.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def port_in_use(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0):
            return True
    except OSError:
        return False


def is_simulator(port):
    """True only if the instance on `port` has sim_target.tcl loaded."""
    try:
        r = drv.Rpc("probe", port, timeout=5)
    except OSError:
        return False
    try:
        return r.bare("info commands sim_do_read", timeout=5) == "sim_do_read"
    except Exception:  # noqa: BLE001
        return False
    finally:
        r.close()


def write_cfg(chip, port, emmc, faultfile, outdir):
    """Write the per-instance OpenOCD config that loads the sim + real .tcl."""
    cfg = f"""
adapter driver dummy
set ::SIM_EMMC {{{emmc}}}
set ::SIM_RUNNING {{{os.path.join(outdir, 'itcm_sim.bin')}}}
set ::SIM_FAULT_FILE {{{faultfile}}}
gdb_port disabled
telnet_port disabled
tcl_port {port}
bindto 127.0.0.1
source {{{os.path.join(HERE, 'sim_target.tcl')}}}
source {{{os.path.join(HERE, 'tconutils.tcl')}}}
source {{{os.path.join(HERE, 'tcondump.tcl')}}}
source {{{os.path.join(HERE, 'pnidprobe.tcl')}}}
source {{{os.path.join(HERE, 'tconbulk.tcl')}}}
init
"""
    cfgpath = os.path.join(outdir, f"sim_{chip}.cfg")
    with open(cfgpath, "w") as f:
        f.write(cfg)
    return cfgpath


def launch(chip, port, emmc, faultfile, logf):
    cfgpath = write_cfg(chip, port, emmc, faultfile, os.path.dirname(faultfile))
    lf = open(logf, "w")
    p = subprocess.Popen([OPENOCD, "-f", cfgpath], stdout=lf, stderr=lf)
    return p, lf


def setup_files(work):
    """Build eMMC images, empty fault files and OpenOCD configs for both chips
    into `work`. Returns the list of fault-file paths (master, slave)."""
    faultfiles = []
    build_itcm(os.path.join(work, "itcm_sim.bin"))
    for chip, port in drv.CHIPS.items():
        emmc = os.path.join(work, f"emmc_{chip}.bin")
        build_emmc(emmc)
        ff = os.path.join(work, f"fault_{chip}.txt")
        open(ff, "w").close()
        faultfiles.append(ff)
        write_cfg(chip, port, emmc, ff, work)
    return faultfiles


# ---------------------------------------------------------------------------
# driver subprocess
# ---------------------------------------------------------------------------
def run_driver(args, tmp):
    cmd = [sys.executable, os.path.join(HERE, "tcon_bulkdump.py")] + args \
        + ["--tmp", tmp]
    r = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True,
                       timeout=300)
    return r.returncode, r.stdout + r.stderr


def set_fault(faultfiles, text):
    for ff in faultfiles:
        with open(ff, "w") as f:
            f.write(text)


def read_journal(chipdir):
    p = os.path.join(chipdir, "journal.txt")
    if not os.path.exists(p):
        return []
    with open(p) as f:
        return [ln.split() for ln in f if ln.strip()
                and not ln.startswith("#")]


# ---------------------------------------------------------------------------
# tcl-level checks (direct RPC into the sim)
# ---------------------------------------------------------------------------
def expect_ok(rpc, cmd):
    try:
        return True, rpc.rpc(cmd, timeout=20)
    except drv.TconError as e:
        return False, str(e)


def expect_err(rpc, cmd, substr):
    try:
        out = rpc.rpc(cmd, timeout=20)
        return False, f"expected error, got TCONOK {out}"
    except drv.TconError as e:
        return (substr in str(e)), str(e)


def recover(rpc):
    """Get the sim back to an armed bulk session after a failure test."""
    rpc.rpc("halt", timeout=20)
    rpc.rpc("tcon_bulk_reset_to_scan", timeout=20)
    rpc.rpc(f"tcon_bulk_begin 0x{drv.STAGE:08x} 0x{drv.CHUNK:x}", timeout=20)


def tcl_level_tests(faultfiles):
    print("\n== tcl-level tconbulk.tcl checks ==")
    m = drv.Rpc("master", drv.CHIPS["master"])
    try:
        set_fault(faultfiles, "")
        ok, d = expect_ok(m, "tcon_bulk_halt_and_guard")
        check("halt_and_guard reports guards ok", ok and "guards=ok" in d, d)

        ok, d = expect_ok(m, "tcon_bulk_reset_to_scan")
        check("reset_to_scan lands at 0x29c2", ok and "pc=0x000029c2" in d, d)

        ok, d = expect_ok(m, f"tcon_bulk_begin 0x{drv.STAGE:08x} 0x{drv.CHUNK:x}")
        check("begin starts a session", ok and "stage=0x20220000" in d, d)

        ok, d = expect_ok(m, "tcon_bulk_read 0x200 0x1000 0x0")
        good = ok and drv.read_ok(d)
        check("bulk_read good read (rc=0, canary=0)", good, d)

        ok, d = expect_ok(m, "tcon_bulk_uniform_selftest")
        want = ("zero=1" in d and "last=0" in d and "ff=1" in d and "mid=0" in d)
        check("uniform self-test", ok and want, d)

        ok, d = expect_ok(m, "tcon_bulk_uniform 0x1000 0x0")
        check("uniform: intact helper reports hr=0", ok and "hr=0" in d, d)
        m.rpc("write_memory 0x2021C000 16 {0 0 0 0}")
        ok, d = expect_ok(m, "tcon_bulk_uniform 0x1000 0x0")
        check("uniform: clobbered helper is rewritten (hr=1)",
              ok and "hr=1" in d, d)
        ok, d = expect_ok(m, "tcon_bulk_uniform 0x1000 0x0")
        check("uniform: helper intact again afterwards", ok and "hr=0" in d, d)

        # failure: a guard dropped from the FPB
        m.rpc("rbp 0x640C")
        ok, d = expect_err(m, "tcon_bulk_read 0x200 0x1000 0x0", "missing")
        check("bulk_read refuses with a guard missing", ok, d)
        recover(m)

        # failure: wait_halt timeout
        set_fault(faultfiles, "timeout")
        ok, d = expect_err(m, "tcon_bulk_read 0x200 0x1000 0x0", "timed out")
        check("bulk_read reports a call timeout", ok, d)
        set_fault(faultfiles, "")
        recover(m)

        # failure: sp changed across the call
        set_fault(faultfiles, "spmismatch")
        ok, d = expect_err(m, "tcon_bulk_read 0x200 0x1000 0x0", "sp")
        check("bulk_read catches an sp mismatch", ok, d)
        set_fault(faultfiles, "")
        recover(m)

        # failure: returned to the wrong pc
        set_fault(faultfiles, "badpc")
        ok, d = expect_err(m, "tcon_bulk_read 0x200 0x1000 0x0", "return trap")
        check("bulk_read catches a wrong return pc", ok, d)
        set_fault(faultfiles, "")
        recover(m)

        # failure: a reset that reaches the blanking routine halts there
        set_fault(faultfiles, "blank")
        ok, d = expect_err(m, "tcon_bulk_reset_to_scan", "640c")
        check("reset_to_scan traps the blanking routine", ok, d)
        set_fault(faultfiles, "")
        recover(m)
    finally:
        m.close()


# ---------------------------------------------------------------------------
# driver-level checks (subprocess)
# ---------------------------------------------------------------------------
def offline_checks(work):
    """Pure host-side checks: region tables and diff coverage."""
    import tcon_diffdump as dd
    import tcon_regions as tr
    print("\n== offline: regions + diff coverage ==")
    full = tr.parse_regions("full")
    covered = tr.merge_intervals([(a, b) for _, a, b in full])
    check("regions 'full' covers the whole user area",
          covered == [(0, tr.CAPACITY)], covered)

    d = os.path.join(work, "diffcov")
    os.makedirs(d, exist_ok=True)
    img = os.path.join(d, "user_swd.bin")
    with open(img, "wb") as f:
        f.truncate(0x40000)
    with open(os.path.join(d, "journal.txt"), "w") as f:
        f.write("D 0x0 0x10000\nX 0x0 0x10000\n")
    cov, _bad, _miss, src = dd.coverage_for(d, img, tr.parse_regions("0x0-0x40000"))
    check("diff: all-invalidated journal compares nothing",
          cov == [] and src == "journal", (cov, src))


def driver_level_tests(work, faultfiles):
    tmp = os.path.join(work, "tmp")
    os.makedirs(tmp, exist_ok=True)
    set_fault(faultfiles, "")

    print("\n== driver: clockcheck ==")
    rc, out = run_driver(["clockcheck", "--speeds", "4000,8000,16000"], tmp)
    check("clockcheck exits 0", rc == 0, f"rc={rc}")
    check("clockcheck recommends a speed", "Recommended" in out)
    check("clockcheck passes despite the unloaded ITCM tail",
          "FAIL" not in out and "matches running.bin" in out,
          [ln for ln in out.splitlines() if "reference" in ln or "FAIL" in ln])

    print("\n== driver: prepare ==")
    rc, out = run_driver(["prepare", "--speed", "8000"], tmp)
    check("prepare exits 0", rc == 0, f"rc={rc}")
    check("prepare reports both prepared", "Prepared" in out)
    check("prepare --speed applies and reports the speed",
          out.count("applied 8000 kHz") == 2,
          [ln for ln in out.splitlines() if "adapter speed" in ln])

    print("\n== driver: pnid ==")
    rc, out = run_driver(["pnid"], tmp)
    check("pnid exits 0", rc == 0, f"rc={rc}")
    check("pnid shows old vs new mismatch",
          "DIFFERS" in out and "1HND0V7S0B" in out and "1HNC0J270B" in out)

    print("\n== driver: verify ==")
    rc, out = run_driver(["verify"], tmp)
    check("verify exits 0", rc == 0, f"rc={rc}")
    check("verify passes all checks", "All verify checks passed" in out, out[-200:])
    l2b = [ln for ln in out.splitlines() if "[2b]" in ln]
    check("verify runs the flag-0 cross-check on both chips",
          len(l2b) == 2 and all("MATCH" in ln and "MISMATCH" not in ln
                                for ln in l2b), l2b)

    print("\n== driver: speedtest ==")
    rc, out = run_driver(["speedtest", "--regions", "0x0-0x10000"], tmp)
    check("speedtest exits 0", rc == 0, f"rc={rc}")
    check("speedtest prints an estimate", "full dump" in out)

    # normal dump of a small region
    print("\n== driver: dump (normal) ==")
    nd = os.path.join(work, "dump_normal")
    rc, out = run_driver(["dump", "--regions", "0x0-0x4000", "--new", nd,
                          "--report-every", "0x1000"], tmp)
    ok = rc == 0
    check("dump(normal) reports rates and an ETA",
          "ETA" in out and "avg" in out and "recent" in out
          and "region set complete:" in out,
          [ln for ln in out.splitlines() if "ETA" in ln or "complete" in ln][:2])
    jm = read_journal(os.path.join(nd, "master"))
    hasD = any(r[0] == "D" for r in jm)
    img = os.path.join(nd, "master", "user_swd.bin")
    check("dump(normal) exits 0", ok, f"rc={rc}")
    check("dump(normal) writes D journal lines", hasD)
    check("dump(normal) writes user_swd.bin", os.path.exists(img)
          and os.path.getsize(img) >= 0x4000)

    # skip-blank
    print("\n== driver: dump (skip-blank) ==")
    nd = os.path.join(work, "dump_blank")
    rc, out = run_driver(["dump", "--regions", "0x00100000-0x00102000",
                          "--skip-blank", "--new", nd], tmp)
    jm = read_journal(os.path.join(nd, "master"))
    hasU = any(r[0] == "U" for r in jm)
    check("dump(skip-blank) exits 0", rc == 0, f"rc={rc}")
    check("dump(skip-blank) records a U (uniform) line", hasU,
          str(jm[:3]))

    print("\n== driver: dump (skip-blank across recheck points) ==")
    nd = os.path.join(work, "dump_blank_recheck")
    rc, out = run_driver(["dump", "--regions", "0x00100000-0x00140000",
                          "--skip-blank", "--recheck-every", "2", "--new", nd], tmp)
    jm = read_journal(os.path.join(nd, "master"))
    nU = sum(1 for r in jm if r[0] == "U")
    check("dump(skip-blank + recheck) exits 0", rc == 0, f"rc={rc} {out[-200:]}")
    check("dump(skip-blank + recheck) covers every chunk (blank recheck "
          "chunks don't end the dump)", nU == 4, f"U lines: {nU} of 4")

    # bad-sector fallback (readfail on one sector)
    print("\n== driver: dump (bad-sector fallback) ==")
    set_fault(faultfiles, "readfail:0x00200800")
    nd = os.path.join(work, "dump_bad")
    rc, out = run_driver(["dump", "--regions", "0x00200000-0x00202000",
                          "--retries", "2", "--new", nd], tmp)
    set_fault(faultfiles, "")
    jm = read_journal(os.path.join(nd, "master"))
    hasB = any(r[0] == "B" for r in jm)
    badf = os.path.join(nd, "master", "bad_sectors.txt")
    badlisted = os.path.exists(badf) and "0x00200800" in open(badf).read()
    check("dump(bad) exits 0 (fallback handles it)", rc == 0, f"rc={rc}")
    check("dump(bad) records a B line", hasB, str(jm))
    check("dump(bad) lists the bad sector", badlisted)

    # double-read mismatch -> abort + power-cycle (master fault only)
    print("\n== driver: dump (double-read mismatch abort) ==")
    set_fault([faultfiles[0]], "mismatch:0x00300000")
    set_fault([faultfiles[1]], "")
    nd = os.path.join(work, "dump_mismatch")
    rc, out = run_driver(["dump", "--regions", "0x00300000-0x00302000",
                          "--recheck-every", "1", "--new", nd], tmp)
    set_fault(faultfiles, "")
    jm = read_journal(os.path.join(nd, "master"))
    hasX = any(r[0] == "X" for r in jm)
    check("dump(mismatch) exits 2", rc == 2, f"rc={rc}")
    check("dump(mismatch) invalidates with X lines", hasX, str(jm))
    check("dump(mismatch) tells the user to power cycle",
          "POWER CYCLE" in out.upper())

    # re-prepare after the abort, then a TCONERR (timeout) abort
    print("\n== driver: re-prepare + dump (TCONERR abort) ==")
    rc, out = run_driver(["prepare"], tmp)
    check("re-prepare exits 0", rc == 0, f"rc={rc}")
    set_fault(faultfiles, "timeout")
    nd = os.path.join(work, "dump_tconerr")
    rc, out = run_driver(["dump", "--regions", "0x00400000-0x00402000",
                          "--new", nd], tmp)
    set_fault(faultfiles, "")
    check("dump(TCONERR) exits 2", rc == 2, f"rc={rc}")
    check("dump(TCONERR) tells the user to power cycle",
          "POWER CYCLE" in out.upper())


def run_all_checks(work):
    """Assumes two sim instances are already listening on the driver's ports.
    Runs the tcl-level and driver-level checks."""
    faultfiles = [os.path.join(work, f"fault_{c}.txt") for c in drv.CHIPS]
    for chip, port in drv.CHIPS.items():
        if not wait_port(port):
            check(f"OpenOCD sim up on {port} ({chip})", False)
            sys.exit(f"sim instance for {chip} not reachable on {port}")
        if not is_simulator(port):
            check(f"port {port} ({chip}) is the simulator", False)
            sys.exit(f"the instance on port {port} does not have sim_target.tcl "
                     f"loaded - refusing to run tests against it")
        check(f"OpenOCD sim up on {port} ({chip})", True)
    offline_checks(work)
    tcl_level_tests(faultfiles)
    driver_level_tests(work, faultfiles)
    fixheader_tests(work, faultfiles)
    copy_tests(work, faultfiles)


def run_fix(args, tmp, work):
    cmd = [sys.executable, os.path.join(HERE, "tcon_fixheader.py")] + args \
        + ["--tmp", tmp, "--out", os.path.join(work, "header_fix")]
    r = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True,
                       timeout=600)
    return r.returncode, r.stdout + r.stderr


def emmc_bytes(work, chip, off, n):
    with open(os.path.join(work, f"emmc_{chip}.bin"), "rb") as f:
        f.seek(off)
        return f.read(n)


def emmc_poke(work, chip, off, data):
    with open(os.path.join(work, f"emmc_{chip}.bin"), "r+b") as f:
        f.seek(off)
        f.write(data)


def fixheader_tests(work, faultfiles):
    tmp = os.path.join(work, "tmp")
    set_fault(faultfiles, "")
    chips = list(drv.CHIPS)
    hdr = fw2_header()

    print("\n== fixheader: loop entry refuses an already-halted SoC ==")
    rc, out = run_fix([], tmp, work)
    check("fix --entry loop refuses when already halted",
          rc == 2 and "already halted" in out, f"rc={rc}")

    # the runbook's power cycle after a STOP: FPB cleared, boot loop running
    for c in chips:
        r = drv.Rpc(c, drv.CHIPS[c])
        try:
            r.bare("sim_power_cycle")
        finally:
            r.close()

    print("\n== fixheader: dry run (entry loop) ==")
    rc, out = run_fix([], tmp, work)
    check("fix dry run exits 0", rc == 0, f"rc={rc} {out[-300:]}")
    check("fix dry run: both chips need restore",
          out.count("needs restore") == 2 and "DRY RUN" in out)
    check("fix dry run writes nothing",
          all(emmc_bytes(work, c, 0, 0x200) == bytes(0x200) for c in chips))

    print("\n== fixheader: refuses on a FW#1/FW#2 body mismatch ==")
    orig = emmc_bytes(work, "slave", 0x500200 + 0x1000, 1)
    emmc_poke(work, "slave", 0x500200 + 0x1000, bytes([orig[0] ^ 0xFF]))
    rc, out = run_fix(["--entry", "none", "--write", "--yes"], tmp, work)
    emmc_poke(work, "slave", 0x500200 + 0x1000, orig)
    check("fix refuses (exit 1) when a body differs", rc == 1, f"rc={rc}")
    check("fix names the body mismatch", "FW#1 body != FW#2 body" in out)
    check("fix refusal writes nothing on ANY chip",
          all(emmc_bytes(work, c, 0, 0x200) == bytes(0x200) for c in chips))

    print("\n== fixheader: refuses on an unexpected FW#2 header ==")
    emmc_poke(work, "master", 0x5001FC, b"\0\0\0\0")
    rc, out = run_fix(["--entry", "none", "--write", "--yes"], tmp, work)
    emmc_poke(work, "master", 0x5001FC, hdr[0x1FC:0x200])
    check("fix refuses (exit 1) on a bad FW#2 checksum field", rc == 1, f"rc={rc}")
    check("fix names the FW#2 header problem", "FW#2 header not as expected" in out)

    print("\n== fixheader: write ==")
    rc, out = run_fix(["--entry", "none", "--write", "--yes"], tmp, work)
    check("fix write exits 0", rc == 0, f"rc={rc} {out[-300:]}")
    check("fix write verified on both chips",
          out.count("written=1 verify=ok guards=ok") == 2)
    check("fix write: eMMC 0x0 now holds FW#2's header on both chips",
          all(emmc_bytes(work, c, 0, 0x200) == hdr for c in chips))
    check("fix write tells the user to power cycle", "Power cycle" in out)
    m = drv.Rpc("master", drv.CHIPS["master"])
    try:
        st = m.rpc("tcon_bulk_state")
    finally:
        m.close()
    check("fix write re-armed the write guards", "guards=ok" in st, st)
    saved = os.listdir(os.path.join(work, "header_fix", "master"))
    check("fix saved pre-write header copies",
          any(n.startswith("fw1_header_") for n in saved), saved)

    print("\n== fixheader: re-run sees it already restored ==")
    rc, out = run_fix(["--entry", "none"], tmp, work)
    check("fix re-run exits 0", rc == 0, f"rc={rc}")
    check("fix re-run skips both chips", out.count("already restored - skip") == 2
          and "Nothing to write" in out)

    print("\n== fixheader: refuses a non-blank, non-FW#2 FW#1 header ==")
    emmc_poke(work, "master", 0, b"\x12\x34" + bytes(0x1FE))
    rc, out = run_fix(["--entry", "none", "--write", "--yes"], tmp, work)
    check("fix refuses (exit 1) on an unknown FW#1 header", rc == 1, f"rc={rc}")
    check("fix leaves the unknown header untouched",
          emmc_bytes(work, "master", 0, 2) == b"\x12\x34")


# ---------------------------------------------------------------------------
# calibration copy: test images (small, sparse "old" / "new" pairs holding
# real-shaped chunks at the real addresses)
# ---------------------------------------------------------------------------
import hashlib  # noqa: E402
import random  # noqa: E402

import tcon_copyplan as cp  # noqa: E402
import tcon_copycal as cc  # noqa: E402
import tcon_regions as tr  # noqa: E402

OLD_PID = b"1HND0V7S0B"
CP_CHUNK = cp.CHUNK
NEW_SIZE = 0x94000000                 # as the real user_swd.bin
# differing chunks (besides the panel-ID ones and LOG), per chip
CP_PLAIN = [0x01000000, 0x02000000,   # ISC_AGE (rt)
            0x06000000,               # ~25 x 1.1MB blocks
            0x0C400000,               # 12 x 4.3MB blocks
            0x16000000,               # block groups (pre bank A)
            0x22000000,               # bank A body
            0x24000000,               # block groups (post bank A)
            0x32000000,               # bank B body
            0x7F000000,               # PFT (not rt)
            0x7F300000]               # PFT +0x300000 (rt)
CP_MASTER_ONLY = [0x04600000]         # MCU_OVER (rt), master only as on the boards
CP_PNID = [0x04400000, 0x04500000, 0x04580000, 0x04800000, 0x05000000,
           0x22008000, 0x32008000]
# LOG header indices (hdr0, hdr1): both orders, as plan section 7 asks
CP_LOG = {("master", "old"): (69, 70), ("slave", "old"): (72, 71),
          ("master", "new"): (40, 39), ("slave", "new"): (38, 39)}


def rbytes(seed, n):
    return random.Random(seed).randbytes(n)


def fix_csum(sec):
    """Set word0 so all 128 words sum to 0xFFFFFFFF (the 0x5608 rule)."""
    s = bytearray(sec)
    rest = sum(struct.unpack("<127I", bytes(s[4:]))) & 0xFFFFFFFF
    s[0:4] = struct.pack("<I", (0xFFFFFFFF - rest) & 0xFFFFFFFF)
    return bytes(s)


def cp_base():
    """Everything identical on both boards: FW#1 body (header blank), FW#2
    header + body, makersheets, ISC_ST. -> {addr: bytes}"""
    with open(RUNNING, "rb") as f:
        running = f.read()
    body = running[:FW_LOADED_END] + rbytes("fwtail", len(running) - FW_LOADED_END)
    return {0x200: body, 0x500000: fw2_header() + body,
            0x60000: rbytes("mk_a", 0x1000), 0x560000: rbytes("mk_b", 0x1000),
            0x3000000: rbytes("isc_st", 0x1000), 0x3800000: rbytes("isc_st", 0x1000)}


def cp_chunks(chip, which):
    """The differing chunks of one image. -> {addr: 32 KiB bytes}"""
    pid = OLD_PID if which == "old" else NEW_PID
    out = {}
    addrs = CP_PLAIN + CP_PNID + (CP_MASTER_ONLY if chip == "master" else [])
    for a in addrs:
        out[a] = bytearray(rbytes(f"{chip}:{a:x}:{which}", CP_CHUNK))

    def hdr(a, off, tag, pidoff, csum=True):
        c = out[a & ~(CP_CHUNK - 1)]
        o = (a & (CP_CHUNK - 1)) + off
        s = bytearray(c[o:o + 0x200])
        s[4:8] = tag
        if pidoff is not None:
            s[pidoff:pidoff + 10] = pid
        c[o:o + 0x200] = fix_csum(s) if csum else s

    hdr(0x04400000, 0, b"LCC\0", 0x28, csum=False)        # no 0x5608 checksum
    hdr(0x04500000, 0, b"iRUN", 0x28, csum=False)
    hdr(0x04502000, 0, b"iRUN", 0x28, csum=False)
    hdr(0x04580000, 0, b"GCM\0", 0x28)
    hdr(0x04580200, 0, b"GCM\0", 0x28)
    hdr(0x04800000, 0, b"VRR\0", 0x28)
    hdr(0x05000800, 0, b"PNID", 0x20)
    hdr(0x05000A00, 0, b"PNID", 0x20)
    hdr(0x2200FE00, 0, b"QMC4", 0x30)
    hdr(0x3200FE00, 0, b"QMC4", 0x30)
    hdr(0x7F000000, 0, b"PFT\0", None)
    if chip == "master":
        hdr(0x04600000, 0, b"MCU_", None)

    # LOG: header pair + entries 1..current index, blank after
    i0, i1 = CP_LOG[(chip, which)]
    last = cp.LOG_ENTRIES + (max(i0, i1) - 1) * tr.SECTOR
    log = bytearray(last + tr.SECTOR - cp.LOG_BASE)
    for n, (a, idx) in enumerate(zip(cp.LOG_HDRS, (i0, i1))):
        s = bytearray(rbytes(f"{chip}:loghdr{n}:{which}", tr.SECTOR))
        s[4:8] = b"LOG\0"
        s[8:12] = struct.pack("<I", idx)
        s[0x18:0x1C] = struct.pack("<I", 0x1000 + idx)
        log[a - cp.LOG_BASE:a - cp.LOG_BASE + tr.SECTOR] = fix_csum(s)
    ent = cp.LOG_ENTRIES - cp.LOG_BASE
    log[ent:] = rbytes(f"{chip}:logent:{which}", len(log) - ent)
    for a in range(0, len(log), CP_CHUNK):
        piece = log[a:a + CP_CHUNK]
        out[cp.LOG_BASE + a] = piece + bytes(CP_CHUNK - len(piece))
    return {a: bytes(v) for a, v in out.items()}


def cp_write_image(path, chip, which, size):
    with open(path, "wb") as f:
        f.truncate(size)
        for a, d in list(cp_base().items()) + list(cp_chunks(chip, which).items()):
            f.seek(a)
            f.write(d)


def cp_expected_set(chip):
    o, n = cp_chunks(chip, "old"), cp_chunks(chip, "new")
    return sorted(a for a in set(o) | set(n)
                  if o.get(a, bytes(CP_CHUNK)) != n.get(a, bytes(CP_CHUNK)))


def cp_build_boards(cpdir):
    """old_board/<chip>/user_a.bin + user_b.bin (full capacity) and
    new_board/<chip>/user_swd.bin + a journal covering the 'all' set."""
    for chip in drv.CHIPS:
        od = os.path.join(cpdir, "old_board", chip)
        nd = os.path.join(cpdir, "new_board", chip)
        os.makedirs(od, exist_ok=True)
        os.makedirs(nd, exist_ok=True)
        for fn in ("user_a.bin", "user_b.bin"):
            cp_write_image(os.path.join(od, fn), chip, "old", tr.CAPACITY)
        cp_write_image(os.path.join(nd, "user_swd.bin"), chip, "new", NEW_SIZE)
        with open(os.path.join(nd, "journal.txt"), "w") as f:
            for _, a, b in tr.DUMP_REGIONS:
                f.write(f"D 0x{a:08x} 0x{b - a:x}\n")


def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(16 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def same_content(p1, p2):
    """Byte-equal, treating the shorter file as zero-padded."""
    n = max(os.path.getsize(p1), os.path.getsize(p2))
    with open(p1, "rb") as a, open(p2, "rb") as b:
        for _ in range(0, n, 16 << 20):
            x, y = a.read(16 << 20), b.read(16 << 20)
            if len(x) != len(y):
                m = max(len(x), len(y))
                x, y = x + bytes(m - len(x)), y + bytes(m - len(y))
            if x != y:
                return False
    return True


def file_at(path, off, n):
    with open(path, "rb") as f:
        f.seek(off)
        return f.read(n)


def file_poke(path, off, data):
    with open(path, "r+b") as f:
        f.seek(off)
        f.write(data)


# ---------------------------------------------------------------------------
# calibration copy: checks
# ---------------------------------------------------------------------------
def run_py(script, args, input_text=None, timeout=900):
    cmd = [sys.executable, os.path.join(HERE, script)] + args
    r = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True,
                       timeout=timeout, input=input_text)
    return r.returncode, r.stdout + r.stderr


def copyplan_tests(cpdir):
    print("\n== copyplan: build packs from the test images ==")
    old, new = os.path.join(cpdir, "old_board"), os.path.join(cpdir, "new_board")
    plan = os.path.join(cpdir, "plan")
    rc, out = run_py("tcon_copyplan.py", ["--old", old, "--new", new, "--out", plan])
    check("copyplan exits 0", rc == 0, f"rc={rc} {out[-400:]}")
    for chip in drv.CHIPS:
        meta, ents = cp.load_manifest(os.path.join(plan, chip))
        want = cp_expected_set(chip)
        check(f"copyplan {chip}: manifest holds exactly the differing chunks",
              [e.addr for e in ents] == want, f"{len(ents)} vs {len(want)}")
        o, n = cp_chunks(chip, "old"), cp_chunks(chip, "new")
        good = True
        with open(os.path.join(plan, chip, "src.bin"), "rb") as fs, \
                open(os.path.join(plan, chip, "bak.bin"), "rb") as fb:
            for e in ents:
                fs.seek(e.idx * CP_CHUNK)
                fb.seek(e.idx * CP_CHUNK)
                ds, db = fs.read(CP_CHUNK), fb.read(CP_CHUNK)
                good &= (ds == o.get(e.addr, bytes(CP_CHUNK))
                         and db == n.get(e.addr, bytes(CP_CHUNK))
                         and hashlib.sha256(ds).hexdigest() == e.sha_src
                         and hashlib.sha256(db).hexdigest() == e.sha_bak)
        check(f"copyplan {chip}: pack data and hashes correct", good)
        check(f"copyplan {chip}: whole-pack hashes recorded",
              meta["src_sha256"] == file_sha(os.path.join(plan, chip, "src.bin"))
              and meta["bak_sha256"] == file_sha(os.path.join(plan, chip, "bak.bin")))
        flags = {e.addr: e.flags.split(",") for e in ents}
        rt = sorted(a for a, f in flags.items() if "rt" in f)
        want_rt = sorted(a for a in want if a >= cp.LOG_BASE or
                         a in (0x01000000, 0x02000000, 0x04600000, 0x05000000,
                               0x7F300000))
        check(f"copyplan {chip}: runtime-writer (rt) chunks flagged", rt == want_rt,
              [hex(a) for a in rt])
        check(f"copyplan {chip}: the 7 panel-ID chunks flagged",
              sorted(a for a, f in flags.items() if "pnid" in f) == CP_PNID)
    lo = {c: cp.load_manifest(os.path.join(plan, c))[0]["log_old"] for c in drv.CHIPS}
    check("copyplan: old LOG in both header orders (master hdr1, slave hdr0)",
          lo["master"].startswith("hdr1 index 0x46 last 0x8000ca00")
          and lo["slave"].startswith("hdr0 index 0x48 last 0x8000ce00"), lo)
    rc, out = run_py("tcon_copyplan.py", ["--old", old, "--new", new, "--out", plan])
    check("copyplan refuses to overwrite existing packs without --force",
          rc != 0 and "--force" in out, f"rc={rc}")

    def refuses(name, chip, off, data, want_text):
        # poke both old images (they are cross-checked) and require the
        # named check itself to FAIL, for this chip
        paths = [os.path.join(old, chip, f) for f in ("user_a.bin", "user_b.bin")]
        orig = file_at(paths[0], off, len(data))
        for p in paths:
            file_poke(p, off, data)
        rp = os.path.join(cpdir, "plan_refused")
        rc, out = run_py("tcon_copyplan.py", ["--old", old, "--new", new, "--out", rp])
        for p in paths:
            file_poke(p, off, orig)
        fails = [ln for ln in out.splitlines() if "[FAIL]" in ln]
        check(f"copyplan refuses {name}", rc == 1 and "REFUSED" in out
              and any(f"{chip}:" in ln and want_text in ln for ln in fails)
              and not os.path.exists(rp), f"rc={rc} " + " | ".join(fails))

    refuses("a corrupted old header (GCM checksum)", "master", 0x04580010,
            b"\xAA", "header checksum")
    refuses("a wrong old panel ID", "slave", 0x04800028, NEW_PID,
            "at all 10 panel-ID sites")
    last = cp.LOG_ENTRIES + (70 - 1) * tr.SECTOR
    refuses("a data sector after the old LOG's indicated end", "master",
            last + 3 * tr.SECTOR, b"\x01", "old LOG blank from")
    # slave's current header (hdr0) pointed 4 entries past the data
    s = bytearray(file_at(os.path.join(old, "slave", "user_a.bin"), cp.LOG_HDRS[0], 0x200))
    s[8:12] = struct.pack("<I", 72 + 4)
    refuses("an old LOG index pointing at a blank sector", "slave",
            cp.LOG_HDRS[0], fix_csum(s), "is non-blank")
    refuses("a differing chunk outside the copied regions (makersheet)",
            "master", 0x60010, b"\x55", "lies in a copied region")
    path = os.path.join(old, "slave", "user_b.bin")
    orig = file_at(path, 0x06000100, 1)
    file_poke(path, 0x06000100, bytes([orig[0] ^ 1]))
    rc, out = run_py("tcon_copyplan.py", ["--old", old, "--new", new, "--out",
                                          os.path.join(cpdir, "plan_refused")])
    file_poke(path, 0x06000100, orig)
    check("copyplan refuses when old user_a != user_b over the write set",
          rc == 1 and any("slave: old user_a == user_b" in ln and "[FAIL]" in ln
                          for ln in out.splitlines()), f"rc={rc}")


def gapcheck_tests(work):
    print("\n== copycal gapcheck: the gap-check rule on journals ==")
    rng = "0x40000000-0x40030000"
    for name, lines, ok in (
            ("only zero U lines pass", ["U 0x40000000 0x30000 0x00000000"], True),
            ("a U line with fill 0xFFFFFFFF is flagged",
             ["U 0x40000000 0x10000 0x00000000", "U 0x40010000 0x10000 0xffffffff",
              "U 0x40020000 0x10000 0x00000000"], False),
            ("a D line is flagged",
             ["U 0x40000000 0x20000 0x00000000", "D 0x40020000 0x10000"], False),
            ("an incomplete gap dump is flagged", ["U 0x40000000 0x10000 0x00000000"], False)):
        d = os.path.join(work, "gapj", name.replace(" ", "_"))
        for chip in drv.CHIPS:
            os.makedirs(os.path.join(d, chip), exist_ok=True)
            with open(os.path.join(d, chip, "journal.txt"), "w") as f:
                f.write("\n".join(lines) + "\n")
        rc, out = run_py("tcon_copycal.py", ["gapcheck", "--new", d, "--regions", rng])
        check(f"gapcheck: {name}", (rc == 0) == ok and
              ("0xffffffff" in out or "fill" not in name), f"rc={rc}")


class Copy:
    """Shared state for the sim copy checks."""

    def __init__(self, work, faultfiles):
        self.work = work
        self.ff = dict(zip(drv.CHIPS, faultfiles))
        self.cpdir = os.path.join(work, "cp")
        self.plan = os.path.join(self.cpdir, "plan")
        self.tmp = os.path.join(work, "tmp")
        self.emmc = {c: os.path.join(work, f"emmc_{c}.bin") for c in drv.CHIPS}
        self.old = {c: os.path.join(self.cpdir, "old_board", c, "user_a.bin")
                    for c in drv.CHIPS}
        self.new = {c: os.path.join(self.cpdir, "new_board", c, "user_swd.bin")
                    for c in drv.CHIPS}
        self.man = {c: cp.load_manifest(os.path.join(self.plan, c))[1]
                    for c in drv.CHIPS}
        self.order = {c: [e.addr for e in cc.ordered(self.man[c], "all")]
                      for c in drv.CHIPS}

    def run(self, args, input_text=None):
        return run_py("tcon_copycal.py", args + ["--plan", self.plan, "--tmp", self.tmp],
                      input_text=input_text)

    def rpc(self, chip, cmd, bare=False):
        r = drv.Rpc(chip, drv.CHIPS[chip])
        try:
            return r.bare(cmd) if bare else r.rpc(cmd, timeout=30)
        finally:
            r.close()

    def power_cycle(self):
        for c in drv.CHIPS:
            self.rpc(c, "sim_power_cycle", bare=True)

    def fault(self, chip, text):
        for c in drv.CHIPS:
            with open(self.ff[c], "w") as f:
                f.write(text if c == chip or chip == "both" else "")
            self.rpc(c, "sim_fault_reset", bare=True)

    def writes(self, chip):
        """The sim's log of FUN_00006DD4 calls."""
        out = self.rpc(chip, "sim_write_log", bare=True)
        return [x.split() for x in out.strip("{} ").split("} {") if x.strip()]

    def journal(self, chip, name="journal.txt"):
        p = os.path.join(self.plan, chip, name)
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [ln.split() for ln in f if ln.strip() and not ln.startswith("#")]

    def written(self, chip, name="journal.txt"):
        return {int(p[1], 0) for p in self.journal(chip, name) if p[0] == "W"}

    def pending(self, chip, name="journal.txt"):
        j = self.journal(chip, name)
        return ({int(p[1], 0) for p in j if p[0] == "S"}
                - {int(p[1], 0) for p in j if p[0] == "W"})

    def sim_chunk(self, chip, addr):
        return file_at(self.emmc[chip], addr, CP_CHUNK)

    def img_chunk(self, which, chip, addr):
        return file_at((self.old if which == "old" else self.new)[chip], addr, CP_CHUNK)


def copy_sim_tests(work, faultfiles):
    x = Copy(work, faultfiles)
    chips = list(drv.CHIPS)
    M = "master"

    print("\n== copycal: sim eMMC starts as the 'new' image ==")
    for c in chips:
        cp_write_image(x.emmc[c], c, "new", NEW_SIZE)
        x.rpc(c, "sim_write_log_clear", bare=True)
    x.fault("both", "")
    x.power_cycle()
    h_new = {c: file_sha(x.emmc[c]) for c in chips}
    check("sim eMMC == the new test image",
          all(same_content(x.emmc[c], x.new[c]) for c in chips))

    print("\n== copycal: dry run (entry loop) ==")
    rc, out = x.run(["dryrun", "--entry", "loop"])
    check("dryrun exits 0", rc == 0, f"rc={rc} {out[-500:]}")
    check("dryrun: every chunk still holds the backup data",
          all(f"{len(x.man[c])} chunks read" in out and
              f"{len(x.man[c])} to write, 0 already" in out for c in chips),
          [ln for ln in out.splitlines() if "chunks read" in ln])
    check("dryrun: panel-ID sites read the backup's ID",
          out.count(NEW_PID.decode()) >= 20 and "expected" not in out)
    check("dryrun writes nothing (sim eMMC hashes unchanged, no write calls)",
          all(file_sha(x.emmc[c]) == h_new[c] and not x.writes(c) for c in chips))

    print("\n== copycal: gap check in the same halted session ==")
    rng = "0x40000000-0x40030000"
    g1 = os.path.join(work, "gaps1")
    rc, out = run_driver(["dump", "--regions", rng, "--skip-blank", "--new", g1], x.tmp)
    rc2, out2 = run_py("tcon_copycal.py", ["gapcheck", "--new", g1, "--regions", rng])
    check("gap dump after the dry run, blank gaps pass", rc == 0 and rc2 == 0,
          f"rc={rc}/{rc2} {out2[-200:]}")
    file_poke(x.emmc[M], 0x40010000, b"\xFF" * 0x10000)
    g2 = os.path.join(work, "gaps2")
    rc, out = run_driver(["dump", "--regions", rng, "--skip-blank", "--new", g2], x.tmp)
    rc2, out2 = run_py("tcon_copycal.py", ["gapcheck", "--new", g2, "--regions", rng])
    file_poke(x.emmc[M], 0x40010000, bytes(0x10000))
    check("gap dump: a 0xFFFFFFFF-filled gap chunk is flagged",
          rc == 0 and rc2 == 1 and "fill 0xffffffff" in out2, f"rc={rc}/{rc2}")

    print("\n== copycal: tcl-level write guards ==")
    probe = os.path.join(x.tmp, "cc_probe.bin")
    with open(probe, "wb") as f:
        f.write(rbytes("probe", CP_CHUNK))
    for g in ("0x6D50", "0x640C", "0x414"):
        x.rpc(M, f"rbp {g}")
        try:
            x.rpc(M, "tcon_write_call 0x04400000 0x8000 0")
            ok, d = False, "no error"
        except drv.TconError as e:
            ok, d = "missing" in str(e), str(e)
        x.rpc(M, f"tcon_bulk_begin 0x{drv.STAGE:08x} 0x{drv.CHUNK:x}")
        check(f"write call refuses with {g} missing from the FPB", ok, d[:120])
    try:
        x.rpc(M, "tcon_write_call 0x04400000 0x10000 0")
        ok, d = False, "no error"
    except drv.TconError as e:
        ok, d = "exceeds" in str(e), str(e)
    check("write call refuses more than 32 KiB", ok, d[:100])
    try:
        x.rpc(M, f"tcon_write_load {{{probe}}} 0 0x8000 0x1 0x2")
        ok, d = False, "no error"
    except drv.TconError as e:
        ok, d = "load_image check failed" in str(e), str(e)
    check("write_load catches data that isn't what was asked for", ok, d[:100])
    check("tcl-level refusals wrote nothing",
          not x.writes(M) and file_sha(x.emmc[M]) == h_new[M])

    print("\n== copycal: refusals ==")
    src = os.path.join(x.plan, M, "src.bin")
    b = file_at(src, 5, 1)
    file_poke(src, 5, bytes([b[0] ^ 1]))
    rc, out = x.run(["write", "--entry", "none", "--yes"])
    file_poke(src, 5, b)
    check("write refuses a pack hash mismatch before connecting",
          rc == 1 and "pack check failed" in out and not x.writes(M), f"rc={rc}")
    rc, out = x.run(["write", "--entry", "loop", "--allow-valid-header", "--yes"])
    check("--entry loop with --allow-valid-header is refused",
          rc == 1 and "cannot be used with --entry loop" in out, f"rc={rc}")
    x.rpc(M, "set_reg {pc 0x1234}")
    rc, out = x.run(["write", "--entry", "none", "--yes"])
    check("write refuses a wrong PC", rc == 1 and "REFUSED at the begin check" in out
          and "pc is 0x00001234" in out and not x.writes(M), f"rc={rc}")
    hdr = fw2_header()
    file_poke(x.emmc["slave"], 0, hdr)
    x.power_cycle()
    rc, out = x.run(["write", "--entry", "loop", "--yes"])
    file_poke(x.emmc["slave"], 0, bytes(0x200))
    check("write refuses a valid (FW#2) FW#1 header without the flag",
          rc == 1 and "refused without --allow-valid-header" in out
          and not any(x.writes(c) for c in chips), f"rc={rc}")

    # pre-read matching neither image, on master's first chunk -> both stop
    first = x.order[M][0]
    b = file_at(x.emmc[M], first + 0x100, 1)
    file_poke(x.emmc[M], first + 0x100, bytes([b[0] ^ 0xFF]))
    x.power_cycle()
    rc, out = x.run(["write", "--entry", "loop", "--yes"])
    file_poke(x.emmc[M], first + 0x100, b)
    check("write STOPs on a pre-read matching neither image",
          rc == 2 and "matches neither" in out and not x.written(M), f"rc={rc}")
    check("an error on one chip halts both (fresh connections)",
          "[master] curstate = halted" in out and "[slave] curstate = halted" in out
          and len(x.written("slave")) < len(x.man["slave"]) and "POWER CYCLE" in out,
          f"slave wrote {len(x.written('slave'))}")

    print("\n== copycal: probe (--limit 1) ==")
    x.power_cycle()
    rc, out = x.run(["write", "--entry", "loop", "--limit", "1", "--yes"])
    check("probe exits 0", rc == 0, f"rc={rc} {out[-300:]}")
    check("probe writes exactly one chunk on master",
          x.written(M) == {first} and "[master] written 1," in out,
          sorted(hex(a) for a in x.written(M)))
    check("probe chunk now holds the old data",
          x.sim_chunk(M, first) == x.img_chunk("old", M, first))

    def next_chunk():
        return next(a for a in x.order[M] if a not in x.written(M)
                    and a not in x.pending(M))

    print("\n== copycal: writecorrupt once -> retried ==")
    a = next_chunk()
    x.fault(M, f"writecorrupt:0x{a + 0x10:08x}:1")
    rc, out = x.run(["write", "--entry", "none", "--limit", "2", "--yes"])
    x.fault("both", "")
    check("a transient corrupt write is retried and passes",
          rc == 0 and "retrying" in out and a in x.written(M)
          and x.sim_chunk(M, a) == x.img_chunk("old", M, a), f"rc={rc}")

    print("\n== copycal: writecorrupt persistent -> STOP ==")
    a = next_chunk()
    x.fault(M, f"writecorrupt:0x{a + 0x10:08x}")
    rc, out = x.run(["write", "--entry", "none", "--yes"])
    x.fault("both", "")
    check("a persistent corrupt write STOPs after 3 attempts",
          rc == 2 and "still differs after 3" in out and a in x.pending(M), f"rc={rc}")
    corrupt_chunk = a

    print("\n== copycal: writenoop -> caught ==")
    x.power_cycle()
    a = next_chunk()
    x.fault(M, f"writenoop:0x{a:08x}")
    rc, out = x.run(["write", "--entry", "loop", "--yes"])
    x.fault("both", "")
    check("resume rewrites the interrupted (corrupt) chunk",
          corrupt_chunk in x.written(M) and "interrupted earlier" in out
          and x.sim_chunk(M, corrupt_chunk) == x.img_chunk("old", M, corrupt_chunk))
    check("a write that does nothing is caught (STOP)",
          rc == 2 and "still differs after 3" in out and a in x.pending(M), f"rc={rc}")

    print("\n== copycal: readnoop -> caught ==")
    x.power_cycle()
    x.run(["write", "--entry", "loop", "--limit", "1", "--yes"])   # clear the noop chunk
    a = next_chunk()
    x.fault(M, f"readnoop:0x{a:08x}")
    x.power_cycle()
    rc, out = x.run(["write", "--entry", "loop", "--yes"])
    x.fault("both", "")
    check("a read that does nothing is caught (STOP)",
          rc == 2 and f"read of 0x{a:08x} failed" in out and a not in x.written(M),
          f"rc={rc}")

    print("\n== copycal: scoped writefail -> STOP ==")
    x.power_cycle()
    x.fault(M, f"writefail:0x{a:08x}")
    rc, out = x.run(["write", "--entry", "loop", "--yes"])
    x.fault("both", "")
    check("a write returning rc!=0 STOPs", rc == 2 and "returned rc=0x1" in out
          and a in x.pending(M), f"rc={rc}")

    print("\n== copycal: torn write (power loss) -> resume ==")
    x.power_cycle()
    x.run(["write", "--entry", "loop", "--limit", "1", "--yes"])   # clear the failed chunk
    a = next_chunk()
    x.fault(M, f"tornwrite:0x{a:08x}")
    x.power_cycle()
    rc, out = x.run(["write", "--entry", "loop", "--yes"])
    x.fault("both", "")
    half = CP_CHUNK // 2
    torn = x.sim_chunk(M, a)
    check("torn write STOPs, chunk left half old / half backup, S without W",
          rc == 2 and "timed out" in out and a in x.pending(M)
          and torn[:half] == x.img_chunk("old", M, a)[:half]
          and torn[half:] == x.img_chunk("new", M, a)[half:], f"rc={rc}")
    x.power_cycle()
    rc, out = x.run(["write", "--entry", "loop", "--phase", "1", "--yes"])
    p1 = {e.addr for e in x.man[M] if e.phase == 1}
    p2 = {e.addr for e in x.man[M] if e.phase == 2}
    check("resume after power cycle completes phase 1, torn chunk rewritten",
          rc == 0 and "interrupted earlier" in out
          and all({e.addr for e in x.man[c] if e.phase == 1} <= x.written(c)
                  for c in chips)
          and x.sim_chunk(M, a) == x.img_chunk("old", M, a), f"rc={rc} {out[-300:]}")
    check("--phase 1 leaves LOG untouched",
          not (p2 & x.written(M)) and all(x.sim_chunk(M, b) == x.img_chunk("new", M, b)
                                          for b in p2))

    print("\n== copycal: phase 2 after a power cycle ==")
    x.power_cycle()
    rc, out = x.run(["write", "--entry", "loop", "--phase", "2", "--yes"])
    check("phase 2 completes", rc == 0 and out.count("copy complete") == 2,
          f"rc={rc} {out[-300:]}")
    check("panel-ID sites read the real panel's ID after the copy",
          out.split("now:")[-1].count(OLD_PID.decode()) == 20
          and "expected" not in out.split("now:")[-1])
    check("full run: sim eMMC == old image (write set copied, all else unchanged)",
          all(same_content(x.emmc[c], x.old[c]) for c in chips))
    check("full run: FW#1 header still blank, makersheet untouched",
          all(file_at(x.emmc[c], 0, 0x200) == bytes(0x200)
              and file_at(x.emmc[c], 0x60000, 0x1000) == rbytes("mk_a", 0x1000)
              for c in chips))
    wl = x.writes(M) + x.writes("slave")
    check("every eMMC write had 0x640C, 0x6D50 and the trap armed, 0x6C8C lifted, "
          "flag 0, 32 KiB",
          wl and all(w[1] == "0x8000" and w[2] == "0x0" and w[3:] == ["1", "1", "1", "0"]
                     for w in wl), f"{len(wl)} writes; bad: "
          + str([w for w in wl if w[3:] != ["1", "1", "1", "0"]][:3]))
    st = x.rpc(M, "tcon_bulk_state")
    check("guards and trap re-armed after the run", "guards=ok" in st and "trap=1" in st, st)
    jm = x.journal(M)
    s_order = [int(p[1], 0) for p in jm if p[0] == "S"]
    pn = [i for i, a in enumerate(s_order) if a in CP_PNID]
    other1 = [i for i, a in enumerate(s_order) if a in p1 and a not in CP_PNID]
    logi = [i for i, a in enumerate(s_order) if a in p2]
    check("order: panel-ID chunks last in phase 1, LOG (header pair first) after",
          pn and max(other1) < min(pn) and max(pn) < min(logi)
          and s_order[logi[0]] == cp.LOG_BASE)

    print("\n== copycal: second run is a no-op ==")
    nw = len(x.writes(M))
    rc, out = x.run(["write", "--entry", "none", "--yes"])
    check("second run: nothing to do", rc == 0 and "Nothing to do" in out
          and len(x.writes(M)) == nw, f"rc={rc}")
    jp = os.path.join(x.plan, M, "journal.txt")
    os.replace(jp, jp + ".aside")
    rc, out = x.run(["write", "--entry", "none", "--chips", M, "--yes"])
    check("a finished board with its journal missing is refused (panel-ID sites "
          "don't match the journal)",
          rc == 1 and "panel-ID sites don't match the journal" in out
          and len(x.writes(M)) == nw, f"rc={rc}")
    # a journal that lost its non-panel-ID W lines: the pre-reads find the
    # old data, journal W and skip without writing
    with open(jp + ".aside") as f, open(jp, "w") as g:
        for ln in f:
            q = ln.split()
            if not (q and q[0] == "W" and int(q[1], 0) not in CP_PNID):
                g.write(ln)
    rc, out = x.run(["write", "--entry", "none", "--chips", M, "--yes"])
    os.replace(jp + ".aside", jp)
    nlost = len(x.man[M]) - len(CP_PNID)
    check("chunks missing their W line: pre-reads find the old data, nothing written",
          rc == 0 and f"written 0, already there {nlost}" in out
          and len(x.writes(M)) == nw, f"rc={rc} {out[-300:]}")

    print("\n== copycal: verify ==")
    rc, out = x.run(["verify", "--entry", "none"])
    check("verify passes on the completed image", rc == 0 and "VERIFY PASSED" in out,
          f"rc={rc} {out[-300:]}")
    b = file_at(x.emmc[M], 0x0C400100, 1)
    file_poke(x.emmc[M], 0x0C400100, bytes([b[0] ^ 1]))
    rc, out = x.run(["verify", "--entry", "none"])
    file_poke(x.emmc[M], 0x0C400100, b)
    check("verify fails on a tampered chunk", rc == 1 and "MISMATCH 0x0c400000" in out,
          f"rc={rc}")

    print("\n== copycal: rollback (--source backup) ==")
    rc, out = x.run(["write", "--source", "backup", "--entry", "none", "--yes"])
    check("rollback exits 0", rc == 0, f"rc={rc} {out[-300:]}")
    check("rollback restores the sim eMMC to the original file's hash",
          all(file_sha(x.emmc[c]) == h_new[c] for c in chips))
    check("rollback retired the forward journal",
          not os.path.exists(os.path.join(x.plan, M, "journal.txt"))
          and any(n.startswith("journal.txt.retired-")
                  for n in os.listdir(os.path.join(x.plan, M))))
    rc, out = x.run(["verify", "--source", "backup", "--entry", "none"])
    check("verify --source backup passes after the rollback", rc == 0, f"rc={rc}")

    print("\n== copycal: --allow-valid-header ==")
    for c in chips:
        file_poke(x.emmc[c], 0, hdr)
    x.power_cycle()
    rc, out = x.run(["write", "--entry", "reset", "--yes"])
    check("valid header + cfg=0 refused without the flag",
          rc == 1 and "refused without --allow-valid-header" in out, f"rc={rc}")
    rc, out = x.run(["write", "--entry", "reset", "--allow-valid-header"],
                    input_text="WRITE\nWRITE\n")
    check("the flag needs VALID HEADER typed first",
          rc == 0 and "Not confirmed" in out and not x.written(M), f"rc={rc}")
    rc, out = x.run(["write", "--entry", "reset", "--allow-valid-header"],
                    input_text="VALID HEADER\nWRITE\n")
    check("with the flag, a valid header + cfg=0 proceeds",
          rc == 0 and "fw1=same" in out and "cfg=0" in out
          and out.count("copy complete") == 2, f"rc={rc} {out[-300:]}")
    check("the valid header is untouched afterwards",
          all(file_at(x.emmc[c], 0, 0x200) == hdr for c in chips))
    sess = [ln for ln in open(os.path.join(x.plan, M, "journal.txt")) if "# session" in ln]
    check("the journal records the flag and the header state",
          sess and "allow_valid_header=1" in sess[-1] and "fw1=same" in sess[-1]
          and "cfg=0" in sess[-1], sess[-1:] if sess else "")
    rc, out = x.run(["verify", "--entry", "none"])
    check("verify without the flag refuses a valid header", rc == 1
          and "REFUSED at the begin check" in out, f"rc={rc}")
    rc, out = x.run(["verify", "--entry", "none", "--allow-valid-header"])
    check("verify with the flag passes", rc == 0 and "VERIFY PASSED" in out, f"rc={rc}")

    rt = {"LOG": 0x80004010, "MCU_OVER": 0x04600010, "ISC_AGE": 0x01000010,
          "0x5000C00": 0x05000C00, "PFT 0x7F300000": 0x7F300010}
    saved = {k: file_at(x.emmc[M], a, 1) for k, a in rt.items()}
    for k, a in rt.items():
        file_poke(x.emmc[M], a, bytes([saved[k][0] ^ 0x5A]))
    rc, out = x.run(["verify", "--entry", "none", "--allow-valid-header"])
    check("with the flag, tampered LOG/MCU_OVER/ISC_AGE/0x5000C00/0x7F300000 "
          "chunks are runtime-updated and pass",
          rc == 0 and "5 runtime-updated, 0 MISMATCH" in out, f"rc={rc} "
          + " | ".join(ln for ln in out.splitlines() if "runtime" in ln))
    for k, a in rt.items():
        file_poke(x.emmc[M], a, saved[k])
    for name, a in (("block-group", 0x0C400100), ("iRUN", 0x04500100),
                    ("PFT 0x7F000000", 0x7F000100)):
        b = file_at(x.emmc[M], a, 1)
        file_poke(x.emmc[M], a, bytes([b[0] ^ 1]))
        rc, out = x.run(["verify", "--entry", "none", "--allow-valid-header"])
        file_poke(x.emmc[M], a, b)
        check(f"with the flag, a tampered {name} chunk still fails verify",
              rc == 1 and f"MISMATCH 0x{a & ~(CP_CHUNK - 1):08x}" in out, f"rc={rc}")

    file_poke(x.emmc[M], 0, b"\x12\x34" + hdr[2:])
    rc, out = x.run(["write", "--source", "backup", "--entry", "reset",
                     "--allow-valid-header", "--yes"])
    check("a header neither blank nor FW#2's is refused even with the flag",
          rc == 1 and "neither blank nor FW#2's" in out
          and file_at(x.emmc[M], 0, 2) == b"\x12\x34", f"rc={rc}")
    file_poke(x.emmc[M], 0, hdr)

    rc, out = x.run(["state"])
    check("state reports journal progress and SoC state",
          rc == 0 and "phase 1" in out and "state=halted" in out, f"rc={rc}")


def copy_tests(work, faultfiles):
    cpdir = os.path.join(work, "cp")
    cp_build_boards(cpdir)
    copyplan_tests(cpdir)
    gapcheck_tests(work)
    copy_sim_tests(work, faultfiles)


def report():
    print("\n" + "=" * 60)
    print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for n in FAIL:
            print(f"  FAILED: {n}")
        return 1
    print("all checks passed")
    return 0


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--setup", metavar="DIR",
                    help="only build eMMC images + fault files + OpenOCD configs "
                         "into DIR, print how to launch them, then exit "
                         "(no OpenOCD launched)")
    ap.add_argument("--external", metavar="DIR",
                    help="run the checks against sim instances already listening "
                         "on the driver ports, using the files in DIR (from a "
                         "prior --setup). Nothing is launched here.")
    args = ap.parse_args()

    if not os.path.exists(OPENOCD):
        sys.exit(f"missing {OPENOCD}")

    # --setup: just materialise the files (useful when OpenOCD must be launched
    # outside this process, e.g. a sandbox that kills child servers).
    if args.setup:
        work = os.path.abspath(args.setup)
        os.makedirs(work, exist_ok=True)
        setup_files(work)
        print(f"sim files written to {work}")
        print("launch the two instances (e.g. from a shell), then run "
              "--external:")
        for chip in drv.CHIPS:
            print(f"  {OPENOCD} -f {os.path.join(work, f'sim_{chip}.cfg')} &")
        print(f"  {sys.executable} {os.path.abspath(__file__)} --external {work}")
        return

    # --external: instances are already running.
    if args.external:
        work = os.path.abspath(args.external)
        os.makedirs(os.path.join(work, "tmp"), exist_ok=True)
        run_all_checks(work)
        sys.exit(report())

    # default: self-contained (build + launch + check + teardown). Correct for a
    # normal machine; a sandbox that kills child server processes needs the
    # --setup/--external split instead.
    busy = [p for p in drv.CHIPS.values() if port_in_use(p)]
    if busy:
        sys.exit(f"port(s) {busy} already in use - refusing to start the "
                 f"simulator (stop whatever is listening there first)")
    work = tempfile.mkdtemp(prefix="tcon_sim_")
    procs, logs = [], []
    try:
        faultfiles = setup_files(work)
        for i, (chip, port) in enumerate(drv.CHIPS.items()):
            emmc = os.path.join(work, f"emmc_{chip}.bin")
            log = os.path.join(work, f"openocd_{chip}.log")
            p, lf = launch(chip, port, emmc, faultfiles[i], log)
            procs.append(p)
            logs.append((lf, log))
        run_all_checks(work)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        for lf, _ in logs:
            lf.close()

    rc = report()
    if rc == 0:
        shutil.rmtree(work, ignore_errors=True)
    else:
        print(f"\n(sim workdir kept for inspection: {work})")
    sys.exit(rc)


if __name__ == "__main__":
    main()

# ---------------------------------------------------------------------------
# pnidprobe.tcl - read the panel-ID sites found in the old board's eMMC
#
# Source AFTER tconutils.tcl and tcondump.tcl:
#     source /path/to/tconutils.tcl
#     source /path/to/tcondump.tcl
#     source /path/to/pnidprobe.tcl
#
# The old board (both SoCs) holds the real panel ID 1HND0V7S0B at every
# site below. If the working board holds 1HNC0J270B there instead, these
# calibration records are the source of "exco pnid: ng".
#
# Read-only: nothing in this file writes to the eMMC.
# ---------------------------------------------------------------------------

set ::TCON_FN_BLANK 0x0000640C   ;# eMMC blanking retry - guard breakpoint

# {sector  id_offset  description} - sector is the 512-byte aligned eMMC
# byte address, id_offset is where the 10-char panel ID sits inside it
set ::TCON_PNID_SITES {
    {0x04400000 0x028 "LCC"}
    {0x04500000 0x028 "iRUN"}
    {0x04502000 0x028 "iRUN +0x2000"}
    {0x04580000 0x028 "GCM"}
    {0x04580200 0x028 "GCM +0x200"}
    {0x04800000 0x028 "VRR"}
    {0x05000800 0x020 "0x5000000 rec +0x800"}
    {0x05000A00 0x020 "0x5000000 rec +0xA00"}
    {0x2200FE00 0x030 "bank A (QMC490EA02)"}
    {0x3200FE00 0x030 "bank B (QMC490EA02)"}
}

proc tcon_ascii {addr len} {
    set s ""
    foreach b [read_memory $addr 8 $len] {
        if {$b >= 0x20 && $b < 0x7f} {
            append s [format %c $b]
        } else {
            append s "."
        }
    }
    return $s
}

# --------------------------------------------------------------------------
# Get this SoC to the verified halt-at-scan state from a normally booted
# board: halt, arm the scan breakpoint plus a guard on the blanking routine,
# then SYSRESETREQ. The core reboots through BL1 and stops just after the
# config scan, before the master/slave handshake.
#
# Halt BOTH SoCs with plain 'halt' before running this on either, then run
# it on the master, then on the slave. The guard stays armed until power
# cycle: if anything ever reaches the blanking routine, the core halts
# instead of zeroing the FW#1 header.
# --------------------------------------------------------------------------
proc tcon_reset_to_scan {} {
    halt
    tcon_rbp_quiet $::TCON_BP_SCAN
    tcon_rbp_quiet $::TCON_TRAP
    tcon_rbp_quiet $::TCON_FN_BLANK
    bp $::TCON_BP_SCAN 2 hw
    bp $::TCON_FN_BLANK 2 hw
    reset run
    set timedout [catch {wait_halt $::TCON_WAIT} waitmsg]
    set pc [tcon_rdreg pc]
    tcon_rbp_quiet $::TCON_BP_SCAN
    if {$timedout} {
        error [format "wait_halt failed (%s); pc 0x%08x - STOP, power cycle" \
                      $waitmsg $pc]
    }
    if {$pc == $::TCON_FN_BLANK} {
        error "halted at the BLANKING routine 0x640c - do NOT resume, power cycle"
    }
    if {$pc != $::TCON_BP_SCAN} {
        error [format "halted at 0x%08x, expected 0x%08x - STOP" $pc $::TCON_BP_SCAN]
    }
    # make sure the Apr-2023 FW is what sits at the breakpoint, not BL1/ROM
    set code [read_memory 0x000029C0 32 2]
    if {[lindex $code 0] != 0x4a04ff2b || [lindex $code 1] != 0x68106851} {
        error [format "code at 0x29c0 is 0x%08x 0x%08x, not the Apr-2023 FW - STOP" \
                      [lindex $code 0] [lindex $code 1]]
    }
    set cfg [tcon_rd32 0x200016B8]
    echo [format "stopped at 0x%08x (post config-scan), FW verified, CFG/MS=%d, blanking guard armed" \
                 $pc $cfg]
    if {$cfg != 0} {
        echo "WARNING: CFG/MS != 0 - this boot took the FW#2/config-1 path. Check the FW#1 header before continuing."
    }
}

# --------------------------------------------------------------------------
# Read every panel-ID site, save each sector, print tag and ID.
# --------------------------------------------------------------------------
proc tcon_pnid_probe {{prefix pnid}} {
    set buf $::TCON_STAGE_ADDR
    echo ""
    echo "=== panel-ID sites (old board reads 1HND0V7S0B everywhere) ==="
    foreach site $::TCON_PNID_SITES {
        lassign $site sector off desc
        if {[catch {tcon_emmc_read_to $sector $buf} err]} {
            echo [format "  0x%08x %-22s READ FAILED: %s" $sector $desc $err]
            continue
        }
        set fname [format "%s_%08x.bin" $prefix $sector]
        if {[catch {dump_image $fname $buf 0x200} derr]} {
            set fname "(dump_image failed: $derr)"
        }
        set head [tcon_ascii $buf 16]
        set id   [tcon_ascii [expr {$buf + $off}] 10]
        echo [format "  0x%08x %-22s head '%s'  id '%s'  -> %s" \
                     $sector $desc $head $id $fname]
    }
}

# --------------------------------------------------------------------------
# Time a 64 KiB read with the existing per-sector method, to calibrate how
# long bulk copies will take. Writes speedtest_0000.bin.
# --------------------------------------------------------------------------
proc tcon_speedtest {{start 0x04400000}} {
    set t0 [clock milliseconds]
    tcon_dump_emmc $start 0x10000 speedtest
    set ms [expr {[clock milliseconds] - $t0}]
    echo [format "64 KiB in %d ms = %.1f KiB/s" $ms [expr {64000.0 / $ms}]]
    return $ms
}

echo "pnidprobe.tcl loaded. Commands:"
echo "  tcon_reset_to_scan   reboot this SoC to the halt-at-scan state (guarded)"
echo "  tcon_pnid_probe PFX  read + save every panel-ID site"
echo "  tcon_speedtest       time one 64 KiB read"

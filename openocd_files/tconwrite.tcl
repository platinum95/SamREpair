# ---------------------------------------------------------------------------
# tconwrite.tcl - the eMMC write call for the calibration copy
# (AgentInfo/calibration_copy_plan.md, section 4). THIS FILE WRITES TO THE
# eMMC, one chunk (<= 32 KiB) per tcon_write_call.
#
# Source AFTER tconutils.tcl, tcondump.tcl, pnidprobe.tcl, tconbulk.tcl and
# tconfix.tcl (tcon_write_begin uses tconfix's header check). Normally driven
# by tcon_copycal.py over the TCL RPC port.
#
# Staging: the standard bulk window, split in two by the driver:
#     stage + 0x0000   A: the source chunk (load_image), the write buffer
#     stage + 0x8000   B: the pre-read and the read-back (tcon_bulk_read)
# ::TCON_BULK_STAGE / ::TCON_BULK_CHUNK stay 0x20220000 / 0x10000, so the
# dump driver can run in the same halted session.
#
# Guards: 0x640C (blanking) and 0x6D50 (the other write path) stay armed the
# whole time. 0x6C8C (FUN_00006DD4's write path) is lifted for each write call
# only, re-armed straight after, and confirmed by reading the FPB back.
# ---------------------------------------------------------------------------

set ::TCON_FN_EMMC_WRITE 0x00006DD4   ;# FUN_00006DD4 (dev, buf, addr, len, flag)
set ::TCON_WRITE_MAX     0x8000       ;# largest firmware write is 0x9400 (0x19316)
set ::TCON_WRITE_KEEP    [list $::TCON_FN_BLANK $::TCON_FN_EMMC_WR2]

proc tcon_write_check_args {addr len off} {
    if {($addr % 0x200) || ($len % 0x200) || ($off % 0x200) || $len <= 0} {
        error "addr, len and off must be multiples of 512"
    }
    if {$len > $::TCON_WRITE_MAX} {
        error [format "len 0x%x exceeds the 0x%x write limit" $len $::TCON_WRITE_MAX]
    }
    if {$off + $len > $::TCON_BULK_CHUNK} {
        error [format "off+len 0x%x exceeds staging size 0x%x" [expr {$off + $len}] $::TCON_BULK_CHUNK]
    }
}

# --------------------------------------------------------------------------
# Begin (or re-join) a write session. Everything tcon_bulk_begin checks (pc
# at 0x29C2 / 0x414, the Apr-2023 code signature, guards + trap armed,
# staging probed, SP pinned), plus:
#   - FW#2's header is the Apr-2023 one;
#   - FW#1's header is blank (the boot loop, header restore still to come),
#     or with allow_valid=1 blank or identical to FW#2's. Anything else is
#     refused whatever allow_valid says;
#   - CFG/MS is 1, or with allow_valid=1 0 or 1.
# CCR is read for the log only.
# --------------------------------------------------------------------------
proc tcon_write_begin {allow_valid {stage ""} {chunk ""}} {
    if {[info commands tcon_fix_header_check] eq ""} {
        error "tconfix.tcl is not loaded"
    }
    tcon_bulk_begin $stage $chunk
    # flag-0 reads through tcon_call; it removes the return trap afterwards
    set hs [tcon_fix_header_check]
    tcon_bulk_begin
    set d [dict create]
    foreach tok [split $hs] {
        set kv [split $tok =]
        if {[llength $kv] == 2} {
            dict set d [lindex $kv 0] [lindex $kv 1]
        }
    }
    set fw1 [dict get $d fw1]
    set fw2 [dict get $d fw2]
    set cfg [dict get $d cfg]
    if {$fw2 ne "ok"} {
        error "FW#2 header not as expected ($fw2) - STOP"
    }
    if {$fw1 eq "same"} {
        if {!$allow_valid} {
            error "FW#1 header is valid (identical to FW#2's), not blank - refused without --allow-valid-header"
        }
    } elseif {$fw1 ne "zero"} {
        error "FW#1 header is neither blank nor FW#2's ($fw1) - unknown state, refused"
    }
    if {$cfg != 1 && !($allow_valid && $cfg == 0)} {
        if {$allow_valid} {
            error "CFG/MS is $cfg; expected 0 or 1"
        }
        error "CFG/MS is $cfg; expected 1 (boot loop) - refused without --allow-valid-header"
    }
    set ccr [tcon_rd32 0xE000ED14]
    return [format "%s allow_valid=%d ccr=0x%08x %s" $hs $allow_valid $ccr [tcon_bulk_state]]
}

# --------------------------------------------------------------------------
# Put len bytes of PATH (a raw binary file) at stage+off. The first and last
# words are poisoned beforehand and must read back as the caller's expected
# values, so a load that silently does nothing is caught here. The eMMC
# read-back after the write is the full check.
# --------------------------------------------------------------------------
proc tcon_write_load {path off len w_first w_last} {
    tcon_bulk_require_halted
    tcon_write_check_args 0 $len $off
    set buf [expr {$::TCON_BULK_STAGE + $off}]
    set tail [expr {$buf + $len - 4}]
    write_memory $buf 32 [list [expr {~$w_first & 0xFFFFFFFF}]]
    write_memory $tail 32 [list [expr {~$w_last & 0xFFFFFFFF}]]
    set t0 [clock milliseconds]
    load_image $path $buf bin
    set ms [expr {[clock milliseconds] - $t0}]
    set a [tcon_rd32 $buf]
    set b [tcon_rd32 $tail]
    if {$a != $w_first || $b != $w_last} {
        error [format "load_image check failed: first 0x%08x (want 0x%08x), last 0x%08x (want 0x%08x)" \
                      $a $w_first $b $w_last]
    }
    return [format "ms=%d" $ms]
}

# --------------------------------------------------------------------------
# One eMMC write: FUN_00006DD4(0, stage+off, addr, len, 0).
# Going in, all three guards and the return trap must be in the FPB. Only
# 0x6C8C is lifted; the call runs through tcon_bulk_call (SP pinned, return
# at the trap with the same SP, timeout -> re-halt) with its guard list
# narrowed to the two that stay armed, so it checks exactly 0x640C, 0x6D50
# and the trap before resuming. Afterwards 0x6C8C is re-armed and the full
# set confirmed in the FPB. Any failure is an error: STOP, power cycle.
# --------------------------------------------------------------------------
proc tcon_write_call {addr len {off 0}} {
    tcon_bulk_require_halted
    tcon_write_check_args $addr $len $off
    if {$::TCON_BULK_SP == 0} {
        error "no bulk session - run tcon_write_begin"
    }
    set all [concat $::TCON_BULK_GUARDS [list $::TCON_TRAP]]
    set miss [tcon_bulk_missing $all]
    if {[llength $miss]} {
        error "breakpoints missing from the FPB before the write: $miss - STOP"
    }
    tcon_rbp_quiet $::TCON_FN_EMMC_WR1
    if {![llength [tcon_bulk_missing [list $::TCON_FN_EMMC_WR1]]]} {
        error "0x6c8c still armed after rbp - not writing, STOP"
    }
    set buf [expr {$::TCON_BULK_STAGE + $off}]
    set saved $::TCON_BULK_GUARDS
    set ::TCON_BULK_GUARDS $::TCON_WRITE_KEEP
    set t0 [clock milliseconds]
    set failed [catch {tcon_bulk_call $::TCON_FN_EMMC_WRITE 0 $buf $addr $len 0} rc]
    set ms [expr {[clock milliseconds] - $t0}]
    set ::TCON_BULK_GUARDS $saved
    set rearm [catch {tcon_bulk_arm [list $::TCON_FN_EMMC_WR1]} rearm_msg]
    if {$failed} {
        set also ""
        if {$rearm} {
            set also " (0x6c8c re-arm also failed)"
        }
        error [format "write 0x%08x failed: %s%s - STOP, do not resume, power cycle" $addr $rc $also]
    }
    if {$rearm} {
        error "0x6c8c could not be re-armed after the write: $rearm_msg - STOP, do not resume, power cycle"
    }
    set miss [tcon_bulk_missing $all]
    if {[llength $miss]} {
        error "breakpoints missing from the FPB after the write: $miss - STOP"
    }
    return [format "rc=0x%x ms=%d" $rc $ms]
}

echo "tconwrite.tcl loaded (WRITES the eMMC; driven by tcon_copycal.py). Commands:"
echo "  tcon_write_begin ALLOW_VALID ?STAGE CHUNK?   start a write session"
echo "  tcon_write_load PATH OFF LEN W0 WLAST        load a chunk into staging"
echo "  tcon_write_call ADDR LEN ?OFF?               one guarded eMMC write"

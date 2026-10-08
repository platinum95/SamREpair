# ---------------------------------------------------------------------------
# tconbulk.tcl - fast, read-only bulk eMMC reads for the TCON over SWD
#
# Source AFTER tconutils.tcl, tcondump.tcl and pnidprobe.tcl:
#     source /path/to/tconutils.tcl
#     source /path/to/tcondump.tcl
#     source /path/to/pnidprobe.tcl
#     source /path/to/tconbulk.tcl
#
# Normally driven by tcon_bulkdump.py over the TCL RPC port (6666 / 6667),
# which sources all four files itself. Wrap any command in tcon_rpc to get a
# single "TCONOK ..." / "TCONERR ..." reply.
#
# How this differs from tcon_call / tcon_dump_emmc:
#   - one FUN_00006A98 call reads a whole chunk, not one sector. The firmware
#     itself reads up to 0x2D8000 bytes per call (0x12592).
#   - SP is pinned. tcon_call moves SP down 8 bytes on every 5-argument call
#     and never restores it: harmless for a few hundred calls, but a bulk dump
#     would walk the stack through all of DTCM.
#   - the return trap stays armed for the whole session, and before every call
#     the FPB is read back to confirm that the trap and the three guards
#     (0x640C blanking, 0x6C8C / 0x6D50 eMMC writes) are really armed.
#   - flag 0xABCD: FUN_00006A98 skips its USB-busy wait (and the IRQ 27
#     enable / disable pair around that wait); the driver still receives
#     flag 0. Disassembly: flag 0 = NVIC enable 27 (0x1842E), wait while USB
#     busy, NVIC disable 27 (0x183D4), read, NVIC enable 27. Flag 0xABCD =
#     read, NVIC enable 27. So IRQ 27 is left ENABLED after every call either
#     way; the difference is that with 0xABCD the read itself runs with IRQ 27
#     enabled rather than disabled.
#   - hard/bus/memmanage faults halt at the vector (vector_catch) instead of
#     running the firmware's fault handler.
#
# Nothing here writes to the eMMC. RAM writes: the staging buffer, one canary
# word per read, and a 24-byte helper routine placed in the firmware's own
# 512-byte eMMC read buffer at 0x2021C000.
# ---------------------------------------------------------------------------

set ::TCON_BULK_FLAG   0xABCD
set ::TCON_BULK_STAGE  0x20220000   ;# staging buffer (probed before use)
set ::TCON_BULK_CHUNK  0x10000      ;# staging size = largest single read
set ::TCON_BULK_CODE   0x2021C000   ;# helper routine (firmware read buffer)
set ::TCON_BULK_WAIT   30000        ;# ms per call
set ::TCON_FN_EMMC_WR1 0x00006C8C   ;# eMMC write (FUN_00006DD4 retries this)
set ::TCON_FN_EMMC_WR2 0x00006D50   ;# eMMC write, second path
set ::TCON_BULK_GUARDS [list $::TCON_FN_BLANK $::TCON_FN_EMMC_WR1 $::TCON_FN_EMMC_WR2]

# base SP of the bulk session; survives re-sourcing, cleared by reset_to_scan
if {![info exists ::TCON_BULK_SP]} {
    set ::TCON_BULK_SP 0
}

# uniform(buf, len) -> r0 = 1 if every word of buf equals the first word
#     ldr r2,[r0]; adds r1,r0,r1
#  1: ldr r3,[r0],#4; cmp r3,r2; bne 2f; cmp r0,r1; bne 1b; movs r0,#1; bx lr
#  2: movs r0,#0; bx lr
set ::TCON_BULK_UNIFORM_CODE {0x6802 0x1841 0xF850 0x3B04 0x4293 0xD103 0x4288 0xD1F9 0x2001 0x4770 0x2000 0x4770}

# --------------------------------------------------------------------------
# RPC wrapper: always returns one line, never raises.
# --------------------------------------------------------------------------
proc tcon_rpc {args} {
    if {[catch {uplevel 1 $args} r]} {
        return "TCONERR [string map [list "\n" " | "] $r]"
    }
    return "TCONOK [string map [list "\n" " | "] $r]"
}

# --------------------------------------------------------------------------
# state helpers
# --------------------------------------------------------------------------
proc tcon_bulk_curstate {} {
    return [[target current] curstate]
}

proc tcon_bulk_require_halted {} {
    set st [tcon_bulk_curstate]
    if {$st ne "halted"} {
        error "target is '$st', not halted"
    }
}

# Enabled code comparators in the FPB, read from the hardware (not from
# OpenOCD's breakpoint list). Handles FPB v1 and v2.
proc tcon_bulk_fpb_addrs {} {
    set ctrl [tcon_rd32 0xE0002000]
    if {!($ctrl & 1)} {
        return {}
    }
    set rev [expr {($ctrl >> 28) & 0xF}]
    set n [expr {(($ctrl >> 8) & 0x70) | (($ctrl >> 4) & 0xF)}]
    set out {}
    foreach c [read_memory 0xE0002008 32 $n] {
        if {!($c & 1)} {
            continue
        }
        if {$rev == 0} {
            set a [expr {$c & 0x1FFFFFFC}]
            if {(($c >> 30) & 3) == 2} {
                set a [expr {$a | 2}]
            }
        } else {
            set a [expr {$c & 0xFFFFFFFE}]
        }
        lappend out [format 0x%08x $a]
    }
    return $out
}

proc tcon_bulk_missing {addrs} {
    set fpb [tcon_bulk_fpb_addrs]
    set miss {}
    foreach g $addrs {
        set found 0
        foreach a $fpb {
            if {$a == $g} {
                set found 1
            }
        }
        if {!$found} {
            lappend miss [format 0x%08x $g]
        }
    }
    return $miss
}

proc tcon_bulk_arm {addrs} {
    foreach g $addrs {
        if {[llength [tcon_bulk_missing [list $g]]]} {
            tcon_rbp_quiet $g
            bp $g 2 hw
        }
    }
    set miss [tcon_bulk_missing $addrs]
    if {[llength $miss]} {
        error "breakpoints not armed in the FPB: $miss"
    }
}

proc tcon_bulk_state {} {
    set st [tcon_bulk_curstate]
    set r "state=$st"
    if {$st ne "halted"} {
        return $r
    }
    append r [format " pc=0x%08x sp=0x%08x" [tcon_rdreg pc] [tcon_rdreg sp]]
    append r " fpb=[join [tcon_bulk_fpb_addrs] ,]"
    set gm [tcon_bulk_missing $::TCON_BULK_GUARDS]
    if {[llength $gm]} {
        append r " guards=MISSING:[join $gm ,]"
    } else {
        append r " guards=ok"
    }
    if {[llength [tcon_bulk_missing [list $::TCON_TRAP]]]} {
        append r " trap=0"
    } else {
        append r " trap=1"
    }
    append r [format " cfg=%d base_sp=0x%08x" [tcon_rd32 0x200016B8] $::TCON_BULK_SP]
    return $r
}

# --------------------------------------------------------------------------
# getting to the dump state
# --------------------------------------------------------------------------

# Plain halt plus the three guards. Used on both SoCs back to back, so a
# watchdog reset of a halted SoC cannot reach the blanking routine unguarded.
proc tcon_bulk_halt_and_guard {} {
    halt
    tcon_bulk_require_halted
    tcon_bulk_arm $::TCON_BULK_GUARDS
    return [tcon_bulk_state]
}

# pnidprobe's tcon_reset_to_scan with all three guards armed through the
# reboot. writeguards=0 drops the two eMMC-write guards for the reboot only
# (use if the boot itself legitimately writes and trips them).
proc tcon_bulk_reset_to_scan {{writeguards 1}} {
    tcon_bulk_require_halted
    if {$writeguards} {
        tcon_bulk_arm $::TCON_BULK_GUARDS
    } else {
        tcon_rbp_quiet $::TCON_FN_EMMC_WR1
        tcon_rbp_quiet $::TCON_FN_EMMC_WR2
        tcon_bulk_arm [list $::TCON_FN_BLANK]
    }
    set ::TCON_BULK_SP 0
    tcon_reset_to_scan
    tcon_bulk_arm $::TCON_BULK_GUARDS
    return [tcon_bulk_state]
}

# Start (or re-join) a bulk session. Valid from the post-scan halt (0x29C2)
# or from the return trap of an earlier session (0x414).
proc tcon_bulk_begin {{stage ""} {chunk ""}} {
    tcon_bulk_require_halted
    if {$stage ne ""} {
        set ::TCON_BULK_STAGE [expr {$stage}]
    }
    if {$chunk ne ""} {
        set ::TCON_BULK_CHUNK [expr {$chunk}]
    }
    if {$::TCON_BULK_CHUNK <= 0 || $::TCON_BULK_CHUNK % 0x200 || $::TCON_BULK_STAGE % 4} {
        error [format "bad staging 0x%08x +0x%x (chunk must be a multiple of 512)" \
                      $::TCON_BULK_STAGE $::TCON_BULK_CHUNK]
    }
    set pc [tcon_rdreg pc]
    if {$pc != $::TCON_BP_SCAN && $pc != $::TCON_TRAP} {
        error [format "pc is 0x%08x; expected 0x%08x (after reset_to_scan) or 0x%08x (bulk session) - run prepare" \
                      $pc $::TCON_BP_SCAN $::TCON_TRAP]
    }
    set code [read_memory 0x000029C0 32 2]
    if {[lindex $code 0] != 0x4a04ff2b || [lindex $code 1] != 0x68106851} {
        error "code at 0x29c0 is not the Apr-2023 FW"
    }
    tcon_bulk_arm $::TCON_BULK_GUARDS
    tcon_bulk_arm [list $::TCON_TRAP]
    catch {cortex_m vector_catch hard_err mm_err bus_err}

    if {![tcon_ram_probe $::TCON_BULK_STAGE $::TCON_BULK_CHUNK]} {
        error [format "staging RAM probe failed at 0x%08x +0x%x" $::TCON_BULK_STAGE $::TCON_BULK_CHUNK]
    }
    if {![tcon_ram_probe $::TCON_BULK_CODE 0x40]} {
        error [format "helper RAM probe failed at 0x%08x" $::TCON_BULK_CODE]
    }
    write_memory $::TCON_BULK_CODE 16 $::TCON_BULK_UNIFORM_CODE
    set back [read_memory $::TCON_BULK_CODE 16 [llength $::TCON_BULK_UNIFORM_CODE]]
    foreach a $back b $::TCON_BULK_UNIFORM_CODE {
        if {$a != $b} {
            error "helper routine read-back mismatch"
        }
    }

    if {$::TCON_BULK_SP == 0} {
        set sp [expr {[tcon_rdreg sp] & ~7}]
        if {$sp < 0x20000800 || $sp > 0x20020000} {
            error [format "sp 0x%08x is not in DTCM - STOP" $sp]
        }
        set ::TCON_BULK_SP $sp
    }
    return [format "%s stage=0x%08x chunk=0x%x" [tcon_bulk_state] $::TCON_BULK_STAGE $::TCON_BULK_CHUNK]
}

# --------------------------------------------------------------------------
# calling target code
# --------------------------------------------------------------------------

# Like tcon_call, but SP is pinned to the session base, the trap stays
# armed, and the guards are checked in the FPB before every call.
proc tcon_bulk_call {func a0 a1 a2 a3 {a4 ""}} {
    tcon_bulk_require_halted
    if {$::TCON_BULK_SP == 0} {
        error "no bulk session - run tcon_bulk_begin"
    }
    set miss [tcon_bulk_missing [concat $::TCON_BULK_GUARDS [list $::TCON_TRAP]]]
    if {[llength $miss]} {
        error "breakpoints missing from the FPB: $miss - STOP"
    }
    set base $::TCON_BULK_SP
    set sp $base
    if {$a4 ne ""} {
        set sp [expr {$base - 8}]
        write_memory $sp 32 [list $a4]
    }
    set regs [list r0 $a0 r1 $a1 r2 $a2 r3 $a3 sp $sp lr [expr {$::TCON_TRAP | 1}] pc $func]
    set psr [tcon_psr_name]
    if {$psr ne ""} {
        lappend regs $psr 0x01000000
    }
    set_reg $regs
    resume
    if {[catch {wait_halt $::TCON_BULK_WAIT} msg]} {
        catch {halt}
        set where "?"
        catch {set where [format 0x%08x [tcon_rdreg pc]]}
        error [format "call 0x%08x timed out (%s); re-halted at %s - STOP, do not resume" \
                      $func $msg $where]
    }
    set pc [tcon_rdreg pc]
    if {$pc != $::TCON_TRAP} {
        error [format "call 0x%08x stopped at 0x%08x, not the return trap - STOP, do not resume" \
                      $func $pc]
    }
    set spnow [tcon_rdreg sp]
    if {$spnow != $sp} {
        error [format "call 0x%08x returned with sp 0x%08x, expected 0x%08x - possible reset, STOP" \
                      $func $spnow $sp]
    }
    set r0 [tcon_rdreg r0]
    set_reg [list sp $base]
    return $r0
}

# One FUN_00006A98 read of len bytes from eMMC addr into stage+off.
# A canary is planted in the last word first; canary=1 means that word was
# not overwritten (short read, or data that happens to match).
proc tcon_bulk_read {addr len {off 0}} {
    if {($addr % 0x200) || ($len % 0x200) || ($off % 0x200) || $len <= 0} {
        error "addr, len and off must be multiples of 512"
    }
    if {$off + $len > $::TCON_BULK_CHUNK} {
        error [format "off+len 0x%x exceeds staging size 0x%x" [expr {$off + $len}] $::TCON_BULK_CHUNK]
    }
    set buf [expr {$::TCON_BULK_STAGE + $off}]
    set tail [expr {$buf + $len - 4}]
    set canary [expr {0xC0DE0000 | ((($addr >> 9) + ($len >> 9)) & 0xFFFF)}]
    write_memory $tail 32 [list $canary]
    set t0 [clock milliseconds]
    set rc [tcon_bulk_call $::FN_EMMC_READ 0 $buf $addr $len $::TCON_BULK_FLAG]
    set ms [expr {[clock milliseconds] - $t0}]
    set hit [expr {[tcon_rd32 $tail] == $canary}]
    return [format "rc=0x%x canary=%d ms=%d" $rc $hit $ms]
}

# Is stage+off .. +len one repeated word? Runs on the target, so blank
# chunks need not cross SWD.
# The helper lives in the firmware's own eMMC read buffer, so check it is
# intact before running it; rewrite (and report hr=1) if anything touched it.
proc tcon_bulk_helper_same {} {
    set n [llength $::TCON_BULK_UNIFORM_CODE]
    foreach a [read_memory $::TCON_BULK_CODE 16 $n] b $::TCON_BULK_UNIFORM_CODE {
        if {$a != $b} {
            return 0
        }
    }
    return 1
}

proc tcon_bulk_helper_check {} {
    if {[tcon_bulk_helper_same]} {
        return 0
    }
    write_memory $::TCON_BULK_CODE 16 $::TCON_BULK_UNIFORM_CODE
    if {![tcon_bulk_helper_same]} {
        error "helper routine at 0x2021c000 corrupted and could not be rewritten - STOP"
    }
    return 1
}

proc tcon_bulk_uniform {len {off 0}} {
    set hr [tcon_bulk_helper_check]
    set buf [expr {$::TCON_BULK_STAGE + $off}]
    set u [tcon_bulk_call $::TCON_BULK_CODE $buf $len 0 0]
    return [format "uni=%d w0=0x%08x hr=%d" $u [tcon_rd32 $buf] $hr]
}

# RAM-only self test of the helper routine.
proc tcon_bulk_uniform_selftest {} {
    tcon_bulk_helper_check
    set buf $::TCON_BULK_STAGE
    set z {}
    set f {}
    for {set i 0} {$i < 64} {incr i} {
        lappend z 0
        lappend f 0xFFFFFFFF
    }
    write_memory $buf 32 $z
    set zero [tcon_bulk_call $::TCON_BULK_CODE $buf 256 0 0]
    write_memory [expr {$buf + 252}] 32 {1}
    set last [tcon_bulk_call $::TCON_BULK_CODE $buf 256 0 0]
    write_memory $buf 32 $f
    set ff [tcon_bulk_call $::TCON_BULK_CODE $buf 256 0 0]
    write_memory [expr {$buf + 128}] 32 {0xFFFFFFFE}
    set mid [tcon_bulk_call $::TCON_BULK_CODE $buf 256 0 0]
    return "zero=$zero last=$last ff=$ff mid=$mid"
}

# Save len bytes of target memory (default: the staging buffer) to path.
proc tcon_bulk_dump {path len {addr ""}} {
    if {$addr eq ""} {
        set addr $::TCON_BULK_STAGE
    }
    set t0 [clock milliseconds]
    dump_image $path $addr $len
    return [format "ms=%d" [expr {[clock milliseconds] - $t0}]]
}

echo "tconbulk.tcl loaded (driven by tcon_bulkdump.py). Commands:"
echo "  tcon_bulk_state              halted? pc, FPB, guards, trap"
echo "  tcon_bulk_begin ?STAGE CHUNK? start a bulk session at 0x29C2"
echo "  tcon_bulk_read ADDR LEN ?OFF? one multi-sector read into staging"
echo "  tcon_bulk_dump PATH LEN ?ADDR? save staging (or ADDR) to PATH"

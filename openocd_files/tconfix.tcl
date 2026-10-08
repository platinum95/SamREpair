# ---------------------------------------------------------------------------
# tconfix.tcl - restore the blanked FW#1 header (eMMC 0x0) from FW#2's
# header (eMMC 0x500000), the verified procedure from dossier section 5,
# with extra checks. THIS FILE WRITES TO THE eMMC (one 512-byte sector at 0x0).
#
# Source AFTER tconutils.tcl, tcondump.tcl, pnidprobe.tcl and tconbulk.tcl.
# Normally driven by tcon_fixheader.py. Reads and the write use tcon_call and
# the firmware's own routines with flag 0, exactly as in section 5.
#
# Buffers: the bulk staging buffer (probed by tcon_bulk_begin):
#     stage + 0x000   FW#2 header as read (the write source)
#     stage + 0x200   FW#1 header as read, and the read-back after the write
# ---------------------------------------------------------------------------

set ::TCON_FN_EMMC_WRITE 0x00006DD4   ;# FUN_00006DD4 (dev, buf, addr, len, flag)
set ::TCON_FW2_HDR_ADDR  0x00500000
set ::TCON_FIX_BUF2      [expr {$::TCON_BULK_STAGE}]
set ::TCON_FIX_BUF1      [expr {$::TCON_BULK_STAGE + 0x200}]

# Exact FW#2 header words of the Apr-2023 build (dossier section 5)
set ::TCON_FW2_MAGIC     0xa5a55a5a
set ::TCON_FW2_TYPE      0xf1000042   ;# +0x1F8, validated by BL1
set ::TCON_FW2_CSUM      0x2cd4c603   ;# +0x1FC, body checksum
set ::TCON_FW2_VERSION   "230423A"    ;# +0x40

proc tcon_fix_require_point {} {
    tcon_bulk_require_halted
    set pc [tcon_rdreg pc]
    if {$pc != $::TCON_BP_SCAN && $pc != $::TCON_TRAP} {
        error [format "pc is 0x%08x; expected 0x%08x (post-scan) or 0x%08x (call trap) - STOP" \
                      $pc $::TCON_BP_SCAN $::TCON_TRAP]
    }
    set code [read_memory 0x000029C0 32 2]
    if {[lindex $code 0] != 0x4a04ff2b || [lindex $code 1] != 0x68106851} {
        error "code at 0x29c0 is not the Apr-2023 FW - STOP"
    }
}

proc tcon_fix_words {addr} {
    return [read_memory $addr 32 128]
}

proc tcon_fix_all_zero {words} {
    foreach w $words {
        if {$w != 0} {
            return 0
        }
    }
    return 1
}

proc tcon_fix_same {wa wb} {
    foreach a $wa b $wb {
        if {$a != $b} {
            return 0
        }
    }
    return 1
}

# Read both headers (flag 0, one sector each) and classify them.
# Returns "fw1=zero|same|other fw2=ok|bad:<why> cfg=N"
proc tcon_fix_header_check {} {
    tcon_fix_require_point
    tcon_emmc_read_to $::TCON_FW2_HDR_ADDR $::TCON_FIX_BUF2
    tcon_emmc_read_to 0 $::TCON_FIX_BUF1
    set w2 [tcon_fix_words $::TCON_FIX_BUF2]
    set w1 [tcon_fix_words $::TCON_FIX_BUF1]

    set why {}
    if {[lindex $w2 0] != $::TCON_FW2_MAGIC} {
        lappend why [format "magic=0x%08x" [lindex $w2 0]]
    }
    if {[lindex $w2 [expr {0x1F8 / 4}]] != $::TCON_FW2_TYPE} {
        lappend why [format "type=0x%08x" [lindex $w2 [expr {0x1F8 / 4}]]]
    }
    if {[lindex $w2 [expr {0x1FC / 4}]] != $::TCON_FW2_CSUM} {
        lappend why [format "csum=0x%08x" [lindex $w2 [expr {0x1FC / 4}]]]
    }
    set ver [tcon_ascii [expr {$::TCON_FIX_BUF2 + 0x40}] [string length $::TCON_FW2_VERSION]]
    if {$ver ne $::TCON_FW2_VERSION} {
        lappend why "version=$ver"
    }
    set fw2 [expr {[llength $why] ? "bad:[join $why ,]" : "ok"}]

    if {[tcon_fix_all_zero $w1]} {
        set fw1 "zero"
    } elseif {[tcon_fix_same $w1 $w2]} {
        set fw1 "same"
    } else {
        set fw1 "other"
    }
    return [format "fw1=%s fw2=%s cfg=%d" $fw1 $fw2 [tcon_rd32 0x200016B8]]
}

# Write FW#2's header over FW#1's, then read back and compare all 512 bytes.
# Re-checks immediately before writing and refuses unless fw1=zero, fw2=ok.
proc tcon_fix_header_write {} {
    set st [tcon_fix_header_check]
    if {![string match "fw1=zero fw2=ok *" $st]} {
        error "refusing to write: $st"
    }
    # the blanking guard stays armed; the two write guards are lifted for
    # this single call only (the write goes FUN_00006DD4 -> FUN_00006C8C)
    tcon_bulk_arm [list $::TCON_FN_BLANK]
    tcon_rbp_quiet $::TCON_FN_EMMC_WR1
    tcon_rbp_quiet $::TCON_FN_EMMC_WR2
    set failed [catch {tcon_call $::TCON_FN_EMMC_WRITE 0 $::TCON_FIX_BUF2 0 0x200 0} rc]
    set rearm [catch {tcon_bulk_arm [list $::TCON_FN_EMMC_WR1 $::TCON_FN_EMMC_WR2]} rearm_msg]
    if {$failed} {
        error "write call failed: $rc - STOP, do not resume, power cycle"
    }
    if {$rc != 0} {
        error [format "write returned 0x%08x - STOP, do not resume, power cycle" $rc]
    }

    # read back into BUF1 and compare word for word with the source
    tcon_emmc_read_to 0 $::TCON_FIX_BUF1
    set w1 [tcon_fix_words $::TCON_FIX_BUF1]
    set w2 [tcon_fix_words $::TCON_FIX_BUF2]
    if {![tcon_fix_same $w1 $w2]} {
        error "READ-BACK MISMATCH after write - STOP, do not resume, power cycle"
    }
    if {$rearm} {
        return "written=1 verify=ok guards=REARM-FAILED:$rearm_msg"
    }
    return "written=1 verify=ok guards=ok"
}

echo "tconfix.tcl loaded (WRITES eMMC 0x0). Commands:"
echo "  tcon_fix_header_check   classify FW#1 / FW#2 headers (read-only)"
echo "  tcon_fix_header_write   restore FW#1 header from FW#2, verify"

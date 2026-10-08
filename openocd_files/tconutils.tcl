# ---------------------------------------------------------------------------
# tconutils.tcl - TCON diagnostics for OpenOCD
#
# Load into a running OpenOCD instance:
#     telnet localhost 4444
#     source /path/to/tconutils.tcl
#
# Procedures:
#     tcon_patch           apply the boot-handshake patches to this target
#     tcon_halt_at_scan    stop just after the config scan returns
#     tcon_validators      run the config validators for cfg 0 and cfg 1
#     tcon_emmc            dump eMMC sectors of interest to files
#     tcon_probe_all       halt at scan point, then validators + eMMC
#     tcon_call FN ARGS    call a target function, returns r0
#     tcon_test_call       verbose single call, for debugging the mechanism
#     tcon_regs            print key registers
#     tcon_reglist         list every register name this build knows
#
# NOTE: tcon_validators / tcon_emmc clobber registers and firmware buffers.
#       Expect to reboot and re-patch afterwards.
# ---------------------------------------------------------------------------

set ::TCON_BP_SCAN   0x000029C2   ;# just after FUN_00002818 (config scan)
set ::TCON_BP_BOOT   0x000029B8   ;# FUN_000029b8 entry, used by tcon_patch
set ::TCON_TRAP      0x00000414   ;# reset handler, used as a return trap
set ::TCON_HARDFAULT 0x0000F160   ;# for recognising a fault return
set ::TCON_WAIT      30000        ;# ms; validators checksum ~1MB
set ::TCON_SCRATCH   0x2021C000   ;# firmware's 512-byte eMMC read buffer
set ::TCON_CLR_PRIMASK 0          ;# set 1 if calls hang waiting on interrupts

# PSR register naming varies between OpenOCD builds; detected at first use.
set ::TCON_PSR_NAME    ""
set ::TCON_PSR_CHECKED 0

# firmware routines (Apr-2023 build)
set ::FN_VAL_BCD     0x000037DC   ;# FUN_000037dc(cfg) - blobs B,C,D
set ::FN_VAL_A       0x000037C4   ;# FUN_000037c4(cfg) - blob A
set ::FN_VAL_SLOT    0x0000380A   ;# FUN_0000380a(cfg) - slot id
set ::FN_EMMC_READ   0x00006A98   ;# FUN_00006a98(dev, buf, addr, len, flag)

# patch table: {address value description}
set ::TCON_PATCHES {
    {0x000029E6 0xBF00 "NOP cbnz r4 - ignore struct0"}
    {0x000029E8 0xBF00 "NOP cbnz r5 - force handshake path"}
    {0x000029FE 0xBF00 "NOP bl 0x640c lo - no eMMC blanking"}
    {0x00002A00 0xBF00 "NOP bl 0x640c hi"}
    {0x00002A02 0xBF00 "NOP bl 0x2a20 lo - no reset on SPI fail"}
    {0x00002A04 0xBF00 "NOP bl 0x2a20 hi"}
    {0x0000277E 0xE003 "cbnz -> b - GPIO5 timeout safety net"}
}

# eMMC offsets to dump: {address filename description}
set ::TCON_EMMC_DUMPS {
    {0x000000 "emmc_000000.bin" "FW#1 header (expect all zeros)"}
    {0x000200 "emmc_000200.bin" "FW#1 body +0x200 (cmp vs running.bin @0)"}
    {0x001000 "emmc_001000.bin" "FW#1 body +0x1000"}
    {0x0B0000 "emmc_0B0000.bin" "cfg0 blob A header"}
    {0x1D0000 "emmc_1D0000.bin" "cfg0 blob B header"}
    {0x2E0000 "emmc_2E0000.bin" "cfg0 blob C header"}
    {0x3F0000 "emmc_3F0000.bin" "cfg0 blob D header"}
    {0x5B0000 "emmc_5B0000.bin" "cfg1 blob A header (known good)"}
    {0x6D0000 "emmc_6D0000.bin" "cfg1 blob B header (known good)"}
}

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

# Find whatever this build calls the program status register.
# On Cortex-M the Thumb bit is always set, so if we cannot find it we
# simply skip setting it - the target is already in Thumb state.
proc tcon_psr_name {} {
    if {$::TCON_PSR_CHECKED} {
        return $::TCON_PSR_NAME
    }
    set ::TCON_PSR_CHECKED 1
    foreach cand {xPSR xpsr XPSR PSR psr cpsr} {
        if {![catch {get_reg $cand}]} {
            set ::TCON_PSR_NAME $cand
            echo [format "PSR register detected as '%s'" $cand]
            return $cand
        }
    }
    echo "note: no PSR register name recognised - skipping T-bit setup"
    echo "      (harmless on Cortex-M, the Thumb bit is always set)"
    echo "      run 'tcon_reglist' to see available names"
    return ""
}

proc tcon_reglist {} {
    echo "registers known to this build:"
    if {[catch {reg} out]} {
        echo "  error: $out"
    } else {
        echo $out
    }
}

proc tcon_rdreg {name} {
    set raw [dict get [get_reg $name] $name]
    return [expr {$raw + 0}]
}

proc tcon_rd32 {addr} {
    return [lindex [read_memory $addr 32 1] 0]
}

proc tcon_rd16 {addr} {
    return [lindex [read_memory $addr 16 1] 0]
}

proc tcon_rbp_quiet {addr} {
    catch {rbp $addr}
}

proc tcon_regs {} {
    set names {pc sp lr r0 r1 r2 r3}
    set psr [tcon_psr_name]
    if {$psr ne ""} {
        lappend names $psr
    }
    foreach r $names {
        if {[catch {tcon_rdreg $r} v]} {
            echo [format "  %-6s <error: %s>" $r $v]
        } else {
            echo [format "  %-6s 0x%08x" $r $v]
        }
    }
}

proc tcon_where {pc} {
    if {$pc == $::TCON_HARDFAULT} {
        return "HardFault handler - check stack alignment"
    }
    if {$pc == $::TCON_TRAP} {
        return "return trap (normal)"
    }
    return "unexpected"
}

# Call a target function. Up to 5 arguments (5th passed on the stack).
proc tcon_call {func args} {
    set nargs [llength $args]
    if {$nargs > 5} {
        error "tcon_call: max 5 args, got $nargs"
    }

    set sp [expr {[tcon_rdreg sp] & ~7}]
    if {$nargs == 5} {
        set sp [expr {$sp - 8}]
        write_memory $sp 32 [list [lindex $args 4]]
    }

    tcon_rbp_quiet $::TCON_TRAP
    bp $::TCON_TRAP 2 hw

    for {set i 0} {$i < 4 && $i < $nargs} {incr i} {
        set_reg [list r$i [lindex $args $i]]
    }

    set reglist [list sp $sp lr [expr {$::TCON_TRAP | 1}] pc $func]
    set psr [tcon_psr_name]
    if {$psr ne ""} {
        lappend reglist $psr 0x01000000
    }
    set_reg $reglist

    if {$::TCON_CLR_PRIMASK} {
        catch {set_reg {primask 0}}
    }

    resume
    set timedout [catch {wait_halt $::TCON_WAIT} waitmsg]
    set pc [tcon_rdreg pc]
    tcon_rbp_quiet $::TCON_TRAP

    if {$timedout} {
        error [format "call 0x%08x: wait_halt failed (%s); pc now 0x%08x - %s" \
                      $func $waitmsg $pc [tcon_where $pc]]
    }
    if {$pc != $::TCON_TRAP} {
        error [format "call 0x%08x returned to 0x%08x - %s" \
                      $func $pc [tcon_where $pc]]
    }
    return [tcon_rdreg r0]
}

proc tcon_test_call {{func 0x000037DC} {arg 1}} {
    echo [format "test call 0x%08x(%d)" $func $arg]
    echo "registers before:"
    tcon_regs
    if {[catch {tcon_call $func $arg} r]} {
        echo [format "ERROR: %s" $r]
        echo "registers after:"
        tcon_regs
        return ""
    }
    echo [format "returned r0 = 0x%08x" $r]
    return $r
}

proc tcon_halt_at_scan {} {
    halt
    tcon_rbp_quiet $::TCON_BP_SCAN
    tcon_rbp_quiet $::TCON_TRAP
    bp $::TCON_BP_SCAN 2 hw
    resume
    set timedout [catch {wait_halt $::TCON_WAIT} waitmsg]
    set pc [tcon_rdreg pc]
    tcon_rbp_quiet $::TCON_BP_SCAN
    if {$timedout} {
        error [format "wait_halt failed (%s); pc 0x%08x" $waitmsg $pc]
    }
    if {$pc != $::TCON_BP_SCAN} {
        error [format "halted at 0x%08x, expected 0x%08x" $pc $::TCON_BP_SCAN]
    }
    echo [format "stopped at 0x%08x (post config-scan)" $pc]
}

# --------------------------------------------------------------------------
# patching
# --------------------------------------------------------------------------

proc tcon_patch {} {
    halt
    tcon_rbp_quiet $::TCON_BP_BOOT
    bp $::TCON_BP_BOOT 2 hw
    resume
    set timedout [catch {wait_halt $::TCON_WAIT} waitmsg]
    set pc [tcon_rdreg pc]
    tcon_rbp_quiet $::TCON_BP_BOOT
    if {$timedout} {
        error [format "wait_halt failed (%s); pc 0x%08x" $waitmsg $pc]
    }
    if {$pc != $::TCON_BP_BOOT} {
        error [format "halted at 0x%08x, expected 0x%08x" $pc $::TCON_BP_BOOT]
    }
    echo [format "stopped at 0x%08x, applying patches" $pc]

    foreach entry $::TCON_PATCHES {
        lassign $entry addr val desc
        write_memory $addr 16 [list $val]
    }

    set ok 1
    foreach entry $::TCON_PATCHES {
        lassign $entry addr val desc
        set got [tcon_rd16 $addr]
        if {$got == $val} {
            set tag "ok "
        } else {
            set tag "BAD"
            set ok 0
        }
        echo [format "  \[%s\] 0x%08x = 0x%04x (want 0x%04x)  %s" \
                     $tag $addr $got $val $desc]
    }
    if {$ok} {
        echo "patches verified - target halted, 'resume' when ready"
    } else {
        echo "VERIFY FAILED - target left halted"
    }
    return $ok
}

# --------------------------------------------------------------------------
# config validators
# --------------------------------------------------------------------------

proc tcon_validators {} {
    echo ""
    echo "=== config validators (nonzero = pass) ==="
    echo "cfg 1 is the control and should pass"
    echo ""

    set checks [list \
        [list "blobsBCD FUN_000037dc" $::FN_VAL_BCD] \
        [list "blobA    FUN_000037c4" $::FN_VAL_A] \
        [list "slotid   FUN_0000380a" $::FN_VAL_SLOT]]

    foreach cfg {1 0} {
        echo [format "  --- config %d ---" $cfg]
        foreach chk $checks {
            lassign $chk label fn
            if {[catch {tcon_call $fn $cfg} r]} {
                echo [format "    %s cfg=%d -> ERROR: %s" $label $cfg $r]
            } else {
                if {$r != 0} {
                    set verdict "PASS"
                } else {
                    set verdict "FAIL"
                }
                echo [format "    %s cfg=%d -> 0x%08x  %s" \
                             $label $cfg $r $verdict]
            }
        }
    }
}

# --------------------------------------------------------------------------
# eMMC dumps
# --------------------------------------------------------------------------

proc tcon_emmc_read {addr {len 0x200}} {
    set rc [tcon_call $::FN_EMMC_READ 0 $::TCON_SCRATCH $addr $len 0]
    if {$rc != 0} {
        echo [format "    warning: read 0x%06x returned 0x%08x" $addr $rc]
    }
    return $rc
}

proc tcon_emmc {} {
    echo ""
    echo "=== eMMC dumps ==="
    foreach entry $::TCON_EMMC_DUMPS {
        lassign $entry addr fname desc
        if {[catch {tcon_emmc_read $addr} err]} {
            echo [format "  0x%06x -> ERROR: %s" $addr $err]
            continue
        }
        if {[catch {dump_image $fname $::TCON_SCRATCH 0x200} derr]} {
            echo [format "  0x%06x -> dump_image failed: %s" $addr $derr]
            continue
        }

        set w0    [tcon_rd32 $::TCON_SCRATCH]
        set magic [tcon_rd32 [expr {$::TCON_SCRATCH + 0x28}]]
        set ver   [tcon_rd16 [expr {$::TCON_SCRATCH + 0x5C}]]
        set csum  [tcon_rd32 [expr {$::TCON_SCRATCH + 0x60}]]

        echo [format "  0x%06x -> %s   %s" $addr $fname $desc]
        echo [format "      word0=0x%08x  +0x28 magic=0x%08x (want 0xcfcfcfcf)" \
                     $w0 $magic]
        echo [format "      +0x5c ver=%d (want 4)  +0x60 csum=0x%08x" \
                     $ver $csum]
    }
    echo ""
    echo "  Verify FW#1 body survived:"
    echo "    cmp -n 512 emmc_000200.bin running.bin && echo MATCH"
}

# --------------------------------------------------------------------------
# top level
# --------------------------------------------------------------------------

proc tcon_probe_all {} {
    tcon_halt_at_scan
    tcon_validators
    tcon_emmc
    echo ""
    echo "Done. Firmware state disturbed - reboot and re-patch"
    echo "(tcon_patch, or patch2.py for the coordinated two-chip resume)."
}

echo "tconutils.tcl loaded. Commands:"
echo "  tcon_patch         apply handshake patches to this target"
echo "  tcon_halt_at_scan  stop just after the config scan"
echo "  tcon_probe_all     halt, then validators + eMMC dumps"
echo "  tcon_validators    validators only (after tcon_halt_at_scan)"
echo "  tcon_emmc          eMMC dumps only (after tcon_halt_at_scan)"
echo "  tcon_test_call     verbose single call, for debugging"
echo "  tcon_regs          print key registers"
echo "  tcon_reglist       list register names this build knows"

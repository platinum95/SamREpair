# ---------------------------------------------------------------------------
# sim_target.tcl - a simulated TCON target for testing tconbulk.tcl and
# tcon_bulkdump.py WITHOUT hardware.
#
# Run the bundled OpenOCD headless with `adapter driver dummy` and source this
# file FIRST, then the four real .tcl files. It shadows every target primitive
# the real files use (halt/resume/wait_halt/reset, bp/rbp, read_memory/
# write_memory, get_reg/set_reg, target, cortex_m, dump_image) with Tcl procs
# that model:
#   - ITCM 0x0..0x60000 backed by running.bin (so 0x29C0 carries the real FW
#     signature and clockcheck's ITCM dump matches),
#   - a 64 KiB staging window at 0x20220000 held as a byte string,
#   - generic byte-addressable RAM elsewhere (for the RAM probe and helper),
#   - an FPB (v2, 8 comparators) so guard/trap arming is observable,
#   - the eMMC user area backed by a sparse file ($::SIM_EMMC),
#   - FUN_00006A98 (eMMC read) and the uniform helper as "executed" by resume.
#
# Fault injection is driven by a control file ($::SIM_FAULT_FILE) that the
# test writes one keyword into:
#   readfail:0xADDR   reads whose range covers ADDR return rc!=0, no fill
#   mismatch:0xADDR   reads covering ADDR return different data every 2nd call
#   timeout           resume leaves the core running (wait_halt times out)
#   spmismatch        eMMC-read calls return with sp shifted
#   badpc             calls return to a wrong pc (not the trap)
#   blank             a reset that has the 0x640C guard armed halts there
#   writefail         eMMC writes succeed but return rc=1
# and, for the calibration copy (tconwrite.tcl / tcon_copycal.py), faults on
# writes / reads whose range covers ADDR. An optional :N after the address
# limits the fault to the first N hits (e.g. writecorrupt:0x4400000:1):
#   writecorrupt:0xADDR  the byte at ADDR is written flipped
#   writenoop:0xADDR     the write returns 0 and writes nothing
#   writefail:0xADDR     the write returns 1 and writes nothing
#   tornwrite:0xADDR     the first half of the write lands, then "power loss":
#                        the core never returns (wait_halt times out)
#   readnoop:0xADDR      the read returns 0 and does not fill the buffer
#
# Every FUN_00006DD4 (eMMC write) call is logged with the FPB state at the
# time (sim_write_log): the test fails a write made with 0x640C, 0x6D50 or the
# trap missing, or with 0x6C8C still armed.
#
# CFG/MS (0x200016B8) is latched at every simulated boot from the eMMC FW#1
# header: blank -> 1 (FW#2 / config 1), anything else -> 0.
#
# Jim here has open/seek/read/clock/string but NO `binary`; bytes round-trip
# through read/puts, so files are copied as byte strings. Set with -c before
# sourcing: SIM_EMMC, SIM_RUNNING, and optionally SIM_FAULT_FILE.
# ---------------------------------------------------------------------------

if {![info exists ::SIM_RUNNING]} { set ::SIM_RUNNING "running.bin" }
if {![info exists ::SIM_EMMC]}    { error "set ::SIM_EMMC before sourcing sim_target.tcl" }

set ::SIM_STAGE_BASE 0x20220000
set ::SIM_STAGE_SIZE 0x10000
set ::SIM_ITCM_END   0x60000
set ::SIM_FPCTRL     0x10000081   ;# enable=1, rev=1 (v2), 8 comparators
set ::SIM_NCMP       8

set ::SIM_STATE "running"
set ::SIM_MISMATCH_TOGGLE 0

array set ::SIM_REG {pc 0x1234 sp 0x2001FF00 lr 0 r0 0 r1 0 r2 0 r3 0}
array set ::SIM_MEM {}
for {set i 0} {$i < $::SIM_NCMP} {incr i} { set ::SIM_CMP($i) 0 }

# staging as a byte string of zeros
set ::SIM_STAGE [string repeat [format %c 0] $::SIM_STAGE_SIZE]

# --------------------------------------------------------------------------
# byte helpers
# --------------------------------------------------------------------------
proc sim_zeros {n} { return [string repeat [format %c 0] $n] }

proc sim_file_read {path off n} {
    if {[catch {open $path r} f]} { return [sim_zeros $n] }
    seek $f $off
    set d [read $f $n]
    close $f
    set got [string length $d]
    if {$got < $n} { append d [sim_zeros [expr {$n - $got}]] }
    return $d
}

proc sim_emmc_read {addr n} { return [sim_file_read $::SIM_EMMC $addr $n] }

proc sim_emmc_write {addr data} {
    set f [open $::SIM_EMMC r+]
    seek $f $addr
    puts -nonewline $f $data
    close $f
}

# A simulated boot: BL1 falls back to FW#2 / config 1 if the FW#1 header is
# blank (dossier section 4), else FW#1 / config 0.
proc sim_latch_cfg {} {
    set h [sim_emmc_read 0 0x200]
    set ::SIM_CFG [expr {$h eq [sim_zeros 0x200] ? 1 : 0}]
    return $::SIM_CFG
}

proc sim_mem_get {a} {
    if {[info exists ::SIM_MEM($a)]} { return $::SIM_MEM($a) }
    return 0
}

# Return exactly n bytes at addr as a byte string.
proc sim_read_bytes {addr n} {
    set end [expr {$addr + $n}]
    if {$end <= $::SIM_ITCM_END} {
        return [sim_file_read $::SIM_RUNNING $addr $n]
    }
    set sb $::SIM_STAGE_BASE
    set se [expr {$sb + $::SIM_STAGE_SIZE}]
    if {$addr >= $sb && $end <= $se} {
        return [string range $::SIM_STAGE [expr {$addr - $sb}] [expr {$end - $sb - 1}]]
    }
    set s ""
    for {set i 0} {$i < $n} {incr i} {
        append s [format %c [sim_mem_get [expr {$addr + $i}]]]
    }
    return $s
}

proc sim_write_bytes {addr str} {
    set n [string length $str]
    set sb $::SIM_STAGE_BASE
    set se [expr {$sb + $::SIM_STAGE_SIZE}]
    set end [expr {$addr + $n}]
    if {$addr >= $sb && $end <= $se} {
        set off [expr {$addr - $sb}]
        set pre [string range $::SIM_STAGE 0 [expr {$off - 1}]]
        set post [string range $::SIM_STAGE [expr {$off + $n}] end]
        set ::SIM_STAGE "$pre$str$post"
        return
    }
    for {set i 0} {$i < $n} {incr i} {
        set ::SIM_MEM([expr {$addr + $i}]) [scan [string index $str $i] %c]
    }
}

proc sim_bytes_to_words {str width} {
    set bpw [expr {$width / 8}]
    set len [string length $str]
    set out {}
    for {set i 0} {$i < $len} {incr i $bpw} {
        set v 0
        for {set b 0} {$b < $bpw} {incr b} {
            set c [scan [string index $str [expr {$i + $b}]] %c]
            if {$c eq ""} { set c 0 }
            set v [expr {$v | ($c << (8 * $b))}]
        }
        lappend out $v
    }
    return $out
}

proc sim_words_to_bytes {vals width} {
    set bpw [expr {$width / 8}]
    set s ""
    foreach v $vals {
        for {set b 0} {$b < $bpw} {incr b} {
            append s [format %c [expr {($v >> (8 * $b)) & 0xFF}]]
        }
    }
    return $s
}

# --------------------------------------------------------------------------
# fault control
# --------------------------------------------------------------------------
proc sim_fault {} {
    if {![info exists ::SIM_FAULT_FILE]} { return "" }
    if {[catch {open $::SIM_FAULT_FILE r} f]} { return "" }
    set s [read $f]
    close $f
    return [string trim $s]
}

proc sim_fault_covers {fault kind addr len} {
    if {![string match "$kind:*" $fault]} { return 0 }
    set t [expr {[lindex [split $fault ":"] 1]}]
    return [expr {$t >= $addr && $t < $addr + $len}]
}

# Like sim_fault_covers, but honours an optional hit limit "kind:ADDR:N".
# Hits are counted per fault string, so writing a new fault resets nothing
# unless the string changes; sim_fault_reset clears the counters.
array set ::SIM_FAULT_HITS {}
proc sim_fault_hit {fault kind addr len} {
    if {![sim_fault_covers $fault $kind $addr $len]} { return 0 }
    set p [split $fault ":"]
    if {[llength $p] < 3} { return 1 }
    if {![info exists ::SIM_FAULT_HITS($fault)]} { set ::SIM_FAULT_HITS($fault) 0 }
    incr ::SIM_FAULT_HITS($fault)
    return [expr {$::SIM_FAULT_HITS($fault) <= [lindex $p 2]}]
}

proc sim_fault_reset {} {
    array unset ::SIM_FAULT_HITS
    array set ::SIM_FAULT_HITS {}
    return ""
}

# The address a "kind:ADDR[:N]" fault names.
proc sim_fault_addr {fault} {
    return [expr {[lindex [split $fault ":"] 1]}]
}

# --------------------------------------------------------------------------
# FPB model
# --------------------------------------------------------------------------
proc sim_cmp_has {addr} {
    set a [expr {$addr & ~1}]
    for {set i 0} {$i < $::SIM_NCMP} {incr i} {
        set v $::SIM_CMP($i)
        if {($v & 1) && (($v & ~1) == $a)} { return 1 }
    }
    return 0
}

# --------------------------------------------------------------------------
# shadowed OpenOCD primitives
# --------------------------------------------------------------------------
proc target {args} {
    if {[lindex $args 0] eq "current"} { return "simtgt" }
    return ""
}
proc simtgt {args} {
    if {[lindex $args 0] eq "curstate"} { return $::SIM_STATE }
    return ""
}
proc cortex_m {args} { return "" }

proc halt {args} { set ::SIM_STATE "halted"; return "" }

proc wait_halt {args} {
    if {$::SIM_STATE ne "halted"} { error "wait_halt: timed out" }
    return ""
}

proc bp {addr size type} {
    set a [expr {$addr & ~1}]
    if {[sim_cmp_has $a]} { return "" }
    for {set i 0} {$i < $::SIM_NCMP} {incr i} {
        if {!($::SIM_CMP($i) & 1)} {
            set ::SIM_CMP($i) [expr {$a | 1}]
            return ""
        }
    }
    error "no free FPB comparator"
}

proc rbp {addr} {
    set a [expr {$addr & ~1}]
    for {set i 0} {$i < $::SIM_NCMP} {incr i} {
        set v $::SIM_CMP($i)
        if {($v & 1) && (($v & ~1) == $a)} { set ::SIM_CMP($i) 0 }
    }
    return ""
}

proc get_reg {name} {
    if {$name eq "xPSR"} { return [list xPSR 0x01000000] }
    if {[info exists ::SIM_REG($name)]} {
        return [list $name $::SIM_REG($name)]
    }
    error "unknown register $name"
}

proc set_reg {vals} {
    foreach {k v} $vals {
        set ::SIM_REG($k) [expr {$v}]
    }
    return ""
}

proc read_memory {addr width count} {
    if {$addr == 0xE0002000 && $width == 32} { return [list $::SIM_FPCTRL] }
    if {$addr == 0xE0002008 && $width == 32} {
        set out {}
        for {set i 0} {$i < $count && $i < $::SIM_NCMP} {incr i} {
            lappend out $::SIM_CMP($i)
        }
        return $out
    }
    if {($addr == 0x200016B8 || $addr == 0x200016B4) && $width == 32} {
        set out {}
        for {set i 0} {$i < $count} {incr i} { lappend out $::SIM_CFG }
        return $out
    }
    set n [expr {($width / 8) * $count}]
    return [sim_bytes_to_words [sim_read_bytes $addr $n] $width]
}

proc write_memory {addr width vals} {
    sim_write_bytes $addr [sim_words_to_bytes $vals $width]
    return ""
}

proc dump_image {path addr len} {
    set data [sim_read_bytes $addr $len]
    set f [open $path w]
    puts -nonewline $f $data
    close $f
    return ""
}

# load_image FILE ADDR ?bin? - only the raw binary form is modelled
proc load_image {path addr args} {
    if {[llength $args] && [lindex $args 0] ne "bin"} {
        error "sim load_image: only 'bin' is modelled"
    }
    set f [open $path r]
    set data [read $f]
    close $f
    sim_write_bytes [expr {$addr}] $data
    return "[string length $data] bytes written at address [format 0x%08x $addr]"
}

# --------------------------------------------------------------------------
# "execution": resume interprets pc, models the call, halts at the trap.
# --------------------------------------------------------------------------
proc sim_do_read {} {
    set buf  $::SIM_REG(r1)
    set addr $::SIM_REG(r2)
    set len  $::SIM_REG(r3)
    set fault [sim_fault]
    if {[sim_fault_covers $fault "readfail" $addr $len]} {
        set ::SIM_REG(r0) 1
        return
    }
    if {[sim_fault_hit $fault "readnoop" $addr $len]} {
        set ::SIM_REG(r0) 0
        return
    }
    set data [sim_emmc_read $addr $len]
    if {[sim_fault_covers $fault "mismatch" $addr $len]} {
        incr ::SIM_MISMATCH_TOGGLE
        if {$::SIM_MISMATCH_TOGGLE % 2 == 0} {
            set b0 [scan [string index $data 0] %c]
            set data "[format %c [expr {($b0 + 1) & 0xFF}]][string range $data 1 end]"
        }
    }
    sim_write_bytes $buf $data
    set ::SIM_REG(r0) 0
}

# Record one FUN_00006DD4 call: {addr len flag 640c 6d50 trap 6c8c}, the last
# four being whether each is armed in the FPB at the time of the call.
set ::SIM_WRITE_LOG {}
proc sim_log_write {} {
    set flag [lindex [sim_bytes_to_words [sim_read_bytes $::SIM_REG(sp) 4] 32] 0]
    lappend ::SIM_WRITE_LOG [list [format 0x%08x $::SIM_REG(r2)] \
        [format 0x%x $::SIM_REG(r3)] [format 0x%x $flag] \
        [sim_cmp_has 0x640C] [sim_cmp_has 0x6D50] [sim_cmp_has 0x414] \
        [sim_cmp_has 0x6C8C]]
}

proc sim_write_log {} { return $::SIM_WRITE_LOG }
proc sim_write_log_clear {} { set ::SIM_WRITE_LOG {}; return "" }

# The write itself, with the copy faults. Returns 0 for a torn write (the
# caller leaves the core "running"), else 1 with r0 set.
proc sim_do_write {fault} {
    set buf  $::SIM_REG(r1)
    set addr $::SIM_REG(r2)
    set len  $::SIM_REG(r3)
    set data [sim_read_bytes $buf $len]
    if {[sim_fault_hit $fault "tornwrite" $addr $len]} {
        sim_emmc_write $addr [string range $data 0 [expr {$len / 2 - 1}]]
        return 0
    }
    if {[sim_fault_hit $fault "writefail" $addr $len]} {
        set ::SIM_REG(r0) 1
        return 1
    }
    if {[sim_fault_hit $fault "writenoop" $addr $len]} {
        set ::SIM_REG(r0) 0
        return 1
    }
    if {[sim_fault_hit $fault "writecorrupt" $addr $len]} {
        set o [expr {[sim_fault_addr $fault] - $addr}]
        set b [scan [string index $data $o] %c]
        set data "[string range $data 0 [expr {$o - 1}]][format %c [expr {$b ^ 0xFF}]][string range $data [expr {$o + 1}] end]"
    }
    sim_emmc_write $addr $data
    set ::SIM_REG(r0) [expr {$fault eq "writefail" ? 1 : 0}]
    return 1
}

proc sim_do_uniform {} {
    set buf $::SIM_REG(r0)
    set len $::SIM_REG(r1)
    set str [sim_read_bytes $buf $len]
    set w0 [string range $str 0 3]
    set uni 1
    for {set i 4} {$i < $len} {incr i 4} {
        if {[string range $str $i [expr {$i + 3}]] ne $w0} { set uni 0; break }
    }
    set ::SIM_REG(r0) $uni
}

proc resume {args} {
    set fault [sim_fault]
    if {$fault eq "timeout"} { set ::SIM_STATE "running"; return "" }
    set pc $::SIM_REG(pc)
    if {$pc == 0x6A98} {
        sim_do_read
        if {$fault eq "spmismatch"} {
            set ::SIM_REG(sp) [expr {$::SIM_REG(sp) - 4}]
        }
        set ::SIM_REG(pc) [expr {$fault eq "badpc" ? 0xdead : 0x414}]
        set ::SIM_STATE "halted"
        return ""
    }
    if {$pc == 0x2021C000} {
        sim_do_uniform
        set ::SIM_REG(pc) 0x414
        set ::SIM_STATE "halted"
        return ""
    }
    if {$pc == 0x6DD4} {
        # eMMC write: FUN_00006DD4 goes through FUN_00006C8C, so an armed
        # write guard halts there first and nothing is written
        sim_log_write
        if {[sim_cmp_has 0x6C8C]} {
            set ::SIM_REG(pc) 0x6C8C
        } elseif {![sim_do_write $fault]} {
            # torn write: power lost mid-write, the core never comes back
            set ::SIM_STATE "running"
            return ""
        } else {
            set ::SIM_REG(pc) 0x414
        }
        set ::SIM_STATE "halted"
        return ""
    }
    # anything else: model the blank-header boot loop, which comes back round
    # to the post-scan point if its breakpoint is armed
    if {[sim_cmp_has 0x29C2]} {
        set ::SIM_REG(pc) 0x29C2
        set ::SIM_REG(sp) 0x2001FF00
        sim_latch_cfg
    }
    set ::SIM_STATE "halted"
    return ""
}

# Test hook: a power cycle at the wall. Clears the FPB (it only survives
# OpenOCD restarts, not power cycles) and leaves the core running from reset.
proc sim_power_cycle {} {
    for {set i 0} {$i < $::SIM_NCMP} {incr i} { set ::SIM_CMP($i) 0 }
    set ::SIM_REG(pc) 0x0
    set ::SIM_REG(sp) 0x2001FF00
    set ::SIM_STATE "running"
    sim_latch_cfg
    return ""
}

proc reset {args} {
    set fault [sim_fault]
    if {$fault eq "blank" && [sim_cmp_has 0x640C]} {
        set ::SIM_REG(pc) 0x640C
    } elseif {[sim_cmp_has 0x29C2]} {
        set ::SIM_REG(pc) 0x29C2
    } else {
        set ::SIM_REG(pc) 0x0
    }
    set ::SIM_REG(sp) 0x2001FF00
    set ::SIM_STATE "halted"
    sim_latch_cfg
    return ""
}

# adapter speed is a real OpenOCD command under the dummy driver; leave it.

sim_latch_cfg

echo "sim_target.tcl loaded (emmc=$::SIM_EMMC running=$::SIM_RUNNING)"

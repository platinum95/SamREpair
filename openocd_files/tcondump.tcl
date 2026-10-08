# ---------------------------------------------------------------------------
# tcondump.tcl - bulk eMMC dumping for the TCON
#
# Source AFTER tconutils.tcl:
#     source /path/to/tconutils.tcl
#     source /path/to/tcondump.tcl
#
# Typical use - dump the whole FW#1 body and compare against running.bin:
#     tcon_halt_at_scan
#     tcon_ram_probe 0x20220000 0x10000      ;# confirm staging RAM is usable
#     tcon_dump_emmc 0x200 0x60000 fw1
#     # then on the host:
#     #   cat fw1_*.bin > fw1_body.bin
#     #   cmp fw1_body.bin running.bin && echo IDENTICAL
#
# The firmware's own read routine only fills 512 bytes at a time, so this
# stages N sectors into consecutive RAM and issues one dump_image per block.
# ---------------------------------------------------------------------------

set ::TCON_STAGE_ADDR 0x20220000   ;# staging buffer base (probe before use!)
set ::TCON_STAGE_SIZE 0x10000      ;# 64 KiB = 128 sectors per block

# --------------------------------------------------------------------------
# RAM probe - verify a region is writable and restore whatever was there.
# --------------------------------------------------------------------------
proc tcon_ram_probe {addr {len 0x10000}} {
    set words 4
    set probes [list $addr \
                     [expr {$addr + ($len / 2)}] \
                     [expr {$addr + $len - 16}]]

    foreach p $probes {
        if {[catch {read_memory $p 32 $words} orig]} {
            echo [format "  0x%08x NOT READABLE (%s)" $p $orig]
            return 0
        }
        set pattern {0xA5A55A5A 0x5A5AA5A5 0xDEADBEEF 0x12345678}
        if {[catch {write_memory $p 32 $pattern} werr]} {
            echo [format "  0x%08x NOT WRITABLE (%s)" $p $werr]
            return 0
        }
        set back [read_memory $p 32 $words]
        # restore original contents before judging
        catch {write_memory $p 32 $orig}

        for {set i 0} {$i < $words} {incr i} {
            if {[lindex $back $i] != [lindex $pattern $i]} {
                echo [format "  0x%08x MISMATCH: wrote 0x%08x read 0x%08x" \
                             $p [lindex $pattern $i] [lindex $back $i]]
                return 0
            }
        }
        echo [format "  0x%08x ok" $p]
    }
    echo [format "staging region 0x%08x +0x%x looks usable" $addr $len]
    return 1
}

# --------------------------------------------------------------------------
# Read one 512-byte sector into an arbitrary buffer address.
# --------------------------------------------------------------------------
proc tcon_emmc_read_to {addr buf {len 0x200}} {
    set rc [tcon_call $::FN_EMMC_READ 0 $buf $addr $len 0]
    if {$rc != 0} {
        error [format "eMMC read 0x%06x -> rc 0x%08x" $addr $rc]
    }
    return $rc
}

# --------------------------------------------------------------------------
# Dump an eMMC range to a series of block files.
#   start  eMMC byte offset (must be sector aligned)
#   bytes  total length to read (multiple of 0x200)
#   prefix output filename prefix; files are <prefix>_0000.bin etc
# --------------------------------------------------------------------------
proc tcon_dump_emmc {start bytes prefix} {
    if {$start % 0x200 != 0} {
        error "start must be 512-byte aligned"
    }
    if {$bytes % 0x200 != 0} {
        error "length must be a multiple of 512"
    }

    set stage $::TCON_STAGE_ADDR
    set blocksz $::TCON_STAGE_SIZE
    set per_block [expr {$blocksz / 0x200}]
    set total_sectors [expr {$bytes / 0x200}]
    set nblocks [expr {($total_sectors + $per_block - 1) / $per_block}]

    echo [format "dumping 0x%x bytes from eMMC 0x%06x" $bytes $start]
    echo [format "  %d sectors, %d block(s) of %d sectors via 0x%08x" \
                 $total_sectors $nblocks $per_block $stage]

    set sector 0
    for {set b 0} {$b < $nblocks} {incr b} {
        set n [expr {$total_sectors - $sector}]
        if {$n > $per_block} { set n $per_block }

        for {set i 0} {$i < $n} {incr i} {
            set emmc_addr [expr {$start + ($sector + $i) * 0x200}]
            set buf [expr {$stage + $i * 0x200}]
            if {[catch {tcon_emmc_read_to $emmc_addr $buf} err]} {
                echo [format "  FAILED at 0x%06x: %s" $emmc_addr $err]
                return 0
            }
        }

        set fname [format "%s_%04d.bin" $prefix $b]
        if {[catch {dump_image $fname $stage [expr {$n * 0x200}]} derr]} {
            echo [format "  dump_image failed: %s" $derr]
            return 0
        }
        set sector [expr {$sector + $n}]
        echo [format "  block %d/%d -> %s  (through eMMC 0x%06x)" \
                     [expr {$b + 1}] $nblocks $fname \
                     [expr {$start + $sector * 0x200 - 1}]]
    }

    echo ""
    echo "done. On the host:"
    echo [format "  cat %s_*.bin > %s_body.bin" $prefix $prefix]
    echo [format "  cmp %s_body.bin running.bin && echo IDENTICAL" $prefix]
    return 1
}

# --------------------------------------------------------------------------
# Convenience: dump the whole FW#1 body (skipping the blanked header)
# to match running.bin exactly.
# --------------------------------------------------------------------------
proc tcon_dump_fw1 {{prefix fw1}} {
    return [tcon_dump_emmc 0x200 0x60000 $prefix]
}

proc tcon_dump_all_emmc {{prefix fw1}} {
    return [tcon_dump_emmc 0x000 0x100000000 $prefix]
}

echo "tcondump.tcl loaded. Commands:"
echo "  tcon_ram_probe ADDR LEN   check a staging region is usable RAM"
echo "  tcon_dump_emmc START LEN PREFIX   bulk dump to block files"
echo "  tcon_dump_fw1             dump FW#1 body (0x200, 0x60000) as fw1_*.bin"
echo ""
echo "Set ::TCON_STAGE_ADDR / ::TCON_STAGE_SIZE if 0x20220000 is unsuitable."

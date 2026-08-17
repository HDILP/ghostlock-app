from capstone import *

kern = 'D:/Downloads/payload_dumper-master/output/ghostlock_analysis/kernel_symbols.elf'

# Direct approach: use the ELF symbol table to get vaddrs, then compute file offsets
# The LOAD segment: vaddr starts at 0xffffffc008000000, file offset 0x1c0
# All kernel text symbols are within this segment.
# Symbol vaddr = 0xffffffc008XXXXXX → file_offset = (XXXXXX) + 0x1c0

# Pre-computed kernel offsets (vaddr - 0xffffffc008000000):
# rb_erase: 0xab0784
# rt_mutex_adjust_prio_chain: 0x1eb65c  
# task_blocks_on_rt_mutex: 0x1ea860
# remove_waiter: 0x1eafc4
# guard: 0x1ec0d0 (inside adjust_prio_chain + 0xa74)

symbols = {
    'rb_erase': 0xab0784,
    'rt_mutex_adjust_prio_chain': 0x1eb65c,
    'task_blocks_on_rt_mutex': 0x1ea860,
    'remove_waiter': 0x1eafc4,
}

with open(kern, 'rb') as f:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    
    def disasm_at(name, koffset, count, markers=None):
        if markers is None:
            markers = {}
        foff = koffset + 0x1c0  # add ELF LOAD segment offset
        f.seek(foff)
        data = f.read(count * 16 + 16)
        print(f"\n=== {name} (koffs=0x{koffset:x}, file@0x{foff:x}) ===")
        n = 0
        for insn in md.disasm(data, 0xffffffc008000000 + koffset):
            m = markers.get(insn.address, "")
            print(f'  0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str}{m}')
            n += 1
            if n >= count:
                break
        print(f"  ({n} insns)")
    
    # rb_erase write at 0xab07f4: show from 0xab07b0 (16 before guard area)
    # rb_erase starts at 0xab0784, write at 0xab07f4 (offset +0x70)
    disasm_at("rb_erase+0x2c to +0xb0 (includes write @+0x70)", 
              0xab07b0, 40, {
                  0xffffffc0081ab07f4: "  <<< WRITE: str x8,[x11]"
              })
    
    # Guard at 0x81ec0d0 = adjust_prio_chain(0x1eb65c) + 0xa74
    # Show from adjust_prio_chain + 0xa54 to +0xb00
    disasm_at("adjust_prio_chain+0xa54 (guard region)", 
              0x1eb65c + 0xa54, 30, {
                  0xffffffc0081ec0d0: "  <<< GUARD: cmp x9,x28"
              })
    
    # List guard at 0x81ebb00 = adjust_prio_chain + 0x4a4
    disasm_at("adjust_prio_chain+0x484 (list guard)", 
              0x1eb65c + 0x484, 30, {
                  0xffffffc0081ebb00: "  <<< LIST GUARD"
              })
    
    # task_blocks_on_rt_mutex
    disasm_at("task_blocks_on_rt_mutex (entry)", 
              0x1ea860, 80)

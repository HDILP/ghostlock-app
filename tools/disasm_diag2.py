from capstone import *

kern = 'D:/Downloads/payload_dumper-master/output/ghostlock_analysis/kernel_symbols.elf'

with open(kern, 'rb') as f:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    
    def disasm_at(koffset, count, markers=None):
        if markers is None:
            markers = {}
        foff = koffset + 0x1c0
        f.seek(foff)
        data = f.read(count * 16 + 16)
        n = 0
        for insn in md.disasm(data, 0xffffffc008000000 + koffset):
            m = markers.get(insn.address, "")
            print(f'  0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str}{m}')
            n += 1
            if n >= count:
                break
    
    # After the guard passes, trace to the actual pi_waiters erase call
    # The guard is at 0x81ec0d0, after passing it goes to 0x81ec0d8
    # Let me trace the full path from guard pass to rb_erase
    print("=== PATH AFTER GUARD PASS (0x81ec0d8 - 0x81ec13c) ===")
    disasm_at(0x1ec0d8, 25, {
        0xffffffc0081ec11c: "  <<< CALL rb_erase (pi_waiters erase)"
    })
    
    # Also look at the path BEFORE the guard to understand what x28 is
    print("\n=== BEFORE GUARD (0x81ebbf0 - 0x81ebc50) ===")
    disasm_at(0x1ebbf0, 25, {
        0xffffffc0081ebc28: "  <<< EARLY SKIP: if x8==x28 → skip pi erase"
    })
    
    # rb_erase entry
    print("\n=== RB_ERASE ENTRY (0x81ab0784) ===")
    disasm_at(0xab0784, 30, {})

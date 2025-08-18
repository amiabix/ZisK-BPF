#!/usr/bin/env python3

def create_mov_test_program():
    """Create a test BPF program using MOV_IMM and MOV_REG opcodes"""
    
    # BPF instruction format: [opcode, dst_src, offset_low, offset_high, imm_low, imm_mid_low, imm_mid_high, imm_high]
    
    program = bytearray()
    
    # Instruction 1: MOV r1, 0x42 (MOV_IMM 0xB7)
    # r1 = 66
    program.extend([0xB7, 0x01, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00])
    
    # Instruction 2: MOV r2, 0x1234 (MOV_IMM 0xB7)
    # r2 = 4660
    program.extend([0xB7, 0x02, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00])
    
    # Instruction 3: MOV r0, r1 (MOV_REG 0xBF)
    # r0 = r1 (copy value 66)
    program.extend([0xBF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    
    # Instruction 4: MOV r3, r2 (MOV_REG 0xBF)
    # r3 = r2 (copy value 4660)
    program.extend([0xBF, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    
    # Instruction 5: EXIT (0x95)
    program.extend([0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    
    return program

def main():
    print("🚀 CREATING MOV TEST PROGRAM")
    print("============================")
    
    program = create_mov_test_program()
    
    print(f"📊 Program size: {len(program)} bytes ({len(program)//8} instructions)")
    print(f"🔧 Instructions: MOV_IMM x2, MOV_REG x2, EXIT x1")
    
    # Save to build/input.bin
    import os
    os.makedirs('build', exist_ok=True)
    
    with open('build/input.bin', 'wb') as f:
        f.write(program)
    
    print("✅ Saved to build/input.bin")
    
    # Show instruction breakdown
    print("\n📋 Instruction Breakdown:")
    instructions = [
        ("MOV_IMM r1, 66", "0xB7 0x01 0x00 0x00 0x42 0x00 0x00 0x00"),
        ("MOV_IMM r2, 4660", "0xB7 0x02 0x00 0x00 0x34 0x12 0x00 0x00"),
        ("MOV_REG r0, r1", "0xBF 0x01 0x00 0x00 0x00 0x00 0x00 0x00"),
        ("MOV_REG r3, r2", "0xBF 0x32 0x00 0x00 0x00 0x00 0x00 0x00"),
        ("EXIT", "0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00"),
    ]
    
    for i, (desc, bytes_hex) in enumerate(instructions):
        print(f"  {i+1}. {desc}: {bytes_hex}")
    
    print(f"\n🎯 Expected final state:")
    print(f"  r0 = 66 (copied from r1)")
    print(f"  r1 = 66 (set by MOV_IMM)")
    print(f"  r2 = 4660 (set by MOV_IMM)")
    print(f"  r3 = 4660 (copied from r2)")
    print(f"  r4-r10 = 0 (unchanged)")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Test Week 1 Arithmetic Opcodes - End-to-End Proof Generation
Creates a BPF program with ADD64_REG, SUB64_REG, MUL64_REG operations
"""

import struct

def create_week1_test_program():
    """Create a BPF program that tests Week 1 arithmetic opcodes"""
    
    # BPF program: r1 = 10, r2 = 5, r3 = r1 + r2, r4 = r1 - r2, r5 = r1 * r2, exit
    program = bytearray()
    
    # MOV r1, 10 (MOV_IMM r1, 10)
    program.extend([0xB7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00])
    
    # MOV r2, 5 (MOV_IMM r2, 5)  
    program.extend([0xB7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00])
    
    # ADD r3, r1, r2 (ADD64_REG r3, r1, r2)
    program.extend([0x0F, 0x31, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00])
    
    # SUB r4, r1, r2 (SUB64_REG r4, r1, r2)
    program.extend([0x1F, 0x41, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00])
    
    # MUL r5, r1, r2 (MUL64_REG r5, r1, r2)
    program.extend([0x2F, 0x51, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00])
    
    # EXIT
    program.extend([0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    
    return program

def write_input_file(program_bytes):
    """Write the BPF program to input.bin for ZisK"""
    with open('input.bin', 'wb') as f:
        f.write(program_bytes)
    print(f"✅ Created input.bin with {len(program_bytes)} bytes")
    print(f"   Program: {program_bytes.hex()}")

def main():
    print("🚀 Creating Week 1 Arithmetic Test Program")
    print("=" * 50)
    
    # Create the test program
    program = create_week1_test_program()
    
    # Write to input file
    write_input_file(program)
    
    print("\n📋 Program Analysis:")
    print(f"   Instructions: 6")
    print(f"   Opcodes: MOV_IMM, MOV_IMM, ADD64_REG, SUB64_REG, MUL64_REG, EXIT")
    print(f"   Expected Results:")
    print(f"     r1 = 10, r2 = 5")
    print(f"     r3 = r1 + r2 = 15")
    print(f"     r4 = r1 - r2 = 5") 
    print(f"     r5 = r1 * r2 = 50")
    
    print("\n🎯 Ready for ZisK proof generation!")
    print("   Run: cargo-zisk build --release")
    print("   Then: cargo-zisk run --release")

if __name__ == "__main__":
    main()

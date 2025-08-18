#!/usr/bin/env python3
"""
Simple Test Program - End-to-End Proof Generation
Creates a BPF program with 8-byte instructions that our decoder can handle
"""

import struct

def create_simple_test_program():
    """Create a simple BPF program with 8-byte instructions"""
    
    # BPF program: r1 = 10, r2 = 5, r3 = r1 + r2, exit
    program = bytearray()
    
    # MOV r1, 10 (8-byte instruction)
    # opcode=0xB7, dst=1, src=0, off=0, imm=10
    program.extend([0xB7, 0x10, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00])
    
    # MOV r2, 5 (8-byte instruction)  
    # opcode=0xB7, dst=2, src=0, off=0, imm=5
    program.extend([0xB7, 0x20, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00])
    
    # ADD r3, r1, r2 (8-byte instruction)
    # opcode=0x0F, dst=3, src=1, off=0, imm=0
    program.extend([0x0F, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    
    # EXIT (8-byte instruction)
    # opcode=0x95, dst=0, src=0, off=0, imm=0
    program.extend([0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    
    return program

def write_input_file(program_bytes):
    """Write the BPF program to input.bin for ZisK"""
    with open('input.bin', 'wb') as f:
        f.write(program_bytes)
    print(f"✅ Created input.bin with {len(program_bytes)} bytes")
    print(f"   Program: {program_bytes.hex()}")

def main():
    print("🚀 Creating Simple 8-Byte BPF Test Program")
    print("=" * 50)
    
    # Create the test program
    program = create_simple_test_program()
    
    # Write to input file
    write_input_file(program)
    
    print("\n📋 Program Analysis:")
    print(f"   Instructions: 4")
    print(f"   Instruction Size: 8 bytes each")
    print(f"   Opcodes: MOV_IMM, MOV_IMM, ADD_REG, EXIT")
    print(f"   Expected Results:")
    print(f"     r1 = 10, r2 = 5")
    print(f"     r3 = r1 + r2 = 15")
    
    print("\n🎯 Ready for ZisK proof generation!")
    print("   Run: cargo-zisk build --release")
    print("   Then: cargo-zisk run --release")

if __name__ == "__main__":
    main()


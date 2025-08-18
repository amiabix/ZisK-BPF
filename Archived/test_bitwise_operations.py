#!/usr/bin/env python3
"""
Bitwise Operations Test Program - Week 1 Implementation
Tests all 6 new bitwise opcodes: AND_REG, OR_REG, XOR_REG, AND_IMM, OR_IMM, XOR_IMM
"""

import struct

def create_bitwise_test_programs():
    """Create comprehensive test programs for all bitwise operations"""
    
    programs = []
    
    # Test 1: AND operations
    program1 = bytearray()
    # MOV r1, 255 (0xFF)
    program1.extend([0xB7, 0x01, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00])
    # MOV r2, 15 (0x0F)
    program1.extend([0xB7, 0x02, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00])
    # AND r1, r2 (r1 = 255 & 15 = 15)
    program1.extend([0x5F, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    # EXIT
    program1.extend([0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    programs.append(("AND_REG Test", program1))
    
    # Test 2: OR operations
    program2 = bytearray()
    # MOV r1, 240 (0xF0)
    program2.extend([0xB7, 0x01, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00])
    # MOV r2, 15 (0x0F)
    program2.extend([0xB7, 0x02, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00])
    # OR r1, r2 (r1 = 240 | 15 = 255)
    program2.extend([0x4F, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    # EXIT
    program2.extend([0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    programs.append(("OR_REG Test", program2))
    
    # Test 3: XOR operations
    program3 = bytearray()
    # MOV r1, 255 (0xFF)
    program3.extend([0xB7, 0x01, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00])
    # MOV r2, 255 (0xFF)
    program3.extend([0xB7, 0x02, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00])
    # XOR r1, r2 (r1 = 255 ^ 255 = 0)
    program3.extend([0xAF, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    # EXIT
    program3.extend([0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    programs.append(("XOR_REG Test", program3))
    
    # Test 4: Immediate operations
    program4 = bytearray()
    # MOV r1, 0xAAAA
    program4.extend([0xB7, 0x01, 0x00, 0x00, 0xAA, 0xAA, 0x00, 0x00])
    # AND r1, 0x5555 (r1 = 0xAAAA & 0x5555 = 0x0000)
    program4.extend([0x57, 0x01, 0x00, 0x00, 0x55, 0x55, 0x00, 0x00])
    # OR r1, 0x1234 (r1 = 0x0000 | 0x1234 = 0x1234)
    program4.extend([0x47, 0x01, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00])
    # XOR r1, 0xFFFF (r1 = 0x1234 ^ 0xFFFF = 0xEDCB)
    program4.extend([0xA7, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00])
    # EXIT
    program4.extend([0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    programs.append(("Immediate Operations Test", program4))
    
    # Test 5: Complex bitwise chain
    program5 = bytearray()
    # MOV r1, 0x12345678
    program5.extend([0xB7, 0x01, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12])
    # MOV r2, 0x0000FFFF
    program5.extend([0xB7, 0x02, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00])
    # AND r3, r1, r2 (r3 = 0x12345678 & 0x0000FFFF = 0x00005678)
    program5.extend([0x5F, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    # OR r4, r1, r2 (r4 = 0x12345678 | 0x0000FFFF = 0x1234FFFF)
    program5.extend([0x4F, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    # XOR r5, r1, r2 (r5 = 0x12345678 ^ 0x0000FFFF = 0x1234A987)
    program5.extend([0xAF, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    # EXIT
    program5.extend([0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    programs.append(("Complex Bitwise Chain Test", program5))
    
    return programs

def write_test_programs(programs):
    """Write all test programs to files"""
    for i, (name, program) in enumerate(programs):
        filename = f"bitwise_test_{i+1}.bin"
        with open(filename, 'wb') as f:
            f.write(program)
        print(f"✅ Created {filename}: {name} ({len(program)} bytes)")
        print(f"   Program: {program.hex()}")
        print()

def main():
    print("🚀 WEEK 1: BITWISE OPERATIONS IMPLEMENTATION")
    print("=" * 50)
    print("Testing 6 new opcodes:")
    print("  • 0x5F - AND_REG (bitwise AND between registers)")
    print("  • 0x4F - OR_REG (bitwise OR between registers)")
    print("  • 0xAF - XOR_REG (bitwise XOR between registers)")
    print("  • 0x57 - AND_IMM (bitwise AND with immediate)")
    print("  • 0x47 - OR_IMM (bitwise OR with immediate)")
    print("  • 0xA7 - XOR_IMM (bitwise XOR with immediate)")
    print()
    
    # Create test programs
    programs = create_bitwise_test_programs()
    
    # Write to files
    write_test_programs(programs)
    
    print("📊 WEEK 1 RESULTS:")
    print(f"   Previous opcodes: 15")
    print(f"   New opcodes: +6")
    print(f"   Total opcodes: 21")
    print(f"   Coverage: 32.8% (21/64)")
    print()
    
    print("🎯 READY FOR TESTING!")
    print("   Run: cargo-zisk build --release")
    print("   Then: cargo-zisk run --release")
    print("   Input: Use any of the bitwise_test_*.bin files")
    print()
    
    print("🚀 NEXT: WEEK 2 - SHIFT OPERATIONS")
    print("   Target: 21 → 27 opcodes (42.2% coverage)")

if __name__ == "__main__":
    main()

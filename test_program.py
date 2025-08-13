#!/usr/bin/env python3

def create_test_program():
    program = bytearray()
    
    # MOV r1, 42
    program.extend([0xB7, 0x01, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00])
    
    # EXIT
    program.extend([0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    
    return program

def main():
    program = create_test_program()
    
    import os
    os.makedirs('build', exist_ok=True)
    
    with open('build/input.bin', 'wb') as f:
        f.write(program)
    
    print(f"✅ Test program created: {len(program)} bytes")
    print("🚀 Ready for ZisK execution!")

if __name__ == "__main__":
    main()

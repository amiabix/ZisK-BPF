#!/usr/bin/env python3

import sys
import os

def extract_bpf_from_so(so_file):
    """Extract actual BPF bytecode from .so file"""
    
    if not os.path.exists(so_file):
        print(f"❌ File not found: {so_file}")
        return []
    
    with open(so_file, 'rb') as f:
        data = f.read()
    
    print(f"📁 Analyzing {so_file} ({len(data)} bytes)")
    
    # Look for BPF instruction patterns
    bpf_sequences = []
    
    for i in range(len(data) - 32):
        # Check if this could be start of BPF code
        if is_valid_bpf_sequence(data[i:i+32]):  # Check 4 instructions
            # Found potential BPF code, extract it
            bpf_code = extract_sequence(data, i)
            if len(bpf_code) >= 16:  # At least 2 instructions
                bpf_sequences.append((i, bpf_code))
                print(f"🔍 Found BPF sequence at offset 0x{i:x}: {len(bpf_code)} bytes")
    
    return bpf_sequences

def is_valid_bpf_sequence(data):
    """Check if data looks like valid BPF instructions"""
    if len(data) < 32:
        return False
    
    valid_opcodes = {0x05, 0x07, 0x0F, 0x15, 0x1F, 0x25, 0x61, 0x62, 0x85, 0x95, 0xB7, 0xBF}
    
    # Check first 4 instructions
    for i in range(0, 32, 8):
        opcode = data[i]
        if opcode not in valid_opcodes:
            return False
    
    return True

def extract_sequence(data, start):
    """Extract BPF sequence starting at offset"""
    sequence = []
    
    for i in range(start, len(data) - 8, 8):
        instruction = data[i:i+8]
        opcode = instruction[0]
        
        # Stop at EXIT or invalid opcode
        if opcode == 0x95:  # EXIT
            sequence.append(instruction)
            break
        elif opcode in {0x05, 0x07, 0x0F, 0x15, 0x1F, 0x25, 0x61, 0x62, 0x85, 0xB7, 0xBF}:
            sequence.append(instruction)
        else:
            break
    
    return b''.join(sequence)

def analyze_elf_sections(so_file):
    """Analyze ELF sections to find .text and other executable sections"""
    with open(so_file, 'rb') as f:
        data = f.read()
    
    print(f"\n🔍 ELF Analysis for {so_file}:")
    
    # Check ELF magic
    if data[:4] != b'\x7fELF':
        print("❌ Not a valid ELF file")
        return
    
    # Parse ELF header (64-bit)
    e_phoff = int.from_bytes(data[32:40], 'little')
    e_phentsize = int.from_bytes(data[54:56], 'little')
    e_phnum = int.from_bytes(data[56:58], 'little')
    
    print(f"📊 Program headers: {e_phnum} entries, offset: 0x{e_phoff:x}")
    
    # Parse program headers
    for i in range(e_phnum):
        ph_offset = e_phoff + i * e_phentsize
        if ph_offset + 56 > len(data):
            continue
            
        p_type = int.from_bytes(data[ph_offset:ph_offset+4], 'little')
        p_flags = int.from_bytes(data[ph_offset+4:ph_offset+8], 'little')
        p_offset = int.from_bytes(data[ph_offset+8:ph_offset+16], 'little')
        p_filesz = int.from_bytes(data[ph_offset+40:ph_offset+48], 'little')
        
        # PT_LOAD = 1 (loadable segment)
        if p_type == 1:
            executable = (p_flags & 0x1) != 0
            print(f"  📦 Segment {i}: offset=0x{p_offset:x}, size=0x{p_filesz:x}, exec={executable}")
            
            if executable and p_filesz > 0:
                # This is executable code, look for BPF patterns
                if p_offset + p_filesz <= len(data):
                    segment_data = data[p_offset:p_offset + p_filesz]
                    print(f"    🔍 Analyzing executable segment...")
                    
                    # Look for BPF patterns in this segment
                    for j in range(0, len(segment_data) - 32, 8):
                        if is_valid_bpf_sequence(segment_data[j:j+32]):
                            print(f"    ✅ Found BPF pattern at segment offset 0x{j:x}")
                            # Extract the sequence
                            bpf_code = extract_sequence(segment_data, j)
                            if len(bpf_code) >= 16:
                                output_file = f"{so_file}_executable_{i}_offset_{j:x}.bpf"
                                with open(output_file, 'wb') as f:
                                    f.write(bpf_code)
                                print(f"    💾 Saved {len(bpf_code)} bytes to {output_file}")

# Extract from your .so files
if __name__ == "__main__":
    so_files = []
    
    # Check for .so files in current directory
    for file in os.listdir('.'):
        if file.endswith('.so'):
            so_files.append(file)
    
    if not so_files:
        print("❌ No .so files found in current directory")
        print("Available files:")
        for file in os.listdir('.'):
            print(f"  - {file}")
        sys.exit(1)
    
    print(f"🚀 Found {len(so_files)} .so files to analyze")
    
    for so_file in so_files:
        print(f"\n{'='*60}")
        print(f"📁 Processing: {so_file}")
        print(f"{'='*60}")
        
        # First analyze ELF structure
        analyze_elf_sections(so_file)
        
        # Then look for BPF patterns
        sequences = extract_bpf_from_so(so_file)
        
        for i, (offset, bpf_code) in enumerate(sequences):
            output_file = f"{so_file}_extracted_{i}.bpf"
            with open(output_file, 'wb') as f:
                f.write(bpf_code)
            print(f"✅ Extracted {len(bpf_code)} bytes to {output_file}")
        
        if not sequences:
            print("⚠️  No BPF sequences found in this file")
    
    print(f"\n🎯 Analysis complete! Check the generated .bpf files for executable code.")

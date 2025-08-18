#!/usr/bin/env python3

import struct
import json
import os
from pathlib import Path

def analyze_bpf_sequence(bpf_data):
    """Analyze a BPF sequence to understand what opcodes it uses"""
    
    if len(bpf_data) < 8:
        return None
    
    instructions = []
    opcodes_used = set()
    
    for i in range(0, len(bpf_data), 8):
        if i + 8 > len(bpf_data):
            break
            
        instruction = bpf_data[i:i+8]
        opcode = instruction[0]
        dst = (instruction[1] & 0x0F)
        src = (instruction[1] & 0xF0) >> 4
        off = struct.unpack('<h', instruction[2:4])[0]
        imm = struct.unpack('<i', instruction[4:8])[0]
        
        opcodes_used.add(opcode)
        instructions.append({
            'opcode': opcode,
            'dst': dst,
            'src': src,
            'off': off,
            'imm': imm,
        })
    
    return {
        'instructions': instructions,
        'opcodes_used': list(opcodes_used),
        'instruction_count': len(instructions),
        'size_bytes': len(bpf_data),
    }

def is_compatible_with_current_implementation(opcodes_used):
    """Check if this BPF sequence uses only implemented opcodes"""
    
    # Your current 8 implemented opcodes
    implemented_opcodes = {
        0x07,  # ADD_IMM
        0x1F,  # SUB_REG
        0x61,  # LDXW
        0x62,  # STW
        0x05,  # JA
        0x15,  # JEQ_IMM
        0x85,  # CALL
        0x95,  # EXIT
    }
    
    return all(opcode in implemented_opcodes for opcode in opcodes_used)

def create_solana_proof_input(bpf_program_data):
    """Create the SolanaProofInput structure your ZisK program expects"""
    
    # This matches your SolanaProofInput struct
    proof_input = {
        'bpf_program': list(bpf_program_data),  # Convert to list for JSON
        'accounts': [
            {
                'pubkey': [0] * 32,  # Dummy account
                'lamports': 1000000000,  # 1 SOL
                'data': [0] * 64,    # 64 bytes account data
                'owner': [0] * 32,   # System program owner
                'executable': False,
                'rent_epoch': 100,
            }
        ],
        'instruction_data': [42, 0, 0, 0],  # Simple test data
        'compute_limit': 200000,
    }
    
    return proof_input

def main():
    print("🔄 CONVERTING EXTRACTED BPF TO ZISK INPUT")
    print("=========================================")
    
    # Find all extracted BPF files
    bpf_files = list(Path('.').glob('*.so_extracted_*.bpf'))
    
    if not bpf_files:
        print("❌ No extracted BPF files found!")
        print("Run extract_bpf_bytecode.py first")
        return
    
    print(f"📁 Found {len(bpf_files)} extracted BPF sequences")
    
    compatible_programs = []
    all_programs = []
    
    # Analyze each BPF sequence
    for bpf_file in bpf_files:
        print(f"\n🔍 Analyzing {bpf_file}...")
        
        with open(bpf_file, 'rb') as f:
            bpf_data = f.read()
        
        analysis = analyze_bpf_sequence(bpf_data)
        if not analysis:
            print(f"  ❌ Invalid BPF data")
            continue
        
        print(f"  📊 {analysis['instruction_count']} instructions, {analysis['size_bytes']} bytes")
        print(f"  🔧 Opcodes: {[f'{op:02x}' for op in analysis['opcodes_used']]}")
        
        compatible = is_compatible_with_current_implementation(analysis['opcodes_used'])
        compatibility_status = "✅ COMPATIBLE" if compatible else "❌ NEEDS MORE OPCODES"
        print(f"  {compatibility_status}")
        
        program_info = {
            'file': str(bpf_file),
            'analysis': analysis,
            'compatible': compatible,
            'bpf_data': bpf_data,
        }
        
        all_programs.append(program_info)
        if compatible:
            compatible_programs.append(program_info)
    
    print(f"\n📊 ANALYSIS SUMMARY:")
    print(f"  Total programs: {len(all_programs)}")
    print(f"  Compatible with current implementation: {len(compatible_programs)}")
    
    if compatible_programs:
        print(f"\n🎯 CREATING INPUT FOR COMPATIBLE PROGRAMS:")
        
        # Create input for the first compatible program
        best_program = compatible_programs[0]
        print(f"  Using: {best_program['file']}")
        
        # Create SolanaProofInput
        proof_input = create_solana_proof_input(best_program['bpf_data'])
        
        # Save as JSON for inspection
        with open('zisk_input_preview.json', 'w') as f:
            json.dump(proof_input, f, indent=2)
        
        print(f"  💾 Preview saved to: zisk_input_preview.json")
        
        # Create input.bin for ZisK
        create_zisk_input_bin(proof_input, best_program)
        
        # Create inputs for top 5 compatible programs
        for i, program in enumerate(compatible_programs[:5]):
            create_individual_input(program, i)
    
    else:
        print(f"\n⚠️ NO COMPATIBLE PROGRAMS FOUND!")
        print(f"Most needed opcodes to add:")
        analyze_missing_opcodes(all_programs)

def create_zisk_input_bin(proof_input, program_info):
    """Create the actual input.bin file for ZisK"""
    
    try:
        # Create a simple text format that your build.rs can parse
        # This avoids bincode dependency issues
        
        # Write the BPF program data directly
        bpf_data = bytes(proof_input['bpf_program'])
        
        # Write to build/input.bin
        Path('build').mkdir(parents=True, exist_ok=True)
        
        with open('build/input.bin', 'wb') as f:
            f.write(bpf_data)
        
        print(f"  ✅ Created build/input.bin ({len(bpf_data)} bytes)")
        print(f"  📊 BPF program: {len(bpf_data)} bytes, {len(bpf_data)//8} instructions")
        
        # Also update your build.rs to use this program
        update_build_rs(program_info)
        
    except Exception as e:
        print(f"  ❌ Failed to create input.bin: {e}")
        print(f"  Error details: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()

def create_simple_binary_format(proof_input):
    """Create simple binary format for testing"""
    
    binary_data = b""
    
    # Program size (4 bytes) + program data
    program_data = bytes(proof_input['bpf_program'])
    binary_data += struct.pack('<I', len(program_data))
    binary_data += program_data
    
    # Account count (4 bytes) + account data
    accounts = proof_input['accounts']
    binary_data += struct.pack('<I', len(accounts))
    
    for account in accounts:
        # Pubkey (32 bytes)
        binary_data += bytes(account['pubkey'])
        # Lamports (8 bytes)
        binary_data += struct.pack('<Q', account['lamports'])
        # Data size (4 bytes) + data
        data = bytes(account['data'])
        binary_data += struct.pack('<I', len(data))
        binary_data += data
        # Owner (32 bytes)
        binary_data += bytes(account['owner'])
        # Executable (1 byte)
        binary_data += struct.pack('<B', 1 if account['executable'] else 0)
        # Rent epoch (8 bytes)
        binary_data += struct.pack('<Q', account['rent_epoch'])
    
    # Instruction data size (4 bytes) + instruction data
    instruction_data = bytes(proof_input['instruction_data'])
    binary_data += struct.pack('<I', len(instruction_data))
    binary_data += instruction_data
    
    # Compute limit (8 bytes)
    binary_data += struct.pack('<Q', proof_input['compute_limit'])
    
    return binary_data

def update_build_rs(program_info):
    """Update build.rs to use the extracted program"""
    
    try:
        # Create a simple version that just copies the binary data
        build_rs_content = f'''use std::fs;
use std::path::Path;

fn main() {{
    println!("cargo:rerun-if-changed=build.rs");
    
    // Use extracted BPF program: {program_info['file']}
    // Instructions: {program_info['analysis']['instruction_count']}
    // Opcodes: {[f"{op:02x}" for op in program_info['analysis']['opcodes_used']]}
    
    let input_data = fs::read("{program_info['file']}")
        .expect("Failed to read extracted BPF program");
    
    // Create build directory
    fs::create_dir_all("build")
        .expect("Failed to create build directory");
    
    // Copy the extracted program as input
    fs::write("build/input.bin", &input_data)
        .expect("Failed to write input.bin");
    
    println!("Generated input.bin with {{}} bytes", input_data.len());
}}
'''
        
        with open('build.rs', 'w') as f:
            f.write(build_rs_content)
        
        print(f"  ✅ Updated build.rs to use {program_info['file']}")
        
    except Exception as e:
        print(f"  ⚠️ Could not update build.rs: {e}")

def create_individual_input(program_info, index):
    """Create individual input file for testing"""
    
    filename = f"build/input_{index}.bin"
    
    with open(filename, 'wb') as f:
        f.write(program_info['bpf_data'])
    
    print(f"  💾 Created {filename} ({len(program_info['bpf_data'])} bytes)")

def analyze_missing_opcodes(all_programs):
    """Analyze what opcodes are most needed"""
    
    opcode_frequency = {}
    
    for program in all_programs:
        for opcode in program['analysis']['opcodes_used']:
            opcode_frequency[opcode] = opcode_frequency.get(opcode, 0) + 1
    
    # Sort by frequency
    sorted_opcodes = sorted(opcode_frequency.items(), key=lambda x: x[1], reverse=True)
    
    implemented = {0x07, 0x1F, 0x61, 0x62, 0x05, 0x15, 0x85, 0x95}
    
    print("\n🎯 TOP MISSING OPCODES TO IMPLEMENT:")
    print("-" * 35)
    
    for opcode, count in sorted_opcodes[:10]:
        if opcode not in implemented:
            name = get_opcode_name(opcode)
            percentage = (count / len(all_programs)) * 100
            print(f"  {opcode:02x} {name:12} {count:3d} programs ({percentage:4.1f}%)")

def get_opcode_name(opcode):
    """Get opcode name"""
    names = {
        0xB7: "MOV_IMM",
        0xBF: "MOV_REG", 
        0x25: "JGT_IMM",
        0x2D: "JGT_REG",
        0x37: "DIV_IMM",
        0x4F: "OR_REG",
        0x5F: "AND_REG",
        0x6F: "LSH_REG",
        0x7F: "RSH_REG",
        0x0F: "ADD_REG",
        0x17: "SUB_IMM",
    }
    return names.get(opcode, f"UNK_{opcode:02x}")

if __name__ == "__main__":
    main()

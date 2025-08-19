#!/usr/bin/env python3
"""
Extract opcode sequence from execution trace
"""

import json
import sys

# BPF opcode names for better readability
BPF_OPCODES = {
    0x00: "EXIT",
    0x01: "CALL",
    0x02: "CALLX",
    0x03: "BRANCH",
    0x04: "BRANCHX",
    0x05: "BRANCH_EQ",
    0x06: "BRANCH_NE",
    0x07: "ADD_IMM",
    0x0F: "ADD_REG",
    0x17: "SUB_IMM",
    0x1F: "SUB_REG",
    0x27: "MUL_IMM",
    0x2F: "MUL_REG",
    0x37: "DIV_IMM",
    0x3F: "DIV_REG",
    0x47: "OR_IMM",
    0x4F: "OR_REG",
    0x57: "AND_IMM",
    0x5F: "AND_REG",
    0x67: "LSH_IMM",
    0x6F: "LSH_REG",
    0x77: "RSH_IMM",
    0x7F: "RSH_REG",
    0x87: "NEG",
    0x8F: "MOD_REG",
    0x97: "XOR_IMM",
    0x9F: "XOR_REG",
    0xA7: "MOV_IMM",
    0xAF: "MOV_REG",
    0xB7: "MOV_IMM64",
    0xBF: "MOV_REG64",
    0xC7: "ARSH_REG",
    0xC8: "MOV_IMM32",
    0xCF: "ENDIAN",
    0xD4: "BE16",
    0xD5: "BE32",
    0xDC: "LE16",
    0xDD: "LE32",
    0xE0: "LD_ABS_B",
    0xE1: "LD_ABS_H",
    0xE2: "LD_ABS_W",
    0xE3: "LD_ABS_DW",
    0xE4: "LD_IND_B",
    0xE5: "LD_IND_H",
    0xE6: "LD_IND_W",
    0xE7: "LD_IND_DW",
    0xF0: "LDX_B",
    0xF1: "LDX_H",
    0xF2: "LDX_W",
    0xF3: "LDX_DW",
    0xF4: "ST_B",
    0xF5: "ST_H",
    0xF6: "ST_W",
    0xF7: "ST_DW",
    0xF8: "STX_B",
    0xF9: "STX_H",
    0xFA: "STX_W",
    0xFB: "STX_DW",
    0xFC: "JA",
    0xFD: "JEQ_IMM",
    0xFE: "JEQ_REG",
    0xFF: "JNE_IMM",
}

def get_opcode_name(opcode):
    """Get human-readable opcode name"""
    if opcode in BPF_OPCODES:
        return BPF_OPCODES[opcode]
    return f"UNKNOWN_{opcode:02X}"

def extract_opcode_sequence(trace_file):
    """Extract opcode sequence from execution trace"""
    try:
        with open(trace_file, 'r') as f:
            trace = json.load(f)
    except FileNotFoundError:
        print(f"Error: {trace_file} not found")
        return
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {trace_file}")
        return

    steps = trace.get('steps', [])
    if not steps:
        print("No steps found in trace")
        return

    print(f"📊 Opcode Sequence Analysis")
    print(f"Total steps: {len(steps)}")
    print(f"Program size: {trace.get('program_size', 'unknown')} bytes")
    print()

    # Extract opcode sequence
    opcode_sequence = []
    for step in steps:
        instruction = step.get('instruction', {})
        opcode = instruction.get('opcode', 0)
        opcode_sequence.append(opcode)

    # Display sequence
    print("🔍 Opcode Sequence (first 50):")
    for i, opcode in enumerate(opcode_sequence[:50]):
        opcode_name = get_opcode_name(opcode)
        print(f"  Step {i:3d}: 0x{opcode:02X} ({opcode_name})")

    if len(opcode_sequence) > 50:
        print(f"  ... and {len(opcode_sequence) - 50} more steps")

    # Opcode frequency analysis
    print(f"\n📈 Opcode Frequency Analysis:")
    opcode_counts = {}
    for opcode in opcode_sequence:
        opcode_counts[opcode] = opcode_counts.get(opcode, 0) + 1

    # Sort by frequency
    sorted_opcodes = sorted(opcode_counts.items(), key=lambda x: x[1], reverse=True)
    
    print("Most frequent opcodes:")
    for opcode, count in sorted_opcodes[:10]:
        opcode_name = get_opcode_name(opcode)
        percentage = (count / len(opcode_sequence)) * 100
        print(f"  0x{opcode:02X} ({opcode_name}): {count} times ({percentage:.1f}%)")

    # Save detailed sequence to file
    output_file = "opcode_sequence.txt"
    with open(output_file, 'w') as f:
        f.write("BPF Opcode Execution Sequence\n")
        f.write("=" * 40 + "\n\n")
        f.write(f"Total steps: {len(opcode_sequence)}\n")
        f.write(f"Program size: {trace.get('program_size', 'unknown')} bytes\n\n")
        
        f.write("Complete sequence:\n")
        for i, opcode in enumerate(opcode_sequence):
            opcode_name = get_opcode_name(opcode)
            f.write(f"Step {i:3d}: 0x{opcode:02X} ({opcode_name})\n")

    print(f"\n💾 Detailed sequence saved to: {output_file}")

if __name__ == "__main__":
    trace_file = "execution_trace.json"
    if len(sys.argv) > 1:
        trace_file = sys.argv[1]
    
    extract_opcode_sequence(trace_file)

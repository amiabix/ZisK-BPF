//! Instruction cost module for BPF opcodes
//! Provides compute cost information for all BPF instructions

/// Get the compute cost for a specific BPF opcode
/// 
/// # Arguments
/// * `opcode` - The BPF opcode byte
/// 
/// # Returns
/// The compute cost in units for the instruction
pub fn get_instruction_cost(opcode: u8) -> u64 {
    match opcode {
        0x95 => 1,   // EXIT
        0xB7 => 2,   // MOV_IMM (32-bit)
        0x0F => 1,   // ADD_REG
        0x1F => 1,   // SUB_REG
        0x2F => 1,   // MUL_REG
        0x3F => 1,   // DIV_REG
        0x4F => 1,   // AND_REG
        0x5F => 1,   // OR_REG
        0x6F => 1,   // XOR_REG
        0x8F => 1,   // LSH_REG
        0x9F => 1,   // RSH_REG
        0xAF => 1,   // ARSH_REG
        0xBF => 2,   // MOV_IMM (32-bit)
        
        // Memory operations (Cost: 2)
        0x61 | 0x62 | 0x63 | 0x64 | 0x65 | 0x66 | 0x67 | 0x68 | 0x69 | 0x6A | 0x6B | 0x6C | 0x6D | 0x6E | 0x6F => 2,
        0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x75 | 0x76 | 0x77 | 0x78 | 0x79 | 0x7A | 0x7B | 0x7C | 0x7D | 0x7E | 0x7F => 2,
        0x80 | 0x81 | 0x82 | 0x83 | 0x84 | 0x86 | 0x87 | 0x88 | 0x89 | 0x8A | 0x8B | 0x8C | 0x8E | 0x8F => 2,
        0x90 | 0x91 | 0x92 | 0x93 | 0x94 | 0x96 | 0x97 | 0x98 | 0x99 | 0x9A | 0x9B | 0x9C | 0x9D | 0x9E => 2,
        0xA0 | 0xA1 | 0xA2 | 0xA3 | 0xA4 | 0xA6 | 0xA7 | 0xA8 | 0xA9 | 0xAA | 0xAB | 0xAC | 0xAD | 0xAE => 2,
        0xB0 | 0xB1 | 0xB2 | 0xB3 | 0xB4 | 0xB5 | 0xB6 | 0xB8 | 0xB9 | 0xBA | 0xBB | 0xBC | 0xBD | 0xBE => 2,
        0xC0 | 0xC1 | 0xC2 | 0xC3 | 0xC4 | 0xC5 | 0xC6 | 0xC8 | 0xC9 | 0xCA | 0xCB | 0xCC | 0xCD | 0xCE => 2,
        0xD0 | 0xD1 | 0xD2 | 0xD3 | 0xD4 | 0xD5 | 0xD6 | 0xD7 | 0xD8 | 0xD9 | 0xDA | 0xDB | 0xDC | 0xDD | 0xDE | 0xDF => 2,
        0xE0 | 0xE1 | 0xE2 | 0xE3 | 0xE4 | 0xE5 | 0xE6 | 0xE7 | 0xE8 | 0xE9 | 0xEA | 0xEB | 0xEC | 0xED | 0xEE | 0xEF => 2,
        0xF0 | 0xF1 | 0xF2 | 0xF3 | 0xF4 | 0xF5 | 0xF6 | 0xF7 | 0xF8 | 0xF9 | 0xFA | 0xFB | 0xFC | 0xFD | 0xFE | 0xFF => 2,
        
        // Control flow instructions (Cost: 1)
        0x05 | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D | 0x45 | 0x4D | 0x55 | 0x5D | 0x65 | 0x6D | 0x75 | 0x7D | 0x9D | 0xA5 | 0xAD | 0xB5 | 0xBD | 0xC5 | 0xCD | 0xD5 | 0xDD | 0xE5 | 0xED | 0xF5 | 0xFD => 1,
        
        // Function calls
        0x80 => 3,   // CALL
        0x85 => 1,   // RET
        
        _ => 1,      // Default cost for unknown opcodes
    }
}

/// Create a HashMap of all instruction costs for the prover
/// CRITICAL: This must match EXACTLY with get_instruction_cost() function
pub fn create_instruction_costs() -> std::collections::HashMap<u8, u64> {
    let mut costs = std::collections::HashMap::new();
    
    // Use the SAME logic as get_instruction_cost() to ensure consistency
    
    // Standard BPF instruction costs (based on Solana's compute model)
    costs.insert(0x95, 1);   // EXIT
    costs.insert(0xB7, 2);   // MOV_IMM (32-bit)
    costs.insert(0x0F, 1);   // ADD_REG
    costs.insert(0x1F, 1);   // SUB_REG
    costs.insert(0x2F, 1);   // MUL_REG
    costs.insert(0x3F, 1);   // DIV_REG
    costs.insert(0x4F, 1);   // AND_REG
    costs.insert(0x5F, 1);   // OR_REG
    costs.insert(0x6F, 1);   // XOR_REG
    costs.insert(0x8F, 1);   // LSH_REG
    costs.insert(0x9F, 1);   // RSH_REG
    costs.insert(0xAF, 1);   // ARSH_REG
    costs.insert(0xBF, 2);   // MOV_IMM (32-bit)
    
    // Memory operations (Cost: 2) - EXACTLY as in get_instruction_cost()
    costs.insert(0x61, 2); costs.insert(0x62, 2); costs.insert(0x63, 2); costs.insert(0x64, 2);
    costs.insert(0x65, 2); costs.insert(0x66, 2); costs.insert(0x67, 2); costs.insert(0x68, 2);
    costs.insert(0x69, 2); costs.insert(0x6A, 2); costs.insert(0x6B, 2); costs.insert(0x6C, 2);
    costs.insert(0x6D, 2); costs.insert(0x6E, 2); costs.insert(0x6F, 2);
    costs.insert(0x70, 2); costs.insert(0x71, 2); costs.insert(0x72, 2); costs.insert(0x73, 2);
    costs.insert(0x74, 2); costs.insert(0x75, 2); costs.insert(0x76, 2); costs.insert(0x77, 2);
    costs.insert(0x78, 2); costs.insert(0x79, 2); costs.insert(0x7A, 2); costs.insert(0x7B, 2);
    costs.insert(0x7C, 2); costs.insert(0x7D, 2); costs.insert(0x7E, 2); costs.insert(0x7F, 2);
    
    costs.insert(0x80, 2); costs.insert(0x81, 2); costs.insert(0x82, 2); costs.insert(0x83, 2);
    costs.insert(0x84, 2); costs.insert(0x86, 2); costs.insert(0x87, 2); costs.insert(0x88, 2);
    costs.insert(0x89, 2); costs.insert(0x8A, 2); costs.insert(0x8B, 2); costs.insert(0x8C, 2);
    costs.insert(0x8E, 2); costs.insert(0x8F, 2);
    costs.insert(0x90, 2); costs.insert(0x91, 2); costs.insert(0x92, 2); costs.insert(0x93, 2);
    costs.insert(0x94, 2); costs.insert(0x96, 2); costs.insert(0x97, 2); costs.insert(0x98, 2);
    costs.insert(0x99, 2); costs.insert(0x9A, 2); costs.insert(0x9B, 2); costs.insert(0x9C, 2);
    costs.insert(0x9D, 2); costs.insert(0x9E, 2);
    costs.insert(0xA0, 2); costs.insert(0xA1, 2); costs.insert(0xA2, 2); costs.insert(0xA3, 2);
    costs.insert(0xA4, 2); costs.insert(0xA6, 2); costs.insert(0xA7, 2); costs.insert(0xA8, 2);
    costs.insert(0xA9, 2); costs.insert(0xAA, 2); costs.insert(0xAB, 2); costs.insert(0xAC, 2);
    costs.insert(0xAD, 2); costs.insert(0xAE, 2);
    costs.insert(0xB0, 2); costs.insert(0xB1, 2); costs.insert(0xB2, 2); costs.insert(0xB3, 2);
    costs.insert(0xB4, 2); costs.insert(0xB5, 2); costs.insert(0xB6, 2); costs.insert(0xB8, 2);
    costs.insert(0xB9, 2); costs.insert(0xBA, 2); costs.insert(0xBB, 2); costs.insert(0xBC, 2);
    costs.insert(0xBD, 2); costs.insert(0xBE, 2);
    costs.insert(0xC0, 2); costs.insert(0xC1, 2); costs.insert(0xC2, 2); costs.insert(0xC3, 2);
    costs.insert(0xC4, 2); costs.insert(0xC5, 2); costs.insert(0xC6, 2); costs.insert(0xC8, 2);
    costs.insert(0xC9, 2); costs.insert(0xCA, 2); costs.insert(0xCB, 2); costs.insert(0xCC, 2);
    costs.insert(0xCD, 2); costs.insert(0xCE, 2);
    costs.insert(0xD0, 2); costs.insert(0xD1, 2); costs.insert(0xD2, 2); costs.insert(0xD3, 2);
    costs.insert(0xD4, 2); costs.insert(0xD5, 2); costs.insert(0xD6, 2); costs.insert(0xD7, 2);
    costs.insert(0xD8, 2); costs.insert(0xD9, 2); costs.insert(0xDA, 2); costs.insert(0xDB, 2);
    costs.insert(0xDC, 2); costs.insert(0xDD, 2); costs.insert(0xDE, 2); costs.insert(0xDF, 2);
    costs.insert(0xE0, 2); costs.insert(0xE1, 2); costs.insert(0xE2, 2); costs.insert(0xE3, 2);
    costs.insert(0xE4, 2); costs.insert(0xE5, 2); costs.insert(0xE6, 2); costs.insert(0xE7, 2);
    costs.insert(0xE8, 2); costs.insert(0xE9, 2); costs.insert(0xEA, 2); costs.insert(0xEB, 2);
    costs.insert(0xEC, 2); costs.insert(0xED, 2); costs.insert(0xEE, 2); costs.insert(0xEF, 2);
    costs.insert(0xF0, 2); costs.insert(0xF1, 2); costs.insert(0xF2, 2); costs.insert(0xF3, 2);
    costs.insert(0xF4, 2); costs.insert(0xF5, 2); costs.insert(0xF6, 2); costs.insert(0xF7, 2);
    costs.insert(0xF8, 2); costs.insert(0xF9, 2); costs.insert(0xFA, 2); costs.insert(0xFB, 2);
    costs.insert(0xFC, 2); costs.insert(0xFD, 2); costs.insert(0xFE, 2); costs.insert(0xFF, 2);
    
    // Control flow instructions (Cost: 1) - EXACTLY as in get_instruction_cost()
    costs.insert(0x05, 1); costs.insert(0x15, 1); costs.insert(0x1D, 1); costs.insert(0x25, 1);
    costs.insert(0x2D, 1); costs.insert(0x35, 1); costs.insert(0x3D, 1); costs.insert(0x45, 1);
    costs.insert(0x4D, 1); costs.insert(0x55, 1); costs.insert(0x5D, 1); costs.insert(0x65, 1);
    costs.insert(0x6D, 1); costs.insert(0x75, 1); costs.insert(0x7D, 1); costs.insert(0x9D, 1);
    costs.insert(0xA5, 1); costs.insert(0xAD, 1); costs.insert(0xB5, 1); costs.insert(0xBD, 1);
    costs.insert(0xC5, 1); costs.insert(0xCD, 1); costs.insert(0xD5, 1); costs.insert(0xDD, 1);
    costs.insert(0xE5, 1); costs.insert(0xED, 1); costs.insert(0xF5, 1); costs.insert(0xFD, 1);
    
    // Function calls
    costs.insert(0x80, 3);   // CALL
    costs.insert(0x85, 1);   // RET
    
    // CRITICAL: Add default cost for ALL other opcodes (matching get_instruction_cost's _ => 1)
    // This ensures every possible opcode has a cost
    for opcode in 0x00..=0xFF {
        if !costs.contains_key(&opcode) {
            costs.insert(opcode, 1); // Default cost for unknown opcodes
        }
    }
    
    costs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_opcode_costs() {
        assert_eq!(get_instruction_cost(0x95), 1);  // EXIT
        assert_eq!(get_instruction_cost(0x0F), 1);  // ADD_REG
        assert_eq!(get_instruction_cost(0x1F), 1);  // SUB_REG
        assert_eq!(get_instruction_cost(0xB7), 2);  // MOV_IMM
    }

    #[test]
    fn test_memory_opcode_costs() {
        assert_eq!(get_instruction_cost(0x61), 2);  // LDXW
        assert_eq!(get_instruction_cost(0x62), 2);  // STW
        assert_eq!(get_instruction_cost(0x71), 2);  // STW
        assert_eq!(get_instruction_cost(0x72), 2);  // STXW
    }

    #[test]
    fn test_control_flow_costs() {
        assert_eq!(get_instruction_cost(0x05), 1);  // JA
        assert_eq!(get_instruction_cost(0x15), 1);  // JEQ_IMM
        assert_eq!(get_instruction_cost(0x25), 1);  // JGT_IMM
    }

    #[test]
    fn test_function_call_costs() {
        assert_eq!(get_instruction_cost(0x80), 3);  // CALL
        assert_eq!(get_instruction_cost(0x85), 1);  // RET
    }

    #[test]
    fn test_unknown_opcode_default_cost() {
        assert_eq!(get_instruction_cost(0xFF), 2);  // Unknown but in memory range
        assert_eq!(get_instruction_cost(0x99), 2);  // Unknown but in memory range
    }
}

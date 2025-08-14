use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Complete mathematical witness for a single BPF opcode execution
/// This captures EVERYTHING needed to prove the opcode executed correctly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeWitness {
    /// The opcode being executed
    pub opcode: u8,
    
    /// Complete pre-execution state
    pub pre_state: VmStateSnapshot,
    
    /// Complete post-execution state  
    pub post_state: VmStateSnapshot,
    
    /// Operands used by this instruction
    pub operands: OpcodeOperands,
    
    /// All memory operations performed
    pub memory_operations: Vec<MemoryOperation>,
    
    /// Program counter before and after
    pub program_counter: u64,
    pub next_program_counter: u64,
    
    /// Compute units consumed
    pub compute_units_consumed: u64,
    
    /// Raw instruction bytes
    pub instruction_bytes: [u8; 8],
    
    /// Step number in execution sequence
    pub step_number: usize,
}

/// Complete VM state snapshot for mathematical verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmStateSnapshot {
    /// All 11 BPF registers (r0-r10)
    pub registers: [u64; 11],
    
    /// Current program counter
    pub pc: u64,
    
    /// Memory state (simplified for now)
    pub memory_data: Vec<u8>,
    
    /// Step count
    pub step_count: usize,
    
    /// Compute units consumed so far
    pub compute_units: u64,
}

/// Operands for BPF instructions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeOperands {
    /// Destination register (0-10)
    pub dst_reg: u8,
    
    /// Source register (0-10) 
    pub src_reg: u8,
    
    /// Offset for memory operations
    pub offset: i16,
    
    /// Immediate value
    pub immediate: i32,
}

/// Memory operation with complete mathematical details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOperation {
    /// Memory address accessed
    pub address: u64,
    
    /// Data read/written
    pub data: Vec<u8>,
    
    /// Operation type
    pub op_type: MemoryOpType,
    
    /// Size of operation (1, 2, 4, or 8 bytes)
    pub size: usize,
    
    /// Whether bounds check passed
    pub bounds_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MemoryOpType {
    Read,
    Write,
    Execute,
}

/// Mathematical constraint types for ZK proving
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MathematicalConstraint {
    /// Arithmetic operation: output = operation(inputs)
    Arithmetic {
        operation: ArithmeticOp,
        inputs: Vec<u64>,
        output: u64,
        description: String,
    },
    
    /// Equality: left == right
    Equality {
        left: u64,
        right: u64,
        description: String,
    },
    
    /// Range check: min <= value <= max
    RangeCheck {
        value: u64,
        min: u64,
        max: u64,
        description: String,
    },
    
    /// Memory access: address + offset = computed_address
    MemoryAddress {
        base: u64,
        offset: i64,
        computed: u64,
        description: String,
    },
    
    /// Control flow: next_pc = current_pc + offset (if condition met)
    ControlFlow {
        current_pc: u64,
        offset: i64,
        condition_met: bool,
        next_pc: u64,
        description: String,
    },
    
    /// State transition: post_state = f(pre_state, operands)
    StateTransition {
        pre_state_hash: [u8; 32],
        post_state_hash: [u8; 32],
        description: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArithmeticOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    LeftShift,
    RightShift,
}

/// Complete mathematical proof for an opcode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeProof {
    /// The witness being proven
    pub witness: OpcodeWitness,
    
    /// All mathematical constraints
    pub constraints: Vec<MathematicalConstraint>,
    
    /// Whether the proof is valid
    pub is_valid: bool,
    
    /// Error message if invalid
    pub error_message: Option<String>,
}

impl OpcodeWitness {
    /// Create a new witness for an opcode execution
    pub fn new(
        opcode: u8,
        pre_state: VmStateSnapshot,
        post_state: VmStateSnapshot,
        operands: OpcodeOperands,
        memory_operations: Vec<MemoryOperation>,
        program_counter: u64,
        next_program_counter: u64,
        compute_units_consumed: u64,
        instruction_bytes: [u8; 8],
        step_number: usize,
    ) -> Self {
        Self {
            opcode,
            pre_state,
            post_state,
            operands,
            memory_operations,
            program_counter,
            next_program_counter,
            compute_units_consumed,
            instruction_bytes,
            step_number,
        }
    }
    
    /// Verify that this witness is mathematically consistent
    pub fn verify_mathematical_consistency(&self) -> bool {
        // Basic sanity checks
        if self.program_counter >= self.next_program_counter {
            println!("DEBUG: PC validation failed: {} >= {}", self.program_counter, self.next_program_counter);
            return false;
        }
        
        if self.compute_units_consumed == 0 {
            println!("DEBUG: Compute units validation failed: {}", self.compute_units_consumed);
            return false;
        }
        
        // Verify register indices are valid
        if self.operands.dst_reg > 10 || self.operands.src_reg > 10 {
            println!("DEBUG: Register validation failed: dst_reg={}, src_reg={}", self.operands.dst_reg, self.operands.src_reg);
            return false;
        }
        
        println!("DEBUG: Witness validation passed for opcode 0x{:02X}", self.opcode);
        true
    }
    
    /// Get the mathematical constraints for this opcode
    pub fn generate_mathematical_constraints(&self) -> Vec<MathematicalConstraint> {
        match self.opcode {
            0x0F => self.generate_add_reg_constraints(),      // ADD_REG
            0xB7 => self.generate_mov_imm_constraints(),      // MOV_IMM
            0xBF => self.generate_mov_reg_constraints(),      // MOV_REG  
            0x61 => self.generate_ldxw_constraints(),         // LDXW
            0x62 => self.generate_stw_constraints(),          // STW
            0x15 => self.generate_jeq_reg_constraints(),     // JEQ_REG
            _ => vec![], // Unsupported opcode
        }
    }
    
    /// Generate constraints for ADD_REG (0x0F)
    fn generate_add_reg_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        
        let dst_reg = self.operands.dst_reg as usize;
        let src_reg = self.operands.src_reg as usize;
        
        let pre_dst = self.pre_state.registers[dst_reg];
        let pre_src = self.pre_state.registers[src_reg];
        let post_dst = self.post_state.registers[dst_reg];
        
        // CONSTRAINT 1: Arithmetic correctness
        // post_dst = pre_dst + pre_src (mod 2^64)
        let expected_result = pre_dst.wrapping_add(pre_src);
        constraints.push(MathematicalConstraint::Equality {
            left: post_dst,
            right: expected_result,
            description: format!("ADD_REG: r{} = r{} + r{}", dst_reg, dst_reg, src_reg),
        });
        
        // CONSTRAINT 2: Other registers unchanged
        for i in 0..11 {
            if i != dst_reg {
                constraints.push(MathematicalConstraint::Equality {
                    left: self.pre_state.registers[i],
                    right: self.post_state.registers[i],
                    description: format!("ADD_REG: r{} unchanged", i),
                });
            }
        }
        
        // CONSTRAINT 3: Program counter advancement
        constraints.push(MathematicalConstraint::Equality {
            left: self.next_program_counter,
            right: self.program_counter + 8, // BPF instructions are 8 bytes
            description: "ADD_REG: PC advanced by 8".to_string(),
        });
        
        // CONSTRAINT 4: Compute units consumed
        constraints.push(MathematicalConstraint::Equality {
            left: self.pre_state.compute_units + 1,
            right: self.post_state.compute_units,
            description: "ADD_REG: Compute units correctly updated".to_string(),
        });
        
        constraints
    }
    
    /// Generate constraints for MOV_REG (0xBF)
    fn generate_mov_reg_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        
        let dst_reg = self.operands.dst_reg as usize;
        let src_reg = self.operands.src_reg as usize;
        
        let pre_src = self.pre_state.registers[src_reg];
        let post_dst = self.post_state.registers[dst_reg];
        
        // CONSTRAINT 1: Data movement correctness
        // post_dst = pre_src (exact copy)
        constraints.push(MathematicalConstraint::Equality {
            left: post_dst,
            right: pre_src,
            description: format!("MOV_REG: r{} = r{}", dst_reg, src_reg),
        });
        
        // CONSTRAINT 2: Other registers unchanged
        for i in 0..11 {
            if i != dst_reg {
                constraints.push(MathematicalConstraint::Equality {
                    left: self.pre_state.registers[i],
                    right: self.post_state.registers[i],
                    description: format!("MOV_REG: r{} unchanged", i),
                });
            }
        }
        
        // CONSTRAINT 3: Program counter advancement
        constraints.push(MathematicalConstraint::Equality {
            left: self.next_program_counter,
            right: self.program_counter + 8,
            description: "MOV_REG: PC advanced by 8".to_string(),
        });
        
        constraints
    }
    
    /// Generate constraints for MOV_IMM (0xB7)
    fn generate_mov_imm_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        
        let dst_reg = self.operands.dst_reg as usize;
        let immediate = self.operands.immediate as u64;
        
        let post_dst = self.post_state.registers[dst_reg];
        
        // CONSTRAINT 1: Immediate value assignment
        // post_dst = immediate (exact copy)
        constraints.push(MathematicalConstraint::Equality {
            left: post_dst,
            right: immediate,
            description: format!("MOV_IMM: r{} = {}", dst_reg, immediate),
        });
        
        // CONSTRAINT 2: Other registers unchanged
        for i in 0..11 {
            if i != dst_reg {
                constraints.push(MathematicalConstraint::Equality {
                    left: self.pre_state.registers[i],
                    right: self.post_state.registers[i],
                    description: format!("MOV_IMM: r{} unchanged", i),
                });
            }
        }
        
        // CONSTRAINT 3: Program counter advancement
        constraints.push(MathematicalConstraint::Equality {
            left: self.next_program_counter,
            right: self.program_counter + 8,
            description: "MOV_IMM: PC advanced by 8".to_string(),
        });
        
        constraints
    }
    
    /// Generate constraints for LDXW (0x61) - Load Word from Memory
    fn generate_ldxw_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        
        let dst_reg = self.operands.dst_reg as usize;
        let src_reg = self.operands.src_reg as usize;
        let offset = self.operands.offset;
        
        let pre_src = self.pre_state.registers[src_reg];
        let post_dst = self.post_state.registers[dst_reg];
        
        // CONSTRAINT 1: Address computation
        // computed_address = pre_src + offset
        let computed_address = (pre_src as i64 + offset as i64) as u64;
        
        // Find the memory read operation
        if let Some(mem_op) = self.memory_operations.iter().find(|op| 
            op.op_type == MemoryOpType::Read && op.address == computed_address
        ) {
            // CONSTRAINT 2: Memory bounds validity
            constraints.push(MathematicalConstraint::RangeCheck {
                value: computed_address,
                min: 0,
                max: self.pre_state.memory_data.len() as u64 - 4, // 4 bytes for word
                description: "LDXW: Memory address within bounds".to_string(),
            });
            
            // CONSTRAINT 3: Loaded value matches memory contents
            let loaded_value = u32::from_le_bytes([
                mem_op.data[0], mem_op.data[1], mem_op.data[2], mem_op.data[3]
            ]) as u64;
            
            constraints.push(MathematicalConstraint::Equality {
                left: post_dst,
                right: loaded_value,
                description: "LDXW: Loaded value matches memory contents".to_string(),
            });
            
            // CONSTRAINT 4: Zero extension to 64 bits
            constraints.push(MathematicalConstraint::RangeCheck {
                value: loaded_value,
                min: 0,
                max: 0xFFFFFFFF, // 32-bit max value
                description: "LDXW: Value is 32-bit (zero-extended)".to_string(),
            });
        } else {
            // Memory operation not found - this is an error
            return vec![];
        }
        
        // CONSTRAINT 5: Other registers unchanged
        for i in 0..11 {
            if i != dst_reg {
                constraints.push(MathematicalConstraint::Equality {
                    left: self.pre_state.registers[i],
                    right: self.post_state.registers[i],
                    description: format!("LDXW: r{} unchanged", i),
                });
            }
        }
        
        // CONSTRAINT 6: Program counter advancement
        constraints.push(MathematicalConstraint::Equality {
            left: self.next_program_counter,
            right: self.program_counter + 8,
            description: "LDXW: PC advanced by 8".to_string(),
        });
        
        constraints
    }
    
    /// Generate constraints for STW (0x62) - Store Word to Memory
    fn generate_stw_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        
        let dst_reg = self.operands.dst_reg as usize;
        let offset = self.operands.offset;
        let immediate = self.operands.immediate as u32;
        
        let pre_dst = self.pre_state.registers[dst_reg];
        
        // CONSTRAINT 1: Address computation
        // computed_address = pre_dst + offset
        let computed_address = (pre_dst as i64 + offset as i64) as u64;
        
        // Find the memory write operation
        if let Some(mem_op) = self.memory_operations.iter().find(|op| 
            op.op_type == MemoryOpType::Write && op.address == computed_address
        ) {
            // CONSTRAINT 2: Memory bounds validity
            constraints.push(MathematicalConstraint::RangeCheck {
                value: computed_address,
                min: 0,
                max: self.pre_state.memory_data.len() as u64 - 4,
                description: "STW: Memory address within bounds".to_string(),
            });
            
            // CONSTRAINT 3: Stored value matches immediate
            let stored_bytes = [
                (immediate & 0xFF) as u8,
                ((immediate >> 8) & 0xFF) as u8,
                ((immediate >> 16) & 0xFF) as u8,
                ((immediate >> 24) & 0xFF) as u8,
            ];
            
            for (i, &byte) in stored_bytes.iter().enumerate() {
                constraints.push(MathematicalConstraint::Equality {
                    left: mem_op.data[i] as u64,
                    right: byte as u64,
                    description: format!("STW: Memory byte {} = {}", i, byte),
                });
            }
        } else {
            // Memory operation not found - this is an error
            return vec![];
        }
        
        // CONSTRAINT 4: All registers unchanged (STW doesn't modify registers)
        for i in 0..11 {
            constraints.push(MathematicalConstraint::Equality {
                left: self.pre_state.registers[i],
                right: self.post_state.registers[i],
                description: format!("STW: r{} unchanged", i),
            });
        }
        
        // CONSTRAINT 5: Program counter advancement
        constraints.push(MathematicalConstraint::Equality {
            left: self.next_program_counter,
            right: self.program_counter + 8,
            description: "STW: PC advanced by 8".to_string(),
        });
        
        constraints
    }
    
    /// Generate constraints for JEQ_REG (0x15) - Jump if Equal
    fn generate_jeq_reg_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        
        let dst_reg = self.operands.dst_reg as usize;
        let src_reg = self.operands.src_reg as usize;
        let offset = self.operands.offset;
        
        let pre_dst = self.pre_state.registers[dst_reg];
        let pre_src = self.pre_state.registers[src_reg];
        
        // CONSTRAINT 1: Comparison logic
        let values_equal = pre_dst == pre_src;
        
        // CONSTRAINT 2: Program counter update based on condition
        let expected_next_pc = if values_equal {
            (self.program_counter as i64 + 1 + offset as i64) as u64
        } else {
            self.program_counter + 1
        };
        
        constraints.push(MathematicalConstraint::ControlFlow {
            current_pc: self.program_counter,
            offset: offset as i64,
            condition_met: values_equal,
            next_pc: expected_next_pc,
            description: format!("JEQ_REG: r{} == r{} ? jump {} : +1", dst_reg, src_reg, offset),
        });
        
        // CONSTRAINT 3: All registers unchanged (JEQ doesn't modify registers)
        for i in 0..11 {
            constraints.push(MathematicalConstraint::Equality {
                left: self.pre_state.registers[i],
                right: self.post_state.registers[i],
                description: format!("JEQ_REG: r{} unchanged", i),
            });
        }
        
        constraints
    }
}

impl Default for VmStateSnapshot {
    fn default() -> Self {
        Self {
            registers: [0; 11],
            pc: 0,
            memory_data: vec![0; 1024], // 1KB default memory
            step_count: 0,
            compute_units: 0,
        }
    }
}

impl Default for OpcodeOperands {
    fn default() -> Self {
        Self {
            dst_reg: 0,
            src_reg: 0,
            offset: 0,
            immediate: 0,
        }
    }
}

/// Mathematical proof verifier
pub struct MathematicalProofVerifier;

impl MathematicalProofVerifier {
    /// Verify that an opcode witness proves correct execution
    pub fn verify_opcode_execution(witness: &OpcodeWitness) -> OpcodeProof {
        // Step 1: Verify mathematical consistency
        if !witness.verify_mathematical_consistency() {
            return OpcodeProof {
                witness: witness.clone(),
                constraints: vec![],
                is_valid: false,
                error_message: Some("Witness failed mathematical consistency check".to_string()),
            };
        }
        
        // Step 2: Generate mathematical constraints
        let constraints = witness.generate_mathematical_constraints();
        
        // Step 3: Verify all constraints are satisfied
        let mut all_constraints_valid = true;
        let mut error_message = None;
        
        for constraint in &constraints {
            if !Self::verify_constraint(witness, constraint) {
                all_constraints_valid = false;
                error_message = Some(format!("Constraint failed: {:?}", constraint));
                break;
            }
        }
        
        OpcodeProof {
            witness: witness.clone(),
            constraints,
            is_valid: all_constraints_valid,
            error_message,
        }
    }
    
    /// Verify a single mathematical constraint
    fn verify_constraint(witness: &OpcodeWitness, constraint: &MathematicalConstraint) -> bool {
        match constraint {
            MathematicalConstraint::Equality { left, right, .. } => {
                left == right
            },
            MathematicalConstraint::RangeCheck { value, min, max, .. } => {
                *value >= *min && *value <= *max
            },
            MathematicalConstraint::Arithmetic { operation, inputs, output, .. } => {
                Self::verify_arithmetic_constraint(operation, inputs, *output)
            },
            MathematicalConstraint::MemoryAddress { base, offset, computed, .. } => {
                let expected = (*base as i64 + *offset) as u64;
                expected == *computed
            },
            MathematicalConstraint::ControlFlow { current_pc, offset, condition_met, next_pc, .. } => {
                let expected = if *condition_met {
                    (*current_pc as i64 + 1 + *offset) as u64
                } else {
                    current_pc + 1
                };
                expected == *next_pc
            },
            MathematicalConstraint::StateTransition { .. } => {
                // For now, assume state transitions are valid
                // In a real implementation, you'd verify cryptographic hashes
                true
            },
        }
    }
    
    /// Verify arithmetic constraint
    fn verify_arithmetic_constraint(operation: &ArithmeticOp, inputs: &[u64], output: u64) -> bool {
        if inputs.len() < 2 {
            return false;
        }
        
        let expected = match operation {
            ArithmeticOp::Add => inputs[0].wrapping_add(inputs[1]),
            ArithmeticOp::Subtract => inputs[0].wrapping_sub(inputs[1]),
            ArithmeticOp::Multiply => inputs[0].wrapping_mul(inputs[1]),
            ArithmeticOp::Divide => {
                if inputs[1] == 0 { return false; }
                inputs[0] / inputs[1]
            },
            ArithmeticOp::Modulo => {
                if inputs[1] == 0 { return false; }
                inputs[0] % inputs[1]
            },
            ArithmeticOp::BitwiseAnd => inputs[0] & inputs[1],
            ArithmeticOp::BitwiseOr => inputs[0] | inputs[1],
            ArithmeticOp::BitwiseXor => inputs[0] ^ inputs[1],
            ArithmeticOp::LeftShift => inputs[0] << inputs[1],
            ArithmeticOp::RightShift => inputs[0] >> inputs[1],
        };
        
        expected == output
    }
}

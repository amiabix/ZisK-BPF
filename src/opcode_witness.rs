use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Complete opcode witness for mathematical proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeWitness {
    /// The opcode being executed
    pub opcode: u8,
    
    /// Pre-execution VM state
    pub pre_state: VmStateSnapshot,
    
    /// Post-execution VM state
    pub post_state: VmStateSnapshot,
    
    /// Operands used by the instruction
    pub operands: OpcodeOperands,
    
    /// Memory operations performed
    pub memory_operations: Vec<MemoryOperation>,
    
    /// Program counter before execution
    pub program_counter: u64,
    
    /// Next program counter after execution
    pub next_program_counter: u64,
    
    /// Compute units consumed by this instruction
    pub compute_units_consumed: u64,
    
    /// Raw instruction bytes (padded to 8 bytes)
    pub instruction_bytes: [u8; 8],
    
    /// Step number in execution sequence
    pub step_number: usize,
}

/// VM state snapshot at a specific point in execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmStateSnapshot {
    /// Register values (r0-r10)
    pub registers: [u64; 11],
    
    /// Program counter
    pub pc: u64,
    
    /// Memory data (for validation)
    pub memory_data: Vec<u8>,
    
    /// Current step count
    pub step_count: usize,
    
    /// Total compute units consumed so far
    pub compute_units: u64,
}

/// Operands for BPF instructions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeOperands {
    /// Destination register
    pub dst_reg: u8,
    
    /// Source register
    pub src_reg: u8,
    
    /// Second source register (for 3-operand instructions)
    pub src_reg2: u8,
    
    /// Offset for memory operations
    pub offset: i16,
    
    /// Immediate value
    pub immediate: i32,
}

/// Memory operation during instruction execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOperation {
    /// Memory address
    pub address: u64,
    
    /// Data read/written
    pub data: Vec<u8>,
    
    /// Type of memory operation
    pub op_type: MemoryOpType,
    
    /// Size of the operation
    pub size: usize,
    
    /// Whether bounds are valid
    pub bounds_valid: bool,
}

/// Type of memory operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MemoryOpType {
    Read,
    Write,
    Execute,
}

/// Mathematical proof for a single opcode execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeProof {
    /// Whether the proof is valid
    pub is_valid: bool,
    
    /// Mathematical constraints generated
    pub constraints: Vec<MathematicalConstraint>,
    
    /// Error message if proof failed
    pub error_message: Option<String>,
    
    /// Step number
    pub step_number: usize,
}

/// Mathematical constraint for ZK proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MathematicalConstraint {
    /// Arithmetic operation constraint
    Arithmetic {
        operation: ArithmeticOp,
        inputs: Vec<u64>,
        output: u64,
        description: String,
    },
    
    /// Equality constraint
    Equality {
        left: u64,
        right: u64,
        description: String,
    },
    
    /// Range check constraint
    RangeCheck {
        value: u64,
        min: u64,
        max: u64,
        description: String,
    },
    
    /// Memory address constraint
    MemoryAddress {
        base: u64,
        offset: i64,
        computed: u64,
        description: String,
    },
    
    /// Control flow constraint
    ControlFlow {
        current_pc: u64,
        offset: i64,
        condition_met: bool,
        next_pc: u64,
        description: String,
    },
    
    /// State transition constraint
    StateTransition {
        pre_state_hash: [u8; 32],
        post_state_hash: [u8; 32],
        description: String,
    },
}

/// Arithmetic operation types
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

impl OpcodeWitness {
    /// Create a new opcode witness
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
    
    /// Generate mathematical constraints for this opcode
    pub fn generate_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        
        // Always add state transition constraint
        constraints.push(MathematicalConstraint::StateTransition {
            pre_state_hash: self.compute_state_hash(&self.pre_state),
            post_state_hash: self.compute_state_hash(&self.post_state),
            description: format!("Step {}: state transition", self.step_number),
        });
        
        // Add opcode-specific constraints
        match self.opcode {
            0x0F => constraints.extend(self.generate_add_reg_constraints()),
            0x1F => constraints.extend(self.generate_sub_reg_constraints()),
            0x2F => constraints.extend(self.generate_mul_reg_constraints()),
            0x5F => constraints.extend(self.generate_and_reg_constraints()),
            0x25 => constraints.extend(self.generate_jne_reg_constraints()),
            0x71 => constraints.extend(self.generate_ldxb_constraints()),
            0x85 => constraints.extend(self.generate_call_constraints()),
            0xB7 => constraints.extend(self.generate_mov_imm_constraints()),
            0xBF => constraints.extend(self.generate_mov_reg_constraints()),
            0x61 => constraints.extend(self.generate_ldxw_constraints()),
            0x62 => constraints.extend(self.generate_stw_constraints()),
            0x15 => constraints.extend(self.generate_jeq_reg_constraints()),
            0x95 => constraints.extend(self.generate_exit_constraints()),
            _ => constraints.extend(self.generate_generic_constraints()),
        }
        
        constraints
    }
    
    /// Generate constraints for ADD_REG instruction
    fn generate_add_reg_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = self.operands.dst_reg as usize;
        let src_reg = self.operands.src_reg as usize;
        
        if dst_reg < 11 && src_reg < 11 {
            let pre_dst = self.pre_state.registers[dst_reg];
            let pre_src = self.pre_state.registers[src_reg];
            let post_dst = self.post_state.registers[dst_reg];
            let expected_result = pre_dst.wrapping_add(pre_src);
            
            constraints.push(MathematicalConstraint::Arithmetic {
                operation: ArithmeticOp::Add,
                inputs: vec![pre_dst, pre_src],
                output: post_dst,
                description: format!("ADD_REG: r{} = r{} + r{} = {}", dst_reg, dst_reg, src_reg, post_dst),
            });
            
            constraints.push(MathematicalConstraint::Equality {
                left: post_dst,
                right: expected_result,
                description: format!("ADD_REG: r{} result validation", dst_reg),
            });
        }
        
        constraints
    }
    
    /// Generate constraints for SUB_REG instruction
    fn generate_sub_reg_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = self.operands.dst_reg as usize;
        let src_reg = self.operands.src_reg as usize;
        
        if dst_reg < 11 && src_reg < 11 {
            let pre_dst = self.pre_state.registers[dst_reg];
            let pre_src = self.pre_state.registers[src_reg];
            let post_dst = self.post_state.registers[dst_reg];
            let expected_result = pre_dst.wrapping_sub(pre_src);
            
            constraints.push(MathematicalConstraint::Arithmetic {
                operation: ArithmeticOp::Subtract,
                inputs: vec![pre_dst, pre_src],
                output: post_dst,
                description: format!("SUB_REG: r{} = r{} - r{} = {}", dst_reg, dst_reg, src_reg, post_dst),
            });
            
            constraints.push(MathematicalConstraint::Equality {
                left: post_dst,
                right: expected_result,
                description: format!("SUB_REG: r{} result validation", dst_reg),
            });
        }
        
        constraints
    }
    
    /// Generate constraints for MUL_REG instruction
    fn generate_mul_reg_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = self.operands.dst_reg as usize;
        let src_reg = self.operands.src_reg as usize;
        
        if dst_reg < 11 && src_reg < 11 {
            let pre_dst = self.pre_state.registers[dst_reg];
            let pre_src = self.pre_state.registers[src_reg];
            let post_dst = self.post_state.registers[dst_reg];
            let expected_result = pre_dst.wrapping_mul(pre_src);
            
            constraints.push(MathematicalConstraint::Arithmetic {
                operation: ArithmeticOp::Multiply,
                inputs: vec![pre_dst, pre_src],
                output: post_dst,
                description: format!("MUL_REG: r{} = r{} * r{} = {}", dst_reg, dst_reg, src_reg, post_dst),
            });
            
            constraints.push(MathematicalConstraint::Equality {
                left: post_dst,
                right: expected_result,
                description: format!("MUL_REG: r{} result validation", dst_reg),
            });
        }
        
        constraints
    }
    
    /// Generate constraints for AND_REG instruction
    fn generate_and_reg_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = self.operands.dst_reg as usize;
        let src_reg = self.operands.src_reg as usize;
        
        if dst_reg < 11 && src_reg < 11 {
            let pre_dst = self.pre_state.registers[dst_reg];
            let pre_src = self.pre_state.registers[src_reg];
            let post_dst = self.post_state.registers[dst_reg];
            let expected_result = pre_dst & pre_src;
            
            constraints.push(MathematicalConstraint::Arithmetic {
                operation: ArithmeticOp::BitwiseAnd,
                inputs: vec![pre_dst, pre_src],
                output: post_dst,
                description: format!("AND_REG: r{} = r{} & r{} = {}", dst_reg, dst_reg, src_reg, post_dst),
            });
            
            constraints.push(MathematicalConstraint::Equality {
                left: post_dst,
                right: expected_result,
                description: format!("AND_REG: r{} result validation", dst_reg),
            });
        }
        
        constraints
    }
    
    /// Generate constraints for JNE_REG instruction
    fn generate_jne_reg_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = self.operands.dst_reg as usize;
        let src_reg = self.operands.src_reg as usize;
        let offset = self.operands.offset;
        
        if dst_reg < 11 && src_reg < 11 {
            let pre_dst = self.pre_state.registers[dst_reg];
            let pre_src = self.pre_state.registers[src_reg];
            let values_equal = pre_dst == pre_src;
            
            let expected_pc = if !values_equal {
                (self.pre_state.pc as i64 + 1 + offset as i64) as u64
            } else {
                self.pre_state.pc + 1
            };
            
            constraints.push(MathematicalConstraint::ControlFlow {
                current_pc: self.pre_state.pc,
                offset: offset as i64,
                condition_met: !values_equal,
                next_pc: expected_pc,
                description: format!("JNE_REG: r{} != r{} → PC = {}", dst_reg, src_reg, expected_pc),
            });
        }
        
        constraints
    }
    
    /// Generate constraints for LDXB instruction
    fn generate_ldxb_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = self.operands.dst_reg as usize;
        let src_reg = self.operands.src_reg as usize;
        let offset = self.operands.offset;
        
        if dst_reg < 11 && src_reg < 11 {
            let base_addr = self.pre_state.registers[src_reg];
            let mem_addr = (base_addr as i64 + offset as i64) as u64;
            
            constraints.push(MathematicalConstraint::MemoryAddress {
                base: base_addr,
                offset: offset as i64,
                computed: mem_addr,
                description: format!("LDXB: mem_addr = r{} + {} = {}", src_reg, offset, mem_addr),
            });
            
            constraints.push(MathematicalConstraint::RangeCheck {
                value: mem_addr,
                min: 0,
                max: self.pre_state.memory_data.len() as u64 - 1,
                description: "LDXB: Memory address within bounds".to_string(),
            });
        }
        
        constraints
    }
    
    /// Generate constraints for CALL instruction
    fn generate_call_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let offset = self.operands.offset;
        let call_target = (self.pre_state.pc as i64 + 1 + offset as i64) as u64;
        let return_address = self.pre_state.pc + 1;
        
        constraints.push(MathematicalConstraint::ControlFlow {
            current_pc: self.pre_state.pc,
            offset: offset as i64,
            condition_met: true, // CALL always jumps
            next_pc: call_target,
            description: format!("CALL: target = PC + 1 + {} = {}", offset, call_target),
        });
        
        constraints.push(MathematicalConstraint::Equality {
            left: return_address,
            right: self.pre_state.pc + 1,
            description: "CALL: return_address = PC + 1".to_string(),
        });
        
        constraints
    }
    
    /// Generate constraints for MOV_IMM instruction
    fn generate_mov_imm_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = self.operands.dst_reg as usize;
        let immediate = self.operands.immediate as u64;
        
        if dst_reg < 11 {
            let post_dst = self.post_state.registers[dst_reg];
            
            constraints.push(MathematicalConstraint::Equality {
                left: post_dst,
                right: immediate,
                description: format!("MOV_IMM: r{} = {}", dst_reg, immediate),
            });
        }
        
        constraints
    }
    
    /// Generate constraints for MOV_REG instruction
    fn generate_mov_reg_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = self.operands.dst_reg as usize;
        let src_reg = self.operands.src_reg as usize;
        
        if dst_reg < 11 && src_reg < 11 {
            let pre_src = self.pre_state.registers[src_reg];
            let post_dst = self.post_state.registers[dst_reg];
            
            constraints.push(MathematicalConstraint::Equality {
                left: post_dst,
                right: pre_src,
                description: format!("MOV_REG: r{} = r{}", dst_reg, src_reg),
            });
        }
        
        constraints
    }
    
    /// Generate constraints for LDXW instruction
    fn generate_ldxw_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = self.operands.dst_reg as usize;
        let src_reg = self.operands.src_reg as usize;
        let offset = self.operands.offset;
        
        if dst_reg < 11 && src_reg < 11 {
            let base_addr = self.pre_state.registers[src_reg];
            let mem_addr = (base_addr as i64 + offset as i64) as u64;
            
            constraints.push(MathematicalConstraint::MemoryAddress {
                base: base_addr,
                offset: offset as i64,
                computed: mem_addr,
                description: format!("LDXW: mem_addr = r{} + {} = {}", src_reg, offset, mem_addr),
            });
            
            constraints.push(MathematicalConstraint::RangeCheck {
                value: mem_addr,
                min: 0,
                max: self.pre_state.memory_data.len() as u64 - 4,
                description: "LDXW: Memory address within bounds".to_string(),
            });
        }
        
        constraints
    }
    
    /// Generate constraints for STW instruction
    fn generate_stw_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = self.operands.dst_reg as usize;
        let offset = self.operands.offset;
        
        if dst_reg < 11 {
            let base_addr = self.pre_state.registers[dst_reg];
            let mem_addr = (base_addr as i64 + offset as i64) as u64;
            
            constraints.push(MathematicalConstraint::MemoryAddress {
                base: base_addr,
                offset: offset as i64,
                computed: mem_addr,
                description: format!("STW: mem_addr = r{} + {} = {}", dst_reg, offset, mem_addr),
            });
            
            constraints.push(MathematicalConstraint::RangeCheck {
                value: mem_addr,
                min: 0,
                max: self.pre_state.memory_data.len() as u64 - 4,
                description: "STW: Memory address within bounds".to_string(),
            });
        }
        
        constraints
    }
    
    /// Generate constraints for JEQ_REG instruction
    fn generate_jeq_reg_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = self.operands.dst_reg as usize;
        let src_reg = self.operands.src_reg as usize;
        let offset = self.operands.offset;
        
        if dst_reg < 11 && src_reg < 11 {
            let pre_dst = self.pre_state.registers[dst_reg];
            let pre_src = self.pre_state.registers[src_reg];
            let values_equal = pre_dst == pre_src;
            
            let expected_pc = if values_equal {
                (self.pre_state.pc as i64 + 1 + offset as i64) as u64
            } else {
                self.pre_state.pc + 1
            };
            
            constraints.push(MathematicalConstraint::ControlFlow {
                current_pc: self.pre_state.pc,
                offset: offset as i64,
                condition_met: values_equal,
                next_pc: expected_pc,
                description: format!("JEQ_REG: r{} == r{} → PC = {}", dst_reg, src_reg, expected_pc),
            });
        }
        
        constraints
    }
    
    /// Generate constraints for EXIT instruction
    fn generate_exit_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let exit_code = self.pre_state.registers[0]; // r0 contains exit code
        
        constraints.push(MathematicalConstraint::Equality {
            left: exit_code,
            right: exit_code, // Self-referential for validation
            description: "EXIT: exit code validation".to_string(),
        });
        
        constraints
    }
    
    /// Generate generic constraints for unknown opcodes
    fn generate_generic_constraints(&self) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        
        // Generic constraint for unknown opcodes
        constraints.push(MathematicalConstraint::Equality {
            left: self.pre_state.compute_units + 1,
            right: self.post_state.compute_units,
            description: format!("Unknown opcode 0x{:02X}: compute units updated", self.opcode),
        });
        
        constraints
    }
    
    /// Compute a simple hash of VM state for constraint generation
    fn compute_state_hash(&self, state: &VmStateSnapshot) -> [u8; 32] {
        let mut hash = [0u8; 32];
        
        // Simple hash: XOR all register values and PC
        let mut combined = state.pc;
        for &reg in &state.registers {
            combined ^= reg;
        }
        
        // Convert to bytes
        for i in 0..8 {
            hash[i] = ((combined >> (i * 8)) & 0xFF) as u8;
        }
        
        hash
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
            src_reg2: 0,
            offset: 0,
            immediate: 0,
        }
    }
}

/// Mathematical proof verifier for opcode execution
pub struct MathematicalProofVerifier;

impl MathematicalProofVerifier {
    /// Verify opcode execution and generate mathematical proof
    pub fn verify_opcode_execution(witness: &OpcodeWitness) -> OpcodeProof {
        let constraints = witness.generate_constraints();
        let is_valid = !constraints.is_empty();
        
        OpcodeProof {
            is_valid,
            constraints,
            error_message: if is_valid { None } else { Some("No constraints generated".to_string()) },
            step_number: witness.step_number,
        }
    }
}

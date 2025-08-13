use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

// Import types from bpf_interpreter module
use crate::bpf_interpreter::{VmState, BpfInstruction};

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct ZkConstraint {
    pub constraint_type: ConstraintType,
    pub step_id: usize,
    pub opcode: u8,
    pub operands: Vec<u64>,
    pub result: u64,
    pub validation_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum ConstraintType {
    OpcodeValidity,
    RegisterTransition,
    MemoryAccess,
    ComputeConsumption,
    ControlFlowTransition,
    ArithmeticOperation,
    BitwiseOperation,
    MemoryOperation,
    ErrorCondition,
}

pub struct ZkConstraintGenerator {
    constraints: Vec<ZkConstraint>,
    step_counter: usize,
    constraint_cache: HashMap<String, Vec<ZkConstraint>>,
}

impl ZkConstraintGenerator {
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            step_counter: 0,
            constraint_cache: HashMap::new(),
        }
    }
    
    pub fn add_instruction_constraints(&mut self, constraints: Vec<ZkConstraint>) {
        self.constraints.extend(constraints);
        self.step_counter += 1;
    }
    
    pub fn add_error_constraint(&mut self, error: &str) {
        let constraint = ZkConstraint {
            constraint_type: ConstraintType::ErrorCondition,
            step_id: self.step_counter,
            opcode: 0xFF, // Error marker
            operands: vec![],
            result: 0,
            validation_data: error.as_bytes().to_vec(),
        };
        self.constraints.push(constraint);
    }
    
    pub fn compute_validation_hash(&self) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        
        // Hash all constraints to create validation proof
        for constraint in &self.constraints {
            constraint.constraint_type.hash(&mut hasher);
            constraint.step_id.hash(&mut hasher);
            constraint.opcode.hash(&mut hasher);
            constraint.operands.hash(&mut hasher);
            constraint.result.hash(&mut hasher);
            constraint.validation_data.hash(&mut hasher);
        }
        
        let hash_result = hasher.finish();
        
        // Convert to 32-byte hash (simplified - in production use SHA256)
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&hash_result.to_le_bytes());
        hash_bytes
    }
    
    pub fn len(&self) -> usize {
        self.constraints.len()
    }
}

// Generate constraints for specific BPF instructions
pub fn generate_instruction_constraints(
    pre_state: &VmState,
    post_state: &VmState,
    instruction: &BpfInstruction,
    step_id: usize,
) -> Vec<ZkConstraint> {
    let mut constraints = Vec::new();
    
    // Always add opcode validity constraint
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::OpcodeValidity,
        step_id,
        opcode: instruction.opcode,
        operands: vec![instruction.opcode as u64],
        result: 1, // Valid opcode
        validation_data: vec![],
    });
    
    // Generate constraints based on instruction type
    match instruction.opcode {
        // ADD_IMM (0x07)
        0x07 => {
            constraints.extend(generate_add_imm_constraints(
                pre_state, post_state, instruction, step_id
            ));
        },
        
        // SUB_REG (0x1F) 
        0x1F => {
            constraints.extend(generate_sub_reg_constraints(
                pre_state, post_state, instruction, step_id
            ));
        },
        
        // LDXW (0x61) - Load word from memory
        0x61 => {
            constraints.extend(generate_ldxw_constraints(
                pre_state, post_state, instruction, step_id
            ));
        },
        
        // STW (0x62) - Store word to memory
        0x62 => {
            constraints.extend(generate_stw_constraints(
                pre_state, post_state, instruction, step_id
            ));
        },
        
        // JA (0x05) - Unconditional jump
        0x05 => {
            constraints.extend(generate_ja_constraints(
                pre_state, post_state, instruction, step_id
            ));
        },
        
        // JEQ_IMM (0x15) - Jump if equal to immediate
        0x15 => {
            constraints.extend(generate_jeq_imm_constraints(
                pre_state, post_state, instruction, step_id
            ));
        },
        
        // CALL (0x85) - Function call
        0x85 => {
            constraints.extend(generate_call_constraints(
                pre_state, post_state, instruction, step_id
            ));
        },
        
        // EXIT (0x95) - Program exit
        0x95 => {
            constraints.extend(generate_exit_constraints(
                pre_state, post_state, instruction, step_id
            ));
        },
        
        _ => {
            // Unsupported opcode - generate error constraint
            constraints.push(ZkConstraint {
                constraint_type: ConstraintType::ErrorCondition,
                step_id,
                opcode: instruction.opcode,
                operands: vec![],
                result: 0,
                validation_data: format!("Unsupported opcode: {:#x}", instruction.opcode).into_bytes(),
            });
        }
    }
    
    // Always add compute consumption constraint
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::ComputeConsumption,
        step_id,
        opcode: instruction.opcode,
        operands: vec![pre_state.compute_units, post_state.compute_units],
        result: post_state.compute_units.saturating_sub(pre_state.compute_units),
        validation_data: vec![],
    });
    
    constraints
}

// Specific constraint generators for each opcode
fn generate_add_imm_constraints(
    pre_state: &VmState,
    post_state: &VmState,
    instruction: &BpfInstruction,
    step_id: usize,
) -> Vec<ZkConstraint> {
    let mut constraints = Vec::new();
    
    let dst_reg = instruction.dst as usize;
    let immediate = instruction.imm as u64;
    let pre_val = pre_state.registers[dst_reg];
    let post_val = post_state.registers[dst_reg];
    
    // Arithmetic correctness constraint
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::ArithmeticOperation,
        step_id,
        opcode: 0x07,
        operands: vec![pre_val, immediate],
        result: post_val,
        validation_data: bincode::serialize(&AddImmValidation {
            expected_result: pre_val.wrapping_add(immediate),
            actual_result: post_val,
            overflow_detected: pre_val > u64::MAX - immediate,
        }).unwrap(),
    });
    
    // Register transition constraints for unchanged registers
    for i in 0..11 {
        if i != dst_reg {
            constraints.push(ZkConstraint {
                constraint_type: ConstraintType::RegisterTransition,
                step_id,
                opcode: 0x07,
                operands: vec![i as u64, pre_state.registers[i], post_state.registers[i]],
                result: if pre_state.registers[i] == post_state.registers[i] { 1 } else { 0 },
                validation_data: vec![],
            });
        }
    }
    
    // PC advancement constraint
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::ControlFlowTransition,
        step_id,
        opcode: 0x07,
        operands: vec![pre_state.pc, post_state.pc],
        result: post_state.pc,
        validation_data: vec![],
    });
    
    constraints
}

#[derive(Serialize, Deserialize)]
struct AddImmValidation {
    expected_result: u64,
    actual_result: u64,
    overflow_detected: bool,
}

fn generate_ldxw_constraints(
    pre_state: &VmState,
    post_state: &VmState,
    instruction: &BpfInstruction,
    step_id: usize,
) -> Vec<ZkConstraint> {
    let mut constraints = Vec::new();
    
    let dst_reg = instruction.dst as usize;
    let src_reg = instruction.src as usize;
    let offset = instruction.off as i16 as i64;
    
    // Bounds check for registers
    if dst_reg >= 11 || src_reg >= 11 {
        return constraints; // Skip invalid register access
    }
    
    let base_addr = pre_state.registers[src_reg];
    let mem_addr = (base_addr as i64 + offset) as u64;
    
    // Memory bounds check constraint
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::MemoryAccess,
        step_id,
        opcode: 0x61,
        operands: vec![mem_addr, 4], // 4-byte word access
        result: if mem_addr.checked_add(4).map_or(false, |sum| sum <= pre_state.memory_size) { 1 } else { 0 },
        validation_data: bincode::serialize(&MemoryAccessValidation {
            address: mem_addr,
            size: 4,
            is_write: false,
            bounds_valid: mem_addr.checked_add(4).map_or(false, |sum| sum <= pre_state.memory_size),
            alignment_valid: mem_addr % 4 == 0,
        }).unwrap(),
    });
    
    // Memory read constraint
    let loaded_value = post_state.registers[dst_reg];
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::MemoryOperation,
        step_id,
        opcode: 0x61,
        operands: vec![mem_addr, loaded_value],
        result: loaded_value,
        validation_data: vec![], // In real implementation, include memory proof
    });
    
    constraints
}

#[derive(Serialize, Deserialize)]
struct MemoryAccessValidation {
    address: u64,
    size: u64,
    is_write: bool,
    bounds_valid: bool,
    alignment_valid: bool,
}

fn generate_stw_constraints(
    pre_state: &VmState,
    post_state: &VmState,
    instruction: &BpfInstruction,
    step_id: usize,
) -> Vec<ZkConstraint> {
    let mut constraints = Vec::new();
    
    let dst_reg = instruction.dst as usize;
    let src_reg = instruction.src as usize;
    let offset = instruction.off as i16 as i64;
    
    // Bounds check for registers
    if dst_reg >= 11 || src_reg >= 11 {
        return constraints; // Skip invalid register access
    }
    
    let base_addr = pre_state.registers[dst_reg];
    let mem_addr = (base_addr as i64 + offset) as u64;
    let store_value = pre_state.registers[src_reg];
    
    // Memory bounds and permissions
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::MemoryAccess,
        step_id,
        opcode: 0x62,
        operands: vec![mem_addr, 4], // 4-byte store
        result: 1, // Assuming valid for now
        validation_data: bincode::serialize(&MemoryAccessValidation {
            address: mem_addr,
            size: 4,
            is_write: true,
            bounds_valid: mem_addr.checked_add(4).map_or(false, |sum| sum <= pre_state.memory_size),
            alignment_valid: mem_addr % 4 == 0,
        }).unwrap(),
    });
    
    // Memory write constraint
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::MemoryOperation,
        step_id,
        opcode: 0x62,
        operands: vec![mem_addr, store_value],
        result: store_value & 0xFFFFFFFF, // 32-bit store
        validation_data: vec![],
    });
    
    constraints
}

fn generate_ja_constraints(
    pre_state: &VmState,
    post_state: &VmState,
    instruction: &BpfInstruction,
    step_id: usize,
) -> Vec<ZkConstraint> {
    let mut constraints = Vec::new();
    
    let offset = instruction.off as i16 as i64;
    let current_pc = pre_state.pc;
    let target_pc = ((current_pc as i64) + 8 + (offset * 8)) as u64;
    
    // Jump target validation
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::ControlFlowTransition,
        step_id,
        opcode: 0x05,
        operands: vec![current_pc, target_pc],
        result: target_pc,
        validation_data: bincode::serialize(&JumpValidation {
            source_pc: current_pc,
            target_pc,
            offset,
            bounds_valid: target_pc < pre_state.program_size,
            alignment_valid: target_pc % 8 == 0,
        }).unwrap(),
    });
    
    constraints
}

#[derive(Serialize, Deserialize)]
struct JumpValidation {
    source_pc: u64,
    target_pc: u64,
    offset: i64,
    bounds_valid: bool,
    alignment_valid: bool,
}

fn generate_jeq_imm_constraints(
    pre_state: &VmState,
    post_state: &VmState,
    instruction: &BpfInstruction,
    step_id: usize,
) -> Vec<ZkConstraint> {
    let mut constraints = Vec::new();
    
    let src_reg = instruction.src as usize;
    let immediate = instruction.imm as u64;
    let offset = instruction.off as i16 as i64;
    
    let reg_value = pre_state.registers[src_reg];
    let is_equal = reg_value == immediate;
    
    let current_pc = pre_state.pc;
    let next_pc = current_pc + 8;
    let jump_target = ((current_pc as i64) + 8 + (offset * 8)) as u64;
    let final_pc = if is_equal { jump_target } else { next_pc };
    
    // Equality check constraint
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::ArithmeticOperation,
        step_id,
        opcode: 0x15,
        operands: vec![reg_value, immediate],
        result: if is_equal { 1 } else { 0 },
        validation_data: vec![],
    });
    
    // Conditional jump constraint
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::ControlFlowTransition,
        step_id,
        opcode: 0x15,
        operands: vec![current_pc, final_pc],
        result: final_pc,
        validation_data: bincode::serialize(&ConditionalJumpValidation {
            condition_met: is_equal,
            jump_target,
            final_destination: final_pc,
        }).unwrap(),
    });
    
    constraints
}

#[derive(Serialize, Deserialize)]
struct ConditionalJumpValidation {
    condition_met: bool,
    jump_target: u64,
    final_destination: u64,
}

fn generate_sub_reg_constraints(
    pre_state: &VmState,
    post_state: &VmState,
    instruction: &BpfInstruction,
    step_id: usize,
) -> Vec<ZkConstraint> {
    let mut constraints = Vec::new();
    
    let dst_reg = instruction.dst as usize;
    let src_reg = instruction.src as usize;
    let pre_dst = pre_state.registers[dst_reg];
    let src_val = pre_state.registers[src_reg];
    let post_dst = post_state.registers[dst_reg];
    
    // Subtraction constraint with underflow handling
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::ArithmeticOperation,
        step_id,
        opcode: 0x1F,
        operands: vec![pre_dst, src_val],
        result: post_dst,
        validation_data: bincode::serialize(&SubRegValidation {
            minuend: pre_dst,
            subtrahend: src_val,
            result: post_dst,
            underflow_occurred: pre_dst < src_val,
        }).unwrap(),
    });
    
    constraints
}

#[derive(Serialize, Deserialize)]
struct SubRegValidation {
    minuend: u64,
    subtrahend: u64,
    result: u64,
    underflow_occurred: bool,
}

fn generate_call_constraints(
    pre_state: &VmState,
    post_state: &VmState,
    instruction: &BpfInstruction,
    step_id: usize,
) -> Vec<ZkConstraint> {
    let mut constraints = Vec::new();
    
    let function_addr = instruction.imm as u64;
    let return_addr = pre_state.pc + 8;
    
    // Call depth validation
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::ControlFlowTransition,
        step_id,
        opcode: 0x85,
        operands: vec![pre_state.call_depth, post_state.call_depth],
        result: post_state.call_depth,
        validation_data: bincode::serialize(&CallValidation {
            function_address: function_addr,
            return_address: return_addr,
            call_depth_valid: post_state.call_depth <= 64, // Max call depth
        }).unwrap(),
    });
    
    constraints
}

#[derive(Serialize, Deserialize)]
struct CallValidation {
    function_address: u64,
    return_address: u64,
    call_depth_valid: bool,
}

fn generate_exit_constraints(
    pre_state: &VmState,
    post_state: &VmState,
    instruction: &BpfInstruction,
    step_id: usize,
) -> Vec<ZkConstraint> {
    let mut constraints = Vec::new();
    
    let exit_code = pre_state.registers[0]; // r0 contains exit code
    
    // Program termination constraint
    constraints.push(ZkConstraint {
        constraint_type: ConstraintType::ControlFlowTransition,
        step_id,
        opcode: 0x95,
        operands: vec![exit_code],
        result: exit_code,
        validation_data: bincode::serialize(&ExitValidation {
            exit_code,
            program_terminated: true,
        }).unwrap(),
    });
    
    constraints
}

#[derive(Serialize, Deserialize)]
struct ExitValidation {
    exit_code: u64,
    program_terminated: bool,
}

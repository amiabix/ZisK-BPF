use crate::opcode_witness::*;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Enhanced trace recorder that generates complete opcode witnesses
/// This is the core of our mathematical proving system
pub struct EnhancedTraceRecorder {
    /// Complete execution trace with witnesses
    pub execution_trace: EnhancedExecutionTrace,
    
    /// Current step number
    current_step: usize,
    
    /// Current VM state
    current_state: VmStateSnapshot,
    
    /// Memory operations for current instruction
    current_memory_operations: Vec<MemoryOperation>,
}

/// Enhanced execution trace with complete mathematical witnesses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedExecutionTrace {
    /// Initial program state
    pub initial_state: VmStateSnapshot,
    
    /// Final program state
    pub final_state: VmStateSnapshot,
    
    /// Complete opcode witnesses for every instruction
    pub opcode_witnesses: Vec<OpcodeWitness>,
    
    /// Program metadata
    pub program_hash: [u8; 32],
    pub total_compute_units: u64,
    pub total_instructions: usize,
    pub success: bool,
}

impl EnhancedTraceRecorder {
    /// Create a new enhanced trace recorder
    pub fn new(initial_registers: [u64; 11], initial_pc: u64, initial_memory: Vec<u8>) -> Self {
        let initial_state = VmStateSnapshot {
            registers: initial_registers,
            pc: initial_pc,
            memory_data: initial_memory,
            step_count: 0,
            compute_units: 0,
        };
        
        Self {
            execution_trace: EnhancedExecutionTrace {
                initial_state: initial_state.clone(),
                final_state: VmStateSnapshot::default(),
                opcode_witnesses: Vec::new(),
                program_hash: [0; 32], // Will be set later
                total_compute_units: 0,
                total_instructions: 0,
                success: false,
            },
            current_step: 0,
            current_state: initial_state,
            current_memory_operations: Vec::new(),
        }
    }
    
    /// Record the start of instruction execution
    pub fn record_instruction_start(
        &mut self,
        opcode: u8,
        instruction_bytes: &[u8],
        operands: OpcodeOperands,
        compute_units: u64,
    ) {
        // Store current state as pre-execution state
        self.current_state.step_count = self.current_step;
        self.current_state.compute_units = self.execution_trace.total_compute_units;
        
        // Reset memory operations for this instruction
        self.current_memory_operations.clear();
        
        // Store instruction metadata
        self.current_step = opcode as usize;
        self.current_step = compute_units as usize;
    }
    
    /// Record a memory operation during instruction execution
    pub fn record_memory_operation(
        &mut self,
        address: u64,
        data: Vec<u8>,
        op_type: MemoryOpType,
        size: usize,
        bounds_valid: bool,
    ) {
        let memory_op = MemoryOperation {
            address,
            data,
            op_type,
            size,
            bounds_valid,
        };
        
        self.current_memory_operations.push(memory_op);
    }
    
    /// Record the completion of instruction execution
    pub fn record_instruction_completion(
        &mut self,
        post_registers: [u64; 11],
        post_pc: u64,
        instruction_bytes: &[u8],
        operands: OpcodeOperands,
        opcode: u8,
        compute_units_consumed: u64,
    ) {
        // Create post-execution state
        let post_state = VmStateSnapshot {
            registers: post_registers,
            pc: post_pc,
            memory_data: self.current_state.memory_data.clone(), // Memory changes handled separately
            step_count: self.current_step + 1,
            compute_units: self.execution_trace.total_compute_units + compute_units_consumed,
        };
        
        // Create complete opcode witness
        let witness = OpcodeWitness::new(
            opcode,
            self.current_state.clone(),
            post_state.clone(),
            operands,
            self.current_memory_operations.clone(),
            self.current_state.pc,
            post_pc,
            compute_units_consumed,
            self.pad_instruction_bytes(instruction_bytes),
            self.current_step,
        );
        
        // Add witness to trace
        self.execution_trace.opcode_witnesses.push(witness);
        
        // Update current state
        self.current_state = post_state;
        self.execution_trace.total_compute_units += compute_units_consumed;
        self.current_step += 1;
    }
    
    /// Record final program state
    pub fn record_final_state(&mut self, final_registers: [u64; 11], final_pc: u64, success: bool) {
        let final_state = VmStateSnapshot {
            registers: final_registers,
            pc: final_pc,
            memory_data: self.current_state.memory_data.clone(),
            step_count: self.current_step,
            compute_units: self.execution_trace.total_compute_units,
        };
        
        self.execution_trace.final_state = final_state;
        self.execution_trace.total_instructions = self.current_step;
        self.execution_trace.success = success;
    }
    
    /// Set program hash
    pub fn set_program_hash(&mut self, program_hash: [u8; 32]) {
        self.execution_trace.program_hash = program_hash;
    }
    
    /// Set initial state including registers
    pub fn set_initial_state(&mut self, registers: [u64; 11]) {
        self.execution_trace.initial_state.registers = registers;
        self.current_state.registers = registers;
    }
    
    /// Get the complete execution trace
    pub fn get_execution_trace(&self) -> &EnhancedExecutionTrace {
        &self.execution_trace
    }
    
    /// Export the trace to JSON
    pub fn export_trace(&self, file_path: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(&self.execution_trace)?;
        std::fs::write(file_path, json)?;
        Ok(())
    }
    
    /// Get mathematical proof for the entire execution
    pub fn generate_mathematical_proof(&self) -> ProgramMathematicalProof {
        let mut all_proofs = Vec::new();
        let mut total_constraints = 0;
        let mut all_valid = true;
        let mut error_messages = Vec::new();
        
        // Verify each opcode witness
        for (step, witness) in self.execution_trace.opcode_witnesses.iter().enumerate() {
            let proof = MathematicalProofVerifier::verify_opcode_execution(witness);
            
            if !proof.is_valid {
                all_valid = false;
                if let Some(error) = &proof.error_message {
                    error_messages.push(format!("Step {}: {}", step, error));
                }
            }
            
            total_constraints += proof.constraints.len();
            all_proofs.push(proof);
        }
        
        // Verify state reconstruction
        let state_reconstruction_valid = self.verify_state_reconstruction();
        
        ProgramMathematicalProof {
            execution_trace: self.execution_trace.clone(),
            opcode_proofs: all_proofs,
            total_constraints,
            all_proofs_valid: all_valid && state_reconstruction_valid,
            state_reconstruction_valid,
            error_messages,
        }
    }
    
    /// Verify that we can reconstruct the final state from initial state + witnesses
    pub fn verify_state_reconstruction(&self) -> bool {
        let mut reconstructed_state = self.execution_trace.initial_state.clone();
        
        println!("DEBUG: State reconstruction - Initial state: r1={}, r2={}, pc={}", 
                 reconstructed_state.registers[1], reconstructed_state.registers[2], reconstructed_state.pc);
        
        // Replay every instruction step by step
        for (step, witness) in self.execution_trace.opcode_witnesses.iter().enumerate() {
            println!("DEBUG: Step {} - Applying opcode 0x{:02X} (dst_reg={}, src_reg={}, immediate={})", 
                     step, witness.opcode, witness.operands.dst_reg, witness.operands.src_reg, witness.operands.immediate);
            
            // Apply the instruction's effects to reconstructed state
            if !self.apply_instruction_to_state(&mut reconstructed_state, witness) {
                println!("DEBUG: Step {} - Failed to apply instruction", step);
                return false;
            }
            
            println!("DEBUG: Step {} - After: r1={}, r2={}, pc={}", 
                     step, reconstructed_state.registers[1], reconstructed_state.registers[2], reconstructed_state.pc);
        }
        
        println!("DEBUG: Final reconstructed state: r1={}, r2={}, pc={}", 
                 reconstructed_state.registers[1], reconstructed_state.registers[2], reconstructed_state.pc);
        println!("DEBUG: Expected final state: r1={}, r2={}, pc={}", 
                 self.execution_trace.final_state.registers[1], self.execution_trace.final_state.registers[2], self.execution_trace.final_state.pc);
        
        // Check if reconstructed state matches final state
        let result = self.states_equal(&reconstructed_state, &self.execution_trace.final_state);
        println!("DEBUG: State reconstruction result: {}", result);
        result
    }
    
    /// Apply an instruction's effects to a state (for reconstruction verification)
    fn apply_instruction_to_state(&self, state: &mut VmStateSnapshot, witness: &OpcodeWitness) -> bool {
        match witness.opcode {
            0x0F => { // ADD_REG
                let dst_reg = witness.operands.dst_reg as usize;
                let src_reg = witness.operands.src_reg as usize;
                
                if dst_reg < 11 && src_reg < 11 {
                    state.registers[dst_reg] = state.registers[dst_reg].wrapping_add(state.registers[src_reg]);
                }
                state.pc += 8;
                state.compute_units += witness.compute_units_consumed;
                true
            },
            0xB7 => { // MOV_IMM
                let dst_reg = witness.operands.dst_reg as usize;
                let immediate = witness.operands.immediate as u64;
                
                if dst_reg < 11 {
                    state.registers[dst_reg] = immediate;
                }
                state.pc += 8;
                state.compute_units += witness.compute_units_consumed;
                true
            },
            0xBF => { // MOV_REG
                let dst_reg = witness.operands.dst_reg as usize;
                let src_reg = witness.operands.src_reg as usize;
                
                if dst_reg < 11 && src_reg < 11 {
                    state.registers[dst_reg] = state.registers[src_reg];
                }
                state.pc += 8;
                state.compute_units += witness.compute_units_consumed;
                true
            },
            0x95 => { // EXIT
                // EXIT instruction - just advance PC and consume compute units
                state.pc += 8;
                state.compute_units += witness.compute_units_consumed;
                true
            },
            0x61 => { // LDXW
                let dst_reg = witness.operands.dst_reg as usize;
                let src_reg = witness.operands.src_reg as usize;
                let offset = witness.operands.offset;
                
                if dst_reg < 11 && src_reg < 11 {
                    let addr = (state.registers[src_reg] as i64 + offset as i64) as u64;
                    
                    // Find memory read operation
                    if let Some(mem_op) = witness.memory_operations.iter().find(|op| 
                        matches!(op.op_type, MemoryOpType::Read) && op.address == addr
                    ) {
                        let loaded_value = u32::from_le_bytes([
                            mem_op.data[0], mem_op.data[1], mem_op.data[2], mem_op.data[3]
                        ]) as u64;
                        state.registers[dst_reg] = loaded_value;
                    }
                }
                state.pc += 8;
                state.compute_units += witness.compute_units_consumed;
                true
            },
            0x62 => { // STW
                let dst_reg = witness.operands.dst_reg as usize;
                let offset = witness.operands.offset;
                let immediate = witness.operands.immediate as u32;
                
                if dst_reg < 11 {
                    let addr = (state.registers[dst_reg] as i64 + offset as i64) as u64;
                    
                    // Find memory write operation and apply it
                    if let Some(mem_op) = witness.memory_operations.iter().find(|op| 
                        matches!(op.op_type, MemoryOpType::Write) && op.address == addr
                    ) {
                        // Apply memory changes to state
                        for (i, &byte) in mem_op.data.iter().enumerate() {
                            if addr + (i as u64) < state.memory_data.len() as u64 {
                                state.memory_data[(addr + i as u64) as usize] = byte;
                            }
                        }
                    }
                }
                state.pc += 8;
                state.compute_units += witness.compute_units_consumed;
                true
            },
            0x15 => { // JEQ_REG
                let dst_reg = witness.operands.dst_reg as usize;
                let src_reg = witness.operands.src_reg as usize;
                let offset = witness.operands.offset;
                
                if dst_reg < 11 && src_reg < 11 {
                    let values_equal = state.registers[dst_reg] == state.registers[src_reg];
                    
                    if values_equal {
                        state.pc = (state.pc as i64 + 1 + offset as i64) as u64;
                    } else {
                        state.pc += 1;
                    }
                }
                state.compute_units += witness.compute_units_consumed;
                true
            },
            _ => {
                // Unsupported opcode - can't reconstruct
                false
            }
        }
    }
    
    /// Check if two states are equal
    fn states_equal(&self, state1: &VmStateSnapshot, state2: &VmStateSnapshot) -> bool {
        state1.registers == state2.registers &&
        state1.pc == state2.pc &&
        state1.memory_data == state2.memory_data &&
        state1.compute_units == state2.compute_units
    }
    
    /// Pad instruction bytes to 8 bytes
    fn pad_instruction_bytes(&self, bytes: &[u8]) -> [u8; 8] {
        let mut result = [0u8; 8];
        for (i, &byte) in bytes.iter().take(8).enumerate() {
            result[i] = byte;
        }
        result
    }
}

/// Complete mathematical proof for an entire program execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramMathematicalProof {
    /// The execution trace being proven
    pub execution_trace: EnhancedExecutionTrace,
    
    /// Mathematical proofs for each opcode
    pub opcode_proofs: Vec<OpcodeProof>,
    
    /// Total number of constraints generated
    pub total_constraints: usize,
    
    /// Whether all opcode proofs are valid
    pub all_proofs_valid: bool,
    
    /// Whether state reconstruction is valid
    pub state_reconstruction_valid: bool,
    
    /// Any error messages from failed proofs
    pub error_messages: Vec<String>,
}

impl ProgramMathematicalProof {
    /// Export the complete proof to JSON
    pub fn export_proof(&self, file_path: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(file_path, json)?;
        Ok(())
    }
    
    /// Get a summary of the proof
    pub fn get_summary(&self) -> String {
        format!(
            "Program Mathematical Proof Summary:\n\
             - Total Instructions: {}\n\
             - Total Constraints: {}\n\
             - All Opcode Proofs Valid: {}\n\
             - State Reconstruction Valid: {}\n\
             - Overall Proof Valid: {}\n\
             - Errors: {}",
            self.execution_trace.total_instructions,
            self.total_constraints,
            self.all_proofs_valid,
            self.state_reconstruction_valid,
            self.all_proofs_valid && self.state_reconstruction_valid,
            if self.error_messages.is_empty() {
                "None".to_string()
            } else {
                self.error_messages.join(", ")
            }
        )
    }
}

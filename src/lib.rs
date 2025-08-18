//! Zisk Solana Prover - Zero-Knowledge Proof Generation for Solana BPF Programs
//! 
//! This library provides:
//! - BPF instruction constraint generation for ZK proofs
//! - Real RBPF integration for execution verification
//! - Comprehensive opcode support (45+ opcodes)
//! - Week 1 arithmetic operations implementation

pub mod zisk_io;
pub mod real_bpf_loader;
pub mod opcode_implementations;
pub mod trace_recorder;
pub mod elf_parser;
pub mod opcode_witness;
pub mod enhanced_trace_recorder;
pub mod enhanced_bpf_loader;
pub mod cpi_handler;
pub mod sol_invoke_signed_prover;

#[cfg(test)]
mod tests;

// Re-export main types for easy access
pub use opcode_implementations::{
    VmState,
    BpfInstruction,
    ZkConstraintSystem,
    ZkConstraint,
    ConstraintType,
    BpfExecutionResult,
    decode_bpf_instruction,
    generate_add_reg_constraints,
    generate_sub_reg_constraints,
    generate_mul_reg_constraints,
    generate_div_reg_constraints,
    generate_mod_reg_constraints,
    generate_add32_imm_constraints,
    generate_add32_reg_constraints,
    generate_neg64_constraints,
    generate_exit_constraints,
};

pub use real_bpf_loader::{
    RealBpfLoader,
    BpfAccount,
    TransactionContext,
    ProgramExecutionResult,
};

pub use sol_invoke_signed_prover::{
    SolInvokeSignedProver,
    SolInvokeSignedWitness,
    Constraint,
    Field,
};

/// Main entry point for generating ZK constraints from BPF program execution
pub fn generate_program_constraints(
    bpf_program: &[u8],
    execution_result: &ProgramExecutionResult,
) -> ZkConstraintSystem {
    use opcode_implementations::*;
    
    let mut constraint_system = ZkConstraintSystem::new();
    
    // Create initial VM state
    let mut vm_state = VmState {
        registers: [0u64; 11],
        pc: 0,
        compute_units: 0,
        step_count: 0,
        terminated: false,
        memory_hash: [0u8; 32],
        program_hash: [0u8; 32],
        error: None,
    };
    
    // Process each instruction and generate constraints
    let mut step = 0;
    let mut pc = 0;
    
    while pc < bpf_program.len() && step < 1000 { // Safety limit
        if pc + 8 > bpf_program.len() {
            break;
        }
        
        let instruction_bytes = &bpf_program[pc..pc + 8];
        let instruction = decode_bpf_instruction(instruction_bytes);
        
        // Capture pre-execution state
        let pre_state = vm_state.clone();
        
        // Execute instruction and update VM state
        match instruction.opcode {
            0x07 => { // ADD_IMM
                let dst = instruction.dst as usize;
                if dst < vm_state.registers.len() {
                    vm_state.registers[dst] = vm_state.registers[dst].wrapping_add(instruction.imm as u64);
                }
                vm_state.pc += 8;
                
                let constraints = generate_add_imm_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.imm as i64, step
                );
                constraint_system.add_constraints(constraints);
            },
            0xB7 => { // MOV_IMM
                let dst = instruction.dst as usize;
                if dst < vm_state.registers.len() {
                    vm_state.registers[dst] = instruction.imm as u64;
                }
                vm_state.pc += 8;
                
                let constraints = generate_mov_imm_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.imm as i64, step
                );
                constraint_system.add_constraints(constraints);
            },
            0xBF => { // MOV_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    vm_state.registers[dst] = vm_state.registers[src];
                }
                vm_state.pc += 8;
                
                let constraints = generate_mov_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x0F => { // ADD64_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    vm_state.registers[dst] = vm_state.registers[dst].wrapping_add(vm_state.registers[src]);
                }
                vm_state.pc += 8;
                
                let constraints = generate_add_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x1F => { // SUB64_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    vm_state.registers[dst] = vm_state.registers[dst].wrapping_sub(vm_state.registers[src]);
                }
                vm_state.pc += 8;
                
                let constraints = generate_sub_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x2F => { // MUL64_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    vm_state.registers[dst] = vm_state.registers[dst].wrapping_mul(vm_state.registers[src]);
                }
                vm_state.pc += 8;
                
                let constraints = generate_mul_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x3F => { // DIV64_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    if vm_state.registers[src] != 0 {
                        vm_state.registers[dst] = vm_state.registers[dst] / vm_state.registers[src];
                    } else {
                        vm_state.error = Some("Division by zero".to_string());
                    }
                }
                vm_state.pc += 8;
                
                let constraints = generate_div_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x9F => { // MOD64_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    if vm_state.registers[src] != 0 {
                        vm_state.registers[dst] = vm_state.registers[dst] % vm_state.registers[src];
                    } else {
                        vm_state.error = Some("Modulo by zero".to_string());
                    }
                }
                vm_state.pc += 8;
                
                let constraints = generate_mod_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x04 => { // ADD32_IMM
                let dst = instruction.dst as usize;
                if dst < vm_state.registers.len() {
                    let imm_val = (instruction.imm as u64) & 0xFFFFFFFF; // 32-bit mask
                    let dst_32 = vm_state.registers[dst] & 0xFFFFFFFF;
                    let result_32 = dst_32.wrapping_add(imm_val);
                    vm_state.registers[dst] = (vm_state.registers[dst] & 0xFFFFFFFF00000000) | result_32;
                }
                vm_state.pc += 8;
                
                let constraints = generate_add32_imm_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.imm, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x0C => { // ADD32_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    let dst_32 = vm_state.registers[dst] & 0xFFFFFFFF;
                    let src_32 = vm_state.registers[src] & 0xFFFFFFFF;
                    let result_32 = dst_32.wrapping_add(src_32);
                    vm_state.registers[dst] = (vm_state.registers[dst] & 0xFFFFFFFF00000000) | result_32;
                }
                vm_state.pc += 8;
                
                let constraints = generate_add32_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x87 => { // NEG64
                let dst = instruction.dst as usize;
                if dst < vm_state.registers.len() {
                    vm_state.registers[dst] = (-(vm_state.registers[dst] as i64)) as u64;
                }
                vm_state.pc += 8;
                
                let constraints = generate_neg64_constraints(
                    &pre_state, &vm_state, instruction.dst, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x95 => { // EXIT
                vm_state.terminated = true;
                
                let constraints = generate_exit_constraints(
                    &pre_state, &vm_state, step
                );
                constraint_system.add_constraints(constraints);
                break;
            },
            _ => {
                // Unknown opcode - skip
                vm_state.pc += 8;
            }
        }
        
        vm_state.step_count += 1;
        vm_state.compute_units += 1;
        pc = vm_state.pc;
        step += 1;
    }
    
    constraint_system
}

// Inline test module removed; external tests live in src/tests/mod.rs

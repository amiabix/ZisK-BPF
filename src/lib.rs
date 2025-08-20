//! Zisk Solana Prover - Zero-Knowledge Proof Generation for Solana BPF Programs

pub mod bin_generator;
pub mod bpf_executor;
pub mod bpf_interpreter;
pub mod constraint_generator;
pub mod cpi_handler;
pub mod elf_parser;
pub mod enhanced_bpf_loader;
pub mod enhanced_trace_recorder;
pub mod instruction_costs;
pub mod opcode_implementations;
pub mod opcode_witness;
pub mod real_bpf_loader;
pub mod sol_invoke_signed_prover;
pub mod trace_recorder;
pub mod zisk_io;

// Re-export key types for easy access
pub use cpi_handler::{CpiHandler, CpiOperation, CpiError, ProgramDerivedAddress, derive_program_address, find_program_address};
pub use opcode_implementations::{ZkConstraintSystem, VmState, BpfInstruction, decode_bpf_instruction};
pub use real_bpf_loader::{RealBpfLoader, BpfAccount, ProgramExecutionResult, TransactionContext};
pub use sol_invoke_signed_prover::{SolInvokeSignedProver, SolInvokeSignedWitness, Constraint};
pub use trace_recorder::{TraceRecorder, ExecutionTrace, TraceStep};
pub use zisk_io::{SolanaExecutionInput, SolanaExecutionOutput, AccountInput, ExecutionParams, MemoryRegion};

// Standalone constraint generation function
pub fn generate_program_constraints(
    program: &[u8],
    execution_result: &ProgramExecutionResult
) -> Result<Vec<Constraint>, String> {
    // This function is kept for backward compatibility but is not actively used
    // The main constraint generation is now handled by SolInvokeSignedProver
    
    let mut constraints = Vec::new();
    
    // Basic program validation
    if program.is_empty() {
        return Err("Program cannot be empty".to_string());
    }
    
    // Add a basic constraint to indicate the function was called
    constraints.push(Constraint::MessageValidation {
        num_instructions: 1,
        num_accounts: 1,
        is_valid: true,
    });
    
    Ok(constraints)
}

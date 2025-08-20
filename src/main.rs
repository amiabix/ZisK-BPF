#![no_main]
ziskos::entrypoint!(main);

use ziskos::{read_input, set_output};
use serde::{Serialize, Deserialize};

// Simple data structures for ZisK to prove
#[derive(Serialize, Deserialize)]
struct BpfInstruction {
    opcode: u8,
    dst_reg: u8,
    src_reg: u8,
    immediate: u64,
    offset: u64,
}

#[derive(Serialize, Deserialize)]
struct BpfExecutionResult {
    instructions: Vec<BpfInstruction>,
    final_registers: [u64; 11],
    final_pc: u64,
    compute_units_consumed: u64,
}

#[derive(Serialize, Deserialize)]
struct ZiskOutput {
    total_instructions: u32,
    total_compute_units: u32,
    final_register_r1: u64,
    final_register_r7: u64,
    final_pc: u64,
    verification_success: bool,
}

fn main() {
    println!("[ZISK-SOLANA] Starting BPF execution verification...");
    
    // Read input using ZisK's standard mechanism
    let input = read_input();
    println!("[ZISK] Read {} bytes from input", input.len());
    
    // Deserialize the BPF execution result
    let execution_result: BpfExecutionResult = match bincode::deserialize(&input) {
        Ok(result) => {
            println!("[ZISK] Successfully deserialized BPF execution result");
            result
        },
        Err(e) => {
            println!("[ZISK] Failed to deserialize input: {}", e);
            // Return early with error state
            set_output(0, 0); // total_instructions
            set_output(1, 0); // total_compute_units
            set_output(2, 0); // final_register_r1
            set_output(3, 0); // final_register_r7
            set_output(4, 0); // final_pc
            set_output(5, 0); // verification_success
            return;
        }
    };
    
    // Perform the computation that ZisK will prove
    let verification_result = verify_bpf_execution(&execution_result);
    
    // Set ZisK outputs
    set_output(0, verification_result.total_instructions);
    set_output(1, verification_result.total_compute_units);
    set_output(2, verification_result.final_register_r1.try_into().unwrap_or(0));
    set_output(3, verification_result.final_register_r7.try_into().unwrap_or(0));
    set_output(4, verification_result.final_pc.try_into().unwrap_or(0));
    set_output(5, verification_result.verification_success as u32);
    
    println!("[ZISK] Verification complete: {} instructions, {} compute units", 
             verification_result.total_instructions, verification_result.total_compute_units);
    println!("[ZISK] Final state: r1={}, r7={}, pc={}", 
             verification_result.final_register_r1, verification_result.final_register_r7, verification_result.final_pc);
    println!("[ZISK] Verification success: {}", verification_result.verification_success);
}

fn verify_bpf_execution(execution_result: &BpfExecutionResult) -> ZiskOutput {
    let total_instructions = execution_result.instructions.len() as u32;
    let total_compute_units = execution_result.compute_units_consumed as u32;
    
    // Simple verification: check that we have instructions and reasonable values
    let verification_success = total_instructions > 0 
        && total_compute_units > 0 
        && total_compute_units <= 1_000_000; // Reasonable upper bound
    
    ZiskOutput {
        total_instructions,
        total_compute_units,
        final_register_r1: execution_result.final_registers[1],
        final_register_r7: execution_result.final_registers[7],
        final_pc: execution_result.final_pc,
        verification_success,
    }
}

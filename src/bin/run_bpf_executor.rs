// run_bpf_executor.rs
// This binary demonstrates how to use the BPF executor outside of ZisK
// It runs BPF programs and generates execution traces that can be fed to ZisK

use std::env;
use std::fs;
use anyhow::Result;
use bincode;
use zisk_solana_prover::bpf_executor::BpfExecutor;
use zisk_solana_prover::zisk_io::SolanaExecutionInput;

fn main() -> Result<()> {
    println!("🚀 [BPF-EXECUTOR] Starting BPF execution outside ZisK...");
    
    // Get command line arguments
    let args: Vec<String> = env::args().collect();
    let default_program = "SolInvoke_test.so".to_string();
    let program_file = args.get(1).unwrap_or(&default_program);
    
    println!("[BPF-EXECUTOR] Loading BPF program: {}", program_file);
    
    // Read the BPF program file
    let program_data = fs::read(program_file)?;
    println!("[BPF-EXECUTOR] Loaded {} bytes of BPF program", program_data.len());
    
    // Create execution input
    let execution_input = SolanaExecutionInput {
        program_data,
        instruction_data: vec![1, 2, 3, 4], // Sample instruction data
        accounts: vec![], // Empty accounts for now
        execution_params: zisk_solana_prover::zisk_io::ExecutionParams {
            compute_unit_limit: 1_400_000,
            max_call_depth: 64,
            enable_logging: true,
            enable_stack_traces: false,
            memory_regions: vec![],
        },
        program_id: Some("TestProgram".to_string()),
    };
    
    // Create BPF executor
    let mut executor = BpfExecutor::new()?;
    println!("[BPF-EXECUTOR] Created BPF executor");
    
    // Execute the BPF program
    println!("⚡ [BPF-EXECUTOR] Executing BPF program...");
    let execution_result = executor.execute_bpf_program(&execution_input)?;
    
    // Display results
    println!("\n🎉 [BPF-EXECUTOR] Execution completed!");
    println!("   Success: {}", execution_result.success);
    println!("   Exit code: {}", execution_result.exit_code);
    println!("   Compute units consumed: {}", execution_result.compute_units_consumed);
    println!("   Instructions executed: {}", execution_result.stats.instructions_executed);
    println!("   Logs: {} entries", execution_result.logs.len());
    
    // Show some logs
    for (i, log) in execution_result.logs.iter().take(5).enumerate() {
        println!("   Log {}: {}", i + 1, log);
    }
    
    // Export results for ZisK consumption
    let output_file = "bpf_execution_result.bin";
    if let Ok(output_data) = bincode::serialize(&execution_result) {
        if let Ok(_) = fs::write(output_file, output_data) {
            println!("[BPF-EXECUTOR] Exported execution result to {}", output_file);
            println!("   This file can now be used as input for ZisK");
        } else {
            println!("  [BPF-EXECUTOR] Failed to write output file");
        }
    } else {
        println!("[BPF-EXECUTOR] Failed to serialize execution result");
    }
    
    println!("\n[BPF-EXECUTOR] Ready to feed results to ZisK for mathematical proof generation!");
    
    Ok(())
}

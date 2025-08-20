use std::fs;
use std::env;
use anyhow::Result;

use zisk_solana_prover::bpf_executor::BpfExecutor;
use zisk_solana_prover::zisk_io::{SolanaExecutionInput, SolanaExecutionOutput};
use zisk_solana_prover::real_bpf_loader::RealBpfLoader;

fn main() -> Result<()> {
    println!("[BPF-EXECUTOR] Starting real BPF execution...");
    
    // Get command line arguments
    let args: Vec<String> = env::args().collect();
    let program_path = if args.len() > 1 {
        &args[1]
    } else {
        "SolInvoke_test.so"
    };
    
            println!("[INFO] [BPF-EXECUTOR] Using BPF program: {}", program_path);
    
    // Check if the program file exists
    if !fs::metadata(program_path).is_ok() {
        eprintln!("[ERROR] [BPF-EXECUTOR] Program file not found: {}", program_path);
        std::process::exit(1);
    }
    
    // Read the program data
    let program_data = fs::read(program_path)?;
            println!("[SUCCESS] [BPF-EXECUTOR] Loaded program: {} bytes", program_data.len());
    
    // Create execution input
    let input = SolanaExecutionInput {
        program_data,
        instruction_data: vec![], // Empty instruction data for now
        accounts: vec![], // Empty accounts for now
        execution_params: zisk_solana_prover::zisk_io::ExecutionParams {
            compute_unit_limit: 200_000,
            max_call_depth: 64,
            enable_logging: true,
            enable_stack_traces: true,
            memory_regions: vec![],
        },
        program_id: Some("test_program".to_string()),
    };
    
    // Create and run the BPF executor
            println!("[BPF-EXECUTOR] Creating BPF executor...");
    let mut executor = BpfExecutor::new()?;
    
            println!("[BPF-EXECUTOR] Executing BPF program...");
    let execution_result = executor.execute_bpf_program(&input)?;
    
    // Export results for ZisK consumption
    let output_file = "bpf_execution_result.bin";
    if let Ok(output_data) = bincode::serialize(&execution_result) {
        let file_size = output_data.len();
        if let Ok(_) = fs::write(output_file, &output_data) {
            println!("[SUCCESS] [BPF-EXECUTOR] Exported execution result to {}", output_file);
            println!("   File size: {} bytes", file_size);
            println!("   This file contains REAL BPF execution traces, not fake data!");
            
            // Print summary
            println!("[INFO] [BPF-EXECUTOR] Execution Summary:");
            println!("   Success: {}", execution_result.success);
            println!("   Exit code: {}", execution_result.exit_code);
            println!("   Compute units consumed: {}", execution_result.compute_units_consumed);
            println!("   Logs count: {}", execution_result.logs.len());
            
            if let Some(ref trace) = execution_result.execution_trace {
                println!("   Execution trace: {} steps", trace.total_instructions);
                println!("   Instruction details: {} details", trace.instruction_details.len());
            }
        } else {
            eprintln!("[ERROR] [BPF-EXECUTOR] Failed to write output file");
            std::process::exit(1);
        }
    } else {
                    eprintln!("[ERROR] [BPF-EXECUTOR] Failed to serialize execution result");
        std::process::exit(1);
    }
    
    println!("[SUCCESS] [BPF-EXECUTOR] Real BPF execution completed successfully!");
    Ok(())
}

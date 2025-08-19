use std::env;
use std::fs;
use std::path::Path;
use anyhow::{Result, anyhow};
use bincode;
use zisk_solana_prover::zisk_io::{SolanaExecutionInput, AccountInput, ExecutionParams, MemoryRegion};

// Simple ELF parser for .so files
fn extract_bpf_from_so(so_file_path: &str) -> Result<Vec<u8>> {
    let data = fs::read(so_file_path)?;
    
    // Check ELF magic number
    if data.len() < 4 || data[0] != 0x7f || data[1] != 0x45 || data[2] != 0x4c || data[3] != 0x46 {
        return Err(anyhow!("Not a valid ELF file"));
    }
    
    // For now, just return the entire file as BPF bytecode
    // In a real implementation, you'd parse the .text section
    println!("📁 [ELF] Extracting BPF from ELF file: {} bytes", data.len());
    Ok(data)
}

fn generate_input_bin_from_so(so_file_path: &str, output_bin_path: &str) -> Result<()> {
    println!("🔧 [BIN] Generating input.bin from {}", so_file_path);
    
    // Extract BPF bytecode from .so file
    let bpf_bytecode = extract_bpf_from_so(so_file_path)?;
    println!("✅ [BIN] Extracted {} bytes of BPF bytecode", bpf_bytecode.len());
    
    // Create structured input for ZisK
    let input = SolanaExecutionInput {
        program_data: bpf_bytecode,
        instruction_data: vec![1, 2, 3, 4], // Sample instruction data
        accounts: vec![], // Empty accounts for now
        execution_params: ExecutionParams {
            compute_unit_limit: 1_400_000,
            max_call_depth: 64,
            enable_logging: true,
            enable_stack_traces: false,
            memory_regions: vec![],
        },
        program_id: Some("TestProgram".to_string()),
    };
    
    // Serialize to binary file
    let bin_data = match bincode::serialize(&input) {
        Ok(data) => {
            println!("✅ [BIN] Bincode serialization successful: {} bytes", data.len());
            println!("🔍 [BIN] First 16 bytes: {:?}", &data[..16.min(data.len())]);
            data
        },
        Err(e) => {
            println!("❌ [BIN] Bincode serialization failed: {}", e);
            return Err(e.into());
        }
    };
    
    let bin_size = bin_data.len();
    match fs::write(output_bin_path, &bin_data) {
        Ok(_) => println!("✅ [BIN] File write successful"),
        Err(e) => {
            println!("❌ [BIN] File write failed: {}", e);
            return Err(e.into());
        }
    };
    
    println!("✅ [BIN] Successfully generated {} ({} bytes)", output_bin_path, bin_size);
    println!("📊 [BIN] Input contains {} bytes of BPF program data", input.program_data.len());
    
    Ok(())
}

fn main() {
    println!("🔧 [BIN-GEN] ZisK Input Generator for Solana BPF");
    
    // Get command line arguments
    let args: Vec<String> = env::args().collect();
    
    match args.as_slice() {
        [_, so_file] => {
            // Generate input.bin from specified .so file
            println!("📁 [BIN-GEN] Processing {}", so_file);
            if let Err(e) = generate_input_bin_from_so(so_file, "input.bin") {
                eprintln!("❌ [BIN-GEN] Failed to generate input.bin: {}", e);
                std::process::exit(1);
            }
        },
        _ => {
            // Generate input.bin from default Test.so
            println!("📁 [BIN-GEN] Using default SolInvoke_test.so");
            if let Err(e) = generate_input_bin_from_so("SolInvoke_test.so", "input.bin") {
                eprintln!("❌ [BIN-GEN] Failed to generate input.bin: {}", e);
                std::process::exit(1);
            }
        }
    }
    
    println!("✅ [BIN-GEN] Successfully generated input.bin");
    println!("🚀 [BIN-GEN] Ready for ZisK execution!");
}

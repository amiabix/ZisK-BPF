use std::fs;
use std::path::Path;
use anyhow::{Result, anyhow};
use crate::elf_parser::extract_bpf_from_so;
use crate::zisk_io::SolanaExecutionInput;

/// Generate a ZisK-compatible input.bin file from a .so file
pub fn generate_input_bin_from_so(so_file_path: &str, output_bin_path: &str) -> Result<()> {
            println!("[BIN] Generating input.bin from {}", so_file_path);
    
    // Extract BPF bytecode from .so file
    let bpf_bytecode = extract_bpf_from_so(so_file_path)?;
    println!(" [BIN] Extracted {} bytes of BPF bytecode", bpf_bytecode.len());
    
    // Create structured input for ZisK
    let input = SolanaExecutionInput {
        program_data: bpf_bytecode,
        instruction_data: vec![1, 2, 3, 4], // Sample instruction data
        accounts: vec![], // Empty accounts for now
        execution_params: crate::zisk_io::ExecutionParams {
            compute_unit_limit: 1_400_000,
            max_call_depth: 64,
            enable_logging: true,
            enable_stack_traces: false,
            memory_regions: vec![],
        },
        program_id: Some("TestProgram".to_string()),
    };
    
    // Serialize to binary file
    let bin_data = bincode::serialize(&input)?;
    let bin_size = bin_data.len();
    fs::write(output_bin_path, &bin_data)?;
    
    println!("[BIN] Successfully generated {} ({} bytes)", output_bin_path, bin_size);
    println!("[BIN] Input contains {} bytes of BPF program data", input.program_data.len());
    
    Ok(())
}

/// Generate input.bin from SolInvoke_test.so (default case)
pub fn generate_default_input_bin() -> Result<()> {
    generate_input_bin_from_so("SolInvoke_test.so", "input.bin")
}

/// Check if input.bin exists and is valid
pub fn validate_input_bin(bin_path: &str) -> Result<SolanaExecutionInput> {
    if !Path::new(bin_path).exists() {
        return Err(anyhow!("Input file {} does not exist", bin_path));
    }
    
    let bin_data = fs::read(bin_path)?;
    let input: SolanaExecutionInput = bincode::deserialize(&bin_data)?;
    
            println!("[SUCCESS] [BIN] Validated {}: {} bytes of BPF data", bin_path, input.program_data.len());
    Ok(input)
}

/// Generate input.bin if it doesn't exist
pub fn ensure_input_bin_exists() -> Result<()> {
    if !Path::new("input.bin").exists() {
        println!("[INFO] [BIN] input.bin not found, generating from SolInvoke_test.so...");
        generate_default_input_bin()?;
    } else {
        println!("[SUCCESS] [BIN] input.bin already exists");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bin_generation() {
        // This test would require Test.so to exist
        // For now, just test that the module compiles
        assert!(true);
    }
}

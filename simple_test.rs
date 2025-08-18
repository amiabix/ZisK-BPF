use std::fs;
use bincode;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemoryRegion {
    address: u64,
    size: u64,
    permissions: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExecutionParams {
    compute_unit_limit: u32,
    max_call_depth: u32,
    enable_logging: bool,
    enable_stack_traces: bool,
    memory_regions: Vec<MemoryRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SolanaExecutionInput {
    program_data: Vec<u8>,
    instruction_data: Vec<u8>,
    accounts: Vec<()>, // Empty accounts
    execution_params: ExecutionParams,
    program_id: Option<String>,
}

fn main() {
    println!("🔍 Creating simple test input...");
    
    let input = SolanaExecutionInput {
        program_data: vec![0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // EXIT instruction
        instruction_data: vec![1, 2, 3, 4],
        accounts: vec![],
        execution_params: ExecutionParams {
            compute_unit_limit: 1_400_000,
            max_call_depth: 64,
            enable_logging: true,
            enable_stack_traces: false,
            memory_regions: vec![],
        },
        program_id: Some("TestProgram".to_string()),
    };
    
    println!("📊 Input created:");
    println!("   Program data: {} bytes", input.program_data.len());
    println!("   Instruction data: {} bytes", input.instruction_data.len());
    println!("   Accounts: {} accounts", input.accounts.len());
    
    match bincode::serialize(&input) {
        Ok(data) => {
            println!("✅ Serialization successful: {} bytes", data.len());
            
            match fs::write("simple_test.bin", &data) {
                Ok(_) => println!("✅ Written to simple_test.bin"),
                Err(e) => println!("❌ Failed to write: {}", e),
            }
            
            // Test deserialization
            match bincode::deserialize::<SolanaExecutionInput>(&data) {
                Ok(deserialized) => {
                    println!("✅ Deserialization successful!");
                    println!("   Program data: {} bytes", deserialized.program_data.len());
                },
                Err(e) => println!("❌ Deserialization failed: {}", e),
            }
        },
        Err(e) => println!("❌ Serialization failed: {}", e),
    }
}

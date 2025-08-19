use std::fs;
use bincode;
use zisk_solana_prover::zisk_io::{SolanaExecutionInput, ExecutionParams, MemoryRegion};

fn main() {
    println!("🔍 Testing bincode serialization...");
    
    // Create a simple test input
    let test_input = SolanaExecutionInput {
        program_data: vec![1, 2, 3, 4, 5],
        instruction_data: vec![10, 20, 30],
        accounts: vec![],
        execution_params: ExecutionParams {
            compute_unit_limit: 1000,
            max_call_depth: 10,
            enable_logging: true,
            enable_stack_traces: false,
            memory_regions: vec![],
        },
        program_id: Some("Test".to_string()),
    };
    
    println!("✅ Created test input with {} bytes of program data", test_input.program_data.len());
    
    // Serialize
    match bincode::serialize(&test_input) {
        Ok(serialized) => {
            println!("✅ Serialization successful: {} bytes", serialized.len());
            println!("🔍 First 16 bytes: {:?}", &serialized[..16.min(serialized.len())]);
            
            // Write to file
            if let Err(e) = fs::write("test_serialization.bin", &serialized) {
                println!("❌ Failed to write file: {}", e);
                return;
            }
            println!("✅ Wrote test_serialization.bin");
            
            // Try to deserialize
            match bincode::deserialize::<SolanaExecutionInput>(&serialized) {
                Ok(deserialized) => {
                    println!("✅ Deserialization successful!");
                    println!("📊 Program data: {} bytes", deserialized.program_data.len());
                    println!("📊 Instruction data: {} bytes", deserialized.instruction_data.len());
                },
                Err(e) => {
                    println!("❌ Deserialization failed: {}", e);
                }
            }
        },
        Err(e) => {
            println!("❌ Serialization failed: {}", e);
        }
    }
}


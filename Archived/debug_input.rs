use std::fs;
use bincode;
use zisk_solana_prover::zisk_io::SolanaExecutionInput;

fn main() {
    println!("🔍 Debugging input.bin deserialization...");
    
    // Read the input.bin file
    match fs::read("input.bin") {
        Ok(data) => {
            println!("✅ Successfully read input.bin ({} bytes)", data.len());
            println!("🔍 First 32 bytes: {:?}", &data[..32.min(data.len())]);
            
            // Try to deserialize
            match bincode::deserialize::<SolanaExecutionInput>(&data) {
                Ok(input) => {
                    println!("✅ Successfully deserialized input.bin!");
                    println!("📊 Program data: {} bytes", input.program_data.len());
                    println!("📊 Instruction data: {} bytes", input.instruction_data.len());
                    println!("📊 Accounts: {} accounts", input.accounts.len());
                    println!("📊 Program ID: {:?}", input.program_id);
                },
                Err(e) => {
                    println!("❌ Failed to deserialize: {}", e);
                    println!("🔍 This suggests a format mismatch");
                }
            }
        },
        Err(e) => {
            println!("❌ Failed to read input.bin: {}", e);
        }
    }
}


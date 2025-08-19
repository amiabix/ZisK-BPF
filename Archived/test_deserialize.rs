use std::fs;
use bincode;
use zisk_solana_prover::zisk_io::SolanaExecutionInput;

fn main() {
    println!("🔍 Testing input.bin deserialization...");
    
    match fs::read("input.bin") {
        Ok(data) => {
            println!("✅ Successfully read input.bin ({} bytes)", data.len());
            
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
                }
            }
        },
        Err(e) => {
            println!("❌ Failed to read input.bin: {}", e);
        }
    }
}

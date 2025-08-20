use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::Result;

// =====================================================
// 1. INPUT STRUCTURES - What ZisK reads from input.bin
// =====================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaExecutionInput {
    /// The BPF program bytecode to execute
    pub program_data: Vec<u8>,
    
    /// Transaction instruction data (passed to program)
    pub instruction_data: Vec<u8>,
    
    /// Account states and data
    pub accounts: Vec<AccountInput>,
    
    /// Execution parameters and limits
    pub execution_params: ExecutionParams,
    
    /// Optional program ID (if not specified, uses default)
    pub program_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInput {
    /// Account public key (base58 encoded)
    pub pubkey: String,
    
    /// Account data (serialized)
    pub data: Vec<u8>,
    
    /// Account owner (program ID)
    pub owner: String,
    
    /// Account is writable
    pub is_writable: bool,
    
    /// Account is signer
    pub is_signer: bool,
    
    /// Account is executable
    pub is_executable: bool,
    
    /// Account rent epoch
    pub rent_epoch: u64,
    
    /// Account lamports (SOL balance)
    pub lamports: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionParams {
    /// Maximum compute units for execution
    pub compute_unit_limit: u32,
    
    /// Maximum call depth
    pub max_call_depth: u32,
    
    /// Whether to enable logging
    pub enable_logging: bool,
    
    /// Whether to enable stack traces
    pub enable_stack_traces: bool,
    
    /// Memory region configuration
    pub memory_regions: Vec<MemoryRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Memory address
    pub address: u64,
    
    /// Memory size in bytes
    pub size: u64,
    
    /// Memory permissions (read, write, execute)
    pub permissions: u32,
}

// =====================================================
// 2. OUTPUT STRUCTURES - What ZisK writes to output
// =====================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaExecutionOutput {
    /// Whether execution completed successfully
    pub success: bool,
    
    /// BPF exit code
    pub exit_code: u32,
    
    /// Compute units consumed
    pub compute_units_consumed: u32,
    
    /// Modified account states
    pub modified_accounts: Vec<AccountOutput>,
    
    /// Program return data
    pub return_data: Option<Vec<u8>>,
    
    /// Execution logs
    pub logs: Vec<String>,
    
    /// Execution statistics
    pub stats: ExecutionStats,
    
    /// Error details if execution failed
    pub error: Option<String>,
    
    /// CRITICAL: The actual execution trace with all instruction details
    pub execution_trace: Option<ExecutionTraceData>,
    
    /// CRITICAL: Mathematical witnesses for ZK proof generation
    pub mathematical_witnesses: Option<Vec<MathematicalWitnessData>>,
    
    /// CRITICAL: Register state snapshots for each instruction
    pub register_states: Option<Vec<RegisterStateSnapshot>>,
    
    /// CRITICAL: Memory operations during execution
    pub memory_operations: Option<Vec<MemoryOperationData>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountOutput {
    /// Account public key
    pub pubkey: String,
    
    /// Modified account data
    pub data: Vec<u8>,
    
    /// Modified lamports
    pub lamports: u64,
    
    /// Whether account was modified
    pub was_modified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStats {
    /// Total execution time in microseconds
    pub execution_time_us: u64,
    
    /// Memory allocated
    pub memory_allocated: u64,
    
    /// Number of instructions executed
    pub instructions_executed: u64,
    
    /// Number of syscalls made
    pub syscalls_made: u32,
    
    /// Peak memory usage
    pub peak_memory_usage: u64,
}

/// CRITICAL: Detailed execution trace data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTraceData {
    /// Total number of instructions executed
    pub total_instructions: usize,
    
    /// Program counter progression
    pub program_counters: Vec<u64>,
    
    /// Opcode sequence
    pub opcode_sequence: Vec<u8>,
    
    /// Instruction details for each step
    pub instruction_details: Vec<InstructionDetail>,
}

/// CRITICAL: Individual instruction detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionDetail {
    /// Step number
    pub step: usize,
    
    /// Program counter
    pub pc: u64,
    
    /// Opcode
    pub opcode: u8,
    
    /// Opcode name
    pub opcode_name: String,
    
    /// Destination register
    pub dst_reg: u8,
    
    /// Source register
    pub src_reg: u8,
    
    /// Immediate value
    pub immediate: i32,
    
    /// Offset value
    pub offset: i16,
    
    /// Raw instruction bytes
    pub raw_bytes: Vec<u8>,
}

/// CRITICAL: Mathematical witness data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MathematicalWitnessData {
    /// Step number
    pub step: usize,
    
    /// Opcode
    pub opcode: u8,
    
    /// Pre-execution state
    pub pre_state: RegisterStateSnapshot,
    
    /// Post-execution state
    pub post_state: RegisterStateSnapshot,
    
    /// Mathematical constraints
    pub constraints: Vec<String>,
}

/// CRITICAL: Register state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterStateSnapshot {
    /// All 11 registers
    pub registers: [u64; 11],
    
    /// Program counter
    pub pc: u64,
    
    /// Step count
    pub step_count: usize,
    
    /// Compute units consumed
    pub compute_units: u64,
}

/// CRITICAL: Memory operation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOperationData {
    /// Step number
    pub step: usize,
    
    /// Memory address
    pub address: u64,
    
    /// Operation type (read/write)
    pub operation_type: String,
    
    /// Data size
    pub size: usize,
    
    /// Data value
    pub value: u64,
}

// =====================================================
// 3. I/O FUNCTIONS - Core functionality
// =====================================================

impl SolanaExecutionInput {
    /// Create a default execution input with test data
    pub fn create_test_input() -> Self {
        // Read the actual SolInvoke_test.so file
        let program_data = match std::fs::read("SolInvoke_test.so") {
            Ok(data) => {
                println!("📁 [TEST] Loaded SolInvoke_test.so: {} bytes", data.len());
                data
            },
            Err(e) => {
                println!("⚠️  [TEST] Failed to load SolInvoke_test.so: {}, using fallback", e);
                // Fallback to hardcoded data
                vec![
                    0xB7, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,  // MOV r1, 10
                    0xB7, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,  // MOV r2, 5
                    0x0F, 0x31, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,  // ADD r3, r1, r2
                    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // EXIT
                ]
            }
        };
        
        Self {
            program_data,
            instruction_data: vec![1, 2, 3, 4],
            accounts: vec![
                AccountInput {
                    pubkey: "11111111111111111111111111111111".to_string(),
                    data: vec![0; 64],
                    owner: "11111111111111111111111111111111".to_string(),
                    is_writable: true,
                    is_signer: false,
                    is_executable: false,
                    rent_epoch: 0,
                    lamports: 1000000,
                },
                AccountInput {
                    pubkey: "22222222222222222222222222222222".to_string(),
                    data: vec![0; 32],
                    owner: "11111111111111111111111111111111".to_string(),
                    is_writable: true,
                    is_signer: false,
                    is_executable: false,
                    rent_epoch: 0,
                    lamports: 500000,
                },
            ],
            execution_params: ExecutionParams {
                compute_unit_limit: 1_400_000,
                max_call_depth: 64,
                enable_logging: true,
                enable_stack_traces: false,
                memory_regions: vec![
                    MemoryRegion {
                        address: 0x400000,
                        size: 0x100000,
                        permissions: 0x7, // RWX
                    },
                ],
            },
            program_id: Some("TestProgram111111111111111111111111111111111".to_string()),
        }
    }
    
    /// Load execution input from a binary file
    pub fn from_file(file_path: &str) -> Result<Self> {
        let data = std::fs::read(file_path)?;
        let input: SolanaExecutionInput = bincode::deserialize(&data)?;
        Ok(input)
    }
    
    /// Save execution input to a binary file
    pub fn to_file(&self, file_path: &str) -> Result<()> {
        let data = bincode::serialize(self)?;
        std::fs::write(file_path, data)?;
        Ok(())
    }
}

impl SolanaExecutionOutput {
    /// Create a default success output
    pub fn create_success() -> Self {
        Self {
            success: true,
            exit_code: 0,
            compute_units_consumed: 0,
            modified_accounts: vec![],
            return_data: None,
            logs: vec!["Program executed successfully".to_string()],
            stats: ExecutionStats {
                execution_time_us: 0,
                memory_allocated: 0,
                instructions_executed: 0,
                syscalls_made: 0,
                peak_memory_usage: 0,
            },
            error: None,
            execution_trace: None,
            mathematical_witnesses: None,
            register_states: None,
            memory_operations: None,
        }
    }
    
    /// Create an error output
    pub fn create_error(error_msg: &str, exit_code: u32) -> Self {
        Self {
            success: false,
            exit_code,
            compute_units_consumed: 0,
            modified_accounts: vec![],
            return_data: None,
            logs: vec![format!("Error: {}", error_msg)],
            stats: ExecutionStats {
                execution_time_us: 0,
                memory_allocated: 0,
                instructions_executed: 0,
                syscalls_made: 0,
                peak_memory_usage: 0,
            },
            error: Some(error_msg.to_string()),
            execution_trace: None,
            mathematical_witnesses: None,
            register_states: None,
            memory_operations: None,
        }
    }
    
    /// Save execution output to a binary file
    pub fn to_file(&self, file_path: &str) -> Result<()> {
        let data = bincode::serialize(self)?;
        std::fs::write(file_path, data)?;
        Ok(())
    }
}

// =====================================================
// 4. UTILITY FUNCTIONS - Helper functions
// =====================================================

/// Generate a test input file for development
pub fn generate_test_input() -> Result<()> {
    let test_input = SolanaExecutionInput::create_test_input();
    test_input.to_file("input.bin")?;
    println!("✅ Generated test input.bin with {} bytes", 
             std::fs::metadata("input.bin")?.len());
    Ok(())
}

/// Convert account input to RealBpfLoader format
pub fn convert_accounts(input_accounts: &[AccountInput]) -> Vec<crate::real_bpf_loader::BpfAccount> {
    input_accounts.iter().map(|acc| {
        // Convert String pubkey to [u8; 32] (simplified for now)
        let mut pubkey_bytes = [0u8; 32];
        let acc_pubkey = acc.pubkey.as_bytes();
        pubkey_bytes[..acc_pubkey.len().min(32)].copy_from_slice(&acc_pubkey[..acc_pubkey.len().min(32)]);
        
        // Convert String owner to [u8; 32] (simplified for now)
        let mut owner_bytes = [0u8; 32];
        let acc_owner = acc.owner.as_bytes();
        owner_bytes[..acc_owner.len().min(32)].copy_from_slice(&acc_owner[..acc_owner.len().min(32)]);
        
        crate::real_bpf_loader::BpfAccount {
            pubkey: pubkey_bytes.to_vec(),
            data: acc.data.clone(),
            owner: owner_bytes.to_vec(),
            lamports: acc.lamports,
            executable: acc.is_executable,
            rent_epoch: acc.rent_epoch,
        }
    }).collect()
}

/// Convert execution params to RealBpfLoader format
pub fn convert_execution_params(params: &ExecutionParams) -> crate::real_bpf_loader::TransactionContext {
    // For now, create a minimal TransactionContext since the existing one is limited
    crate::real_bpf_loader::TransactionContext {
        blockhash: [0u8; 32],
        fee_payer: [0u8; 32],
        compute_budget: params.compute_unit_limit as u64,
    }
}

// =====================================================
// 5. TESTING FUNCTIONS - For development and testing
// =====================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_input_creation() {
        let input = SolanaExecutionInput::create_test_input();
        assert_eq!(input.program_data.len(), 32);
        assert_eq!(input.accounts.len(), 2);
        assert_eq!(input.execution_params.compute_unit_limit, 1_400_000);
    }
    
    #[test]
    fn test_serialization() -> Result<()> {
        let input = SolanaExecutionInput::create_test_input();
        let data = bincode::serialize(&input)?;
        let deserialized: SolanaExecutionInput = bincode::deserialize(&data)?;
        
        assert_eq!(input.program_data, deserialized.program_data);
        assert_eq!(input.accounts.len(), deserialized.accounts.len());
        Ok(())
    }
    
    #[test]
    fn test_file_io() -> Result<()> {
        let input = SolanaExecutionInput::create_test_input();
        let test_file = "test_input.bin";
        
        // Save to file
        input.to_file(test_file)?;
        
        // Load from file
        let loaded = SolanaExecutionInput::from_file(test_file)?;
        assert_eq!(input.program_data, loaded.program_data);
        
        // Cleanup
        std::fs::remove_file(test_file)?;
        Ok(())
    }
}

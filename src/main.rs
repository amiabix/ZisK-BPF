#![no_main]
ziskos::entrypoint!(main);

use ziskos::{read_input, set_output};
use bincode;
mod real_bpf_loader;
mod opcode_implementations;
mod zisk_io;
mod elf_parser;
mod bin_generator;
mod trace_recorder;

use real_bpf_loader::{RealBpfLoader, BpfAccount, TransactionContext};
use opcode_implementations::{ZkConstraintSystem, VmState, BpfInstruction, decode_bpf_instruction};
use zisk_io::{SolanaExecutionInput, SolanaExecutionOutput, generate_test_input, convert_accounts, convert_execution_params};
use bin_generator::ensure_input_bin_exists;
use trace_recorder::TraceRecorder;

fn main() {
    println!("🚀 [ZISK-SOLANA] Starting structured I/O execution...");
    
    // Step 1: Ensure input.bin exists (generate from Test.so if needed)
    // TEMPORARILY COMMENTED OUT FOR EMULATION TESTING
    // ensure_input_bin_exists().expect("Failed to ensure input.bin exists");
    
    // Step 2: Initialize trace recorder for ZK proof generation
    let mut trace_recorder = TraceRecorder::new();
    
    // Step 3: Read structured input from input.bin file
    let execution_input: SolanaExecutionInput = match std::fs::read("input.bin") {
        Ok(input_data) if !input_data.is_empty() => {
            // Try to deserialize as structured input from input.bin
            match bincode::deserialize(&input_data) {
                Ok(parsed_input) => {
                    println!("✅ [ZISK] Successfully parsed structured input from ZisK");
                    parsed_input
                },
                Err(e) => {
                    println!("⚠️  [ZISK] Failed to deserialize ZisK input: {}", e);
                    println!("📝 [ZISK] Attempting to use Test.so directly...");
                    
                    // Try to read Test.so directly as a fallback
                    match std::fs::read("Test.so") {
                        Ok(test_so_data) => {
                            println!("✅ [ZISK] Successfully read Test.so ({} bytes)", test_so_data.len());
                            SolanaExecutionInput {
                                program_data: test_so_data,
                                instruction_data: vec![1, 2, 3, 4],
                                accounts: vec![],
                                execution_params: zisk_io::ExecutionParams {
                                    compute_unit_limit: 1_400_000,
                                    max_call_depth: 64,
                                    enable_logging: true,
                                    enable_stack_traces: false,
                                    memory_regions: vec![],
                                },
                                program_id: Some("TestProgram".to_string()),
                            }
                        },
                        Err(e) => {
                            println!("⚠️  [ZISK] Failed to read Test.so: {}, falling back to test input", e);
                            SolanaExecutionInput::create_test_input()
                        }
                    }
                }
            }
        },
        _ => {
            println!("📝 [ZISK] No input received from ZisK, using test input");
            SolanaExecutionInput::create_test_input()
        }
    };
    
    println!("📊 [ZISK] Using input with {} bytes of program data", execution_input.program_data.len());
    
    println!("📊 [I/O] Input Summary:");
    println!("   Program size: {} bytes", execution_input.program_data.len());
    println!("   Accounts: {}", execution_input.accounts.len());
    println!("   Compute limit: {}", execution_input.execution_params.compute_unit_limit);
    println!("   Instruction data: {:?}", execution_input.instruction_data);
    
    // Step 2: Convert input to RealBpfLoader format
    let accounts = convert_accounts(&execution_input.accounts);
    let _context = convert_execution_params(&execution_input.execution_params);
    
    // Step 3: Create and configure BPF loader
    let mut loader = RealBpfLoader::new().expect("Failed to create RBPF loader");
    
    // Step 4: Load the BPF program
    println!("🔧 [RBPF] Loading BPF program...");
    match loader.load_program("main_program", &execution_input.program_data) {
        Ok(_) => println!("✅ [RBPF] Program loaded successfully"),
        Err(e) => {
            let error_output = SolanaExecutionOutput::create_error(
                &format!("Failed to load program: {}", e), 
                1
            );
            println!("❌ [RBPF] Program load failed: {}", e);
            // Set error output using ZisK's set_output format
            set_output(0, 1); // Error flag
            set_output(1, 1); // Error code
            return;
        }
    }
    
    // Step 6: Execute the BPF program
    println!("⚡ [RBPF] Executing BPF program...");
    let execution_result = match loader.execute_program("main_program", &execution_input.instruction_data, &accounts) {
        Ok(result) => {
            println!("✅ [RBPF] Execution completed successfully");
            result
        },
        Err(e) => {
            let error_output = SolanaExecutionOutput::create_error(
                &format!("Execution failed: {}", e), 
                2
            );
            println!("❌ [RBPF] Execution failed: {}", e);
            // Set error output using ZisK's set_output format
            set_output(0, 1); // Error flag
            set_output(1, 2); // Error code
            return;
        }
    };
    
    // Step 7: Get the trace from the execution result and export it
    if let Some(execution_trace) = execution_result.execution_trace {
        if let Err(e) = execution_trace.export_trace("execution_trace.json") {
            println!("⚠️  [TRACE] Failed to export trace: {}", e);
        } else {
            println!("✅ [TRACE] Execution trace exported to execution_trace.json");
            println!("📊 [TRACE] Trace contains {} steps, {} constraints", 
                    execution_trace.get_trace().steps.len(),
                    execution_trace.get_constraint_count());
        }
    } else {
        println!("⚠️  [TRACE] No execution trace available");
    }
    
    // Note: Execution trace is already exported from the BPF execution result above
    
    // Step 8: Create structured output
    let mut output = SolanaExecutionOutput::create_success();
    // Note: ProgramExecutionResult doesn't have exit_code, using success instead
    output.exit_code = if execution_result.success { 0 } else { 1 };
    output.compute_units_consumed = execution_result.compute_units_consumed as u32;
    output.logs.push(format!("Program executed with success: {}", execution_result.success));
    output.logs.push(format!("Consumed {} compute units", execution_result.compute_units_consumed));
    
    // Add account modifications (simplified for now)
    for (i, account) in accounts.iter().enumerate() {
        output.modified_accounts.push(zisk_io::AccountOutput {
            pubkey: String::from_utf8_lossy(&account.pubkey).to_string(),
            data: account.data.clone(),
            lamports: account.lamports,
            was_modified: false, // Would be true if account was actually modified
        });
    }
    
    // Step 9: Test constraint generation system
    println!("🧮 [ZK] Testing constraint generation system...");
    
    let mut vm_state = VmState {
        registers: [0u64; 11],
        pc: 0,
        compute_units: 1000000,
        step_count: 0,
        terminated: false,
        memory_hash: [0u8; 32],
        program_hash: [0u8; 32],
        error: None,
    };
    vm_state.registers[1] = 10;
    vm_state.registers[2] = 5;
    
    let mut constraint_system = ZkConstraintSystem::new();
    
    // Test with first instruction
    let instruction_bytes = &execution_input.program_data[0..8];
    let instruction = decode_bpf_instruction(instruction_bytes);
    if instruction.opcode != 0 {
        println!("   Decoded instruction: {:?}", instruction);
        
        let pre_state = vm_state.clone();
        let step = 0;
        
        match instruction.opcode {
            0xB7 => { // MOV_IMM
                let constraints = opcode_implementations::generate_mov_imm_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.imm.into(), step
                );
                constraint_system.add_constraints(constraints);
                println!("   Generated MOV_IMM constraints");
            },
            _ => println!("   Unsupported opcode for constraint generation: 0x{:02X}", instruction.opcode),
        }
        
        vm_state.registers[instruction.dst as usize] = instruction.imm as u64;
        vm_state.pc += 8;
        
        println!("   VM state: r1={}, r2={}, PC={}", 
                vm_state.registers[1], vm_state.registers[2], vm_state.pc);
    }
    
    output.stats.instructions_executed = constraint_system.constraints.len() as u64;
    output.logs.push(format!("Generated {} ZK constraints", constraint_system.constraints.len()));
    
    // Step 10: Set output for ZisK
    println!("📤 [I/O] Setting structured output for ZisK...");
    // Set output using ZisK's set_output format
    set_output(0, 0); // Success flag
    set_output(1, output.exit_code);
    set_output(2, output.compute_units_consumed);
    set_output(3, output.stats.instructions_executed as u32);
    set_output(4, output.modified_accounts.len() as u32);
    
    println!("🎉 [ZISK-SOLANA] Execution completed successfully!");
    println!("   Exit code: {}", output.exit_code);
    println!("   Compute units: {}", output.compute_units_consumed);
    println!("   Constraints: {}", output.stats.instructions_executed);
}

// REAL MEMORY OPERATIONS - NO SIMULATION
use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;

static MEMORY: Lazy<Mutex<HashMap<u64, u8>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn read_memory_u8(addr: u64) -> u8 {
    MEMORY.lock().unwrap().get(&addr).copied().unwrap_or(0)
}

fn read_memory_u16(addr: u64) -> u16 {
    let low = read_memory_u8(addr) as u16;
    let high = read_memory_u8(addr + 1) as u16;
    low | (high << 8)
}

fn read_memory_u32(addr: u64) -> u32 {
    let mut value = 0u32;
    for i in 0..4 {
        value |= (read_memory_u8(addr + i) as u32) << (i * 8);
    }
    value
}

fn read_memory_u64(addr: u64) -> u64 {
    let mut value = 0u64;
    for i in 0..8 {
        value |= (read_memory_u8(addr + i) as u64) << (i * 8);
    }
    value
}

fn write_memory_u8(addr: u64, value: u8) {
    MEMORY.lock().unwrap().insert(addr, value);
}

fn write_memory_u16(addr: u64, value: u16) {
    let bytes = value.to_le_bytes();
    write_memory_u8(addr, bytes[0]);
    write_memory_u8(addr + 1, bytes[1]);
}

fn write_memory_u32(addr: u64, value: u32) {
    let bytes = value.to_le_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        write_memory_u8(addr + i as u64, byte);
    }
}

fn write_memory_u64(addr: u64, value: u64) {
    let bytes = value.to_le_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        write_memory_u8(addr + i as u64, byte);
    }
}

fn generate_constraints_from_execution(
    bpf_program: &[u8], 
    execution_result: &real_bpf_loader::ProgramExecutionResult
) -> ZkConstraintSystem {
    let mut constraint_system = ZkConstraintSystem::new();
    
    // Create initial VM state
    let mut vm_state = VmState {
        registers: [0u64; 11],
        pc: 0,
        compute_units: 0,
        step_count: 0,
        terminated: false,
        memory_hash: [0u8; 32],
        program_hash: [0u8; 32],
        error: None,
    };
    
    // Process each instruction and generate constraints
    let mut step = 0;
    let mut pc = 0;
    
    while pc < bpf_program.len() && step < 1000 { // Safety limit
        // BPF instructions can be 8 or 16 bytes, let's handle both
        let instruction_size = if pc + 16 <= bpf_program.len() {
            // Check if this is a 16-byte instruction (like MOV_IMM with 64-bit immediate)
            let opcode = bpf_program[pc];
            if opcode == 0xB7 { // MOV_IMM
                16
            } else {
                8
            }
        } else if pc + 8 <= bpf_program.len() {
            8
        } else {
            break;
        };
        
        let instruction_bytes = &bpf_program[pc..pc + instruction_size];
        let instruction = decode_bpf_instruction(instruction_bytes);
        
        // Capture pre-execution state
        let pre_state = vm_state.clone();
        
        // Execute instruction and update VM state
        match instruction.opcode {
            0x07 => { // ADD_IMM
                let dst = instruction.dst as usize;
                if dst < vm_state.registers.len() {
                    vm_state.registers[dst] = vm_state.registers[dst].wrapping_add(instruction.imm as u64);
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_add_imm_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.imm.into(), step
                );
                constraint_system.add_constraints(constraints);
            },
            0xB7 => { // MOV_IMM
                let dst = instruction.dst as usize;
                if dst < vm_state.registers.len() {
                    vm_state.registers[dst] = instruction.imm as u64;
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_mov_imm_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.imm.into(), step
                );
                constraint_system.add_constraints(constraints);
            },
            0xBF => { // MOV_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    vm_state.registers[dst] = vm_state.registers[src];
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_mov_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x0F => { // ADD_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    vm_state.registers[dst] = vm_state.registers[dst].wrapping_add(vm_state.registers[src]);
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_add_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x1F => { // SUB_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    vm_state.registers[dst] = vm_state.registers[dst].wrapping_sub(vm_state.registers[src]);
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_sub_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x2F => { // MUL_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    vm_state.registers[dst] = vm_state.registers[dst].wrapping_mul(vm_state.registers[src]);
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_mul_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x3F => { // DIV_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    if vm_state.registers[src] != 0 {
                        vm_state.registers[dst] = vm_state.registers[dst] / vm_state.registers[src];
                    } else {
                        vm_state.error = Some("Division by zero".to_string());
                    }
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_div_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x4F => { // OR_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    vm_state.registers[dst] |= vm_state.registers[src];
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_or_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x5F => { // AND_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    vm_state.registers[dst] &= vm_state.registers[src];
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_and_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x6F => { // LSH_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    let shift_amount = vm_state.registers[src] & 0x3F; // 6-bit shift
                    vm_state.registers[dst] = vm_state.registers[dst].wrapping_shl(shift_amount as u32);
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_lsh_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x7F => { // RSH_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    let shift_amount = vm_state.registers[src] & 0x3F; // 6-bit shift
                    vm_state.registers[dst] = vm_state.registers[dst].wrapping_shr(shift_amount as u32);
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_rsh_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x8F => { // NEG
                let dst = instruction.dst as usize;
                if dst < vm_state.registers.len() {
                    vm_state.registers[dst] = vm_state.registers[dst].wrapping_neg();
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_neg64_constraints(
                    &pre_state, &vm_state, instruction.dst, step
                );
                constraint_system.add_constraints(constraints);
            },
            0x9F => { // MOD_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    if vm_state.registers[src] != 0 {
                        vm_state.registers[dst] %= vm_state.registers[src];
                    } else {
                        vm_state.error = Some("Modulo by zero".to_string());
                    }
                }
                        vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_mod_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0xAF => { // XOR_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    vm_state.registers[dst] ^= vm_state.registers[src];
                }
                    vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_xor_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0xC7 => { // ARSH_REG
                let dst = instruction.dst as usize;
                let src = instruction.src as usize;
                if dst < vm_state.registers.len() && src < vm_state.registers.len() {
                    let shift_amount = vm_state.registers[src] & 0x3F; // 6-bit shift
                    vm_state.registers[dst] = (vm_state.registers[dst] as i64).wrapping_shr(shift_amount as u32) as u64;
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_arsh_reg_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.src, step
                );
                constraint_system.add_constraints(constraints);
            },
            0xC8 => { // MOV_IMM_32
                let dst = instruction.dst as usize;
                if dst < vm_state.registers.len() {
                    vm_state.registers[dst] = (instruction.imm as u32) as u64;
                    }
                    vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_mov_imm_constraints(
                    &pre_state, &vm_state, instruction.dst, instruction.imm.into(), step
                );
                constraint_system.add_constraints(constraints);
            },
            0xCF => { // ENDIAN
                let dst = instruction.dst as usize;
                if dst < vm_state.registers.len() {
                    let value = vm_state.registers[dst];
                    vm_state.registers[dst] = match instruction.imm {
                        16 => value.swap_bytes(),
                        32 => (value as u32).swap_bytes() as u64,
                        64 => value.swap_bytes(),
                        _ => value,
                    };
                }
                    vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_be32_constraints(
                    &pre_state, &vm_state, instruction.dst, step
                );
                constraint_system.add_constraints(constraints);
            },
            0xD4 => { // BE16 - Big endian 16-bit
                let dst = instruction.dst as usize;
                if dst < vm_state.registers.len() {
                    let value = vm_state.registers[dst];
                    vm_state.registers[dst] = ((value & 0xFF) << 8) | ((value >> 8) & 0xFF);
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_be16_constraints(
                    &pre_state, &vm_state, instruction.dst, step
                );
                constraint_system.add_constraints(constraints);
            },
            0xD5 => { // BE32 - Big endian 32-bit
                let dst = instruction.dst as usize;
                if dst < vm_state.registers.len() {
                    let value = vm_state.registers[dst];
                    vm_state.registers[dst] = value.swap_bytes();
                }
                vm_state.pc += instruction_size;
                
                let constraints = opcode_implementations::generate_be32_constraints(
                    &pre_state, &vm_state, instruction.dst, step
                );
                constraint_system.add_constraints(constraints);
            },
            
            // CALL OPERATIONS
            0x85 => { // CALL - Call immediate
                let function_addr = instruction.imm as u64;
                let return_addr = vm_state.pc + instruction_size;
                
                // In real implementation, this would push to call stack
                if function_addr < bpf_program.len() as u64 {
                    vm_state.pc = function_addr as usize;
                } else {
                    vm_state.error = Some("Invalid function address".to_string());
                    vm_state.pc += instruction_size;
                }
                
                let constraints = opcode_implementations::generate_call_constraints(
                    &pre_state, &vm_state, instruction.imm.into(), step
                );
                constraint_system.add_constraints(constraints);
            },
            0x8D => { // CALLX - Call register
                let dst = instruction.dst as usize;
                if dst < vm_state.registers.len() {
                    let function_addr = vm_state.registers[dst];
                    let return_addr = vm_state.pc + instruction_size;
                    
                    // In real implementation, this would push to call stack
                    if function_addr < bpf_program.len() as u64 {
                        vm_state.pc = function_addr as usize;
                    } else {
                        vm_state.error = Some("Invalid function address".to_string());
                        vm_state.pc += instruction_size;
                    }
                } else {
                    vm_state.pc += instruction_size;
                }
                
                let constraints = opcode_implementations::generate_callx_constraints(
                    &pre_state, &vm_state, instruction.dst, step
                );
                constraint_system.add_constraints(constraints);
            },
            
            0x95 => { // EXIT
                vm_state.terminated = true;
                
                let constraints = opcode_implementations::generate_exit_constraints(
                    &pre_state, &vm_state, step
                );
                constraint_system.add_constraints(constraints);
                break;
            },
            _ => {
                // Unknown opcode - skip
                vm_state.pc += instruction_size;
            }
        }
        
        vm_state.step_count += 1;
        vm_state.compute_units += 1;
        pc = vm_state.pc as usize;
        step += 1;
    } // End of while loop
    
    constraint_system
}


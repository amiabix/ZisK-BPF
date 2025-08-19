use std::collections::HashMap;
use anyhow::Result;
use crate::real_bpf_loader::RealBpfLoader;
use crate::opcode_implementations::{ZkConstraintSystem, VmState, decode_bpf_instruction};
use crate::zisk_io::{SolanaExecutionInput, SolanaExecutionOutput, convert_accounts, convert_execution_params};
use crate::trace_recorder::TraceRecorder;
use crate::sol_invoke_signed_prover::{SolInvokeSignedProver, SolInvokeSignedWitness};

/// BPF Executor - Runs outside ZisK to execute BPF programs and generate execution traces
pub struct BpfExecutor {
    loader: RealBpfLoader,
    trace_recorder: TraceRecorder,
}

impl BpfExecutor {
    pub fn new() -> Result<Self> {
        let loader = RealBpfLoader::new()?;
        let trace_recorder = TraceRecorder::new();
        
        Ok(BpfExecutor {
            loader,
            trace_recorder,
        })
    }
    
    /// Execute a BPF program and return the execution result with trace
    pub fn execute_bpf_program(&mut self, input: &SolanaExecutionInput) -> Result<SolanaExecutionOutput> {
        println!("🔧 [BPF-EXECUTOR] Starting BPF execution...");
        
        // Convert input to RealBpfLoader format
        let accounts = convert_accounts(&input.accounts);
        let _context = convert_execution_params(&input.execution_params);
        
        // Load the BPF program
        println!("🔧 [BPF-EXECUTOR] Loading BPF program...");
        match self.loader.load_program("main_program", &input.program_data) {
            Ok(_) => println!("[BPF-EXECUTOR] Program loaded successfully"),
            Err(e) => {
                let error_output = SolanaExecutionOutput::create_error(
                    &format!("Failed to load program: {}", e), 
                    1
                );
                println!("[BPF-EXECUTOR] Program load failed: {}", e);
                return Ok(error_output);
            }
        }
        
        // Execute the BPF program
        println!("⚡ [BPF-EXECUTOR] Executing BPF program...");
        let mut execution_result = match self.loader.execute_program("main_program", &input.instruction_data, &accounts) {
            Ok(result) => {
                println!("[BPF-EXECUTOR] Execution completed successfully");
                result
            },
            Err(e) => {
                let error_output = SolanaExecutionOutput::create_error(
                    &format!("Execution failed: {}", e), 
                    2
                );
                println!("[BPF-EXECUTOR] Execution failed: {}", e);
                return Ok(error_output);
            }
        };
        
        // Get the trace from the execution result and export it
        if let Some(ref mut execution_trace) = execution_result.execution_trace {
            if let Err(e) = execution_trace.export_trace("execution_trace.json") {
                println!("[BPF-EXECUTOR] Failed to export trace: {}", e);
            } else {
                println!("✅ [BPF-EXECUTOR] Execution trace exported to execution_trace.json");
                println!("📊 [BPF-EXECUTOR] Trace contains {} steps, {} constraints", 
                        execution_trace.get_trace().steps.len(),
                        execution_trace.get_constraint_count());
            }
            
            // Generate Mathematical Proofs for Every BPF Operation
            println!("🧮 [BPF-EXECUTOR] Generating mathematical proofs for every BPF operation...");
            execution_trace.generate_mathematical_witnesses();
            
            let total_constraints = execution_trace.get_total_constraints();
            let mathematical_proof_valid = execution_trace.is_mathematical_proof_valid();
            
            println!("✅ [BPF-EXECUTOR] Mathematical proof generation complete:");
            println!("   Total constraints generated: {}", total_constraints);
            println!("   Mathematical proof valid: {}", mathematical_proof_valid);
            
            // Export mathematical proof to file
            if let Err(e) = execution_trace.export_mathematical_proof("mathematical_proof.json") {
                println!("⚠️  [BPF-EXECUTOR] Failed to export mathematical proof: {}", e);
            } else {
                println!("✅ [BPF-EXECUTOR] Mathematical proof exported to mathematical_proof.json");
            }
        }
        
        // Create structured output
        let mut output = SolanaExecutionOutput::create_success();
        output.exit_code = if execution_result.success { 0 } else { 1 };
        output.compute_units_consumed = execution_result.compute_units_consumed as u32;
        output.logs.push(format!("Program executed with success: {}", execution_result.success));
        output.logs.push(format!("Consumed {} compute units", execution_result.compute_units_consumed));
        
        // Add account modifications
        for (_i, account) in accounts.iter().enumerate() {
            output.modified_accounts.push(crate::zisk_io::AccountOutput {
                pubkey: String::from_utf8_lossy(&account.pubkey).to_string(),
                data: account.data.clone(),
                lamports: account.lamports,
                was_modified: false,
            });
        }
        
        // Generate ZK proof using SolInvokeSignedProver
        if let Some(execution_trace) = &execution_result.execution_trace {
            println!("[BPF-EXECUTOR] Starting SolInvokeSignedProver proof generation...");
            
            let mut prover = SolInvokeSignedProver::new_with_program_id([0x01, 0x02, 0x03, 0x04]);
            
            // Create witness from the execution trace
            let witness = create_sol_invoke_signed_witness(&execution_trace.get_trace(), input);
            
            // Generate the proof
            match prover.prove_sol_invoke_signed(&witness) {
                Ok(constraints) => {
                    println!("✅ [BPF-EXECUTOR] Successfully generated {} constraints", constraints.len());
                    output.stats.instructions_executed = constraints.len() as u64;
                    output.logs.push(format!("Generated {} SolInvokeSigned constraints", constraints.len()));
                },
                Err(e) => {
                    println!("❌ [BPF-EXECUTOR] Failed to generate proof: {}", e);
                    output.logs.push(format!("Proof generation failed: {}", e));
                }
            }
        }
        
        Ok(output)
    }
    
    /// Generate constraints from execution trace
    pub fn generate_constraints_from_execution(
        &self,
        bpf_program: &[u8], 
        execution_result: &crate::real_bpf_loader::ProgramExecutionResult
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
        
        while pc < bpf_program.len() && step < 1000 {
            let instruction_size = if pc + 16 <= bpf_program.len() {
                let opcode = bpf_program[pc];
                if opcode == 0xB7 { 16 } else { 8 }
            } else if pc + 8 <= bpf_program.len() { 8 } else { break };
            
            let instruction_bytes = &bpf_program[pc..pc + instruction_size];
            let instruction = decode_bpf_instruction(instruction_bytes);
            
            let pre_state = vm_state.clone();
            
            // Execute instruction and update VM state
            match instruction.opcode {
                0x07 => { // ADD_IMM
                    let dst = instruction.dst as usize;
                    if dst < vm_state.registers.len() {
                        vm_state.registers[dst] = vm_state.registers[dst].wrapping_add(instruction.imm as u64);
                    }
                    vm_state.pc += instruction_size;
                    
                    let constraints = crate::opcode_implementations::generate_add_imm_constraints(
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
                    
                    let constraints = crate::opcode_implementations::generate_mov_imm_constraints(
                        &pre_state, &vm_state, instruction.dst, instruction.imm.into(), step
                    );
                    constraint_system.add_constraints(constraints);
                },
                0x95 => { // EXIT
                    vm_state.terminated = true;
                    let constraints = crate::opcode_implementations::generate_exit_constraints(
                        &pre_state, &vm_state, step
                    );
                    constraint_system.add_constraints(constraints);
                    break;
                },
                _ => {
                    vm_state.pc += instruction_size;
                }
            }
            
            vm_state.step_count += 1;
            vm_state.compute_units += 1;
            pc = vm_state.pc as usize;
            step += 1;
        }
        
        constraint_system
    }
}

/// Create a SolInvokeSignedWitness from the execution trace and input
fn create_sol_invoke_signed_witness(
    execution_trace: &crate::trace_recorder::ExecutionTrace,
    execution_input: &SolanaExecutionInput
) -> SolInvokeSignedWitness {
    // Convert trace steps to VmExecutionStep format
    let mut vm_trace = Vec::new();
    for (i, step) in execution_trace.steps.iter().enumerate() {
        vm_trace.push(crate::sol_invoke_signed_prover::VmExecutionStep {
            step_index: i as u64,
            program_counter: step.pc,
            instruction: step.instruction.raw_bytes,
            registers: step.post_state.registers,
            memory_operations: vec![],
            compute_consumed: 0,
        });
    }
    
    // Create basic witness structure
    let witness = SolInvokeSignedWitness {
        message: crate::sol_invoke_signed_prover::MessageWitness {
            header: crate::sol_invoke_signed_prover::MessageHeader {
                num_required_signatures: 0,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            account_keys: vec![[0u8; 32]],
            recent_blockhash: [0u8; 32],
            instructions: vec![crate::sol_invoke_signed_prover::CompiledInstruction {
                program_id_index: 0,
                accounts: vec![0],
                data: execution_input.instruction_data.clone(),
            }],
            nonce_account: None,
            derived_privileges: vec![],
        },
        alt: None,
        loader: crate::sol_invoke_signed_prover::LoaderWitness {
            program_account: crate::sol_invoke_signed_prover::ProgramAccount {
                address: [0u8; 32],
                owner: [0u8; 32],
                executable: true,
                programdata_address: None,
            },
            programdata_account: None,
            loader_type: crate::sol_invoke_signed_prover::LoaderType::BpfLoaderV2,
            executable_bytes: execution_input.program_data.clone(),
            no_write_violations: vec![],
        },
        elf: crate::sol_invoke_signed_prover::ElfWitness {
            elf_header: crate::sol_invoke_signed_prover::ElfHeader {
                entry_point: 0,
                program_header_offset: 0,
                section_header_offset: 0,
                flags: 0,
                header_size: 64,
                program_header_size: 0,
                section_header_size: 0,
            },
            sections: vec![crate::sol_invoke_signed_prover::ElfSection {
                name: ".text".to_string(),
                section_type: 1,
                flags: 0x4,
                address: 0,
                offset: 0,
                size: execution_input.program_data.len() as u64,
                data: execution_input.program_data.clone(),
                is_executable: true,
                is_writable: false,
            }],
            relocations: vec![],
            verified_opcodes: vec![],
            stack_frame_config: crate::sol_invoke_signed_prover::StackFrameConfig {
                max_call_depth: 64,
                max_frame_size: 1000,
                stack_size: 10000,
            },
            syscall_whitelist: vec![],
        },
        state_commitment: crate::sol_invoke_signed_prover::StateCommitmentWitness {
            pre_state_root: [0u8; 32],
            post_state_root: [0u8; 32],
            touched_accounts: vec![],
            merkle_tree_height: 0,
            lamports_conservation: crate::sol_invoke_signed_prover::LamportsConservation {
                pre_total: 0,
                post_total: 0,
                fees_collected: 0,
                rent_collected: 0,
                burn_amount: 0,
            },
        },
        execution: crate::sol_invoke_signed_prover::ExecutionWitness {
            vm_trace,
            compute_budget: crate::sol_invoke_signed_prover::ComputeBudget {
                max_units: execution_input.execution_params.compute_unit_limit as u64,
                consumed_units: 0,
                per_instruction_costs: HashMap::new(),
                syscall_costs: HashMap::new(),
            },
            memory_regions: crate::sol_invoke_signed_prover::MemoryLayout {
                program_region: crate::sol_invoke_signed_prover::MemoryRegion {
                    start_address: 0,
                    length: execution_input.program_data.len() as u64,
                    is_writable: false,
                    is_executable: true,
                },
                stack_region: crate::sol_invoke_signed_prover::MemoryRegion {
                    start_address: 0x1000000,
                    length: 0x10000,
                    is_writable: true,
                    is_executable: false,
                },
                heap_region: crate::sol_invoke_signed_prover::MemoryRegion {
                    start_address: 0x2000000,
                    length: 0x100000,
                    is_writable: true,
                    is_executable: false,
                },
                account_regions: HashMap::new(),
            },
            syscall_invocations: vec![],
        },
        cpi_stack: crate::sol_invoke_signed_prover::CpiStackWitness {
            pre_stack: crate::sol_invoke_signed_prover::InvokeStack {
                frames: vec![],
                depth: 0,
                max_depth: 64,
            },
            post_stack: crate::sol_invoke_signed_prover::InvokeStack {
                frames: vec![crate::sol_invoke_signed_prover::InvokeFrame {
                    program_id: [0u8; 32],
                    loader_id: [0u8; 32],
                    instruction: crate::sol_invoke_signed_prover::CompiledInstruction {
                        program_id_index: 0,
                        accounts: vec![0],
                        data: execution_input.instruction_data.clone(),
                    },
                    account_indices: vec![],
                    account_infos: vec![],
                    signer_seeds: vec![],
                }],
                depth: 1,
                max_depth: 64,
            },
            invoke_instruction: crate::sol_invoke_signed_prover::CpiInstruction {
                target_program: [0u8; 32],
                instruction_data: execution_input.instruction_data.clone(),
                account_metas: vec![],
            },
            signer_seeds: vec![],
            privilege_inheritance: crate::sol_invoke_signed_prover::PrivilegeInheritance {
                parent_privileges: vec![],
                child_privileges: vec![],
                pda_authorities: vec![],
            },
            return_data: None,
        },
        system_program: crate::sol_invoke_signed_prover::SystemProgramWitness {
            system_instructions: vec![],
            rent_calculations: vec![],
            fee_payments: vec![],
            lamports_flows: vec![],
        },
        sysvars: crate::sol_invoke_signed_prover::SysvarWitness {
            clock: crate::sol_invoke_signed_prover::ClockSysvar {
                slot: 0,
                epoch_start_timestamp: 0,
                epoch: 0,
                leader_schedule_epoch: 0,
                unix_timestamp: 0,
            },
            rent: crate::sol_invoke_signed_prover::RentSysvar {
                lamports_per_byte_year: 3480,
                exemption_threshold: 2.0,
                burn_percent: 50,
            },
            epoch_schedule: crate::sol_invoke_signed_prover::EpochScheduleSysvar {
                slots_per_epoch: 432000,
                leader_schedule_slot_offset: 432000,
                warmup: false,
                first_normal_epoch: 0,
                first_normal_slot: 0,
            },
            recent_blockhashes: crate::sol_invoke_signed_prover::RecentBlockhashesSysvar {
                blockhashes: vec![],
            },
            instructions: crate::sol_invoke_signed_prover::InstructionsSysvar {
                instructions: vec![],
            },
            feature_set: crate::sol_invoke_signed_prover::FeatureSetWitness {
                active_features: HashMap::new(),
                slot: 0,
                feature_activations: vec![],
            },
            read_only_enforcements: vec![],
            consistency_checks: vec![],
        },
    };
    
    println!("📊 [WITNESS] Created witness with {} trace steps", witness.execution.vm_trace.len());
    
    witness
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bpf_executor_creation() {
        let executor = BpfExecutor::new();
        assert!(executor.is_ok());
    }
}

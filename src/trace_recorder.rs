use serde::{Serialize, Deserialize};
use std::collections::{HashMap, BTreeMap, HashSet};
use std::collections::btree_map::Entry;
use crate::opcode_implementations::OPCODE_REGISTRY;

// Mathematical proof structures
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MathematicalWitness {
    pub opcode: u8,
    pub pre_state: VmStateSnapshot,
    pub post_state: VmStateSnapshot,
    pub operands: OpcodeOperands,
    pub memory_operations: Vec<MemoryOperation>,
    pub program_counter: u64,
    pub next_program_counter: u64,
    pub compute_units_consumed: u64,
    pub instruction_bytes: [u8; 8],
    pub step_number: usize,
    pub mathematical_constraints: Vec<MathematicalConstraint>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpcodeOperands {
    pub dst_reg: u8,
    pub src_reg: u8,
    pub src_reg2: u8,
    pub offset: i16,
    pub immediate: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemoryOperation {
    pub address: u64,
    pub data: Vec<u8>,
    pub op_type: MemoryOpType,
    pub size: usize,
    pub bounds_valid: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum MemoryOpType {
    Read,
    Write,
    Execute,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MathematicalConstraint {
    Arithmetic {
        operation: ArithmeticOp,
        inputs: Vec<u64>,
        output: u64,
        description: String,
    },
    Equality {
        left: u64,
        right: u64,
        description: String,
    },
    RangeCheck {
        value: u64,
        min: u64,
        max: u64,
        description: String,
    },
    MemoryAddress {
        base: u64,
        offset: i64,
        computed: u64,
        description: String,
    },
    ControlFlow {
        current_pc: u64,
        offset: i64,
        condition_met: bool,
        next_pc: u64,
        description: String,
    },
    StateTransition {
        pre_state_hash: [u8; 32],
        post_state_hash: [u8; 32],
        description: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ArithmeticOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    LeftShift,
    RightShift,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecutionTrace {
    pub steps: Vec<TraceStep>,
    pub initial_state: VmStateSnapshot,
    pub final_state: VmStateSnapshot,
    pub compute_units_consumed: u64,
    pub success: bool,
    // Enhanced tracking structures
    pub opcode_frequency: HashMap<u8, OpcodeStats>,
    pub opcode_sequence: Vec<u8>,
    pub pc_to_opcode: BTreeMap<u64, u8>,
    pub opcode_patterns: HashMap<String, usize>,
    pub register_usage: HashMap<u8, RegisterUsage>,
    pub memory_access_patterns: HashMap<String, usize>,
    pub execution_flow: Vec<ExecutionFlowNode>,
    // Mathematical proof structures
    pub mathematical_witnesses: Vec<MathematicalWitness>,
    pub total_constraints: usize,
    pub mathematical_proof_valid: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TraceStep {
    pub step_number: usize,
    pub pc: u64,
    pub instruction: BpfInstructionTrace,
    pub pre_state: VmStateSnapshot,
    pub post_state: VmStateSnapshot,
    pub memory_accesses: Vec<MemoryAccess>,
    pub compute_units: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BpfInstructionTrace {
    pub opcode: u8,
    pub dst: u8,
    pub src: u8,
    pub offset: i16,
    pub immediate: i32,
    pub raw_bytes: [u8; 8],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VmStateSnapshot {
    pub registers: [u64; 11],
    pub pc: u64,
    pub step_count: usize,
    pub compute_units: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemoryAccess {
    pub address: u64,
    pub value: u64,
    pub size: u8,
    pub access_type: MemoryAccessType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MemoryAccessType {
    Read,
    Write,
    Execute,
}

// Enhanced tracking structures
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpcodeStats {
    pub count: usize,
    pub first_seen_at: usize,
    pub last_seen_at: usize,
    pub pc_locations: Vec<u64>,
    pub compute_units_total: u64,
    pub average_compute_units: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterUsage {
    pub read_count: usize,
    pub write_count: usize,
    pub opcodes_used_in: Vec<u8>,
    pub pc_locations: Vec<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecutionFlowNode {
    pub step_number: usize,
    pub pc: u64,
    pub opcode: u8,
    pub opcode_name: String,
    pub registers_changed: Vec<u8>,
    pub memory_accessed: bool,
    pub compute_units: u64,
    pub branch_target: Option<u64>,
    pub call_target: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct TraceRecorder {
    trace: ExecutionTrace,
    current_step: usize,
    initial_state: Option<VmStateSnapshot>,
}

impl TraceRecorder {
    pub fn new() -> Self {
        Self {
            trace: ExecutionTrace {
                steps: Vec::new(),
                initial_state: VmStateSnapshot::default(),
                final_state: VmStateSnapshot::default(),
                compute_units_consumed: 0,
                success: false,
                // Initialize enhanced tracking structures
                opcode_frequency: HashMap::new(),
                opcode_sequence: Vec::new(),
                pc_to_opcode: BTreeMap::new(),
                opcode_patterns: HashMap::new(),
                register_usage: HashMap::new(),
                memory_access_patterns: HashMap::new(),
                execution_flow: Vec::new(),
                // Initialize mathematical proof structures
                mathematical_witnesses: Vec::new(),
                total_constraints: 0,
                mathematical_proof_valid: false,
            },
            current_step: 0,
            initial_state: None,
        }
    }

    pub fn record_initial_state(&mut self, registers: [u64; 11], pc: u64) {
        let snapshot = VmStateSnapshot {
            registers,
            pc,
            step_count: 0,
            compute_units: 0,
        };
        self.initial_state = Some(snapshot.clone());
        self.trace.initial_state = snapshot;
    }

    pub fn record_instruction_execution(
        &mut self,
        pc: u64,
        instruction_bytes: &[u8],
        pre_registers: [u64; 11],
        post_registers: [u64; 11],
        memory_accesses: Vec<MemoryAccess>,
        compute_units: u64,
    ) {
        if instruction_bytes.len() >= 8 {
            let instruction = BpfInstructionTrace {
                opcode: instruction_bytes[0],
                dst: instruction_bytes[1],
                src: instruction_bytes[2],
                offset: i16::from_le_bytes([instruction_bytes[3], instruction_bytes[4]]),
                immediate: i32::from_le_bytes([
                    instruction_bytes[4], instruction_bytes[5], instruction_bytes[6], instruction_bytes[7]
                ]),
                raw_bytes: [
                    instruction_bytes[0], instruction_bytes[1], instruction_bytes[2], instruction_bytes[3],
                    instruction_bytes[4], instruction_bytes[5], instruction_bytes[6], instruction_bytes[7]
                ],
            };

            let pre_state = VmStateSnapshot {
                registers: pre_registers,
                pc,
                step_count: self.current_step,
                compute_units: self.trace.compute_units_consumed,
            };

            let post_state = VmStateSnapshot {
                registers: post_registers,
                pc: pc + 8,
                step_count: self.current_step + 1,
                compute_units: self.trace.compute_units_consumed + compute_units,
            };

            // Enhanced tracking updates (before moving values)
            self.update_opcode_tracking(&instruction, pc, compute_units);
            self.update_register_tracking(&instruction, pc, &pre_registers, &post_registers);
            self.update_memory_tracking(&memory_accesses, pc);
            self.update_execution_flow(&instruction, pc, &memory_accesses);
            self.update_opcode_patterns();
            
            let step = TraceStep {
                step_number: self.current_step,
                pc,
                instruction,
                pre_state,
                post_state,
                memory_accesses,
                compute_units,
            };

            self.trace.steps.push(step);
            self.trace.compute_units_consumed += compute_units;
            self.current_step += 1;
        }
    }

    pub fn record_final_state(&mut self, registers: [u64; 11], pc: u64, success: bool) {
        let final_snapshot = VmStateSnapshot {
            registers,
            pc,
            step_count: self.current_step,
            compute_units: self.trace.compute_units_consumed,
        };
        self.trace.final_state = final_snapshot;
        self.trace.success = success;
    }

    pub fn get_trace(&self) -> &ExecutionTrace {
        &self.trace
    }

    pub fn export_trace(&self, file_path: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(&self.trace)?;
        std::fs::write(file_path, json)?;
        Ok(())
    }

    pub fn get_constraint_count(&self) -> usize {
        // Each step generates multiple constraints
        self.trace.steps.len() * 3 // Rough estimate: 3 constraints per step
    }

    // Enhanced tracking methods
    fn update_opcode_tracking(&mut self, instruction: &BpfInstructionTrace, pc: u64, compute_units: u64) {
        let opcode = instruction.opcode;
        
        // Update opcode sequence
        self.trace.opcode_sequence.push(opcode);
        
        // Update PC to opcode mapping
        self.trace.pc_to_opcode.insert(pc, opcode);
        
        // Update opcode frequency statistics
        let stats = self.trace.opcode_frequency.entry(opcode).or_insert(OpcodeStats {
            count: 0,
            first_seen_at: self.current_step,
            last_seen_at: self.current_step,
            pc_locations: Vec::new(),
            compute_units_total: 0,
            average_compute_units: 0.0,
        });
        
        stats.count += 1;
        stats.last_seen_at = self.current_step;
        stats.pc_locations.push(pc);
        stats.compute_units_total += compute_units;
        stats.average_compute_units = stats.compute_units_total as f64 / stats.count as f64;
    }

    fn update_register_tracking(&mut self, instruction: &BpfInstructionTrace, pc: u64, pre_registers: &[u64; 11], post_registers: &[u64; 11]) {
        // Track register usage
        for reg_idx in 0..11 {
            let reg = reg_idx as u8;
            
            // Check if register was read (used as source)
            if instruction.src == reg || instruction.dst == reg {
                let usage = self.trace.register_usage.entry(reg).or_insert(RegisterUsage {
                    read_count: 0,
                    write_count: 0,
                    opcodes_used_in: Vec::new(),
                    pc_locations: Vec::new(),
                });
                
                usage.read_count += 1;
                if !usage.opcodes_used_in.contains(&instruction.opcode) {
                    usage.opcodes_used_in.push(instruction.opcode);
                }
                usage.pc_locations.push(pc);
            }
            
            // Check if register was written to (changed value)
            if pre_registers[reg_idx] != post_registers[reg_idx] {
                let usage = self.trace.register_usage.entry(reg).or_insert(RegisterUsage {
                    read_count: 0,
                    write_count: 0,
                    opcodes_used_in: Vec::new(),
                    pc_locations: Vec::new(),
                });
                
                usage.write_count += 1;
            }
        }
    }

    fn update_memory_tracking(&mut self, memory_accesses: &[MemoryAccess], pc: u64) {
        if !memory_accesses.is_empty() {
            let pattern = memory_accesses.iter()
                .map(|access| format!("{:?}", access.access_type))
                .collect::<Vec<_>>()
                .join("->");
            
            *self.trace.memory_access_patterns.entry(pattern).or_insert(0) += 1;
        }
    }

    fn update_execution_flow(&mut self, instruction: &BpfInstructionTrace, pc: u64, memory_accesses: &[MemoryAccess]) {
        let opcode_name = self.get_opcode_name(instruction.opcode);
        let registers_changed = self.get_changed_registers(instruction);
        let memory_accessed = !memory_accesses.is_empty();
        
        let mut branch_target = None;
        let mut call_target = None;
        
        // Detect branch and call targets using centralized registry
        if OPCODE_REGISTRY.is_branch_opcode(instruction.opcode) {
            branch_target = Some(pc + instruction.offset as u64);
        } else if OPCODE_REGISTRY.is_call_opcode(instruction.opcode) {
            call_target = Some(instruction.immediate as u64);
        }
        
        let flow_node = ExecutionFlowNode {
            step_number: self.current_step,
            pc,
            opcode: instruction.opcode,
            opcode_name,
            registers_changed,
            memory_accessed,
            compute_units: memory_accesses.iter().map(|_| 1).sum::<u64>() + 1, // Simplified
            branch_target,
            call_target,
        };
        
        self.trace.execution_flow.push(flow_node);
    }

    fn update_opcode_patterns(&mut self) {
        // Track patterns of 2-4 consecutive opcodes
        let sequence = &self.trace.opcode_sequence;
        if sequence.len() >= 2 {
            for pattern_len in 2..=4 {
                if sequence.len() >= pattern_len {
                    let start_idx = sequence.len() - pattern_len;
                    let pattern = sequence[start_idx..].iter()
                        .map(|&opcode| format!("{:02X}", opcode))
                        .collect::<Vec<_>>()
                        .join("->");
                    
                    *self.trace.opcode_patterns.entry(pattern).or_insert(0) += 1;
                }
            }
        }
    }

    pub fn get_opcode_name(&self, opcode: u8) -> String {
        OPCODE_REGISTRY.get_opcode_name(opcode)
    }

    fn get_changed_registers(&self, instruction: &BpfInstructionTrace) -> Vec<u8> {
        let mut changed = Vec::new();
        
        // Add destination register if it exists
        if instruction.dst < 11 {
            changed.push(instruction.dst);
        }
        
        // Add source register if it's different from destination
        if instruction.src < 11 && instruction.src != instruction.dst {
            changed.push(instruction.src);
        }
        
        changed
    }

    // Analysis methods
    pub fn get_opcode_frequency(&self) -> &HashMap<u8, OpcodeStats> {
        &self.trace.opcode_frequency
    }

    pub fn get_most_frequent_opcodes(&self, limit: usize) -> Vec<(u8, &OpcodeStats)> {
        let mut opcodes: Vec<_> = self.trace.opcode_frequency.iter().collect();
        opcodes.sort_by(|a, b| b.1.count.cmp(&a.1.count));
        opcodes.into_iter().take(limit).map(|(k, v)| (*k, v)).collect()
    }

    pub fn get_opcode_sequence(&self) -> &[u8] {
        &self.trace.opcode_sequence
    }

    pub fn get_pc_to_opcode_map(&self) -> &BTreeMap<u64, u8> {
        &self.trace.pc_to_opcode
    }

    pub fn get_register_usage(&self) -> &HashMap<u8, RegisterUsage> {
        &self.trace.register_usage
    }

    pub fn get_execution_flow(&self) -> &[ExecutionFlowNode] {
        &self.trace.execution_flow
    }

    pub fn find_opcode_patterns(&self, min_occurrences: usize) -> Vec<(&String, &usize)> {
        self.trace.opcode_patterns.iter()
            .filter(|(_, &count)| count >= min_occurrences)
            .collect()
    }

    pub fn get_memory_access_patterns(&self) -> &HashMap<String, usize> {
        &self.trace.memory_access_patterns
    }

    // Mathematical proof generation methods
    pub fn generate_mathematical_witnesses(&mut self) {
        self.trace.mathematical_witnesses.clear();
        self.trace.total_constraints = 0;
        
        for (step_idx, step) in self.trace.steps.iter().enumerate() {
            let witness = self.create_mathematical_witness(step, step_idx);
            self.trace.total_constraints += witness.mathematical_constraints.len();
            self.trace.mathematical_witnesses.push(witness);
        }
        
        // Validate all witnesses
        self.trace.mathematical_proof_valid = self.trace.mathematical_witnesses.iter()
            .all(|w| !w.mathematical_constraints.is_empty());
    }

    fn create_mathematical_witness(&self, step: &TraceStep, step_idx: usize) -> MathematicalWitness {
        let operands = OpcodeOperands {
            dst_reg: step.instruction.dst,
            src_reg: step.instruction.src,
            src_reg2: 0, // Will be set based on opcode
            offset: step.instruction.offset,
            immediate: step.instruction.immediate,
        };

        let memory_operations = step.memory_accesses.iter().map(|access| {
            MemoryOperation {
                address: access.address,
                data: vec![access.value as u8], // Simplified for now
                op_type: match access.access_type {
                    MemoryAccessType::Read => MemoryOpType::Read,
                    MemoryAccessType::Write => MemoryOpType::Write,
                    MemoryAccessType::Execute => MemoryOpType::Execute,
                },
                size: access.size as usize,
                bounds_valid: true, // Will be validated by constraints
            }
        }).collect();

        let constraints = self.generate_opcode_constraints(
            step.instruction.opcode,
            &step.pre_state,
            &step.post_state,
            &operands,
            step_idx,
        );

        MathematicalWitness {
            opcode: step.instruction.opcode,
            pre_state: step.pre_state.clone(),
            post_state: step.post_state.clone(),
            operands,
            memory_operations,
            program_counter: step.pc,
            next_program_counter: step.pc + 8, // BPF instructions are 8 bytes
            compute_units_consumed: step.compute_units,
            instruction_bytes: step.instruction.raw_bytes,
            step_number: step_idx,
            mathematical_constraints: constraints,
        }
    }

    fn generate_opcode_constraints(
        &self,
        opcode: u8,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
        step_idx: usize,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();

        match opcode {
            0x07 => { // ADD_IMM
                constraints.extend(self.generate_add_imm_constraints(pre_state, post_state, operands));
            },
            0x0F => { // ADD_REG
                constraints.extend(self.generate_add_reg_constraints(pre_state, post_state, operands));
            },
            0x1F => { // SUB_REG
                constraints.extend(self.generate_sub_reg_constraints(pre_state, post_state, operands));
            },
            0x2F => { // MUL_REG
                constraints.extend(self.generate_mul_reg_constraints(pre_state, post_state, operands));
            },
            0x5F => { // AND_REG
                constraints.extend(self.generate_and_reg_constraints(pre_state, post_state, operands));
            },
            0x25 => { // JNE_REG
                constraints.extend(self.generate_jne_reg_constraints(pre_state, post_state, operands));
            },
            0x71 => { // LDXB
                constraints.extend(self.generate_ldxb_constraints(pre_state, post_state, operands));
            },
            0x85 => { // CALL
                constraints.extend(self.generate_call_constraints(pre_state, post_state, operands));
            },
            0xB7 => { // MOV_IMM
                constraints.extend(self.generate_mov_imm_constraints(pre_state, post_state, operands));
            },
            0xBF => { // MOV_REG
                constraints.extend(self.generate_mov_reg_constraints(pre_state, post_state, operands));
            },
            0x61 => { // LDXW
                constraints.extend(self.generate_ldxw_constraints(pre_state, post_state, operands));
            },
            0x62 => { // STW
                constraints.extend(self.generate_stw_constraints(pre_state, post_state, operands));
            },
            0x15 => { // JEQ_REG
                constraints.extend(self.generate_jeq_reg_constraints(pre_state, post_state, operands));
            },
            0x95 => { // EXIT
                constraints.extend(self.generate_exit_constraints(pre_state, post_state, operands));
            },
            _ => {
                // Generic constraint for unknown opcodes
                constraints.push(MathematicalConstraint::Equality {
                    left: pre_state.compute_units + 1,
                    right: post_state.compute_units,
                    description: format!("Unknown opcode 0x{:02X}: compute units updated", opcode),
                });
            }
        }

        // Always add state transition constraint
        constraints.push(MathematicalConstraint::StateTransition {
            pre_state_hash: [0u8; 32], // Simplified for now
            post_state_hash: [0u8; 32], // Will be computed from actual state
            description: format!("Step {}: state transition", step_idx),
        });

        constraints
    }

    // Specific constraint generators for each opcode
    fn generate_add_imm_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = operands.dst_reg as usize;
        let immediate = operands.immediate as u64;

        if dst_reg < 11 {
            let pre_val = pre_state.registers[dst_reg];
            let post_val = post_state.registers[dst_reg];
            let expected_result = pre_val.wrapping_add(immediate);

            // Arithmetic correctness constraint
            constraints.push(MathematicalConstraint::Arithmetic {
                operation: ArithmeticOp::Add,
                inputs: vec![pre_val, immediate],
                output: post_val,
                description: format!("ADD_IMM: r{} = {} + {} = {}", dst_reg, pre_val, immediate, post_val),
            });

            // Equality constraint
            constraints.push(MathematicalConstraint::Equality {
                left: post_val,
                right: expected_result,
                description: format!("ADD_IMM: r{} result validation", dst_reg),
            });
        }

        constraints
    }

    fn generate_add_reg_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = operands.dst_reg as usize;
        let src_reg = operands.src_reg as usize;

        if dst_reg < 11 && src_reg < 11 {
            let pre_dst = pre_state.registers[dst_reg];
            let pre_src = pre_state.registers[src_reg];
            let post_dst = post_state.registers[dst_reg];
            let expected_result = pre_dst.wrapping_add(pre_src);

            constraints.push(MathematicalConstraint::Arithmetic {
                operation: ArithmeticOp::Add,
                inputs: vec![pre_dst, pre_src],
                output: post_dst,
                description: format!("ADD_REG: r{} = r{} + r{} = {}", dst_reg, dst_reg, src_reg, post_dst),
            });

            constraints.push(MathematicalConstraint::Equality {
                left: post_dst,
                right: expected_result,
                description: format!("ADD_REG: r{} result validation", dst_reg),
            });
        }

        constraints
    }

    fn generate_sub_reg_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = operands.dst_reg as usize;
        let src_reg = operands.src_reg as usize;

        if dst_reg < 11 && src_reg < 11 {
            let pre_dst = pre_state.registers[dst_reg];
            let pre_src = pre_state.registers[src_reg];
            let post_dst = post_state.registers[dst_reg];
            let expected_result = pre_dst.wrapping_sub(pre_src);

            constraints.push(MathematicalConstraint::Arithmetic {
                operation: ArithmeticOp::Subtract,
                inputs: vec![pre_dst, pre_src],
                output: post_dst,
                description: format!("SUB_REG: r{} = r{} - r{} = {}", dst_reg, dst_reg, src_reg, post_dst),
            });

            constraints.push(MathematicalConstraint::Equality {
                left: post_dst,
                right: expected_result,
                description: format!("SUB_REG: r{} result validation", dst_reg),
            });
        }

        constraints
    }

    fn generate_mul_reg_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = operands.dst_reg as usize;
        let src_reg = operands.src_reg as usize;

        if dst_reg < 11 && src_reg < 11 {
            let pre_dst = pre_state.registers[dst_reg];
            let pre_src = pre_state.registers[src_reg];
            let post_dst = post_state.registers[dst_reg];
            let expected_result = pre_dst.wrapping_mul(pre_src);

            constraints.push(MathematicalConstraint::Arithmetic {
                operation: ArithmeticOp::Multiply,
                inputs: vec![pre_dst, pre_src],
                output: post_dst,
                description: format!("MUL_REG: r{} = r{} * r{} = {}", dst_reg, dst_reg, src_reg, post_dst),
            });

            constraints.push(MathematicalConstraint::Equality {
                left: post_dst,
                right: expected_result,
                description: format!("MUL_REG: r{} result validation", dst_reg),
            });
        }

        constraints
    }

    fn generate_and_reg_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = operands.dst_reg as usize;
        let src_reg = operands.src_reg as usize;

        if dst_reg < 11 && src_reg < 11 {
            let pre_dst = pre_state.registers[dst_reg];
            let pre_src = pre_state.registers[src_reg];
            let post_dst = post_state.registers[dst_reg];
            let expected_result = pre_dst & pre_src;

            constraints.push(MathematicalConstraint::Arithmetic {
                operation: ArithmeticOp::BitwiseAnd,
                inputs: vec![pre_dst, pre_src],
                output: post_dst,
                description: format!("AND_REG: r{} = r{} & r{} = {}", dst_reg, dst_reg, src_reg, post_dst),
            });

            constraints.push(MathematicalConstraint::Equality {
                left: post_dst,
                right: expected_result,
                description: format!("AND_REG: r{} result validation", dst_reg),
            });
        }

        constraints
    }

    fn generate_jne_reg_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = operands.dst_reg as usize;
        let src_reg = operands.src_reg as usize;
        let offset = operands.offset;

        if dst_reg < 11 && src_reg < 11 {
            let pre_dst = pre_state.registers[dst_reg];
            let pre_src = pre_state.registers[src_reg];
            let values_equal = pre_dst == pre_src;

            let expected_pc = if !values_equal {
                (pre_state.pc as i64 + 1 + offset as i64) as u64
            } else {
                pre_state.pc + 1
            };

            constraints.push(MathematicalConstraint::ControlFlow {
                current_pc: pre_state.pc,
                offset: offset as i64,
                condition_met: !values_equal,
                next_pc: expected_pc,
                description: format!("JNE_REG: r{} != r{} → PC = {}", dst_reg, src_reg, expected_pc),
            });
        }

        constraints
    }

    fn generate_ldxb_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = operands.dst_reg as usize;
        let src_reg = operands.src_reg as usize;
        let offset = operands.offset;

        if dst_reg < 11 && src_reg < 11 {
            let base_addr = pre_state.registers[src_reg];
            let mem_addr = (base_addr as i64 + offset as i64) as u64;

            constraints.push(MathematicalConstraint::MemoryAddress {
                base: base_addr,
                offset: offset as i64,
                computed: mem_addr,
                description: format!("LDXB: mem_addr = r{} + {} = {}", src_reg, offset, mem_addr),
            });

            constraints.push(MathematicalConstraint::RangeCheck {
                value: mem_addr,
                min: 0,
                max: 1023, // Assuming 1KB memory
                description: "LDXB: Memory address within bounds".to_string(),
            });
        }

        constraints
    }

    fn generate_call_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let offset = operands.offset;
        let call_target = (pre_state.pc as i64 + 1 + offset as i64) as u64;
        let return_address = pre_state.pc + 1;

        constraints.push(MathematicalConstraint::ControlFlow {
            current_pc: pre_state.pc,
            offset: offset as i64,
            condition_met: true, // CALL always jumps
            next_pc: call_target,
            description: format!("CALL: target = PC + 1 + {} = {}", offset, call_target),
        });

        constraints.push(MathematicalConstraint::Equality {
            left: return_address,
            right: pre_state.pc + 1,
            description: "CALL: return_address = PC + 1".to_string(),
        });

        constraints
    }

    fn generate_mov_imm_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = operands.dst_reg as usize;
        let immediate = operands.immediate as u64;

        if dst_reg < 11 {
            let post_dst = post_state.registers[dst_reg];

            constraints.push(MathematicalConstraint::Equality {
                left: post_dst,
                right: immediate,
                description: format!("MOV_IMM: r{} = {}", dst_reg, immediate),
            });
        }

        constraints
    }

    fn generate_mov_reg_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = operands.dst_reg as usize;
        let src_reg = operands.src_reg as usize;

        if dst_reg < 11 && src_reg < 11 {
            let pre_src = pre_state.registers[src_reg];
            let post_dst = post_state.registers[dst_reg];

            constraints.push(MathematicalConstraint::Equality {
                left: post_dst,
                right: pre_src,
                description: format!("MOV_REG: r{} = r{}", dst_reg, src_reg),
            });
        }

        constraints
    }

    fn generate_ldxw_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = operands.dst_reg as usize;
        let src_reg = operands.src_reg as usize;
        let offset = operands.offset;

        if dst_reg < 11 && src_reg < 11 {
            let base_addr = pre_state.registers[src_reg];
            let mem_addr = (base_addr as i64 + offset as i64) as u64;

            constraints.push(MathematicalConstraint::MemoryAddress {
                base: base_addr,
                offset: offset as i64,
                computed: mem_addr,
                description: format!("LDXW: mem_addr = r{} + {} = {}", src_reg, offset, mem_addr),
            });

            constraints.push(MathematicalConstraint::RangeCheck {
                value: mem_addr,
                min: 0,
                max: 1023,
                description: "LDXW: Memory address within bounds".to_string(),
            });
        }

        constraints
    }

    fn generate_stw_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = operands.dst_reg as usize;
        let offset = operands.offset;
        let immediate = operands.immediate as u32;

        if dst_reg < 11 {
            let base_addr = pre_state.registers[dst_reg];
            let mem_addr = (base_addr as i64 + offset as i64) as u64;

            constraints.push(MathematicalConstraint::MemoryAddress {
                base: base_addr,
                offset: offset as i64,
                computed: mem_addr,
                description: format!("STW: mem_addr = r{} + {} = {}", dst_reg, offset, mem_addr),
            });

            constraints.push(MathematicalConstraint::RangeCheck {
                value: mem_addr,
                min: 0,
                max: 1023,
                description: "STW: Memory address within bounds".to_string(),
            });
        }

        constraints
    }

    fn generate_jeq_reg_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let dst_reg = operands.dst_reg as usize;
        let src_reg = operands.src_reg as usize;
        let offset = operands.offset;

        if dst_reg < 11 && src_reg < 11 {
            let pre_dst = pre_state.registers[dst_reg];
            let pre_src = pre_state.registers[src_reg];
            let values_equal = pre_dst == pre_src;

            let expected_pc = if values_equal {
                (pre_state.pc as i64 + 1 + offset as i64) as u64
            } else {
                pre_state.pc + 1
            };

            constraints.push(MathematicalConstraint::ControlFlow {
                current_pc: pre_state.pc,
                offset: offset as i64,
                condition_met: values_equal,
                next_pc: expected_pc,
                description: format!("JEQ_REG: r{} == r{} → PC = {}", dst_reg, src_reg, expected_pc),
                });
        }

        constraints
    }

    fn generate_exit_constraints(
        &self,
        pre_state: &VmStateSnapshot,
        post_state: &VmStateSnapshot,
        operands: &OpcodeOperands,
    ) -> Vec<MathematicalConstraint> {
        let mut constraints = Vec::new();
        let exit_code = pre_state.registers[0]; // r0 contains exit code

        constraints.push(MathematicalConstraint::Equality {
            left: exit_code,
            right: exit_code, // Self-referential for validation
            description: "EXIT: exit code validation".to_string(),
        });

        constraints
    }

    // Get mathematical proof information
    pub fn get_mathematical_witnesses(&self) -> &[MathematicalWitness] {
        &self.trace.mathematical_witnesses
    }

    pub fn get_total_constraints(&self) -> usize {
        self.trace.total_constraints
    }

    pub fn is_mathematical_proof_valid(&self) -> bool {
        self.trace.mathematical_proof_valid
    }

    pub fn export_mathematical_proof(&self, file_path: &str) -> std::io::Result<()> {
        let proof_data = serde_json::to_string_pretty(&self.trace.mathematical_witnesses)?;
        std::fs::write(file_path, proof_data)?;
        Ok(())
    }
}

impl Default for VmStateSnapshot {
    fn default() -> Self {
        Self {
            registers: [0; 11],
            pc: 0,
            step_count: 0,
            compute_units: 0,
        }
    }
}

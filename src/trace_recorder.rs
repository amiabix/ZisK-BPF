use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecutionTrace {
    pub steps: Vec<TraceStep>,
    pub initial_state: VmStateSnapshot,
    pub final_state: VmStateSnapshot,
    pub compute_units_consumed: u64,
    pub success: bool,
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

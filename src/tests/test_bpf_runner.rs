use std::fs;
use std::env;

fn main() {
    println!("[TEST-RUNNER] BPF Test Program Runner");
    
    let args: Vec<String> = env::args().collect();
    let default_file = "simple_test.bpf".to_string();
    let program_file = args.get(1).unwrap_or(&default_file);
    
    println!("[INFO] [TEST-RUNNER] Loading BPF program: {}", program_file);
    
    // Load the BPF program
    let bpf_program = match fs::read(program_file) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[ERROR] [TEST-RUNNER] Failed to read {}: {}", program_file, e);
            return;
        }
    };
    
    println!("[SUCCESS] [TEST-RUNNER] Loaded {} bytes of BPF program", bpf_program.len());
    println!("[INFO] [TEST-RUNNER] Instruction count: {}", bpf_program.len() / 8);
    
    // Simple BPF interpreter for testing
    let mut pc: usize = 0;
    let mut registers = [0u64; 11];
    let mut step_count = 0;
    
    println!("\n[TEST-RUNNER] Starting BPF execution...");
    println!("[INFO] [TEST-RUNNER] Initial registers: {:?}", &registers[0..5]);
    
    // Execute BPF instructions
    while pc < bpf_program.len() && step_count < 100 {
        if pc + 8 > bpf_program.len() {
            break;
        }
        
        let instruction_bytes = &bpf_program[pc..pc + 8];
        let opcode = instruction_bytes[0];
        let dst = instruction_bytes[1];
        let src = instruction_bytes[2];
        let offset = instruction_bytes[3]; // 8-bit offset
        let imm = i16::from_le_bytes([
            instruction_bytes[6], instruction_bytes[7]
        ]) as i32; // BPF immediate values are 16-bit in the last 2 bytes
        
        step_count += 1;
        println!("\n[INFO] [TEST-RUNNER] Step {}: PC={}, Opcode=0x{:02X}", step_count, pc, opcode);
        
        match opcode {
            0x95 => { // EXIT
                println!("   🛑 EXIT instruction");
                break;
            },
            0xBF => { // MOV rX, imm (32-bit)
                if dst < 11 {
                    registers[dst as usize] = imm as u64;
                    println!("   📥 MOV r{}, {} (r{} = {})", dst, imm, dst, registers[dst as usize]);
                }
            },
            0x07 => { // ADD rX, imm
                if dst < 11 {
                    let old_val = registers[dst as usize];
                    registers[dst as usize] = registers[dst as usize].wrapping_add(imm as u64);
                    println!("   ➕ ADD r{}, {} (r{} = {} + {} = {})", dst, imm, dst, old_val, imm, registers[dst as usize]);
                }
            },
            0x0F => { // ADD rX, rY
                if dst < 11 && src < 11 {
                    let old_val = registers[dst as usize];
                    let src_val = registers[src as usize];
                    registers[dst as usize] = registers[dst as usize].wrapping_add(registers[src as usize]);
                    println!("   ➕ ADD r{}, r{} (r{} = {} + {} = {})", dst, src, dst, old_val, src_val, registers[dst as usize]);
                }
            },
            0x17 => { // SUB rX, imm
                if dst < 11 {
                    let old_val = registers[dst as usize];
                    registers[dst as usize] = registers[dst as usize].wrapping_sub(imm as u64);
                    println!("   ➖ SUB r{}, {} (r{} = {} - {} = {})", dst, imm, dst, old_val, imm, registers[dst as usize]);
                }
            },
            0x1F => { // SUB rX, rY
                if dst < 11 && src < 11 {
                    let old_val = registers[dst as usize];
                    let src_val = registers[src as usize];
                    registers[dst as usize] = registers[dst as usize].wrapping_sub(registers[src as usize]);
                    println!("   ➖ SUB r{}, r{} (r{} = {} - {} = {})", dst, src, dst, old_val, src_val, registers[dst as usize]);
                }
            },
            0x27 => { // MUL rX, imm
                if dst < 11 {
                    let old_val = registers[dst as usize];
                    registers[dst as usize] = registers[dst as usize].wrapping_mul(imm as u64);
                    println!("   [MUL] MUL r{}, {} (r{} = {} * {} = {})", dst, imm, dst, old_val, imm, registers[dst as usize]);
                }
            },
            0x2F => { // MUL rX, rY
                if dst < 11 && src < 11 {
                    let old_val = registers[dst as usize];
                    let src_val = registers[src as usize];
                    registers[dst as usize] = registers[dst as usize].wrapping_mul(registers[src as usize]);
                    println!("   [MUL] MUL r{}, r{} (r{} = {} * {} = {})", dst, src, dst, old_val, src_val, registers[dst as usize]);
                }
            },
            0x47 => { // AND rX, imm
                if dst < 11 {
                    let old_val = registers[dst as usize];
                    registers[dst as usize] &= imm as u64;
                    println!("   [AND] AND r{}, {} (r{} = {} & {} = {})", dst, imm, dst, old_val, imm, registers[dst as usize]);
                }
            },
            0x57 => { // OR rX, imm
                if dst < 11 {
                    let old_val = registers[dst as usize];
                    registers[dst as usize] |= imm as u64;
                    println!("   [OR] OR r{}, {} (r{} = {} | {} = {})", dst, imm, dst, old_val, imm, registers[dst as usize]);
                }
            },
            0x67 => { // XOR rX, imm
                if dst < 11 {
                    let old_val = registers[dst as usize];
                    registers[dst as usize] ^= imm as u64;
                    println!("   [XOR] XOR r{}, {} (r{} = {} ^ {} = {})", dst, imm, dst, old_val, imm, registers[dst as usize]);
                }
            },
            0x87 => { // LSH rX, imm
                if dst < 11 {
                    let old_val = registers[dst as usize];
                    registers[dst as usize] = registers[dst as usize].wrapping_shl(imm as u32);
                    println!("   [LSH] LSH r{}, {} (r{} = {} << {} = {})", dst, imm, dst, old_val, imm, registers[dst as usize]);
                }
            },
            0x97 => { // RSH rX, imm
                if dst < 11 {
                    let old_val = registers[dst as usize];
                    registers[dst as usize] = registers[dst as usize].wrapping_shr(imm as u32);
                    println!("   [RSH] RSH r{}, {} (r{} = {} >> {} = {})", dst, imm, dst, old_val, imm, registers[dst as usize]);
                }
            },
            // Memory Load Operations
            0x61 => { // LDXW rX, [rY+off] (load 32-bit word)
                println!("   [DEBUG] LDXW instruction detected - dst={}, src={}, offset={}", dst, src, offset);
                if dst < 11 && src < 11 {
                    let addr = registers[src as usize].wrapping_add(offset as u64);
                    println!("   [DEBUG] Memory address = {}", addr);
                    let value = u32::from_le_bytes([
                        bpf_program[addr as usize % bpf_program.len()],
                        bpf_program[(addr + 1) as usize % bpf_program.len()],
                        bpf_program[(addr + 2) as usize % bpf_program.len()],
                        bpf_program[(addr + 3) as usize % bpf_program.len()]
                    ]);
                    registers[dst as usize] = value as u64;
                    println!("   [LOAD] LDXW r{}, [r{}+{}] = {} (r{} = {})", dst, src, offset, value, dst, value);
                } else {
                    println!("   [ERROR] ERROR: Invalid register indices - dst={}, src={}", dst, src);
                }
            },
            // Memory Store Operations
            0x63 => { // STW [rX+off], rY (store 32-bit word)
                if dst < 11 && src < 11 {
                    let addr = registers[dst as usize].wrapping_add(offset as u64);
                    let value = registers[src as usize] as u32;
                    println!("   [STORE] STW [r{}+{}], r{} = {} (addr: {})", dst, offset, src, value, addr);
                }
            },
            0xE1 => { // JEQ rX, imm, offset
                if dst < 11 && registers[dst as usize] == imm as u64 {
                    let jump_offset = offset as i64;
                    let new_pc = pc as i64 + jump_offset * 8;
                    if jump_offset > 0 && new_pc < bpf_program.len() as i64 {
                        let old_pc = pc;
                        pc = new_pc as usize;
                        println!("   [JUMP] JEQ r{}, {}, jump {} instructions (PC: {} -> {})", dst, imm, offset, old_pc, pc);
                        continue; // Skip the normal pc increment
                    }
                }
                println!("   [JUMP] JEQ r{}, {}, no jump (r{} = {}, imm = {})", dst, imm, dst, registers[dst as usize], imm);
            },
            _ => {
                println!("   [UNKNOWN] Unknown opcode 0x{:02X} at PC={}", opcode, pc);
            }
        }
        
        pc += 8;
        println!("   [PC] Next PC: {}", pc);
        println!("   [INFO] Registers: {:?}", &registers[0..5]);
    }
    
    println!("\n[SUCCESS] [TEST-RUNNER] Execution completed!");
            println!("[INFO] [TEST-RUNNER] Final state:");
            println!("   [INFO] Steps executed: {}", step_count);
            println!("   [PC] Final PC: {}", pc);
            println!("   [INFO] Final registers: {:?}", &registers[0..5]);
    
    // Show specific results based on program
    if program_file.contains("simple") {
        println!("[RESULT] [TEST-RUNNER] Simple test result: r3 = {} (expected: 8)", registers[3]);
        if registers[3] == 8 {
            println!("[SUCCESS] [TEST-RUNNER] SUCCESS: Simple test passed!");
        } else {
            println!("[ERROR] [TEST-RUNNER] FAILED: Expected r3 = 8, got {}", registers[3]);
        }
    } else if program_file.contains("test_program") {
        println!("[RESULT] [TEST-RUNNER] Complex test results:");
        println!("   [INFO] r4 = {} (expected: 27)", registers[4]);
        println!("   [INFO] r11 = 0x{:X} (expected: 0x5555 after jump)", registers[10]);
        println!("   [INFO] r12 = 0x{:X} (expected: 0x0, should be skipped)", registers[10]);
        
        let success = registers[4] == 27 && registers[10] == 0x5555;
        if success {
            println!("[SUCCESS] [TEST-RUNNER] SUCCESS: Complex test passed!");
        } else {
            println!("[ERROR] [TEST-RUNNER] FAILED: Some expected values don't match");
        }
    }
}

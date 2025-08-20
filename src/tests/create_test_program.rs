use std::fs;

fn main() {
    println!("[TEST] Creating complex BPF test program...");
    
    // Create a complex BPF program that tests multiple opcodes
    let mut bpf_program = Vec::new();
    
    // Test program: Calculate (a + b) * 2 - c, where a=10, b=5, c=3
    // Expected result: (10 + 5) * 2 - 3 = 15 * 2 - 3 = 30 - 3 = 27
    
    // MOV r1, 10 (16-bit immediate)
    bpf_program.extend_from_slice(&[0xBF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00]);
    
    // MOV r2, 5 (16-bit immediate)
    bpf_program.extend_from_slice(&[0xBF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00]);
    
    // MOV r3, 3 (16-bit immediate)
    bpf_program.extend_from_slice(&[0xBF, 0x03, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00]);
    
    // ADD r4, r1 (r4 = r1 = 10)
    bpf_program.extend_from_slice(&[0x0F, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
    
    // ADD r4, r2 (r4 = r4 + r2 = 10 + 5 = 15)
    bpf_program.extend_from_slice(&[0x0F, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]);
    
    // MOV r5, 2 (16-bit immediate)
    bpf_program.extend_from_slice(&[0xBF, 0x05, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00]);
    
    // MUL r4, r4, r5 (r4 = r4 * r5 = 15 * 2 = 30)
    bpf_program.extend_from_slice(&[0x2F, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00]);
    
    // SUB r4, r4, r3 (r4 = r4 - r3 = 30 - 3 = 27)
    bpf_program.extend_from_slice(&[0x1F, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00]);
    
    // Test bitwise operations
    // AND r6, r4, 0xFF (r6 = r4 & 0xFF = 27 & 255 = 27)
    bpf_program.extend_from_slice(&[0x47, 0x06, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00]);
    
    // OR r7, r6, 0x100 (r7 = r6 | 0x100 = 27 | 256 = 283)
    bpf_program.extend_from_slice(&[0x57, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    
    // XOR r8, r7, 0xFF (r8 = r7 ^ 0xFF = 283 ^ 255 = 44)
    bpf_program.extend_from_slice(&[0x67, 0x08, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00]);
    
    // Test shifts
    // LSH r9, r8, 2 (r9 = r8 << 2 = 44 << 2 = 176)
    bpf_program.extend_from_slice(&[0x87, 0x09, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00]);
    
    // RSH r10, r9, 1 (r10 = r9 >> 1 = 176 >> 1 = 88)
    bpf_program.extend_from_slice(&[0x97, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    
    // Test memory operations
    // Store r4 (27) to memory at offset 0
    bpf_program.extend_from_slice(&[0x63, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
    
    // Load from memory at offset 0 into r6
    bpf_program.extend_from_slice(&[0x61, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    
    // Test conditional jumps
    // JEQ r4, 27, 2 (if r4 == 27, jump 2 instructions forward to skip the next 2)
    bpf_program.extend_from_slice(&[0xE1, 0x04, 0x00, 0x02, 0x00, 0x00, 0x1B, 0x00]);
    
    // MOV r11, 0xDEAD (marker for successful jump - should be skipped)
    bpf_program.extend_from_slice(&[0xBF, 0x0B, 0x00, 0x00, 0x00, 0x00, 0xAD, 0xDE]);
    
    // MOV r12, 0xCAFE (marker for successful jump - should be skipped)
    bpf_program.extend_from_slice(&[0xBF, 0x0C, 0x00, 0x00, 0x00, 0x00, 0xFE, 0xCA]);
    
    // MOV r11, 0xSUCCESS (this should execute after the jump)
    bpf_program.extend_from_slice(&[0xBF, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55]);
    
    // EXIT
    bpf_program.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    
    // Write the test program to a file
    fs::write("test_program.bpf", &bpf_program).expect("Failed to write test program");
    
    println!("[SUCCESS] [TEST] Created complex BPF test program:");
            println!("   [INFO] Size: {} bytes", bpf_program.len());
            println!("   [INFO] Instructions: {}", bpf_program.len() / 8);
            println!("   [RESULT] Expected result: r4 = 27, r11 = 0xDEAD");
            println!("   [INFO] Saved to: test_program.bpf");
    
    // Also create a simple test with just arithmetic
    let mut simple_program = Vec::new();
    
    // Simple: r1 = 5, r2 = 3, r3 = r1 + r2 = 8
    simple_program.extend_from_slice(&[0xBF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00]); // MOV r1, 5
    simple_program.extend_from_slice(&[0xBF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00]); // MOV r2, 3
    simple_program.extend_from_slice(&[0x0F, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]); // ADD r3, r1
    simple_program.extend_from_slice(&[0x0F, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]); // ADD r3, r2
    simple_program.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // EXIT
    
    fs::write("simple_test.bpf", &simple_program).expect("Failed to write simple test");
    
    println!("[SUCCESS] [TEST] Created simple test program:");
            println!("   [INFO] Size: {} bytes", simple_program.len());
            println!("   [RESULT] Expected: r3 = 8");
            println!("   [INFO] Saved to: simple_test.bpf");
    
    println!("[TEST] Ready for testing enhanced BPF opcodes!");
}

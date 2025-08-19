//! Week 1 Arithmetic Opcodes Test Module
//! Tests the core arithmetic operations: ADD, SUB, MUL, DIV, MOD, NEG, ADD32

use crate::opcode_implementations::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_vm_state() -> VmState {
        VmState {
            registers: [0u64; 11],
            pc: 0,
            compute_units: 0,
            step_count: 0,
            terminated: false,
            memory_hash: [0u8; 32],
            program_hash: [0u8; 32],
            error: None,
        }
    }

    #[test]
    fn test_week1_add64_reg() {
        let mut pre_state = create_test_vm_state();
        let mut post_state = create_test_vm_state();
        
        // Test ADD64_REG (0x0F)
        pre_state.registers[1] = 100;
        pre_state.registers[2] = 50;
        pre_state.program_hash[0] = 0x0F;
        
        post_state.registers[1] = 150; // 100 + 50
        post_state.registers[2] = 50;  // Unchanged
        post_state.pc = 1;
        post_state.step_count = 1;
        
        let constraints = generate_add_reg_constraints(&pre_state, &post_state, 1, 2, 0);
        
        assert!(!constraints.is_empty());
        println!("ADD64_REG generated {} constraints", constraints.len());
        
        // Verify arithmetic constraint exists
        let arithmetic_constraint = constraints.iter()
            .find(|c| c.description.contains("add_reg_arithmetic"))
            .expect("Should have arithmetic constraint");
        
        match &arithmetic_constraint.constraint_type {
            ConstraintType::Equality { left, right } => {
                assert_eq!(*left, 150);
                assert_eq!(*right, 150);
            }
            _ => panic!("Expected equality constraint"),
        }
    }

    #[test]
    fn test_week1_sub64_reg() {
        let mut pre_state = create_test_vm_state();
        let mut post_state = create_test_vm_state();
        
        // Test SUB64_REG (0x1F)
        pre_state.registers[1] = 100;
        pre_state.registers[2] = 30;
        pre_state.program_hash[0] = 0x1F;
        
        post_state.registers[1] = 70;  // 100 - 30
        post_state.registers[2] = 30;  // Unchanged
        post_state.pc = 1;
        post_state.step_count = 1;
        
        let constraints = generate_sub_reg_constraints(&pre_state, &post_state, 1, 2, 0);
        
        assert!(!constraints.is_empty());
        println!("SUB64_REG generated {} constraints", constraints.len());
        
        // Verify subtraction constraint exists
        let arithmetic_constraint = constraints.iter()
            .find(|c| c.description.contains("sub_reg_arithmetic"))
            .expect("Should have arithmetic constraint");
        
        match &arithmetic_constraint.constraint_type {
            ConstraintType::Equality { left, right } => {
                assert_eq!(*left, 70);
                assert_eq!(*right, 70);
            }
            _ => panic!("Expected equality constraint"),
        }
    }

    #[test]
    fn test_week1_mul64_reg() {
        let mut pre_state = create_test_vm_state();
        let mut post_state = create_test_vm_state();
        
        // Test MUL64_REG (0x2F)
        pre_state.registers[1] = 6;
        pre_state.registers[2] = 7;
        pre_state.program_hash[0] = 0x2F;
        
        post_state.registers[1] = 42;  // 6 * 7
        post_state.registers[2] = 7;   // Unchanged
        post_state.pc = 1;
        post_state.step_count = 1;
        
        let constraints = generate_mul_reg_constraints(&pre_state, &post_state, 1, 2, 0);
        
        assert!(!constraints.is_empty());
        println!("MUL64_REG generated {} constraints", constraints.len());
        
        // Verify multiplication constraint exists
        let arithmetic_constraint = constraints.iter()
            .find(|c| c.description.contains("mul_reg_arithmetic"))
            .expect("Should have arithmetic constraint");
        
        match &arithmetic_constraint.constraint_type {
            ConstraintType::Equality { left, right } => {
                assert_eq!(*left, 42);
                assert_eq!(*right, 42);
            }
            _ => panic!("Expected equality constraint"),
        }
    }

    #[test]
    fn test_week1_div64_reg() {
        let mut pre_state = create_test_vm_state();
        let mut post_state = create_test_vm_state();
        
        // Test DIV64_REG (0x3F)
        pre_state.registers[1] = 100;
        pre_state.registers[2] = 4;
        pre_state.program_hash[0] = 0x3F;
        
        post_state.registers[1] = 25;  // 100 / 4
        post_state.registers[2] = 4;   // Unchanged
        post_state.pc = 1;
        post_state.step_count = 1;
        
        let constraints = generate_div_reg_constraints(&pre_state, &post_state, 1, 2, 0);
        
        assert!(!constraints.is_empty());
        println!("DIV64_REG generated {} constraints", constraints.len());
        
        // Verify division constraint exists
        let arithmetic_constraint = constraints.iter()
            .find(|c| c.description.contains("div_reg_arithmetic"))
            .expect("Should have arithmetic constraint");
        
        match &arithmetic_constraint.constraint_type {
            ConstraintType::Equality { left, right } => {
                assert_eq!(*left, 25);
                assert_eq!(*right, 25);
            }
            _ => panic!("Expected equality constraint"),
        }
    }

    #[test]
    fn test_week1_mod64_reg() {
        let mut pre_state = create_test_vm_state();
        let mut post_state = create_test_vm_state();
        
        // Test MOD64_REG (0x9F)
        pre_state.registers[1] = 17;
        pre_state.registers[2] = 5;
        pre_state.program_hash[0] = 0x9F;
        
        post_state.registers[1] = 2;   // 17 % 5
        post_state.registers[2] = 5;   // Unchanged
        post_state.pc = 1;
        post_state.step_count = 1;
        
        let constraints = generate_mod_reg_constraints(&pre_state, &post_state, 1, 2, 0);
        
        assert!(!constraints.is_empty());
        println!("MOD64_REG generated {} constraints", constraints.len());
        
        // Verify modulo constraint exists
        let arithmetic_constraint = constraints.iter()
            .find(|c| c.description.contains("mod_reg_arithmetic"))
            .expect("Should have arithmetic constraint");
        
        match &arithmetic_constraint.constraint_type {
            ConstraintType::Equality { left, right } => {
                assert_eq!(*left, 2);
                assert_eq!(*right, 2);
            }
            _ => panic!("Expected equality constraint"),
        }
    }

    #[test]
    fn test_week1_neg64() {
        let mut pre_state = create_test_vm_state();
        let mut post_state = create_test_vm_state();
        
        // Test NEG64 (0x87)
        pre_state.registers[1] = 42;
        pre_state.program_hash[0] = 0x87;
        
        post_state.registers[1] = (-42i64) as u64;
        post_state.pc = 1;
        post_state.step_count = 1;
        
        let constraints = generate_neg64_constraints(&pre_state, &post_state, 1, 0);
        
        assert!(!constraints.is_empty());
        println!("NEG64 generated {} constraints", constraints.len());
        
        // Verify negation constraint exists
        let arithmetic_constraint = constraints.iter()
            .find(|c| c.description.contains("neg64_arithmetic"))
            .expect("Should have arithmetic constraint");
        
        match &arithmetic_constraint.constraint_type {
            ConstraintType::Equality { left, right } => {
                assert_eq!(*left, (-42i64) as u64);
                assert_eq!(*right, (-42i64) as u64);
            }
            _ => panic!("Expected equality constraint"),
        }
    }

    #[test]
    fn test_week1_add32_imm() {
        let mut pre_state = create_test_vm_state();
        let mut post_state = create_test_vm_state();
        
        // Test ADD32_IMM (0x04)
        pre_state.registers[1] = 0x1234567890ABCDEF;
        pre_state.program_hash[0] = 0x04;
        
        // Add 0x12345678 to lower 32 bits
        let imm = 0x12345678;
        let expected = (0x1234567890ABCDEF & 0xFFFFFFFF00000000) | 
                      ((0x90ABCDEF + 0x12345678) & 0xFFFFFFFF);
        
        post_state.registers[1] = expected;
        post_state.pc = 1;
        post_state.step_count = 1;
        
        let constraints = generate_add32_imm_constraints(&pre_state, &post_state, 1, imm, 0);
        
        assert!(!constraints.is_empty());
        println!("ADD32_IMM generated {} constraints", constraints.len());
        
        // Verify 32-bit addition constraint exists
        let arithmetic_constraint = constraints.iter()
            .find(|c| c.description.contains("add32_imm_arithmetic"))
            .expect("Should have arithmetic constraint");
        
        match &arithmetic_constraint.constraint_type {
            ConstraintType::Equality { left, right } => {
                assert_eq!(*left, expected);
                assert_eq!(*right, expected);
            }
            _ => panic!("Expected equality constraint"),
        }
    }

    #[test]
    fn test_week1_add32_reg() {
        let mut pre_state = create_test_vm_state();
        let mut post_state = create_test_vm_state();
        
        // Test ADD32_REG (0x0C)
        pre_state.registers[1] = 0x1234567890ABCDEF;
        pre_state.registers[2] = 0x1111111111111111;
        pre_state.program_hash[0] = 0x0C;
        
        // Add lower 32 bits only
        let dst_32 = 0x90ABCDEF;
        let src_32 = 0x11111111;
        let result_32 = dst_32 + src_32;
        let expected = (0x1234567890ABCDEF & 0xFFFFFFFF00000000) | result_32;
        
        post_state.registers[1] = expected;
        post_state.registers[2] = 0x1111111111111111; // Unchanged
        post_state.pc = 1;
        post_state.step_count = 1;
        
        let constraints = generate_add32_reg_constraints(&pre_state, &post_state, 1, 2, 0);
        
        assert!(!constraints.is_empty());
        println!("ADD32_REG generated {} constraints", constraints.len());
        
        // Verify 32-bit register addition constraint exists
        let arithmetic_constraint = constraints.iter()
            .find(|c| c.description.contains("add32_reg_arithmetic"))
            .expect("Should have arithmetic constraint");
        
        match &arithmetic_constraint.constraint_type {
            ConstraintType::Equality { left, right } => {
                assert_eq!(*left, expected);
                assert_eq!(*right, expected);
            }
            _ => panic!("Expected equality constraint"),
        }
    }

    #[test]
    fn test_week1_integration() {
        // Test that all Week 1 opcodes work together in sequence
        let mut vm_state = create_test_vm_state();
        let mut step = 0;
        
        // Step 1: ADD64_REG
        let mut pre_state = vm_state.clone();
        vm_state.registers[1] = 10;
        vm_state.registers[2] = 5;
        vm_state.program_hash[0] = 0x0F;
        vm_state.registers[1] = 15; // 10 + 5
        vm_state.pc = 1;
        vm_state.step_count = 1;
        
        let constraints1 = generate_add_reg_constraints(&pre_state, &vm_state, 1, 2, step);
        assert!(!constraints1.is_empty());
        step += 1;
        
        // Step 2: SUB64_REG
        let mut pre_state = vm_state.clone();
        vm_state.registers[1] = 20;
        vm_state.registers[2] = 8;
        vm_state.program_hash[0] = 0x1F;
        vm_state.registers[1] = 12; // 20 - 8
        vm_state.pc = 2;
        vm_state.step_count = 2;
        
        let constraints2 = generate_sub_reg_constraints(&pre_state, &vm_state, 1, 2, step);
        assert!(!constraints2.is_empty());
        step += 1;
        
        // Step 3: MUL64_REG
        let mut pre_state = vm_state.clone();
        vm_state.registers[1] = 6;
        vm_state.registers[2] = 7;
        vm_state.program_hash[0] = 0x2F;
        vm_state.registers[1] = 42; // 6 * 7
        vm_state.pc = 3;
        vm_state.step_count = 3;
        
        let constraints3 = generate_mul_reg_constraints(&pre_state, &vm_state, 1, 2, step);
        assert!(!constraints3.is_empty());
        
        println!("Week 1 integration test passed! Generated constraints:");
        println!("  ADD64_REG: {} constraints", constraints1.len());
        println!("  SUB64_REG: {} constraints", constraints2.len());
        println!("  MUL64_REG: {} constraints", constraints3.len());
    }
}

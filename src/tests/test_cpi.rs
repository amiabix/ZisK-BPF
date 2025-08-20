use zisk_solana_prover::cpi_handler::{CpiHandler, derive_program_address, find_program_address};

fn main() {
    println!("[TEST] Testing CPI and PDA Implementation");
    
    // Test PDA derivation
    test_pda_derivation();
    
    // Test CPI handling
    test_cpi_invocation();
    
    println!("[SUCCESS] All CPI/PDA tests completed");
}

fn test_pda_derivation() {
    println!("\n🔑 Testing PDA Derivation");
    
    let program_id = [1u8; 4];
    let seeds = vec![b"test_seed".to_vec(), b"another_seed".to_vec()];
    
    match derive_program_address(&seeds, &program_id) {
        Ok(pda) => {
            println!("[SUCCESS] PDA derived successfully");
            println!("   Address: {:?}", hex::encode(pda.address));
            println!("   Bump seed: {}", pda.bump_seed);
            
            // Test find_program_address convenience function
            match find_program_address(&seeds, &program_id) {
                Ok(found_pda) => {
                    assert_eq!(found_pda.address, pda.address);
                    assert_eq!(found_pda.bump_seed, pda.bump_seed);
                    println!("[SUCCESS] find_program_address matches derive_program_address");
                },
                Err(e) => println!("[ERROR] find_program_address failed: {:?}", e),
            }
        },
        Err(e) => println!("[ERROR] PDA derivation failed: {:?}", e),
    }
}

fn test_cpi_invocation() {
    println!("\n📞 Testing CPI Invocation");
    
    let program_id = [2u8; 4];
    let mut cpi_handler = CpiHandler::new(program_id);
    
    // Add some test accounts
    let account_key = [3u8; 32];
    let account_info = zisk_solana_prover::cpi_handler::AccountInfo {
        key: account_key,
        lamports: 1000000,
        data: vec![0u8; 100],
        owner: [2u8; 32], // Keep as 32 bytes for account owner
        executable: false,
        rent_epoch: 0,
        is_signer: false,
        is_writable: true,
    };
    
    cpi_handler.available_accounts.insert(account_key, account_info);
    
    // Test basic invoke
    let target_program = [4u8; 4];
    let accounts = vec![account_key]; // Keep as Vec<[u8; 32]>
    let instruction_data = vec![1, 2, 3, 4];
    let mut registers = [0u64; 11];
    let mut memory = vec![0u8; 4096];
    
    match cpi_handler.handle_invoke(target_program, &accounts, &instruction_data, &mut registers, &mut memory) {
        Ok(()) => println!("[SUCCESS] Basic CPI invoke successful"),
        Err(e) => println!("[ERROR] CPI invoke failed: {:?}", e),
    }
    
    // Test invoke_signed
    let seeds = vec![b"signer_seed".to_vec()]; // Keep as Vec<Vec<u8>> for seeds
    match cpi_handler.handle_invoke_signed(target_program, &accounts, &instruction_data, &seeds, &mut registers, &mut memory) {
        Ok(()) => println!("[SUCCESS] CPI invoke_signed successful"),
        Err(e) => println!("[ERROR] CPI invoke_signed failed: {:?}", e),
    }
}

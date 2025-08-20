use std::fs;
use std::path::Path;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[BUILD] Starting REAL BPF execution build script...");
    
    // Get the output directory from cargo
    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    
    println!("[BUILD] Output directory: {}", out_dir);
    println!("[BUILD] Manifest directory: {}", manifest_dir);
    
    // Check if SolInvoke_test.so exists
    let so_file_path = format!("{}/SolInvoke_test.so", manifest_dir);
    let bin_file_path = format!("{}/bpf_execution_result.bin", manifest_dir);
    
    if !Path::new(&so_file_path).exists() {
        println!("[ERROR] [BUILD] SolInvoke_test.so not found!");
        println!("   Cannot generate real execution data without BPF program.");
        return Ok(());
    }
    
            println!("[SUCCESS] [BUILD] Found SolInvoke_test.so: {} bytes", fs::metadata(&so_file_path)?.len());
    
    // Check if we have the BPF executor binary (it should be built by now)
    let executor_path = format!("{}/target/debug/run_bpf_executor", manifest_dir);
    
    if Path::new(&executor_path).exists() {
        println!("[SUCCESS] [BUILD] Found BPF executor binary: {}", executor_path);
        println!("   The build script will generate REAL execution data when run.");
        println!("   To generate the .bin file, run: cargo run --bin run_bpf_executor");
    } else {
        println!("[WARNING] [BUILD] BPF executor binary not found at: {}", executor_path);
        println!("   This means the build script cannot generate real execution data yet.");
        println!("   The binary will be available after the first successful build.");
    }
    
    // Note: We can't run the executor during build due to potential circular dependencies
    // Instead, we'll provide instructions for manual execution
    println!("[BUILD] Build script completed");
    println!("[BUILD] To generate REAL execution data, run: cargo run --bin run_bpf_executor");
    
    Ok(())
}

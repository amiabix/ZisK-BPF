#!/bin/bash
set -e

echo "🚀 [ZISK] Starting ZisK proof generation workflow..."
echo "📁 [ZISK] Working directory: $(pwd)"

# Check prerequisites
echo "🔍 [ZISK] Checking prerequisites..."
if ! command -v cargo-zisk &> /dev/null; then
    echo "❌ [ZISK] cargo-zisk not found. Please install ZisK first."
    exit 1
fi

# Step 1: Build the program for ZisK (RISC-V architecture)
echo "🔧 [ZISK] Step 1: Building program for ZisK..."
cargo-zisk build --release

if [ $? -ne 0 ]; then
    echo "❌ [ZISK] Build failed"
    exit 1
fi

echo "✅ [ZISK] Build completed successfully"

# Step 2: Create proof directory
echo "📁 [ZISK] Step 2: Creating proof directory..."
mkdir -p proof

# Step 3: Generate program setup files
echo "⚙️ [ZISK] Step 3: Generating program setup files..."
cargo-zisk rom-setup \
    -e target/riscv64ima-zisk-zkvm-elf/release/zisk_solana_prover \
    -k $HOME/.zisk/provingKey

if [ $? -ne 0 ]; then
    echo "❌ [ZISK] Program setup failed"
    exit 1
fi

echo "✅ [ZISK] Program setup completed"

# Step 4: Verify constraints (optional but recommended)
echo "🔍 [ZISK] Step 4: Verifying constraints..."
cargo-zisk verify-constraints \
    -e target/riscv64ima-zisk-zkvm-elf/release/zisk_solana_prover \
    -i input.bin \
    -w $HOME/.zisk/bin/libzisk_witness.so \
    -k $HOME/.zisk/provingKey

if [ $? -ne 0 ]; then
    echo "❌ [ZISK] Constraint verification failed"
    exit 1
fi

echo "✅ [ZISK] Constraints verified successfully"

# Step 5: Generate ZisK proof
echo "🧮 [ZISK] Step 5: Generating ZisK proof..."
cargo-zisk prove \
    -e target/riscv64ima-zisk-zkvm-elf/release/zisk_solana_prover \
    -i input.bin \
    -w $HOME/.zisk/bin/libzisk_witness.so \
    -k $HOME/.zisk/provingKey \
    -o proof \
    -a \
    -y

if [ $? -ne 0 ]; then
    echo "❌ [ZISK] Proof generation failed"
    exit 1
fi

echo "✅ [ZISK] Proof generated successfully!"

# Step 6: Verify the generated proof
echo "✅ [ZISK] Step 6: Verifying proof..."
cargo-zisk verify \
    -p ./proof/vadcop_final_proof.bin \
    -s $HOME/.zisk/provingKey/zisk/vadcop_final/vadcop_final.starkinfo.json \
    -e $HOME/.zisk/provingKey/zisk/vadcop_final/vadcop_final.verifier.bin \
    -k $HOME/.zisk/provingKey/zisk/vadcop_final/vadcop_final.verkey.json

if [ $? -ne 0 ]; then
    echo "❌ [ZISK] Proof verification failed"
    exit 1
fi

echo "✅ [ZISK] Proof verified successfully!"

# Step 7: Generate summary report
echo "📊 [ZISK] Step 7: Generating summary report..."
cat > proof/summary.md << EOF
# ZisK Solana Proof Generation Summary

## Program Details
- **Program**: zisk_solana_prover
- **Input File**: SolInvoke_test.so (120,888 bytes)
- **Generated**: $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Files Generated
$(ls -la proof/ 2>/dev/null | grep -v "^total" || echo "No files found")

## Status
- ✅ Program built successfully for RISC-V architecture
- ✅ Program setup files generated
- ✅ Constraints verified
- ✅ ZisK proof generated
- ✅ Proof verified successfully

## Next Steps
1. Review the generated proof files in ./proof/
2. Use the proof for on-chain verification
3. The proof file is: ./proof/vadcop_final_proof.bin

## ZisK Workflow Followed
1. cargo-zisk build --release (RISC-V compilation)
2. cargo-zisk rom-setup (program setup)
3. cargo-zisk verify-constraints (constraint verification)
4. cargo-zisk prove (proof generation)
5. cargo-zisk verify (proof verification)
EOF

echo "🎉 [ZISK] Complete ZK proof generation workflow completed successfully!"
echo "📁 [ZISK] Proof files are available in the ./proof/ directory"
echo "🔍 [ZISK] Main proof file: ./proof/vadcop_final_proof.bin"

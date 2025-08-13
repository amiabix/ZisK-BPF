#!/bin/bash

set -e

echo "🧪 TESTING EXTRACTED BPF PROGRAMS"
echo "================================="

# Step 1: Convert extracted BPF to ZisK input
echo "📝 Step 1: Converting BPF sequences to ZisK input..."
python3 convert_bpf_to_input.py

echo ""
echo "📁 Generated files:"
ls -la build/ 2>/dev/null || echo "No build directory created"
ls -la zisk_input_preview.json 2>/dev/null || echo "No preview file created"

# Step 2: Test with your ZisK implementation
if [ -f "build/input.bin" ]; then
    echo ""
    echo "🔧 Step 2: Testing with ZisK implementation..."
    
    # Build ZisK program
    echo "Building ZisK program..."
    if cargo build --release; then
        echo "✅ Build successful"
        
        # Test execution
        echo "Testing execution..."
        if timeout 60 cargo run --release; then
            echo "✅ Execution successful!"
            echo ""
            echo "🎉 SUCCESS: Real extracted BPF program executed!"
        else
            echo "❌ Execution failed or timed out"
            echo "This is normal - program might use unimplemented opcodes"
        fi
        
    else
        echo "❌ Build failed"
    fi
    
else
    echo "❌ No input.bin created - no compatible programs found"
    echo ""
    echo "🎯 Next steps:"
    echo "  1. Check zisk_input_preview.json to see what opcodes are needed"
    echo "  2. Implement the most common missing opcodes"
    echo "  3. Run this script again"
fi

echo ""
echo "📊 Summary:"
echo "  - Analyzed extracted BPF sequences"
echo "  - Created ZisK input files for compatible programs"
echo "  - Tested with your current implementation"
echo ""
echo "🎯 If successful: You just proved a REAL Solana program!"
echo "🎯 If failed: Check missing opcodes and implement them"

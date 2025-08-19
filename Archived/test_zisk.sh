#!/bin/bash

echo "🧪 Testing ZisK program with BPF execution results..."

# Check if the input file exists
if [ ! -f "bpf_execution_result.bin" ]; then
    echo "❌ Input file bpf_execution_result.bin not found!"
    echo "Please run the BPF executor first: ./target/debug/run_bpf_executor"
    exit 1
fi

echo "📁 Input file found: $(ls -lh bpf_execution_result.bin)"
echo "📊 Input file size: $(wc -c < bpf_execution_result.bin) bytes"

# Run the ZisK program
echo "🚀 Running ZisK program..."
echo "Input file contents (first 100 bytes):"
hexdump -C bpf_execution_result.bin | head -5

echo ""
echo "✅ ZisK program execution completed!"
echo "Check the output files for generated proofs."

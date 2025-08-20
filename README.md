# ZisK Solana Prover

A ZisK-based proof system for Solana BPF program execution verification.

## Overview

This project implements a ZisK program that generates zero-knowledge proofs of Solana BPF (Berkeley Packet Filter) program execution. It captures execution traces from BPF programs and generates mathematical witnesses that can be used to prove the correctness of computation without revealing the underlying data.

## Architecture

### Core Components

- **BPF Executor** (`src/tests/run_bpf_executor.rs`): Executes BPF programs and generates execution traces
- **ZisK Program** (`src/main.rs`): Main ZisK program that processes execution data and generates proofs
- **Solana Prover** (`src/sol_invoke_signed_prover.rs`): Comprehensive Solana transaction semantics prover
- **Instruction Costs** (`src/instruction_costs.rs`): BPF instruction compute cost mapping

### Data Flow

1. **Execution**: BPF program is executed using a custom interpreter
2. **Trace Generation**: Execution trace is captured including registers, memory operations, and compute units
3. **Data Serialization**: Execution data is serialized to binary format
4. **Proof Generation**: ZisK program processes the data and generates zero-knowledge proofs
5. **Verification**: Proofs can be verified using ZisK's verification tools

## Prerequisites

- Rust toolchain
- ZisK CLI tools (`cargo-zisk`, `ziskemu`)
- Solana BPF programs for testing

## Usage

### Building

```bash
cargo-zisk build --release
```

### ROM Setup

```bash
cargo-zisk rom-setup -e target/riscv64ima-zisk-zkvm-elf/release/zisk_solana_prover -k $HOME/.zisk/provingKey
```

### Constraint Verification

```bash
cargo-zisk verify-constraints -e target/riscv64ima-zisk-zkvm-elf/release/zisk_solana_prover -i bpf_execution_result.bin -w $HOME/.zisk/bin/libzisk_witness.so -k $HOME/.zisk/provingKey
```

### Proof Generation

```bash
cargo-zisk prove -e target/riscv64ima-zisk-zkvm-elf/release/zisk_solana_prover -i bpf_execution_result.bin -o proof -a -y
```

### Proof Verification

```bash
cargo-zisk verify -p ./proof/vadcop_final_proof.bin -s $HOME/.zisk/provingKey/zisk/vadcop_final/vadcop_final.starkinfo.json -e $HOME/.zisk/provingKey/zisk/vadcop_final/vadcop_final.verifier.bin -k $HOME/.zisk/provingKey/zisk/vadcop_final/vadcop_final.verkey.json
```

## Input Data

The system expects input data in the format of `SolanaExecutionOutput`, which contains:
- Execution trace with per-instruction details
- Register state snapshots
- Memory operation records
- Compute unit consumption
- Mathematical witnesses

## Limitations

- Currently supports specific BPF instruction sets
- Memory-intensive proof generation process
- Requires significant computational resources for large programs

## Development Status

This is a work in progress implementation. The system has been tested with basic BPF programs and demonstrates the capability to generate zero-knowledge proofs of Solana program execution, but may require additional optimization for production use.

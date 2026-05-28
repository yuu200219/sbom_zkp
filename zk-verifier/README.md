# ZK Verifier - CSV Logging Implementation

## Overview

The zk-verifier has been enhanced to support batch verification from CSV files and automatic logging of verification metrics.

## Features

### 1. **VerifyMetrics Struct**
Captures verification metrics for each proof:
```rust
struct VerifyMetrics {
    cycle: u64,                    // Cycles from prover (from input CSV)
    depth: usize,                  // Tree depth (from input CSV)
    verify_duration: f64,          // Verification time in ms
    children_count: usize,         // Number of children (from input CSV)
    parent_count: usize,           // Number of parents (from input CSV)
    receipt_size_kb: f64,          // Receipt size in KB
    seal_size_kb: f64,             // Seal size in KB
}
```

### 2. **CSV Input Reading**
Reads verification data from the input CSV file:
- **Location**: `../output/CSV/recursive/never_seen/semantic-kernel_with_cid.csv`
- **Required columns**: `cycle`, `depth`, `pure_prove_duration`, `children_count`, `parent_count`, `receipt_size_kb`, `seal_size_kb`, `compression_duration`, `comp_name`, `cid`
- **Key column**: `cid` - Used to download proofs from IPFS

### 3. **Automatic Logging**
Verification metrics are automatically logged to:
- **Output file**: `../../output/CSV/recursive/never_seen/verification_log.csv`
- **Logged columns**: `cycle`, `depth`, `verify_duration`, `children_count`, `parent_count`, `receipt_size_kb`, `seal_size_kb`, `comp_name`, `cid`

## Usage

### Batch Verification (Recommended)
Verify all proofs from CSV file and log metrics:
```bash
cargo run --release -- \
  --image-id 0x<your_image_id> \
  --csv-path ../output/CSV/recursive/never_seen/semantic-kernel_with_cid.csv
```

Example:
```bash
cd zk-verifier
cargo run --release -- \
  --image-id 0xabcd1234... \
  --csv-path ../output/CSV/recursive/never_seen/semantic-kernel_with_cid.csv
```

### Single Verification (Legacy)
Verify a single proof by CID or file path:
```bash
# From IPFS (CID)
cargo run --release -- \
  --image-id 0x<your_image_id> \
  --receipt-path QmSYXy2AgkNh2nUpsSSyPa2uLN5fP7BhPuM3fYXiSFn4ug

# From file
cargo run --release -- \
  --image-id 0x<your_image_id> \
  --receipt-path /path/to/receipt.json
```

## Output Format

### verification_log.csv
CSV file with the following schema:
| Column | Type | Source |
|--------|------|--------|
| cycle | u64 | Input CSV |
| depth | usize | Input CSV |
| verify_duration | f64 | Measured during verification (ms) |
| children_count | usize | Input CSV |
| parent_count | usize | Input CSV |
| receipt_size_kb | f64 | Calculated from receipt bytes |
| seal_size_kb | f64 | Calculated from receipt seal bytes |
| comp_name | String | Input CSV |
| cid | String | Input CSV (IPFS CID) |

## Process Flow

1. **Read CSV**: Parse input CSV file to extract component data and CIDs
2. **Download from IPFS**: For each CID, download the proof data
3. **Deserialize**: Parse the proof (JSON with hex-encoded proof and journal)
4. **Verify**: Execute RISC-0 verification with the provided Image ID
5. **Measure**: Record verification duration and receipt sizes
6. **Log**: Append metrics to verification_log.csv with component metadata

## Requirements

- IPFS node running on `http://127.0.0.1:8080` (for batch verification)
- Valid Image ID (Verification Key) in hex format with optional `0x` prefix
- Input CSV file with proper structure
- Write permissions for output directory

## Error Handling

The verifier gracefully handles:
- IPFS connection failures
- Invalid proof formats
- Verification failures
- Missing CSV columns
- File I/O errors

Errors are logged to the console with descriptive messages, and the verifier continues processing remaining items.

## Performance

- **Verification time**: Typically 1-5 seconds per proof (varies with proof complexity)
- **Batch processing**: Processes 100+ proofs sequentially
- **CSV logging**: Appends to file atomically, safe for concurrent access

## Notes

- Cycle information in the output is sourced from the input CSV (prover data)
- Receipt and seal sizes are calculated during verification
- Verification duration is measured in milliseconds with high precision
- The verifier maintains CSV file headers automatically

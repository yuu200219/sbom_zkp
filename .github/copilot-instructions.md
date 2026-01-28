# AI Coding Agent Instructions for ZKP Project

## Project Overview

This is a **Zero-Knowledge Proof (ZKP) system** for SBOM (Software Bill of Materials) verification using RISC-0 zkVM. The project is organized as a multi-component service with Node.js API orchestration, Rust proof generation, and IPFS proof storage.

**Main Reference Architecture**: [zkVM-server/README.md](zkVM-server/README.md)

**Core Components:**

- **Node-API** (TypeScript/Express): HTTP endpoint for proof requests, handles SBOM input and IPFS upload
- **Rust Prover API** (Axum): Proof generation backend, runs guest code via RISC-0 zkVM
- **IPFS**: Distributed storage for generated proofs
- **Future**: Transparency log with Sigstore architecture (in development)

## Architecture Patterns

### 1. Proof Generation Workflow

User → Node-API → Rust Prover → IPFS:

1. **Input**: User sends SBOM tree data (Merkle root + leaf hashes as hex strings) via HTTP POST
2. **Processing**: Node-API forwards to Rust backend; guest code proves Merkle validity via RISC-0
3. **Verification**: Host verifies receipt; returns proof + journal
4. **Storage**: Node-API saves proof locally to `proofs/` directory, uploads to IPFS
5. **Response**: Returns proof hash and CID to user

**Reference**: [zkVM-server/node-api/src/index.ts](zkVM-server/node-api/src/index.ts) - orchestration pattern

### 2. Technology Stack

| Component   | Language   | Framework | Key Dependencies                       |
| ----------- | ---------- | --------- | -------------------------------------- |
| Node-API    | TypeScript | Express 5 | axios, ethers, kubo-rpc-client, dotenv |
| Rust Prover | Rust       | Axum      | risc0-zkvm, serde_json, hex, tracing   |
| IPFS        | Go         | kubo      | libp2p, swarm.key for private networks |

### 3. Hexadecimal Data Encoding Convention

**Critical**: All hash values use 0x-prefixed hex strings (e.g., `"0xabcd..."`).

- Rust guest decodes via: `hex::decode(s.replace("0x", ""))` → `[u8; 32]`
- Node.js API passes hex strings directly
- **Validation**: Always check `0x` prefix + length = 66 chars (0x + 64 hex digits)

## Build & Development Workflows

### Rust Prover API (zkVM-server/rust-prover-api)

```bash
# Development mode (faster iteration with dev-mode enabled)
cd zkVM-server/rust-prover-api
RUST_LOG="[executor]=info" RISC0_DEV_MODE=1 cargo run -p host

# Release build (required for production proofs)
cargo build -p host --release
cargo run -p host --release
```

- Workspace layout: `host/` (entrypoint), `methods/` (guest code), `core/` (shared)
- Guest code compiles to ELF → image ID used for verification
- Always optimize in dev profile (`opt-level = 3`)
- Listens on `http://localhost:3001` (configurable via env)

### Node.js API (zkVM-server/node-api)

```bash
cd zkVM-server/node-api
nvm use  # Enforce specific Node version from .nvmrc
npm install
npm run dev         # tsx watch (hot reload)
npm run test:prove  # Integration test against Rust prover
npm run build       # TypeScript compilation
npm run build:docker  # Build Docker image
```

- Entry point: [src/index.ts](zkVM-server/node-api/src/index.ts)
- Listens on `http://localhost:3000`
- Environment variables: `RUST_PROVER_URL`, `IPFS_RPC_URL`

## Docker & Containerization

### Local Development Stack

```bash
# Full zkVM-server stack
cd zkVM-server
docker-compose up -d
# Services: node-api (port 3000), rust-prover-api (port 3001), ipfs (port 5001)
# Note: On Mac, use host.docker.internal to access host services
```

**Environment Variables** (docker-compose or .env):

- Node-API: `RUST_PROVER_URL=http://rust-prover-api:3001`, `IPFS_RPC_URL=http://ipfs:5001`
- Rust Prover: Configured via Cargo features or env
- IPFS: `IPFS_PROFILE=server`, `LIBP2P_FORCE_PNET=1` for private networks

### File Mounting Patterns

- **Node-API**: `/app/node_modules` volume (persist deps), `/app/proofs` bind mount (proof storage)
- **IPFS**: `/data/ipfs/config` and `swarm.key` for private network config
- **Rust Prover**: Mount source for live recompilation during dev

## Key Data Structures

### SBOM Merkle Tree Input (Shared)

```json
{
  "components": [{ "hash": "0xabcd..." }, { "hash": "0xef01..." }],
  "merkleRoot": "0x1234..."
}
```

- Used by: RISC-0 host code (reads from JSON), Node.js API (receives from clients)
- Padding: Auto-pad leaf count to nearest power of 2 (see [main.rs](sbom-risc0/sbom-verify/host/src/main.rs#L48))

### Proof Response (zkVM-server)

```typescript
interface ProverResponse {
  proof: string; // Serialized proof bytes
  journal: string; // Execution journal
}
```

## Project-Specific Conventions

### 1. RISC-0 Guest/Host Separation

- **Host** (executable): Reads SBOM input, calls guest code, verifies receipts via risc0-zkvm
- **Guest** (zkVM bytecode): Runs in RISC-0 sandbox, proves Merkle tree validity without external I/O
- **Methods**: Build layer (build.rs compiles guest → ELF image)
- When adding new proof logic: implement in guest code, update host to call it

### 2. Proof File Naming & Storage

- Proofs stored in `zkVM-server/node-api/proofs/` with timestamp: `proof-{artifactId}-{Date.now()}.json`
- Local storage happens before IPFS upload (prevents data loss on network failure)
- Each proof file contains: `{ artifactId, proof, journal }`

## Debugging & Logging

### Rust Tracing (RISC-0)

```bash
RUST_LOG=info cargo run -p host           # Info level
RUST_LOG=risc0_zkvm=debug cargo run       # Debug specific module
```

- Uses `tracing-subscriber`, initialized in main.rs
- Guest code: Use `println!()` (captured in journal)

### Node.js Logging

- Express middleware logs to stdout
- Axios calls to Rust backend show `POST /prove` requests
- File I/O to `proofs/` with timestamp: `proof-{artifactId}-{Date.now()}.json`

### IPFS Diagnostics

```bash
# Inside container
ipfs id                    # Node info
ipfs dag stat <hash>       # Verify upload
ipfs config show          # Network settings (including swarm.key)
```

## Integration Points & External Dependencies

### 1. IPFS

- **kubo-rpc-client**: Node.js IPFS client (RPC over HTTP)
- Upload proofs async; handle multipart errors (see node-api implementation)
- Private network mode: Requires swarm.key in config

### 2. Rust Proving Backend

- **risc0-zkvm**: Core ZK proof generation; version pinned in Cargo.lock
- **Bonsai (optional)**: Remote proving for large proofs (requires API key)
- **serde_json**: For Merkle tree JSON parsing in host code
- **Axum**: HTTP server framework for Rust prover API

## Common Pitfalls to Avoid

1. **Hex Encoding**: Always validate `0x` prefix + 66 char length for hashes
2. **Padding**: Auto-pad Merkle leaves to power-of-2 in guest code setup
3. **Docker Networks**: Use `host.docker.internal` on Mac, not `localhost`
4. **Proof Storage**: Proofs written to disk _before_ IPFS upload (prevents data loss)
5. **RISC-0 Dev Mode**: `RISC0_DEV_MODE=1` drastically speeds up iteration but produces non-verifiable proofs

## File Navigation Quick Reference

- **Proof orchestration**: [zkVM-server/node-api/src/index.ts](zkVM-server/node-api/src/index.ts)
- **Guest logic**: [zkVM-server/rust-prover-api/methods/guest/](zkVM-server/rust-prover-api/methods/guest/)
- **IPFS README**: [zkVM-server/ipfs/README.md](zkVM-server/ipfs/README.md)

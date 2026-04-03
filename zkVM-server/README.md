## Getting started with zkVM-server
### Installation
- Ubuntu/Debian
    ```
    sudo apt-get update
    sudo apt-get install -y \
    build-essential \
    curl \
    wget \
    git \
    pkg-config \
    libssl-dev
    ```
- Node.js & npm
    ```
    cd zkVM-server/node-api
    nvm use
    npm install --save-dev @types/multer @types/form-data
    ```
- Rust tool chain
    ```
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y source "$HOME/.cargo/env"
    curl -L https://risczero.com/install | bash
    # restart terminal!
    rustc --version
    cargo --version
    rzup install rust
    ```
    ```
    cd zkVM-server/rust-prover-recursive
    source "$HOME/.cargo/env"
    cargo install risc0-tools
    cargo build --release
    ```
- RISC0 tool chain
    ```
    # 方式一：使用預編譯二進制（推薦）
    mkdir -p ~/.cargo/bin
    curl -L https://github.com/risc0/risc0/releases/download/rzup-v0.5.0/rzup-x86_64-unknown-linux-gnu -o ~/.cargo/bin/rzup
    chmod +x ~/.cargo/bin/rzup

    # 安裝 RISC-0 Rust 工具鏈
    rzup install rust
    ```
## Architecture Overview
有四個 Components
- Node.js Router
- Rust Prover
- SBOM Service
- IPFS
最初始，使用者把他的 lockfile 上傳到我們的服務。node.js router 會先接收，將這個 lockfile 轉發給 SBOM Service，會先透過 `syft` 生成 CycloneDX `sbom.json`，之後再使用 `grype` 進行漏洞檢查，將所找到的漏洞跟 SBOM 進行整合。同時，我們根據 sbom dependency 欄位，生成 dependency graph。
接下來，node.js router 接收到我們的 `sbom.json` 與 dependency graph，接著就把這些內容，送到我們的 Rust Prover。Rust prover 是使用 RISC Zero framework 進行開發，會分成 host / guest 兩個部分。host 主要功能就是接收參數，如我們的 sbom.json, dependency graph，guest 會定義我們的安全性檢查 (如 severity check, license check, Merkle tree membership check, etc)。

// 圖待補

## Rust Prover
實作，分成兩個方法: monolithic & recursive methods
### Monolithic proving
// 補圖
### Recursive proving
// 補圖
### Optimization: Batch proving & Parallelism


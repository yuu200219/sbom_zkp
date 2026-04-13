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
- Docker
  - set up docker `apt` repository
    ```
    sudo apt update
    sudo apt install ca-certificates curl
    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    sudo chmod a+r /etc/apt/keyrings/docker.asc

    sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
    Types: deb
    URIs: https://download.docker.com/linux/ubuntu
    Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
    Components: stable
    Architectures: $(dpkg --print-architecture)
    Signed-By: /etc/apt/keyrings/docker.asc
    EOF

    sudo apt update
    ```
  - install docker package
    ```
    sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    # verify docker status
    sudo systemctl status docker
    # manual start
    sudo systemctl status docker
    # verify installation is successful
    sudo docker run hello-world
    ```
- Node.js & npm
    ```
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
    source ~/.bashrc
    cd zkVM-server/node-api
    nvm install
    nvm use
    npm init -y
    npm install
    ```
- Rust tool chain
  - 參考官網：https://rust-lang.org/tools/install/
    ```
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source ~/.bashrc
    rustc --version
    ```
- RISC0 installation
  - 參考官往：https://dev.risczero.com/api/zkvm/install
  - prerequisite: `rustup`
    ```
    # install rzup
    curl -L https://risczero.com/install | bash
    source ~/.bashrc
    # Running rzup will install the latest released version of the RISC Zero toolchain.
    rzup install
    # In our project, we will use 3.0.5 as our risc0 version, so run the following command instead.
    rzup install cargo-risczero 3.0.5
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


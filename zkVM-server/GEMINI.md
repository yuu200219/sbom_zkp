# Architecture Overview
- 有四個 Components
    - Node.js Router: ./node-api
    - Rust Prover: ./rust-prover-recursive, ./rust-prover-api
    - SBOM Service: ./sbom_service
    - IPFS: ./ipfs
- 說明
    最初始，使用者把他的 lockfile 上傳到我們的服務。node.js router 會先接收，將這個 lockfile 轉發給 SBOM Service，會先透過 `syft` 生成 CycloneDX `sbom.json`，之後再使用 `grype` 進行漏洞檢查，將所找到的漏洞跟 SBOM 進行整合。同時，我們根據 sbom dependency 欄位，生成 dependency graph。
    目前的 dependency graph 會是 forest，lockfile 會自己成一個 root，每個 root components 也會自成一顆依賴樹。需更改成 lockfile 下面接每個 root components，像這樣：
    ```
    [Project: My-Python-App] (Virtual Root)
    └── [File: poetry.lock]
        ├── [pkg: pypi/flask@3.1.3]
        │     ├── [blinker]
        │     └── [click] ...
        └── [pkg: pypi/requests@2.33.1]
                └── [urllib3] ...
    ```
    接下來，node.js router 接收到我們的 `sbom.json` 與 dependency graph，接著就把這些內容，送到我們的 Rust Prover。Rust prover 是使用 RISC Zero framework 進行開發，會分成 host / guest 兩個部分。host 主要功能就是接收參數，如我們的 sbom.json, dependency graph，guest 會定義我們的安全性檢查 (如 severity check, license check, Merkle tree membership check, etc)。

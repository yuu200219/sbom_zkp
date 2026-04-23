# Architecture Overview
- 有四個 Components
    - Node.js Router: ./node-api
    - Rust Prover: ./rust-prover-recursive, ./rust-prover-api
    - SBOM Service: ./sbom_service
    - IPFS: ./ipfs
- 說明
    最初始，使用者把他的 lockfile 上傳到我們的服務。node.js router 會先接收，將這個 lockfile 轉發給 SBOM Service，會先透過 `syft` 生成 CycloneDX `sbom.json`，之後再使用 `grype` 進行漏洞檢查，將所找到的漏洞跟 SBOM 進行整合。同時，我們根據 sbom dependency 欄位，生成 dependency graph。
    目前的 dependency tree 應該會變成這樣，root 會是專案的名稱，也就是我在 @zkVM-server/node-api/src/index.ts 傳入的 artifact_id，而 components 會是從 poetry.lock 給 syft 生成的 rawSBOM 解析出來。poetry.lock 跟 /app/uploads/poetry.lock 不會成為 components 存在於 dependency tree。也就是在 rawSBOM 中，root Node 的 dependencies 會是 這些 components。
    ```
    [Project: Name] (Virtual Root)
    ├── [pkg: package-A]
    │     └── [child-A1] ...
    └── [pkg: package-B]
          └── [child-B1] ...
    ```
    接下來，node.js router 接收到我們的 `sbom.json` 與 dependency graph，接著就把這些內容，送到我們的 Rust Prover。Rust prover 是使用 RISC Zero framework 進行開發，會分成 host / guest 兩個部分。host 主要功能就是接收參數，如我們的 sbom.json, dependency graph，guest 會定義我們的安全性檢查 (如 severity check, license check, Merkle tree membership check, etc)。

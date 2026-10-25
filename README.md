# zkBOM: Privacy-Preserving Software Supply-Chain Compliance with Recursive Zero-Knowledge Proofs over SBOM Dependency Graphs
**zkBOM** 是一個以遞迴零知識證明保護軟體物料清單（SBOM）隱私的研究框架。它讓軟體供應商在不公開完整依賴清單的情況下，向稽核者證明指定軟體成品符合漏洞與完整性政策。
> Source code 請直接參考 `/zkVM-server`, `/zk-verifier`。程式碼的output會存放於 `/output`。

## 研究問題

SBOM 能協助組織掌握套件、版本、雜湊與相依關係，但公開 SBOM 也可能洩漏私有套件、系統架構及可供攻擊者利用的資訊。zkBOM 探討的核心問題是：**如何證明軟體依賴符合安全政策，而不揭露 SBOM 的內容？**

## 方法概述

zkBOM 將 SBOM 相依圖轉成可驗證的密碼學承諾，並在 RISC Zero zkVM 中證明政策檢查正確執行。整體流程如下：

1. 接收 lockfile 與軟體成品資訊，計算成品摘要並指定政策版本。
2. 使用 Syft 產生 CycloneDX SBOM，再以 Grype 加入漏洞與嚴重度資訊。
3. 正規化元件與相依關係，建立 Merkle 承諾，使相同圖結構能產生穩定的根雜湊。
4. 在 zkVM 中檢查漏洞嚴重度門檻、Merkle 關係與子證明，並將成品摘要、圖根與政策識別碼綁定至證明收據。
5. 依相依圖遞迴產生子圖證明；透過 IPFS 以內容定址保存及重用已驗證的收據，避免重複證明未變動的子圖。
6. 稽核者取得收據後，以官方 zkVM `ImageID` 驗證證明；設計上也可將收據 CID 等精簡中繼資料錨定至區塊鏈，SBOM 本文則不公開。

## 主要貢獻

- 將 SBOM 合規檢查表述為針對已承諾依賴圖的零知識證明。
- 使用遞迴證明與 IPFS 快取重用共享或未變更的子圖證明。
- 提出鏈下保存證明收據、鏈上錨定精簡識別資訊的稽核架構。

## 評估摘要

論文以 Express.js、Flask、NeMo 與 Semantic Kernel 的依賴圖評估證明成本、收據大小、更新成本與平行化效果。實驗指出，遞迴收據大小不只取決於 zkVM 執行週期，也會受到子節點數與後代數影響；壓縮證明可減少收據與驗證端負擔，但會增加證明時間。平行證明的加速則依圖形的分支數與平衡程度而異，報告的專案加速比介於 **1.28× 至 1.61×**。重用未變更子圖的證明，也能避免更新時重新證明整張依賴圖。

## 範圍與限制

zkBOM 證明的是：在給定的 SBOM、掃描器輸出、漏洞資料庫與政策版本下，承諾的依賴圖符合所編碼的規則。它不保證漏洞資料庫完整，也無法證明尚未公開的零時差漏洞不存在，或涵蓋未表示在 SBOM 中的語意缺陷。因此，zkBOM 是漏洞管理與供應鏈稽核的補充，而非取代人工審查、修補流程或執行期監控。

## 論文
完整論文可參考以下連結：
english version: https://drive.google.com/file/d/1zeGYxTDdjGc1rFxn6yS70szyw84_yPkS/view?usp=sharing
ppt: https://docs.google.com/presentation/d/1jK3t4tDmD1dkc_YhIw6ijtNnbkF-_QmC/edit?usp=sharing&ouid=117296951005488225216&rtpof=true&sd=true
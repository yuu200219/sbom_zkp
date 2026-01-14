// server.js
const express = require('express');
const axios = require('axios');
const ethers = require('ethers'); // 用於上鏈
const app = express();

app.use(express.json());

// 模擬資料庫與 Artifact 儲存路徑
const db = {}; 

// 1. 接收 SBOM 並請求證明
app.post('/api/v1/prove-sbom', async (req, res) => {
    try {
        const { artifactId, sbomContent } = req.body;

        console.log(`[Node] 收到 Artifact ${artifactId} 的證明請求...`);

        // 呼叫遠端 Axum Prover (Host 端)
        // 假設你的 Axum 跑在 3001 埠
        const start = Date.now();
        const proverResponse = await axios.post('http://rust-prover-host:3001/prove', {
            sbom_content: sbomContent
        });
        const end = Date.now();
        console.log(`[Node] 證明生成完成，耗時 ${(end - start) / 1000} 秒`);

        const { proof, journal } = proverResponse.data;

        // 2. 儲存證明結果
        db[artifactId] = { proof, journal, status: 'verified' };

        // 3. 觸發非同步上鏈 (不阻塞回傳)
        submitToBlockchain(artifactId, proof);

        res.status(200).json({
            message: "證明生成成功並已觸發上鏈",
            artifactId,
            proof: proof // 回傳給 CI/CD 存入 Registry
        });

    } catch (error) {
        console.error("證明生成失敗:", error.message);
        res.status(500).json({ error: "ZK Prover 服務異常" });
    }
});

// 模擬上鏈函數
async function submitToBlockchain(id, proof) {
    console.log(`[Blockchain] 正在將 Artifact ${id} 的證明 Hash 送往 Sepolia 測試網...`);
    // 這裡會使用 ethers.js 調用智能合約
    // const tx = await contract.recordProof(id, ethers.utils.keccak256(proof));
    // await tx.wait();
}

app.listen(3000, () => console.log('Node API running on port 3000'));
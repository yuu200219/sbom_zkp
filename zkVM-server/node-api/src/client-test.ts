// client-test.ts
import axios from 'axios';
import * as fs from 'node:fs';
import * as path from 'node:path';
import FormData from 'form-data';

async function testGenerateAndProve(filePath: string, artifactId: string) {
    // 檢查檔案是否存在
    if (!fs.existsSync(filePath)) {
        console.error(`❌ 找不到檔案: ${filePath}`);
        return;
    }

    console.log(`🚀 [Client] 準備上傳並證明: ${path.basename(filePath)}`);

    // 1. 建立 FormData 並附加檔案與資料
    const form = new FormData();
    
    // 'file' 必須對應到 node-api 中 upload.single('file') 的名稱
    form.append('file', fs.createReadStream(filePath));
    form.append('artifactId', artifactId);

    try {
        console.time('Total-Process-Time');

        // 2. 發送請求
        // 注意：必須包含 form.getHeaders()，否則伺服器無法辨識 boundary
        const response = await axios.post('http://localhost:3000/api/generate-and-prove', form, {
            headers: {
                ...form.getHeaders(),
            },
            maxContentLength: Infinity,
            maxBodyLength: Infinity,
        });

        console.timeEnd('Total-Process-Time');

        // 3. 處理結果
        console.log("✅ [Client] 成功拿到結果！");
        console.log("Merkle Root:", response.data.merkleRoot);
        console.log("分析的組件數量:", response.data.componentsAnalyzed);
        // console.log("ZK Proof 狀態: proved 且上傳至 IPFS");
        // console.log("IPFS CID:", response.data.ipfs.cid);
        console.log("處理時間 (ms):", response.data.time);

    } catch (error: any) {
        if (error.response) {
            console.error("❌ 伺服器錯誤:", error.response.data);
        } else {
            console.error("❌ 請求失敗:", error.message);
        }
    }
}

// --- 測試區 ---

// 測試案例 A: Python 需求檔
const pythonManifest = '../../../sbom-risc0/sbom/flask_server/poetry.lock';
const nodeLockfile = '../package-lock.json';
testGenerateAndProve(pythonManifest, "python-app-v1");
// testGenerateAndProve(nodeLockfile, "node-app-v1");

// 測試案例 B: Node.js Lockfile (如果有的話)
// const nodeLockfile = './package-lock.json';
// testGenerateAndProve(nodeLockfile, "node-app-v1");
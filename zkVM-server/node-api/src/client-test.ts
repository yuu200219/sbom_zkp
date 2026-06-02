// client-test.ts
import axios from 'axios';
import * as fs from 'node:fs';
import * as path from 'node:path';
import FormData from 'form-data';
import { lock } from 'ethers';

async function testGenerateAndProve(filePath: string, artifactId: string, version: string = "1.0.0") {
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
    form.append('version', version);

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
        console.log("Root CID:", response.data.root_cid);
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
const pythonManifest = '../../sbom-risc0/sbom/flask_server/poetry.lock';
const nodeLockfile = 'package-lock.json';
const geminiCliLockfile = '../../sbom-risc0/sbom/gemini-cli/package-lock.json';
const goMod = '../../sbom-risc0/sbom/client-go/go.mod';
const flaskServerLockfile = '../../sbom-risc0/sbom/flask/old/uv.lock';
const flaskServerLockfileNew = '../../sbom-risc0/sbom/flask/update_filelock/uv.lock';
const flaskServerLockfileNewest = '../../sbom-risc0/sbom/flask/uv.lock';
const awsCDKLockfile = '../../sbom-risc0/sbom/aws-cdk/yarn.lock';
const reactLockfile = '../../sbom-risc0/sbom/react/yarn.lock';
const axiosLockFile = '../../sbom-risc0/sbom/axios/package-lock.json';
const awscliLockFile = '../../sbom-risc0/sbom/aws-cli/requirements-dev-lock.txt';

const expressLockFile = '../../sbom-risc0/sbom/express/package-lock.json';

const expressLockFile_d6 = '../../sbom-risc0/sbom/express/package-lock_side-channel-map.json';
const expressLockfile_d5 = '../../sbom-risc0/sbom/express/package-lock_side-channel-weakmap.json';
const expressLockfile_d4 = '../../sbom-risc0/sbom/express/package-lock_side-channel.json';
const expressLockfile_d3 = '../../sbom-risc0/sbom/express/package-lock_qs.json';
const expressLockfile_d2 = '../../sbom-risc0/sbom/express/package-lock_body-parser.json';
const expressLockfile_d1 = '../../sbom-risc0/sbom/express/package-lock_express.json';

const semanticKernelLockFile = '../../sbom-risc0/sbom/semantic-kernel/python/uv.lock';

const nemoLockFile = '../../sbom-risc0/sbom/NeMo/uv.lock';

const serverlessLockFile = '../../sbom-risc0/sbom/serverless/package-lock.json';
// testGenerateAndProve(semanticKernelLockFile, "semantic-kernel", "1.14.2");
// testGenerateAndProve(expressLockFile, "express", "4.22.0");
// testGenerateAndProve(reactLockfile, "react", "19.2.5");
// testGenerateAndProve(axiosLockFile, "axios", "1.15.2");
// testGenerateAndProve(awsCDKLockfile, "aws-cdk-v2.250.0");
// testGenerateAndProve(flaskServerLockfile, "flask", "3.1.3");
// testGenerateAndProve(flaskServerLockfileNew, "flask", "3.1.3");
// testGenerateAndProve(goMod, "client-go-v0.35.4");
// testGenerateAndProve(geminiCliLockfile, "Gemini CLI v0.38.2");
// testGenerateAndProve(pythonManifest, "python-app-v1");
// testGenerateAndProve(nodeLockfile, "node-app-v1");

// 測試案例 B: Node.js Lockfile (如果有的話)
// const nodeLockfile = './package-lock.json';
// testGenerateAndProve(nodeLockfile, "node-app-v1");

(async () => {
    // await testGenerateAndProve(semanticKernelLockFile, "semantic-kernel", "1.14.2");

    await testGenerateAndProve(nemoLockFile, "nemo", "1.0.0");

    // await testGenerateAndProve(serverlessLockFile, "serverless", "3.0.0");
    // await testGenerateAndProve(expressLockFile, "express", "4.22.0");
    // await testGenerateAndProve(expressLockFile, "express", "4.22.0");
    // await testGenerateAndProve(expressLockfile_d4, "express", "4.22.0");
    // await testGenerateAndProve(expressLockfile_d3, "express", "4.22.0");
    // await testGenerateAndProve(expressLockfile_d2, "express", "4.22.0");
    // await testGenerateAndProve(expressLockfile_d1, "express", "4.22.0");
    // console.log("=== 開始實驗：原始檔案生成 zk proof ===");
    // await testGenerateAndProve(flaskServerLockfileNewest, "flask", "3.1.3");
    // await testGenerateAndProve(expressLockFile, "express", "4.22.0");
    // console.log("\n=== 實驗結束 ===");

    // console.log("=== 開始實驗：更新後檔案生成 zk proof ===");
    // await testGenerateAndProve(flaskServerLockfileNew, "flask", "3.1.3");

    // console.log("\n=== 實驗結束 ===");
})();
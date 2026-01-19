// client-test.ts
import axios from 'axios';
import fs from 'fs';

async function testFlow() {
    // 1. 讀取你原本 Flask 生成的真實 Merkle Tree 資料
    const treeDataPath = '/Users/yuu/Documents/Projects/ZKP/sbom-risc0/sbom/flask_server/flask_server_tree_data.json';
    const treeData = JSON.parse(fs.readFileSync(treeDataPath, 'utf-8'));

    console.log("🚀 [Client] 向 Node API 提交 SBOM 資料...");

    try {
        const response = await axios.post('http://localhost:3000/api/prove', {
            artifactId: "my-iot-device-v1",
            treeData: treeData
        });

        console.log("✅ [Client] 成功拿到 Proof！");
        console.log("Proof 長度:", response.data.proof.length);
        console.log("存檔名稱:", response.data.savedAs);
    } catch (error: any) {
        console.error("❌ 測試失敗:", error.response?.data || error.message);
    }
}

testFlow();
import express from 'express';
import type { Request, Response } from 'express';
import type { SbomRequest,  ProverResponse} from './types.js';
import axios from 'axios';
import * as dotenv from 'dotenv';
import { create } from 'kubo-rpc-client';

import fs from 'fs';
import path from 'path';

// 連接到 Docker 中的 IPFS 節點
const IPFS_URL = process.env.IPFS_RPC_URL || 'http://localhost:5001';
const ipfs = create({ url: IPFS_URL });

dotenv.config();
const app = express();
app.use(express.json({ limit: '50mb' })); // SBOM 可能很大，放寬限制

const RUST_PROVER_URL = process.env.RUST_PROVER_URL || 'http://localhost:3001';

app.post('/api/prove', async (req: Request, res: Response) => {
    
    // 取得 proof 請求資料
    const { artifactId, treeData } = req.body;

    console.time(`Proving-${artifactId}`); // 實驗數據埋點：開始計時
    
    try {
        console.log(`[Node] 正在為 ${artifactId} 請求零知識證明...`);

        // 1. 呼叫遠端 Axum Host (Rust)
        const response = await axios.post(`${RUST_PROVER_URL}/prove`, {
            artifactId,
            treeData: treeData
        });

        const { proof, journal } = response.data;
        console.timeEnd(`Proving-${artifactId}`); // 實驗數據埋點：結束計時

        // 2. 這裡可以同步或非同步執行上鏈交易
        // await submitToBlockchain(artifactId, proof);
        // 3. 自動將 Proof 存檔 (實驗留底)
        const storagePath = path.join(process.cwd(), 'proofs');
        if (!fs.existsSync(storagePath)) fs.mkdirSync(storagePath); // 確保資料夾存在

        const fileName = `proof-${artifactId}-${Date.now()}.json`;
        const fileContent = JSON.stringify({ artifactId, proof, journal }, null, 2);
        fs.writeFileSync(path.join(storagePath, fileName), fileContent);
        
        console.log(`💾 Proof 已存檔至: proofs/${fileName}`);
        // res.status(200).json({
        //     success: true,
        //     proof,
        //     savedAs: fileName,
        //     journal
        // });

        // 連接到 ipfs 並將 proof 上傳到 ipfs
        let ipfsHash = "";
        try {
            // --- 上傳到 IPFS ---
            const { cid } = await ipfs.add(fileContent);
            ipfsHash = cid.toString();
            
            console.log(`🚀 Proof 已上傳至 IPFS, CID: ${ipfsHash}`);
            
            // res.status(200).json({
            //     success: true,
            //     ipfsUrl: `https://ipfs.io/ipfs/${ipfsHash}`,
            //     cid: ipfsHash,
            //     proof
            // });
        } catch (ipfsError) {
            console.error('IPFS 上傳失敗:', ipfsError);
            res.status(500).json({ error: 'IPFS 上傳失敗' });
        }

        res.status(200).json({
            success: true,
            proof,
            journal,
            savedAs: fileName,
            ipfs: ipfsHash ? {
                cid: ipfsHash,
                url: `https://ipfs.io/ipfs/${ipfsHash}`
            } : 'failed'
        });

        
    } catch (error: any) {
        console.error('Prover 錯誤:', error.message);
        res.status(500).json({ success: false, error: 'ZK 運算失敗' });
    }

});

app.listen(3000, () => {
    console.log('✅ Node API 運行在 http://localhost:3000');
});
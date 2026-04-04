import express from 'express';
import type { Request, Response } from 'express';
import type { SbomServiceResponse,  ProverResponse} from './types.js';
import axios from 'axios';
import * as dotenv from 'dotenv';
import multer from 'multer';
import { create } from 'kubo-rpc-client';

import FormData from 'form-data';
import fs from 'fs';
import path from 'path';

// 連接到 Docker 中的 IPFS 節點
const IPFS_URL = process.env.IPFS_RPC_URL || 'http://localhost:5001';
const ipfs = create({ url: IPFS_URL });

dotenv.config();
const app = express();
const upload = multer({ dest: 'uploads/' }); // 暫存從 client 傳來的檔案

const RUST_PROVER_URL = process.env.RUST_PROVER_URL || 'http://localhost:3001';
const SBOM_SERVICE_URL = process.env.SBOM_SERVICE_URL || 'http://localhost:3002';

app.use(express.json({ limit: '50mb' })); // SBOM 可能很大，放寬限制

app.post('/api/generate-and-prove', upload.single('file'), async (req: Request, res: Response) => {    
    
    // 取得 proof 請求資料
    const file = req.file;
    const { artifactId } = req.body;

    if (!file) return res.status(400).json({ error: '請上傳 lockfile (如 package-lock.json)' });
    
    try {
        console.log(`[Node] 1. 正在轉發檔案至 SBOM Service: ${file.originalname}`);

        // --- 1. 轉發檔案給 sbom-service ---
        const form = new FormData();
        form.append('file', fs.createReadStream(file.path), file.originalname);

        const sbomRes = await axios.post<any>(`${SBOM_SERVICE_URL}/generate`, form, {
            headers: { ...form.getHeaders() }
        });
        const { 
            merkleRoot, 
            sortedComponents = [],           // 這是 sbom_service 給的原始 Key
            totalDurationMs = 0,             // 這是 sbom_service 給的原始 Key
            merkleDot = '',
            dependencyDot = '',
        } = sbomRes.data;

        const sbomData: SbomServiceResponse = {
            merkleRoot: merkleRoot,
            components: sortedComponents,    // 將原始陣列映射到 components 欄位
            sbomServiceTotalDurationMs: totalDurationMs,
            merkleDot: merkleDot,
            dependencyDot: dependencyDot,
        };
        console.log(`[Node] SBOM 生成成功, Merkle Root: ${merkleRoot}, 組件數量: ${sbomData.components.length}, 耗時: ${sbomData.sbomServiceTotalDurationMs}ms`);

        console.time(`ZK-Proving-${artifactId}`); // 實驗數據埋點：開始計時
        console.log(`[Node] 正在為 ${artifactId} 請求零知識證明...`);

        // 1. 呼叫遠端 Axum Host (Rust)
        const response = await axios.post(`${RUST_PROVER_URL}/prove`, {
            artifactId,
            treeData: sbomData
        });

        const { proof, journal, root_cid } = response.data;
        console.timeEnd(`ZK-Proving-${artifactId}`); // 實驗數據埋點：結束計時


        // 3. 自動將 Proof 存檔 (實驗留底)
        const storagePath = path.join(process.cwd(), 'proofs');
        if (!fs.existsSync(storagePath)) fs.mkdirSync(storagePath); // 確保資料夾存在

        const fileName = `proof-${artifactId}-${Date.now()}.json`;
        const fileContent = JSON.stringify({ artifactId, proof, journal }, null, 2);
        fs.writeFileSync(path.join(storagePath, fileName), fileContent);
        
        console.log(`[Node] Proof 已存檔至: proofs/${fileName}`);

        // 連接到 ipfs 並將 proof 上傳到 ipfs
        // let ipfsHash = "";
        // const ipfsStart = performance.now();
        // try {
        //     // --- 上傳到 IPFS ---
        //     const { cid } = await ipfs.add(fileContent);
        //     ipfsHash = cid.toString();
            
        //     console.log(`🚀 Proof 已上傳至 IPFS, CID: ${ipfsHash}`);
            
        //     // res.status(200).json({
        //     //     success: true,
        //     //     ipfsUrl: `https://ipfs.io/ipfs/${ipfsHash}`,
        //     //     cid: ipfsHash,
        //     //     proof
        //     // });
        // } catch (ipfsError) {
        //     console.error('IPFS 上傳失敗:', ipfsError);
        //     res.status(500).json({ error: 'IPFS 上傳失敗' });
        // }
        // const ipfsTime = performance.now() - ipfsStart;

        res.status(200).json({
            success: true,
            proof,
            journal,
            root_cid,
            merkleRoot,
            componentsAnalyzed: sbomData.components.length,
            time: {
                'sbomServiceTotalDurationMs': sbomData.sbomServiceTotalDurationMs,
                'proveDurationMs': response.data.proveDurationMs,
                // 'ipfsUploadMs': ipfsTime,
                'totalProcessTimeMs': sbomData.sbomServiceTotalDurationMs // + response.data.proveDurationMs + ipfsTime
            },
            // ipfs: ipfsHash ? {
            //     cid: ipfsHash,
            //     url: `https://ipfs.io/ipfs/${ipfsHash}`
            // } : 'failed'
        });

        
    } catch (error: any) {
        console.error('流程錯誤:', error.message);
        res.status(500).json({ success: false, error: '整合流程失敗', details: error.message });
    } finally {
        // 清理 node-api 的暫存檔案
        if (file && fs.existsSync(file.path)) fs.unlinkSync(file.path);
    }

});

app.post('/api/prove', async (req: Request, res: Response) => {
    // 取得 proof 請求資料
    const form = new FormData();
    const { artifactId, treeData } = req.body;

    console.time(`Proving-${artifactId}`); // 實驗數據埋點：開始計時
    try {
        console.log(`[Node] 正在為 ${artifactId} 請求零知識證明...`);

        // 1. 呼叫遠端 Axum Host (Rust)
        const response = await axios.post(`${RUST_PROVER_URL}/prove`, {
            artifactId,
            treeData: treeData
        });

        const merkleRoot = treeData.merkleRoot;

        const { proof, journal, root_cid } = response.data;
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

        // // 連接到 ipfs 並將 proof 上傳到 ipfs
        // let ipfsHash = "";
        // try {
        //     // --- 上傳到 IPFS ---
        //     const { cid } = await ipfs.add(fileContent);
        //     ipfsHash = cid.toString();
        //     console.log(`🚀 Proof 已上傳至 IPFS, CID: ${ipfsHash}`);
        // } catch (ipfsError) {
        //     console.error('IPFS 上傳失敗:', ipfsError);
        //     res.status(500).json({ error: 'IPFS 上傳失敗' });
        // }

        res.status(200).json({
                success: true,
                proof,
                journal,
                root_cid,
                merkleRoot,
                savedAs: fileName,
                time: {
                    'proveDurationMs': response.data.proveDurationMs,
                    'totalProcessTimeMs': response.data.proveDurationMs // 現在只有 proveDurationMs，可擴充
                }
                // ipfs: ipfsHash ? {
                //     cid: ipfsHash,
                //     url: `http://localhost:8080/ipfs/${ipfsHash}`  // 本地 IPFS 網關 URL，適用於私有網絡
                // } : 'failed'
        });
    } catch (error: any) {
        console.error('Prover 錯誤:', error.message);
        res.status(500).json({ success: false, error: 'ZK 運算失敗' });
    }
});

app.listen(3000, () => {
    console.log('✅ Node API 運行在 http://localhost:3000');
});
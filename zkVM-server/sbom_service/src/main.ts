import express, { type Request, type Response } from 'express';
import multer from 'multer';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { SbomProcessor } from './processor.ts';

// 初始化
const app = express();
const upload = multer({ dest: 'uploads/' }); // 暫存檔案目錄
const processor = new SbomProcessor();
const PORT = process.env.PORT || 3002;

app.use(express.json());

/**
 * 主路由：接收 Lockfile/Manifest 並生成 Merkle Tree
 * 使用 upload.single('file') 處理名為 'file' 的上傳欄位
 */
app.post('/generate', upload.single('file'), async (req: Request, res: Response) => {
    const file = req.file;

    if (!file) {
        return res.status(400).json({ success: false, error: '未上傳任何檔案' });
    }

    const tempFilePath = file.path; // Multer 生成的臨時路徑
    const sbomOutputPath = `${tempFilePath}.json`;

    try {
        console.log(`[SBOM Service] 正在處理來自 ${file.originalname} 的 SBOM...`);

        // 1. 執行 Syft 產生 CycloneDX JSON
        // -q: 安靜模式, -o: 輸出格式
        try {
            execSync(`syft ${tempFilePath} -o cyclonedx-json > ${sbomOutputPath}`);
        } catch (syftError: any) {
            console.error('Syft 執行出錯:', syftError.message);
            throw new Error('無法解析該檔案，請確保檔案格式正確 (如 package-lock.json, requirements.txt)');
        }

        // 2. 讀取 Syft 產生的 JSON
        const rawSbom = JSON.parse(fs.readFileSync(sbomOutputPath, 'utf-8'));

        // 3. 使用 Processor 提取過濾後的節點 (Leaves)
        const { leaves, leafInfo } = processor.extractLeaves(rawSbom);

        // 4. 計算 Merkle Tree 並生成 Root 與證明路徑
        const result = processor.buildTree(leaves, leafInfo);

        // 5. 回傳結果
        res.json({
            success: true,
            fileName: file.originalname,
            ...result
        });

    } catch (error: any) {
        console.error('[Error]:', error.message);
        res.status(500).json({
            success: false,
            error: error.message
        });
    } finally {
        // 6. 清理戰場：刪除上傳的檔案與產生的中間 JSON
        [tempFilePath, sbomOutputPath].forEach(p => {
            if (fs.existsSync(p)) fs.unlinkSync(p);
        });
    }
});

app.listen(PORT, () => {
    console.log(`✅ SBOM Generation Service 運行於 http://localhost:${PORT}`);
});
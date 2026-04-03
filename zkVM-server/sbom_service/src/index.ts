import express, { type Request, type Response } from 'express';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import { execSync, exec } from 'child_process';
import { SbomProcessor, type DependencyNode } from './processor.js';
import crypto from 'crypto';
import cron from 'node-cron';

const app = express();
const storage = multer.diskStorage({
    destination: 'uploads/',
    filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage: storage });
const processor = new SbomProcessor();
const PORT = process.env.PORT || 3002;


console.log(`[Init] 正在背景觸發初始 Grype 資料庫更新...`);
exec('grype db update', (error, stdout, stderr) => {
    if (error) {
        console.error(`[Init] 初始 Grype 資料庫更新失敗:`, error.message);
        return;
    }
    console.log(`[Init] 初始 Grype 資料庫更新完成`);
});

// Background task: 每天 a.m 2:00 自動更新 grype 漏洞資料庫
cron.schedule('0 2 * * *', () => {
    console.log(`[Cron] 開始自動更新 Grype 漏洞資料庫... (${new Date().toISOString()})`);
    try {
        execSync('grype db update', { stdio: 'inherit' });
        console.log(`[Cron] Grype 資料庫更新成功！`);
    } catch (error: any) {
        console.error(`[Cron] Grype 資料庫更新失敗:`, error.message);
    }
});

const SEVERITY_RANK: Record<string, number> = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Negligible": 1,
    "Unknown": 0
};

function transformCycloneDXToNodes(rawSbom: any): DependencyNode[] {
    const nodes: DependencyNode[] = [];
    
    // 建立一個 Map 方便快速查找元件資訊
    const componentMap = new Map<string, any>();
    
    // 處理主程式 (metadata.component) 與 所有套件 (components)
    const allComponents = [
        ...(rawSbom.metadata?.component ? [rawSbom.metadata.component] : []),
        ...(rawSbom.components || [])
    ];

    allComponents.forEach(c => {
        // bom-ref 是 CycloneDX 用來串連關係的唯一識別碼
        const ref = c['bom-ref'] || `${c.name}@${c.version}`;
        componentMap.set(ref, c);
    });

    // 2. 遍歷 CycloneDX 的 dependencies 區塊來建立關係
    const dependencyMap = new Map<string, string[]>();
    if (rawSbom.dependencies) {
        rawSbom.dependencies.forEach((dep: any) => {
            dependencyMap.set(dep.ref, dep.dependsOn || []);
        });
    }

    // 3. 組合成你的 DependencyNode 格式
    allComponents.forEach(c => {
        const ref = c['bom-ref'] || `${c.name}@${c.version}`;
        
        // 生成該組件的 Hash (用於後續 Merkle Tree)
        // 這裡建議用 name + version + content 雜湊
        const content = `${c.name}${c.version}${c.purl || ''}`;
        const hash = crypto.createHash('sha256').update(content).digest('hex');

        nodes.push({
            id: ref,
            name: c.name,
            version: c.version,
            hash: hash,
            dependencies: dependencyMap.get(ref) || [], // 取得該節點依賴的所有 ref
        });
    });

    return nodes;
}

app.use(express.json());
// ----------------------------------------

app.post('/generate', upload.single('file'), async (req: Request, res: Response) => {
    const file = req.file;
    const startSbom = performance.now();

    if (!file) return res.status(400).json({ success: false, error: '未上傳任何檔案' });

    // 定義暫存 SBOM 的路徑，供 Grype 讀取
    const tempSbomPath = `${file.path}_sbom.json`;

    try {
        console.log(`\n[SBOM Service] 正在處理 ${file.originalname}...`);

        // 1. 執行 Syft & 進行 grype 漏洞掃描
        console.log(`[Debug] 執行 syft 生成 SBOM...`);
        const command = `syft ${file.path} -o cyclonedx-json`;
        const stdout = execSync(command, { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'], shell: '/bin/bash' });
        const rawSbom = JSON.parse(stdout);
        console.log(`[Debug] syft 完成生成 SBOM`);
        if (!rawSbom.components) rawSbom.components = []; 

        // 處理 SBOM，餵所有的套件補齊唯一 Hash
        rawSbom.components.forEach((c: any) => {
            // 檢查 Syft 是否有算出官方 Hash
            if (c.hashes && c.hashes.length > 0) {
                c.hash = c.hashes[0].content; // 使用官方 SHA-256
            } else {
                // 若沒有 Hash，沿用你之前的邏輯，生成一個強關聯的防篡改 Hash
                const fallbackContent = `${c.name}@${c.version}${c.purl || ''}`; // hash(name | version | purl)
                c.hash = crypto.createHash('sha256').update(fallbackContent).digest('hex');
            }
        });

        console.log(`[Debug] 執行 Grype 漏洞掃描...`);
        fs.writeFileSync(tempSbomPath, stdout); // 將 Syft 結果寫入暫存檔

        // GRYPE_DB_AUTO_UPDATE=false 確保 API 不會因為連網更新而卡住
        // maxBuffer 加大，避免 Grype 輸出的 JSON 太大導致錯誤
        const grypeCommand = `GRYPE_DB_AUTO_UPDATE=false grype sbom:${tempSbomPath} -o json`;
        const grypeStdout = execSync(grypeCommand, { 
            encoding: 'utf-8', 
            shell: '/bin/bash',
            maxBuffer: 50 * 1024 * 1024 // 允許最高 50MB 的輸出
        });

        const grypeResult = JSON.parse(grypeStdout);
        const severityMap = new Map<string, string>(); // 記錄 pkgName -> 最高 Severity

        if (grypeResult.matches) {
            for (const match of grypeResult.matches) {
                const pkgName = match.artifact.name;
                // 注意：Grype 的 severity 首字母可能是大寫 (如 "High")
                const severity = match.vulnerability.severity; 
                
                const currentHighest = severityMap.get(pkgName) || "Unknown";
                
                // 比較嚴重等級，只保留最嚴重的
                if ((SEVERITY_RANK[severity] || 0) > (SEVERITY_RANK[currentHighest] || 0)) {
                    severityMap.set(pkgName, severity);
                }
            }
        }
        console.log(`[Debug] Grype 掃描完成，發現 ${severityMap.size} 個套件含有已知漏洞。`);

        // 2. 核心：解析依賴圖與拓撲排序 (Bottom-Up)
        const { sortedComponents } = processor.analyzeDependencies(rawSbom);
        console.log(`[Debug] 拓撲排序完成，共 ${sortedComponents.length} 個有效節點待處理。`);
        // 將 Grype 的漏洞資訊整合到 sortedComponents 中
        sortedComponents.forEach((c: any) => {
            c.severity = severityMap.get(c.name) || "Unknown";
        });

        // 4. 準備 Merkle Tree 以確保「專案完整性」不被竄改
        // 將所有組件的 Hash 抽出來建立平坦的 Merkle Tree
        const leaves = sortedComponents.map(c => c.hash);
        const leafInfo = sortedComponents.map(c => ({ name: c.name, version: c.version }));

        console.log(`[Debug] 開始建立 Merkle Tree Visual, Leaves 數量: ${leaves.length}`);
        const merkleTreeResult = processor.buildTreeVisual(leaves, leafInfo);
        console.log(`[Debug] Merkle Tree 生成成功，Root: ${merkleTreeResult.merkleRoot}`);

        console.log(`[Debug] 開始建立 Dependency Graph...`);
        const rawNodes = transformCycloneDXToNodes(rawSbom);
        const dependencyDot = processor.buildDependencyGraph(rawNodes);
        console.log(`[Debug] Dependency Graph 生成成功，長度: ${dependencyDot.length}`);

        const outputDir = path.join(process.cwd(), 'output_graphs');
        // console.log(`[Debug] 準備寫入資料夾: ${outputDir}`);
        try {
            if (!fs.existsSync(outputDir)) {
                fs.mkdirSync(outputDir, { recursive: true });
            }

            // 寫入 Merkle Tree
            if (merkleTreeResult.dot) {
                fs.writeFileSync(path.join(outputDir, 'merkle_tree.dot'), merkleTreeResult.dot);
            }
            
            // 寫入 Dependency Tree
            if (dependencyDot) {
                fs.writeFileSync(path.join(outputDir, 'dependency_tree.dot'), dependencyDot);
            }

            console.log(`[Debug] Merkle Tree 與 Dependency Tree 已生成於 ${outputDir}`);
        } catch (ioErr: any) {
            console.error(`[IO Error] 無法寫入檔案: ${ioErr.message}`);
        }
        const totalTime = performance.now() - startSbom;

        res.json({
            success: true,
            fileName: file.originalname,
            merkleRoot: merkleTreeResult.merkleRoot,
            dependencyDot: dependencyDot,
            sortedComponents: sortedComponents,
            totalDurationMs: Math.round(totalTime),
        });

    } catch (error: any) {
        console.error('[Error]:', error.message);
        res.status(500).json({ success: false, error: error.message });
    } finally {
        // 清理暫存檔案
        try {
            // if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
            if (fs.existsSync(tempSbomPath)) fs.unlinkSync(tempSbomPath);
        } catch (cleanupErr) {
            console.error('[Warn] 暫存檔清理失敗:', cleanupErr);
        }
    }
});

app.listen(PORT, () => {
    console.log(`✅ ZK-SBOM Orchestrator 運行於 http://localhost:${PORT}`);
});
import express, { type Request, type Response } from 'express';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import { execSync, exec } from 'child_process';
import { SbomProcessor, type SbomComponent, type MerkleData } from './processor.js';
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

const globalMerkleCache = new Map<string, MerkleData>();

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


// function transformCycloneDXToNodes(rawSbom: any): DependencyNode[] {
//     const nodes: DependencyNode[] = [];

//     // 1. 先處理所有元件，並將其轉換為符合 SbomComponent 介面的物件
//     const rawComponents = [
//         ...(rawSbom.metadata?.component ? [rawSbom.metadata.component] : []),
//         ...(rawSbom.components || [])
//     ];

//     // 建立一個 Lookup Map (Key: ref, Value: SbomComponent)
//     const componentLookup = new Map<string, SbomComponent>();

//     rawComponents.forEach(c => {
//         // 正規化識別碼
//         const ref = c['bom-ref'] || `${c.name}@${c.version}`;

//         // 生成內容 Hash (你的核心識別)
//         const content = `${c.name}${c.version}${c.purl || ''}`;
//         const nodeHash = crypto.createHash('sha256').update(content).digest('hex');

//         // 建立符合介面的物件
//         const component: SbomComponent = {
//             bomRef: ref, // 這裡統一轉成介面的 bomRef
//             name: c.name,
//             version: c.version,
//             hash: nodeHash,
//             type: c.type || 'library',
//             purl: c.purl || '',
//             license: c.licenses?.[0]?.license?.id || 'Unknown',
//             severity: 'Unknown', // 稍後由 severityMap 填入
//         };

//         componentLookup.set(ref, component);
//     });

//     // 2. 取得依賴關係 Map
//     const dependencyMap = new Map<string, string[]>();
//     rawSbom.dependencies?.forEach((dep: any) => {
//         dependencyMap.set(dep.ref, dep.dependsOn || []);
//     });

//     // 3. 產出 DependencyNode (這是給 Graph 用的)
//     // 同時，這些 nodes 裡面的物件引用可以跟 SbomComponent 共用
//     componentLookup.forEach((comp, ref) => {
//         nodes.push({
//             id: comp.bomRef,
//             name: comp.name,
//             version: comp.version,
//             hash: comp.hash,
//             dependencies: dependencyMap.get(ref) || [],
//         });
//     });

//     return nodes;
// }

// function transformCycloneDXToNodes(rawSbom: any): DependencyNode[] {
//     const nodes: DependencyNode[] = [];

//     // 建立一個 Map 方便快速查找元件資訊
//     const componentMap = new Map<string, any>();

//     // 處理主程式 (metadata.component) 與 所有套件 (components)
//     const allComponents = [
//         ...(rawSbom.metadata?.component ? [rawSbom.metadata.component] : []),
//         ...(rawSbom.components || [])
//     ];

//     allComponents.forEach(c => {
//         // bom-ref 是 CycloneDX 用來串連關係的唯一識別碼
//         const ref = c['bom-ref'] || `${c.name}@${c.version}`;
//         componentMap.set(ref, c);
//     });

//     // 2. 遍歷 CycloneDX 的 dependencies 區塊來建立關係
//     const dependencyMap = new Map<string, string[]>();
//     if (rawSbom.dependencies) {
//         rawSbom.dependencies.forEach((dep: any) => {
//             dependencyMap.set(dep.ref, dep.dependsOn || []);
//         });
//     }

//     // 3. 組合成你的 DependencyNode 格式
//     allComponents.forEach(c => {
//         const ref = c['bomRef'] || `${c.name}@${c.version}`;

//         // 生成該組件的 Hash (用於後續 Merkle Tree)
//         // 這裡建議用 name + version + content 雜湊
//         const content = `${c.name}${c.version}${c.purl || ''}`;
//         const hash = crypto.createHash('sha256').update(content).digest('hex');

//         nodes.push({
//             id: ref,
//             name: c.name,
//             version: c.version,
//             hash: hash,
//             dependencies: dependencyMap.get(ref) || [], // 取得該節點依賴的所有 ref
//         });
//     });

//     return nodes;
// }

app.use(express.json());
// ----------------------------------------

app.post('/generate', upload.single('file'), async (req: Request, res: Response) => {
    const file = req.file;
    const startSbom = performance.now();

    if (!file) return res.status(400).json({ success: false, error: '未上傳任何檔案' });

    // 定義暫存 SBOM 的路徑，供 Grype 讀取
    const tempSbomPath = `${file.path}_sbom.json`;

    try {
        // 定義 component 的正規化函式，確保每個 component 都有 bomRef 和 hash
        const normalize = (c: any) => {
            // 優先順序：已經有的 bomRef -> 原始的 bom-ref -> 組合名稱
            c.bomRef = c.bomRef || c['bom-ref'] || `${c.name}@${c.version}`;
            c.bomRef = c.bomRef.trim(); // 修復：去除前後空格
            // 補齊 Hash (如果沒有 hash 欄位)
            if (!c.hash) {
                const content = `${c.name}${c.version}${c.purl || ''}`;
                c.hash = crypto.createHash('sha256').update(content).digest('hex');
            }
        };
        console.log(`\n[SBOM Service] 正在處理 ${file.originalname}...`);
        //

        // 1. 執行 Syft & 進行 grype 漏洞掃描
        console.log(`[Debug] 執行 syft 生成 SBOM...`);
        const command = `syft ${file.path} -o cyclonedx-json`;
        const stdout = execSync(command, { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'], shell: '/bin/bash' });
        const rawSbom = JSON.parse(stdout);
        console.log(`[Debug] syft 完成生成 SBOM`);
        if (!rawSbom.components) rawSbom.components = [];

        // 處理 SBOM，餵所有的套件補齊唯一 Hash, bomRef
        if (rawSbom.metadata?.component) {
            normalize(rawSbom.metadata.component);
        }

        rawSbom.components?.forEach(normalize);

        // 更新 dependencies 中的 ref 以匹配 normalize 後的 bomRef
        const allComponents = [
            ...(rawSbom.metadata?.component ? [rawSbom.metadata.component] : []),
            ...(rawSbom.components || [])
        ];

        const refMap = new Map<string, string>();
        allComponents.forEach(c => {
            const oldRef = c['bom-ref'];
            const newRef = c.bomRef;
            if (oldRef && oldRef !== newRef) {
                refMap.set(oldRef, newRef);
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
        // const { sortedComponents } = processor.analyzeDependencies(rawSbom);
        // console.log(`[Debug] 拓撲排序完成，共 ${sortedComponents.length} 個有效節點待處理。`);


        // 3. 建立 preorder graph
        console.log('[Debug] 開始建立 Preorder Graph...]');
        // console.log('rawSbom.components length:', rawSbom.components?.length);
        // console.log('rawSbom.metadata.component:', rawSbom.metadata?.component);
        // console.log('Before preorderTraversal');
        const { preorderComponents, dependencyMap, componentMap } = processor.preorderTraversal(rawSbom);
        // console.log('After preorderTraversal, preorderComponents length:', preorderComponents.length);
        console.log(`[Debug] Preorder Graph 生成成功，Preorder Components 數量: ${preorderComponents.length}`);
        // 將 Grype 的漏洞資訊整合到 sortedComponents 中
        preorderComponents.forEach((c: any) => {
            c.severity = severityMap.get(c.name) || "Unknown";
        });

        // 4. 準備 Merkle Tree 以確保「專案完整性」不被竄改
        // 將所有組件的 Hash 抽出來建立平坦的 Merkle Tree
        // const leaves = preorderComponents.map(c => c.hash);
        // const leafInfo = preorderComponents.map(c => ({ name: c.name, version: c.version }));

        console.log(`[Debug] 開始為每個 Component 生成獨立的 Merkle Tree...`);
        for (const c of preorderComponents) {
            const componentId = c.bomRef;
            const childrenRefs = dependencyMap.get(componentId) || [];
            const childrenComponents = childrenRefs
                .map(ref => componentMap.get(ref))
                .filter(child => child !== undefined); // 過濾掉找不到的節點
            const childrenHashes = childrenComponents.map(child => child.hash);

            const fingerprint = crypto.createHash('sha256')
                .update([c.hash, ...[...childrenHashes].sort()].join('|'))
                .digest('hex');

            if (globalMerkleCache.has(fingerprint)) {
                const cachedRoot = globalMerkleCache.get(fingerprint)!;
                // 實作 TODO: 即使是快取，也要填入介面規定的 merkleData
                c.merkleData = globalMerkleCache.get(fingerprint);
                // console.log(`[Debug] Component: ${c.name} | 快取命中。`);
                continue;
            }
            const localLeaves = [
                c.hash,
                ...childrenComponents.map(child => child.hash)
            ];
            const localLeafInfo = [
                { name: c.name, version: c.version },
                ...childrenComponents.map(child => ({
                    name: `${child.name} (Dep)`,
                    version: child.version
                }))
            ];

            try {
                const result = processor.buildMerkleTree(localLeaves, localLeafInfo);
                c.merkleData = result;
                globalMerkleCache.set(fingerprint, result);

                // console.log(`[Debug] Component: ${c.name} | Leaves: ${localLeaves.length} | Root: ${c.merkleData.merkleRoot}`);

                // 如果你想存下每個組件的 DOT 圖，可以用 c.id 作為 key
                // c.merkleDot = result.dot; 

            } catch (error) {
                console.error(`[Error] 建立 ${c.name} 的 Merkle Tree 失敗:`, error);
            }
        }
        console.log(`[Debug] 所有組件 Merkle Tree 生成完成且放入 preorderComponents 中，目前 globalMerkleCache 總 row 數: ${globalMerkleCache.size}`);

        console.log(`[Debug] 開始建立 Dependency Graph...`);
        // const rawNodes = transformCycloneDXToNodes(rawSbom);
        const dependencyDot = processor.buildGraphFromComponents(preorderComponents, dependencyMap);
        console.log(`[Debug] Dependency Graph 生成成功，長度: ${dependencyDot.length}`);



        const outputDir = path.join(process.cwd(), 'output_graphs');
        // console.log(`[Debug] 準備寫入資料夾: ${outputDir}`);
        try {
            if (!fs.existsSync(outputDir)) {
                fs.mkdirSync(outputDir, { recursive: true });
            }

            // 寫入 Merkle Tree
            // if (merkleTreeResult.dot) {
            //     fs.writeFileSync(path.join(outputDir, 'merkle_tree.dot'), merkleTreeResult.dot);
            // }

            // 寫入 Dependency Tree
            if (dependencyDot) {
                fs.writeFileSync(path.join(outputDir, 'dependency_tree.dot'), dependencyDot);
            }

            console.log(`[Debug] Dependency Tree 已生成於 ${outputDir}`);
        } catch (ioErr: any) {
            console.error(`[IO Error] 無法寫入檔案: ${ioErr.message}`);
        }
        const totalTime = performance.now() - startSbom;

        res.json({
            success: true,
            fileName: file.originalname,
            // merkleRoot: merkleTreeResult.merkleRoot,
            // dependencyDot: dependencyDot,
            preorderComponents: preorderComponents,
            dependencyMap: Object.fromEntries(dependencyMap),
            componentMap: Object.fromEntries(componentMap),
            totalDurationMs: Math.round(totalTime),
        });

    } catch (error: any) {
        console.error('[Error]:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
    // finally {
    //     // 清理暫存檔案
    //     try {
    //         // if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
    //         if (fs.existsSync(tempSbomPath)) fs.unlinkSync(tempSbomPath);
    //     } catch (cleanupErr) {
    //         console.error('[Warn] 暫存檔清理失敗:', cleanupErr);
    //     }
    // }
});

app.listen(PORT, () => {
    console.log(`✅ ZK-SBOM Orchestrator 運行於 http://localhost:${PORT}`);
});
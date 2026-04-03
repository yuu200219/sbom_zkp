import crypto from 'crypto';

// --- 基礎型別定義 ---
export interface MerklePath {
    pathElements: string[];
    pathIndices: number[]; // 0: Left, 1: Right
}

export interface SbomComponent {
    bomRef: string;
    name: string;
    version: string;
    hash: string;
    type: string;
    purl: string;
    license: string;
    severity: string;
}

export interface DependencyNode {
    id: string;       // 通常是 "name@version"
    name: string;
    version: string;
    hash: string;
    dependencies: string[]; // 存儲子節點的 ID
}

export interface MerkleLeaf{
    name: string;
    version: string;
    hash: string;
    merklePath?: MerklePath;
}

export interface MerkleTreeResult {
    merkleRoot: string;
    components: MerkleLeaf[];
    dot?: string; // 可選的 Merkle Tree 視覺化 DOT 格式
}


/**
 * 處理 SBOM 轉換與 Merkle Tree 計算
 */
export class SbomProcessor {
    private readonly DROP_NAMES = new Set(["pip", "setuptools", "wheel"]);
    private readonly DROP_TYPES = new Set(["file"]);
    private readonly DROP_PURL_PREFIXES = ["file:", "exe:", "generic:"];
    private readonly PADDING_VALUE = '0'.repeat(64);

    // public extractLeaves(sbomJson: any): { leaves: string[], leafInfo: { name: string, version: string }[] } {
    //     const leaves: string[] = [];
    //     const leafInfo: { name: string, version: string }[] = [];

    //     // 修正 1: 如果沒有 components，就當作空陣列，不要報錯
    //     const components = sbomJson.components || [];

    //     for (const comp of components) {
    //         const name = (comp?.name || "").toLowerCase();
    //         const type = (comp?.type || "").toLowerCase();
    //         const purl = (comp?.purl || "").toLowerCase();

    //         if (!name) continue;
    //         if (this.DROP_NAMES.has(name)) continue;
    //         if (type && this.DROP_TYPES.has(type)) continue;
    //         if (this.DROP_PURL_PREFIXES.some(pre => purl.startsWith(pre))) continue;

    //         let targetHash = "";

    //         // 修正 2: 嘗試抓取真實雜湊，如果沒有，就用 name + version 自己算一個
    //         if (comp.hashes && Array.isArray(comp.hashes)) {
    //             const sha256Prop = comp.hashes.find((p: any) => p.alg === 'SHA-256');
    //             if (sha256Prop?.content) {
    //                 targetHash = sha256Prop.content.toString().replace('0x', '').trim();
    //             }
    //         }

    //         // 修正 3: 如果 SBOM 裡沒有雜湊（如 requirements.txt），我們幫它生一個
    //         // 這樣這個套件才能參與 Merkle Tree 的完整性驗證
    //         if (!targetHash) {
    //             const version = comp.version || "unknown";
    //             // 簡單生成一個 sha256 作為葉子節點
    //             targetHash = crypto.createHash('sha256').update(`${name}@${version}`).digest('hex');
    //         }

    //         leaves.push(targetHash);
    //         leafInfo.push({
    //             name: comp.name,
    //             version: comp.version || "unknown"
    //         });
    //     }

    //     // 如果還是空的，給一個 PADDING 作為唯一的葉子，確保 Tree 至少能長出來
    //     if (leaves.length === 0) {
    //         leaves.push(this.PADDING_VALUE);
    //         leafInfo.push({ name: "empty-manifest", version: "0.0.0" });
    //     }

    //     return { leaves, leafInfo };
    // }   
    public analyzeDependencies(sbomJson: any): { 
        sortedComponents: SbomComponent[], 
        componentMap: Map<string, SbomComponent> 
    } {
        const componentsArray = sbomJson.components || [];
        const dependenciesArray = sbomJson.dependencies || [];

        const componentMap = new Map<string, SbomComponent>();
        const validBomRefs = new Set<string>();

        // 1. 萃取並過濾有效組件，確保每個組件都有 Hash
        for (const comp of componentsArray) {
            const name = (comp?.name || "").toLowerCase();
            const type = (comp?.type || "").toLowerCase();
            const purl = (comp?.purl || "").toLowerCase();
            const bomRef = comp['bom-ref'];

            if (!bomRef || !name || this.DROP_NAMES.has(name) || this.DROP_TYPES.has(type) || this.DROP_PURL_PREFIXES.some(pre => purl.startsWith(pre))) {
                continue;
            }

            let targetHash = "";
            if (comp.hashes && Array.isArray(comp.hashes)) {
                const sha256Prop = comp.hashes.find((p: any) => p.alg === 'SHA-256');
                if (sha256Prop?.content) {
                    targetHash = sha256Prop.content.toString().replace('0x', '').trim();
                }
            }
            if (!targetHash) {
                targetHash = crypto.createHash('sha256').update(`${name}@${comp.version || "unknown"}`).digest('hex');
            }

            const validComp: SbomComponent = {
                bomRef, name: comp.name, version: comp.version || "unknown", hash: targetHash, type, purl, license: comp.license || "unknown", severity: comp.severity || "Unknown"
            };
            componentMap.set(bomRef, validComp);
            validBomRefs.add(bomRef);
        }

        // 2. 建立反向依賴圖 (Adjacency List) 用於由下而上的拓撲排序
        // 圖的方向： B -> A (代表 A 依賴 B，所以 B 必須先被證明)
        const adjList = new Map<string, string[]>();
        const inDegree = new Map<string, number>();

        // 初始化圖節點
        for (const ref of validBomRefs) {
            adjList.set(ref, []);
            inDegree.set(ref, 0);
        }

        // 填入邊 (Edges)
        for (const dep of dependenciesArray) {
            const parentRef = dep.ref;
            if (!validBomRefs.has(parentRef)) continue;

            const childrenRefs = dep.dependsOn || [];
            for (const childRef of childrenRefs) {
                if (!validBomRefs.has(childRef)) continue;
                // B (child) -> A (parent)
                adjList.get(childRef)!.push(parentRef);
                inDegree.set(parentRef, inDegree.get(parentRef)! + 1);
            }
        }

        // 3. 拓撲排序 (Kahn's Algorithm)
        const queue: string[] = [];
        const sortedComponents: SbomComponent[] = [];

        // 找出所有入度為 0 的節點 (也就是最底層、不依賴別人的葉子套件)
        for (const [ref, degree] of inDegree.entries()) {
            if (degree === 0) queue.push(ref);
        }

        while (queue.length > 0) {
            const currentRef = queue.shift()!;
            sortedComponents.push(componentMap.get(currentRef)!);

            for (const parentRef of adjList.get(currentRef)!) {
                const currentDegree = inDegree.get(parentRef)! - 1;
                inDegree.set(parentRef, currentDegree);
                if (currentDegree === 0) {
                    queue.push(parentRef);
                }
            }
        }

        // 檢查是否有循環依賴 (防禦機制)
        if (sortedComponents.length !== validBomRefs.size) {
            console.warn("[Warn] SBOM 依賴圖中存在循環依賴或孤立節點，部分組件可能無法正確排序！");
            // 強制把沒排進去的補在最後面
            const sortedRefs = new Set(sortedComponents.map(c => c.bomRef));
            for (const ref of validBomRefs) {
                if (!sortedRefs.has(ref)) sortedComponents.push(componentMap.get(ref)!);
            }
        }

        return { sortedComponents, componentMap };
    }

    public buildDependencyGraph(nodes: DependencyNode[]): string {
        let dot = 'digraph DependencyTree {\n';
        dot += '    node [fontname="Arial", fontsize=10, shape=record];\n';
        dot += '    rankdir=LR;\n'; // 從左到右顯示依賴關係

        nodes.forEach(node => {
            // 定義節點樣式
            dot += `    "${node.id}" [label="{ ${node.name} | ${node.version} }", style=filled, fillcolor="#e1f5fe"];\n`;
            
            // 建立連線：A 依賴於 B (A -> B)
            node.dependencies.forEach(depId => {
                dot += `    "${node.id}" -> "${depId}";\n`;
            });
        });

        dot += '}\n';
        return dot;
    }
    /**
     * 第二步：計算 Merkle Tree 並生成證明路徑
     */
    public buildTree(leaves: string[], leafInfo: { name: string, version: string }[]): MerkleTreeResult {
        const realLeafCount = leaves.length;
        if (realLeafCount === 0) throw new Error("No valid hashes found after filtering");

        // 1. 補齊至 2 的冪次方 (避免 undefined 的核心)
        let nextPowerOf2 = 1;
        while (nextPowerOf2 < realLeafCount) nextPowerOf2 *= 2;
        
        const workingLayer = [...leaves];
        while (workingLayer.length < nextPowerOf2) {
            workingLayer.push(this.PADDING_VALUE);
        }

        const layers: string[][] = [workingLayer];
        let currentLayer = workingLayer;

        // 2. 逐層向上計算
        while (currentLayer.length > 1) {
            const nextLayer: string[] = [];
            for (let i = 0; i < currentLayer.length; i += 2) {
                // 使用非斷言 (!) 或明確檢查，因為我們已經保證了長度是 2 的冪次方
                const left = currentLayer[i]!;
                const right = currentLayer[i + 1]!;
                nextLayer.push(this.sha256(left, right));
            }
            layers.push(nextLayer);
            currentLayer = nextLayer;
        }

        const merkleRoot = currentLayer[0] || this.PADDING_VALUE;

        // 3. 生成 Merkle Path
        const components: MerkleLeaf[] = [];
        for (let i = 0; i < realLeafCount; i++) {
            const pathElements: string[] = [];
            const pathIndices: number[] = [];
            let currentIndex = i;

            for (let L = 0; L < layers.length - 1; L++) {
                const layer = layers[L]!;
                const isRightNode = currentIndex % 2 === 1;
                const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;
                
                // 這裡絕對不會是 undefined，因為補齊了冪次方
                const sibling = layer[siblingIndex]!;
                pathElements.push(sibling);
                pathIndices.push(isRightNode ? 1 : 0);
                
                currentIndex = Math.floor(currentIndex / 2);
            }

            components.push({
                name: leafInfo[i]!.name,
                version: leafInfo[i]!.version,
                hash: leaves[i]!,
                merklePath: {
                    pathElements,
                    pathIndices
                }
            });
        }

        return { merkleRoot, components };
    }

    public buildTreeVisual(leaves: string[], leafInfo: { name: string, version: string }[]): MerkleTreeResult {
        const realLeafCount = leaves.length;
        if (realLeafCount === 0) throw new Error("No valid hashes found after filtering");

        // 輔助函式：縮短 Hash 顯示
        const shortHash = (h: string) => `${h.slice(0, 6)}...${h.slice(-4)}`;
        
        // 1. 補齊至 2 的冪次方
        let nextPowerOf2 = 1;
        while (nextPowerOf2 < realLeafCount) nextPowerOf2 *= 2;
        
        const workingLayer = [...leaves];
        while (workingLayer.length < nextPowerOf2) {
            workingLayer.push(this.PADDING_VALUE);
        }

        // 初始化 DOT 內容
        let dot = 'digraph MerkleTree {\n';
        dot += '    node [fontname="Arial", fontsize=10];\n';
        dot += '    rankdir=BT;\n';

        // 繪製葉子節點 (Layer 0)
        for (let i = 0; i < workingLayer.length; i++) {
            const nodeId = `L0_${i}`;
            const hashLabel = shortHash(workingLayer[i]!);
            if (i < realLeafCount) {
                const info = leafInfo[i]!; 
                const label = `${info.name}\\n${info.version}\\n${hashLabel}`;
                dot += `    "${nodeId}" [label="${label}", shape=box, style=filled, fillcolor="#e6f3ff", color="#0066cc"];\n`;
            } else {
                dot += `    "${nodeId}" [label="Padding\\n${hashLabel}", shape=box, style="dashed,filled", fillcolor="#f0f0f0", fontcolor="#999999"];\n`;
            }
        }

        const layers: string[][] = [workingLayer];
        let currentLayer = workingLayer;
        let layerIdx = 0;

        // 2. 逐層向上計算並生成 DOT Edge
        while (currentLayer.length > 1) {
            const nextLayer: string[] = [];
            for (let i = 0; i < currentLayer.length; i += 2) {
                const left = currentLayer[i]!;
                const right = currentLayer[i + 1]!;
                const parentHash = this.sha256(left, right);
                nextLayer.push(parentHash);

                const parentId = `L${layerIdx + 1}_${i / 2}`;
                const leftChildId = `L${layerIdx}_${i}`;
                const rightChildId = `L${layerIdx}_${i + 1}`;

                // 定義父節點（如果是最後一層則是 Root）
                const isRoot = nextLayer.length === 1 && currentLayer.length === 2;
                if (isRoot) {
                    dot += `    "${parentId}" [label="ROOT\\n${shortHash(parentHash)}", shape=diamond, style=filled, fillcolor="#fff3e6", color="#ff9900", penwidth=2];\n`;
                } else {
                    dot += `    "${parentId}" [label="${shortHash(parentHash)}", shape=box, style=filled, fillcolor="#ffffff", color="#666666"];\n`;
                }

                // 建立連接線
                dot += `    "${leftChildId}" -> "${parentId}";\n`;
                dot += `    "${rightChildId}" -> "${parentId}";\n`;
            }
            layers.push(nextLayer);
            currentLayer = nextLayer;
            layerIdx++;
        }

        dot += '}\n';
        const merkleRoot = currentLayer[0] || this.PADDING_VALUE;

        // 3. 生成 Merkle Path (保持原邏輯)
        const components: MerkleLeaf[] = [];
        for (let i = 0; i < realLeafCount; i++) {
            const pathElements: string[] = [];
            const pathIndices: number[] = [];
            let currentIndex = i;

            for (let L = 0; L < layers.length - 1; L++) {
                const layer = layers[L]!;
                const isRightNode = currentIndex % 2 === 1;
                const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;
                pathElements.push(layer[siblingIndex]!);
                pathIndices.push(isRightNode ? 1 : 0);
                currentIndex = Math.floor(currentIndex / 2);
            }

            components.push({
                name: leafInfo[i]!.name,
                version: leafInfo[i]!.version,
                hash: leaves[i]!,
                merklePath: { pathElements, pathIndices }
            });
        }

        return { merkleRoot, components, dot };
    }

    private sha256(left: string, right: string): string {
        const buffer = Buffer.concat([
            Buffer.from(left, 'hex'),
            Buffer.from(right, 'hex')
        ]);
        return crypto.createHash('sha256').update(buffer).digest('hex');
    }
}
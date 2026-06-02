import crypto from 'crypto';

// --- 基礎型別定義 ---

export interface MerklePath {
    pathElements: string[];
    pathIndices: number[]; // 0: Left, 1: Right
}

export interface MerkleLeaf {
    name: string;
    version: string;
    hash: string;
    merklePath?: MerklePath;
}


export interface MerkleData {
    merkleRoot: string;
    components: MerkleLeaf[];
}

export interface MerkleTreeResult {
    merkleData: MerkleData;
    dot?: string; // 可選的 Merkle Tree 視覺化 DOT 格式
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
    depth: number; // 最深路徑深度
    parent_count: number; // 新增：被依賴的次數 (Fan-in)
    merkleData?: MerkleData;
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
    public preorderTraversal(rawSbom: any, projectNameFromApi?: string, projectVersionFromApi?: string): {
        preorderComponents: SbomComponent[],
        dependencyMap: Map<string, string[]>,
        componentMap: Map<string, SbomComponent>
    } {
        const preorderComponents: SbomComponent[] = [];
        const visited = new Set<string>();
        const getRef = (c: any) => (c.bomRef || c['bom-ref'] || `${c.name}@${c.version}`).trim();

        // 1. 正規化：整合所有組件並建立 Lookup Map
        // 注意：根據最新需求，Lockfile 不再作為獨立組件參與 Graph，
        // 而是由 Virtual Root (Project Root) 直接連接到各個頂層依賴。
        const metadataRoot = rawSbom.metadata?.component;
        const metadataRootRef = metadataRoot ? getRef(metadataRoot) : null;

        const allRaw = [
            // 不再包含 metadataRoot (通常是 lockfile)
            ...(rawSbom.components || []).filter((c: any) => {
                const ref = getRef(c);
                const name = (c.name || "").toLowerCase();
                const type = (c.type || "").toLowerCase();

                // 1. 排除與 metadataRoot 相同的組件 (bom-ref 或名稱匹配)
                if (metadataRootRef && ref === metadataRootRef) return false;
                if (metadataRoot && name === metadataRoot.name.toLowerCase()) return false;

                // 2. 額外排除：類型為 'file' 且附檔名為 .lock 的組件 (Syft 有時會重複列出)
                if (type === 'file' && (name.endsWith('.lock') || name.endsWith('.json'))) return false;

                return true;
            })
        ];

        const componentLookup = new Map<string, SbomComponent>();
        allRaw.forEach(c => {
            const ref = getRef(c);
            let hash = "";
            if (c.hashes && c.hashes.length > 0) {
                hash = c.hashes[0].content;
            } else {
                const content = `${c.name}${c.version}${c.purl || ''}`;
                hash = crypto.createHash('sha256').update(content).digest('hex');
            }

            componentLookup.set(ref, {
                bomRef: ref,
                name: c.name,
                version: c.version,
                hash: hash,
                type: c.type || 'unknown',
                purl: c.purl || '',
                license: c.licenses?.[0]?.license?.id || 'Unknown',
                severity: 'Unknown',
                depth: 0, // 初始化，將在後續計算
                parent_count: 0
            });
        });

        // 2. 建立相依關係 Map，並紀錄所有被依賴過的子節點
        const dependencyMap = new Map<string, string[]>();
        const allChildRefs = new Set<string>();
        rawSbom.dependencies?.forEach((dep: any) => {
            const ref = (dep.ref || "").trim();
            if (!ref) return;

            // 過濾掉自我依賴，並確保 child 在 componentLookup 中
            const children = (dep.dependsOn || [])
                .map((d: string) => d.trim())
                .filter((d: string) => d !== ref);

            dependencyMap.set(ref, children);

            // 注意：如果這個父節點不是 Lockfile，才將其子節點加入 allChildRefs。
            // 這樣一來，原本只被 Lockfile 依賴的套件就會被視為「沒被任何人依賴」，
            // 從而成為 Top-level packages 並接在 Virtual Root 下。
            if (ref !== metadataRootRef) {
                children.forEach((c: string) => allChildRefs.add(c));
            }
        });

        // 3. 建立虛擬根節點 (Virtual Root) 並重新串接依賴關係
        // 現在將所有頂層元件 (Top-level packages) 直接接在 Virtual Root 下
        const virtualRootRef = metadataRootRef || "virtual-root";

        // 嘗試從 metadata 取得專案名稱，如果 metadata 是 file 類型則使用預設名稱
        let projectName = projectNameFromApi || "Project-Root";
        let projectVersion = projectVersionFromApi || "1.0.0";
        if (!projectNameFromApi && metadataRoot && metadataRoot.type !== 'file') {
            projectName = metadataRoot.name;
            projectVersion = metadataRoot.version || "1.0.0";
        }

        // 找出原本 SBOM 中沒被任何人依賴的「頂層套件」(孤立森林的根)
        const topLevelPackageRefs: string[] = [];
        for (const ref of componentLookup.keys()) {
            // 排除虛擬根 (此時尚未加入) 且沒被任何人依賴
            if (ref !== virtualRootRef && !allChildRefs.has(ref)) {
                topLevelPackageRefs.push(ref);
            }
        }

        // 將這些頂層套件接在 Virtual Root 之下
        dependencyMap.set(virtualRootRef, topLevelPackageRefs);

        // 計算虛擬根節點的雜湊，應包含專案資訊與頂層依賴的雜湊，確保唯一性與完整性
        const topLevelHashes = topLevelPackageRefs
            .map(ref => componentLookup.get(ref)?.hash || "")
            .sort()
            .join('|');
        const rootContent = `project:${projectName}:${projectVersion}:${topLevelHashes}`;
        const rootHash = crypto.createHash('sha256').update(rootContent).digest('hex');

        const virtualRoot: SbomComponent = {
            bomRef: virtualRootRef,
            name: projectName,
            version: projectVersion,
            hash: rootHash,
            type: "project",
            purl: "",
            license: "Unknown",
            severity: "Unknown",
            depth: 0, // 初始化，將在後續計算
            parent_count: 0
        };
        componentLookup.set(virtualRootRef, virtualRoot);

        const finalRootRef = virtualRootRef;

        // --- 計算每個組件的最深路徑深度 ---
        const depthMemo = new Map<string, number>();
        const calculateComponentDepth = (ref: string, currentDepth: number): number => {
            const memoizedDepth = depthMemo.get(ref);
            if (memoizedDepth !== undefined && memoizedDepth >= currentDepth) {
                return memoizedDepth;
            }
            depthMemo.set(ref, currentDepth);
            const children = dependencyMap.get(ref) || [];
            let maxSubDepth = currentDepth;
            for (const child of children) {
                maxSubDepth = Math.max(maxSubDepth, calculateComponentDepth(child, currentDepth + 1));
            }
            return maxSubDepth;
        };

        // 從根節點開始計算所有組件的深度
        calculateComponentDepth(finalRootRef, 0);

        // 更新所有組件的深度
        for (const [ref, component] of componentLookup.entries()) {
            component.depth = depthMemo.get(ref) || 0;
        }

        // --- 新增：重平衡依賴圖以避免過大的 Fan-out ---
        // 降低 MAX_CHILDREN 以適應 RISC Zero gRPC 緩衝區限制 (未壓縮的收據體積很大)
        const MAX_CHILDREN = 50;
        const balanceTree = (ref: string) => {
            let children = dependencyMap.get(ref) || [];
            let iteration = 0;

            // 使用 while 迴圈確保即使批次節點超過限制，也會被再次分層 (Batching the batches)
            while (children.length > MAX_CHILDREN) {
                console.log(`[Balance] 節點 ${ref} 子節點過多 (${children.length}), 正在進行第 ${iteration + 1} 層分層...`);
                const batchedChildren: string[] = [];
                for (let i = 0; i < children.length; i += MAX_CHILDREN) {
                    const chunk = children.slice(i, i + MAX_CHILDREN);
                    const batchId = `batch-${ref}-iter${iteration}-${i}`;

                    // 虛擬批次節點的雜湊由其子節點雜湊組合而成
                    const batchContent = chunk.map(cRef => componentLookup.get(cRef)?.hash || "").sort().join('|');
                    const batchHash = crypto.createHash('sha256').update(batchContent).digest('hex');

                    // 批次節點不計算深度，因為它們不是真實組件
                    // 只是為了限制 Fan-out 的虛擬節點
                    const batchNode: SbomComponent = {
                        bomRef: batchId,
                        name: `Batch-L${iteration}-${Math.floor(i / MAX_CHILDREN) + 1}`,
                        version: "1.0.0",
                        hash: batchHash,
                        type: "virtual-batch",
                        purl: "",
                        license: "Unknown",
                        severity: "Unknown",
                        depth: 0,  // 虛擬節點，不計入深度
                        parent_count: 0
                    };

                    componentLookup.set(batchId, batchNode);
                    dependencyMap.set(batchId, chunk);
                    batchedChildren.push(batchId);
                }
                dependencyMap.set(ref, batchedChildren);
                children = batchedChildren; // 進入下一輪 while 檢查
                iteration++;
            }
        };

        // 對所有原始組件進行檢查與平衡
        const originalRefs = Array.from(componentLookup.keys());
        originalRefs.forEach(ref => balanceTree(ref));

        // --- 新增：計算每個組件的 parent_count (Fan-in) ---
        for (const [parentRef, children] of dependencyMap.entries()) {
            for (const childRef of children) {
                const child = componentLookup.get(childRef);
                if (child) {
                    child.parent_count++;
                }
            }
        }

        // 4. 定義前序遞迴 (根 -> 子)
        const traverse = (ref: string) => {
            if (visited.has(ref)) return;

            const comp = componentLookup.get(ref);
            if (comp) {
                visited.add(ref);
                preorderComponents.push(comp);

                const childrenRefs = dependencyMap.get(ref) || [];
                [...childrenRefs].sort().forEach(childRef => traverse(childRef));
            }
        };

        // 5. 從最終根節點開始啟動
        if (finalRootRef) {
            traverse(finalRootRef);
        }

        // 6. 防禦性處理：處理任何仍然孤立的節點
        Array.from(componentLookup.keys()).sort().forEach(ref => {
            if (!visited.has(ref)) {
                traverse(ref);
            }
        });

        this.printTreeStats(finalRootRef, dependencyMap, componentLookup);

        return {
            preorderComponents,
            dependencyMap,
            componentMap: componentLookup
        };
    }

    private printTreeStats(rootRef: string, dependencyMap: Map<string, string[]>, componentMap: Map<string, SbomComponent>) {
        let batchNodes = 0;
        let leafNodes = 0;

        // Use memoization map instead of visited set
        // Key: node ref, Value: maximum depth reached to that node
        const depthMemo = new Map<string, number>();

        const getDepth = (ref: string, currentDepth: number): number => {
            // Check if we've already computed a deeper path to this node
            const memoizedDepth = depthMemo.get(ref);
            if (memoizedDepth !== undefined && memoizedDepth >= currentDepth) {
                // We've already found a deeper or equal path; skip this branch
                // console.log(`[Memo] 已訪問 ${ref}，當前深度 ${currentDepth}，已記錄深度 ${memoizedDepth}，跳過此分支`);
                return memoizedDepth;
            }

            // Update memo with current depth (longest path so far)
            depthMemo.set(ref, currentDepth);
            console.log(`[Traverse] ${ref} (${ref}), depth: ${currentDepth}`);

            const children = dependencyMap.get(ref) || [];

            // Count leaf nodes (nodes with no children)
            if (children.length === 0) {
                leafNodes++;
                return currentDepth;
            }

            // Recurse to all children and track maximum depth
            let maxSubDepth = currentDepth;
            for (const child of children) {
                maxSubDepth = Math.max(maxSubDepth, getDepth(child, currentDepth + 1));
            }
            return maxSubDepth;
        };

        componentMap.forEach(c => {
            if (c.type === 'virtual-batch') batchNodes++;
        });

        const maxDepth = getDepth(rootRef, 0);

        console.log("\n========================================");
        console.log("📊 SBOM Dependency Tree Statistics");
        console.log("----------------------------------------");
        console.log(`- Total Nodes (Inc. Batches): ${componentMap.size}`);
        console.log(`- Virtual Batch Nodes:       ${batchNodes}`);
        console.log(`- Actual Components:         ${componentMap.size - batchNodes}`);
        console.log(`- Leaf Nodes (No Deps):      ${leafNodes}`);
        console.log(`- Tree Max Depth:            ${maxDepth}`);
        console.log("========================================\n");
    }


    // public analyzeDependencies(sbomJson: any): {
    //     sortedComponents: SbomComponent[],
    //     componentMap: Map<string, SbomComponent>
    // } {
    //     const componentsArray = sbomJson.components || [];
    //     const dependenciesArray = sbomJson.dependencies || [];

    //     const componentMap = new Map<string, SbomComponent>();
    //     const validBomRefs = new Set<string>();

    //     // 1. 萃取並過濾有效組件，確保每個組件都有 Hash
    //     for (const comp of componentsArray) {
    //         const name = (comp?.name || "").toLowerCase();
    //         const type = (comp?.type || "").toLowerCase();
    //         const purl = (comp?.purl || "").toLowerCase();
    //         const bomRef = comp['bom-ref'];

    //         if (!bomRef || !name || this.DROP_NAMES.has(name) || this.DROP_TYPES.has(type) || this.DROP_PURL_PREFIXES.some(pre => purl.startsWith(pre))) {
    //             continue;
    //         }

    //         let targetHash = "";
    //         if (comp.hashes && Array.isArray(comp.hashes)) {
    //             const sha256Prop = comp.hashes.find((p: any) => p.alg === 'SHA-256');
    //             if (sha256Prop?.content) {
    //                 targetHash = sha256Prop.content.toString().replace('0x', '').trim();
    //             }
    //         }
    //         if (!targetHash) {
    //             targetHash = crypto.createHash('sha256').update(`${name}@${comp.version || "unknown"}`).digest('hex');
    //         }

    //         const validComp: SbomComponent = {
    //             bomRef, name: comp.name, version: comp.version || "unknown", hash: targetHash, type, purl, license: comp.license || "unknown", severity: comp.severity || "Unknown"
    //         };
    //         componentMap.set(bomRef, validComp);
    //         validBomRefs.add(bomRef);
    //     }

    //     // 2. 建立反向依賴圖 (Adjacency List) 用於由下而上的拓撲排序
    //     // 圖的方向： B -> A (代表 A 依賴 B，所以 B 必須先被證明)
    //     const adjList = new Map<string, string[]>();
    //     const inDegree = new Map<string, number>();

    //     // 初始化圖節點
    //     for (const ref of validBomRefs) {
    //         adjList.set(ref, []);
    //         inDegree.set(ref, 0);
    //     }

    //     // 填入邊 (Edges)
    //     for (const dep of dependenciesArray) {
    //         const parentRef = dep.ref;
    //         if (!validBomRefs.has(parentRef)) continue;

    //         const childrenRefs = dep.dependsOn || [];
    //         for (const childRef of childrenRefs) {
    //             if (!validBomRefs.has(childRef)) continue;
    //             // B (child) -> A (parent)
    //             adjList.get(childRef)!.push(parentRef);
    //             inDegree.set(parentRef, inDegree.get(parentRef)! + 1);
    //         }
    //     }

    //     // 3. 拓撲排序 (Kahn's Algorithm)
    //     const queue: string[] = [];
    //     const sortedComponents: SbomComponent[] = [];

    //     // 找出所有入度為 0 的節點 (也就是最底層、不依賴別人的葉子套件)
    //     for (const [ref, degree] of inDegree.entries()) {
    //         if (degree === 0) queue.push(ref);
    //     }

    //     while (queue.length > 0) {
    //         const currentRef = queue.shift()!;
    //         sortedComponents.push(componentMap.get(currentRef)!);

    //         for (const parentRef of adjList.get(currentRef)!) {
    //             const currentDegree = inDegree.get(parentRef)! - 1;
    //             inDegree.set(parentRef, currentDegree);
    //             if (currentDegree === 0) {
    //                 queue.push(parentRef);
    //             }
    //         }
    //     }

    //     // 檢查是否有循環依賴 (防禦機制)
    //     if (sortedComponents.length !== validBomRefs.size) {
    //         console.warn("[Warn] SBOM 依賴圖中存在循環依賴或孤立節點，部分組件可能無法正確排序！");
    //         // 強制把沒排進去的補在最後面
    //         const sortedRefs = new Set(sortedComponents.map(c => c.bomRef));
    //         for (const ref of validBomRefs) {
    //             if (!sortedRefs.has(ref)) sortedComponents.push(componentMap.get(ref)!);
    //         }
    //     }

    //     return { sortedComponents, componentMap };
    // }

    public buildGraphFromComponents(components: SbomComponent[], dependencyMap: Map<string, string[]>): string {
        let dot = 'digraph DependencyGraph {\n';
        dot += '    node [fontname="Arial", fontsize=10, shape=record];\n';
        dot += '    rankdir=LR;\n';

        components.forEach(c => {
            // 1. 定義節點 (加上 hash 的前 6 碼讓它看起來更專業)
            const shortHash = c.hash.substring(0, 6);
            dot += `    "${c.bomRef}" [label="{ ${c.name} | ${c.version} | ${shortHash} }", style=filled, fillcolor="#e1f5fe"];\n`;

            // 2. 建立連線
            const children = dependencyMap.get(c.bomRef) || [];
            children.forEach(childRef => {
                dot += `    "${c.bomRef}" -> "${childRef}";\n`;
            });
        });

        dot += '}\n';
        return dot;
    }
    /**
     * 第二步：計算 Merkle Tree 並生成證明路徑
     */
    public buildMerkleTree(leaves: string[], leafInfo: { name: string, version: string }[]): MerkleData {
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

        return {
            merkleData: { merkleRoot, components },
            dot
        };
    }

    private sha256(left: string, right: string): string {
        const buffer = Buffer.concat([
            Buffer.from(left, 'hex'),
            Buffer.from(right, 'hex')
        ]);
        return crypto.createHash('sha256').update(buffer).digest('hex');
    }
}
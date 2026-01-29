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

export interface MerkleTreeResult {
    merkleRoot: string;
    components: MerkleLeaf[];
}

/**
 * 處理 SBOM 轉換與 Merkle Tree 計算
 */
export class SbomProcessor {
    private readonly DROP_NAMES = new Set(["pip", "setuptools", "wheel"]);
    private readonly DROP_TYPES = new Set(["file"]);
    private readonly DROP_PURL_PREFIXES = ["file:", "exe:", "generic:"];
    private readonly PADDING_VALUE = '0'.repeat(64);

    /**
     * 第一步：從 Syft JSON 中提取並過濾組件
     */
    public extractLeaves(sbomJson: any): { leaves: string[], leafInfo: { name: string, version: string }[] } {
        const leaves: string[] = [];
        const leafInfo: { name: string, version: string }[] = [];

        if (!sbomJson.components || !Array.isArray(sbomJson.components)) {
            throw new Error("Invalid SBOM format: missing components array");
        }

        for (const comp of sbomJson.components) {
            const name = (comp?.name || "").toLowerCase();
            const type = (comp?.type || "").toLowerCase();
            const purl = (comp?.purl || "").toLowerCase();

            // 過濾邏輯
            if (!name) continue;
            if (this.DROP_NAMES.has(name)) continue;
            if (type && this.DROP_TYPES.has(type)) continue;
            if (this.DROP_PURL_PREFIXES.some(pre => purl.startsWith(pre))) continue;

            if (comp.hashes && Array.isArray(comp.hashes)) {
                const sha256Prop = comp.hashes.find((p: any) => p.alg === 'SHA-256');
                if (sha256Prop && sha256Prop.content) {
                    const cleanHash = sha256Prop.content.toString().replace('0x', '').trim();
                    leaves.push(cleanHash);
                    leafInfo.push({
                        name: comp.name,
                        version: comp.version || "unknown"
                    });
                }
            }
        }

        return { leaves, leafInfo };
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

    private sha256(left: string, right: string): string {
        const buffer = Buffer.concat([
            Buffer.from(left, 'hex'),
            Buffer.from(right, 'hex')
        ]);
        return crypto.createHash('sha256').update(buffer).digest('hex');
    }
}
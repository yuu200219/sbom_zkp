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

export interface SbomComponent {
    bomRef: string;
    name: string;
    version: string;
    hash: string;
    type: string;
    purl: string;
    merkleData?: MerkleData; // 可選的 Merkle Tree 資料
    depth: number; // 可選的深度資訊，方便前端展示樹狀結構
}

export interface SbomServiceResponse {
    components: SbomComponent[];
    dependencyMap?: Map<string, string[]>; // 可選的依賴關係圖
    componentMap?: Map<string, SbomComponent>; // 可選的元件詳細資料圖
    sbomServiceTotalDurationMs: number;
    merkleDot?: string;
    dependencyDot?: string;
}

export interface ProverResponse {
    proof: string;    // Base64 或 Hex 編碼的 Receipt
    journal: string;  // zkVM 輸出的一般資料
}
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
}

export interface SbomServiceResponse {
    components: SbomComponent[];
    sbomServiceTotalDurationMs: number;
    merkleDot?: string;
    dependencyDot?: string;
}

export interface ProverResponse {
    proof: string;    // Base64 或 Hex 編碼的 Receipt
    journal: string;  // zkVM 輸出的一般資料
}
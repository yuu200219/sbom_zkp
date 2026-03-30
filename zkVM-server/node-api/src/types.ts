export interface MerklePath {
    pathElements: string[];
    pathIndices: number[]; // 0 for left, 1 for right
}

export interface SbomComponent {
    bomRef: string;
    name: string;
    version: string;
    hash: string;
    type: string;
    purl: string;
}

export interface SbomServiceResponse {
    merkleRoot: string;
    components: SbomComponent[];
    sbomServiceTotalDurationMs: number;
    merkleDot: string;
    dependencyDot: string;
}

export interface ProverResponse {
    proof: string;    // Base64 或 Hex 編碼的 Receipt
    journal: string;  // zkVM 輸出的一般資料
}
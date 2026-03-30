export interface MerklePath {
    pathElements: string[];
    pathIndices: number[];
}
export interface SbomComponent {
    name: string;
    version: string;
    hash: string;
    merklePath: MerklePath;
}
export interface SbomServiceResponse {
    merkleRoot: string;
    components: SbomComponent[];
    sbomGenerationMs: number;
    dot?: string;
}
export interface ProverResponse {
    proof: string;
    journal: string;
}

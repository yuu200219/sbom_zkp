export interface SbomRequest {
    artifactId: string;
    sbomContent: any; // 這裡可以放入你原本 Rust 專案預期的 JSON 格式
}

export interface ProverResponse {
    proof: string;    // Base64 或 Hex 編碼的 Receipt
    journal: string;  // zkVM 輸出的一般資料
}
use core::MerkleInput; // 確保你的資料結構已定義在某處
use axum::{routing::post, Json, Router, response::IntoResponse, http::StatusCode};
use methods::{GUEST_CODE_FOR_ZKP_ELF, GUEST_CODE_FOR_ZKP_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;

// --- 與 Node.js 對接的請求格式 ---
#[derive(Deserialize)]
struct ProveRequest {
    #[serde(rename = "artifactId")]
    artifact_id: String,
    // 這裡直接接收 Node.js 傳來的 JSON 內容
    #[serde(rename = "treeData")]
    tree_data: Value, 
}

// --- 回傳給 Node.js 的格式 ---
#[derive(Serialize)]
struct ProveResponse {
    proof: String,   // Hex 編碼的 Receipt
    journal: String, // Hex 編碼的 Journal (用於快速驗證)
}

// 輔助函式：Hex 轉換邏輯保持不變
fn decode_hex_32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s.replace("0x", "")).expect("Invalid hex");
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    array
}

// --- Axum Handler: 這裡就是你原本 main 的邏輯 ---
async fn handle_prove(Json(payload): Json<ProveRequest>) -> Result<Json<ProveResponse>, (StatusCode, String)> {
    let tree_data = payload.tree_data;
    
    // 1. 處理 Merkle Leaf (與你原本邏輯一致)
    let mut all_leaf_hashes: Vec<[u8; 32]> = tree_data["components"]
        .as_array()
        .ok_or((StatusCode::BAD_REQUEST, "Invalid components".into()))?
        .iter()
        .map(|c| decode_hex_32(c["hash"].as_str().unwrap()))
        .collect();

    // 2. Padding 至 2 的冪次方
    let mut next_power_of_2 = 1;
    while next_power_of_2 < all_leaf_hashes.len() {
        next_power_of_2 *= 2;
    }
    while all_leaf_hashes.len() < next_power_of_2 {
        all_leaf_hashes.push([0u8; 32]);
    }

    let root = decode_hex_32(tree_data["merkleRoot"].as_str().unwrap());
    let my_input = MerkleInput { root, all_leaf_hashes };

    // 3. 執行 RISC Zero (注意：這是 CPU 密集運算)
    // 在正式環境建議使用 tokio::task::spawn_blocking
    println!("[-] Generating Proof for artifact: {}", payload.artifact_id);
    
    // let env = ExecutorEnv::builder()
    //     .write(&my_input).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    //     .build().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // spawn_blocking 用於避免阻塞異步執行緒
    let prove_result = tokio::task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write(&my_input)
            .expect("Failed to build env inside thread")
            .build()
            .expect("Failed to build env");

        let prover = default_prover();
        prover.prove(env, GUEST_CODE_FOR_ZKP_ELF)
    }).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Thread error: {}", e)))?
      .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Prover error: {}", e)))?;

    let receipt = prove_result.receipt;

    // 4. 序列化 Receipt
    let proof_encoded = hex::encode(bincode::serialize(&receipt).expect("Serialize receipt failed"));
    let journal_encoded = hex::encode(receipt.journal.bytes.clone());

    Ok(Json(ProveResponse {
        proof: proof_encoded,
        journal: journal_encoded,
    }))
}

#[tokio::main]
async fn main() {
    // 初始化日誌
    tracing_subscriber::fmt::init();

    // 建立路由
    let app = Router::new()
        .route("/prove", post(handle_prove));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    println!("🚀 ZK Prover Server (Axum) running on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
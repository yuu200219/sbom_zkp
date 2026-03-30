use core::MerkleInput; // 確保你的資料結構已定義在某處
use axum::{routing::post, Json, Router, response::IntoResponse, http::StatusCode};
use methods::{GUEST_CODE_FOR_ZKP_ELF, GUEST_CODE_FOR_ZKP_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use std::time::Instant;

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
    #[serde(rename = "proveDurationMs")] // 讓 Rust 欄位對應到 Node 的 JSON 鍵名
    prove_duration_ms: u128 
}

// 輔助函式：Hex 轉換邏輯保持不變
fn decode_hex_32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s.replace("0x", "")).expect("Invalid hex");
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    array
}

// --- Axum Handler: 這裡就是你原本 main 的邏輯 ---
// async fn handle_prove(
//     rejection: Result<Json<ProveRequest>, axum::extract::rejection::JsonRejection>
// ) -> impl IntoResponse {
//     match rejection {
//         Ok(Json(payload)) => {
//             // 原本的邏輯放在這裡
//             println!("✅ 收到合法請求: {}", payload.artifact_id);
//             // ... 呼叫你原本的處理代碼 ...
//             (StatusCode::OK, "Success").into_response()
//         }
//         Err(err) => {
//             // 這行非常重要！它會告訴你 Rust 為什麼不爽
//             println!("❌ JSON 解析失敗: {}", err.body_text());
//             (StatusCode::BAD_REQUEST, format!("JSON Error: {}", err.body_text())).into_response()
//         }
//     }
// }
async fn handle_prove(
    rejection: Result<Json<ProveRequest>, axum::extract::rejection::JsonRejection>
) -> impl IntoResponse {
    // 1. 先處理 JSON 解析錯誤 (Rejection)
    let Json(payload) = match rejection {
        Ok(p) => p,
        Err(err) => return (StatusCode::BAD_REQUEST, format!("JSON Error: {}", err.body_text())).into_response(),
    };

    println!("✅ 收到合法請求: {}", payload.artifact_id);
    let start_calc = Instant::now();

    let tree_data: Value = payload.tree_data;
    // println!("[-] Tree Data: {}", tree_data);
    
    // 提取組件陣列
    let components = match tree_data["components"].as_array() {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "Invalid components: missing array").into_response(),
    };

    // 提取 Hash
    let mut all_leaf_hashes: Vec<[u8; 32]> = Vec::new();
    for comp in components {
        if let Some(comp_type) = comp["type"].as_str() {
            // 如果 type 不是 "library"，直接跳過不處理 (排除 "file" 等)
            if comp_type != "library" {
                continue; 
            }
        } else {
            // 如果 JSON 裡這個 component 根本沒有 type 欄位，為了嚴謹也跳過
            continue;
        }
        let h_str = match comp["hash"].as_str() {
            Some(s) => s,
            None => return (StatusCode::BAD_REQUEST, "Missing hash in component").into_response(),
        };
        all_leaf_hashes.push(decode_hex_32(h_str));
    }

    // Padding 邏輯保持不變
    let mut next_power_of_2 = 1;
    while next_power_of_2 < all_leaf_hashes.len() {
        next_power_of_2 *= 2;
    }
    while all_leaf_hashes.len() < next_power_of_2 {
        all_leaf_hashes.push([0u8; 32]);
    }

    // 提取 Merkle Root
    let root_str = match tree_data["merkleRoot"].as_str() {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "Missing merkleRoot").into_response(),
    };
    
    let root = decode_hex_32(root_str);
    let my_input = MerkleInput { root, all_leaf_hashes };

    println!("[-] Generating Proof for artifact: {}", payload.artifact_id);

    // 3. 執行 RISC Zero
    let prove_result = match tokio::task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write(&my_input)
            .expect("Failed to build env inside thread")
            .build()
            .expect("Failed to build env");

        let prover = default_prover();
        prover.prove(env, GUEST_CODE_FOR_ZKP_ELF)
    }).await {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Prover error: {}", e)).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Thread error: {}", e)).into_response(),
    };

    let receipt = prove_result.receipt;

    // 4. 序列化結果並回傳
    let proof_encoded = hex::encode(bincode::serialize(&receipt.inner).expect("Serialize InnerReceipt failed"));
    let journal_encoded = hex::encode(receipt.journal.bytes.clone());
    let proveTime = start_calc.elapsed().as_millis();
    // 這裡直接回傳 Json，它會自動實作 IntoResponse
    Json(ProveResponse {
        proof: proof_encoded,
        journal: journal_encoded,
        prove_duration_ms: proveTime,
    }).into_response()
}
#[tokio::main]
async fn main() {
    let image_id_hex = GUEST_CODE_FOR_ZKP_ID
        .iter()
        .flat_map(|n| n.to_be_bytes()) // 轉為大端序位元組
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    println!("========================================");
    println!("🚀 ZK Prover Server 啟動中...");
    println!("🔑 Current Image ID (Verification Key):");
    println!("0x{}", image_id_hex); // 這串就是下游開發者需要的 vk
    println!("========================================");
    // 初始化日誌
    tracing_subscriber::fmt::init();

    // 建立路由
    let app = Router::new()
        .route("/prove", post(handle_prove));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    println!("✅ ZK Prover Server (Axum)  運行在 {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
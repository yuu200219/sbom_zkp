use shared_data::{ComponentInput, MerkleInput};
use axum::{routing::post, Json, Router, response::IntoResponse, http::StatusCode};
use methods::{GUEST_CODE_FOR_ZKP_ELF, GUEST_CODE_FOR_ZKP_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use std::time::Instant;
use std::collections::HashMap;

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

async fn handle_prove(
    rejection: Result<Json<ProveRequest>, axum::extract::rejection::JsonRejection>
) -> impl IntoResponse {
    let Json(payload) = match rejection {
        Ok(p) => p,
        Err(err) => return (StatusCode::BAD_REQUEST, format!("JSON Error: {}", err.body_text())).into_response(),
    };

    println!("✅ 開始處理遞歸證明任務: {}", payload.artifact_id);
    let start_calc = Instant::now();
    let tree_data = payload.tree_data;

    let components = match tree_data["components"].as_array() {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "Invalid components array").into_response(),
    };

    // 1. 預處理：抽出所有的 Leaf Hash 供 Merkle Tree 使用
    let mut all_leaf_hashes: Vec<[u8; 32]> = Vec::new();
    for comp in components {
        if let Some(h_str) = comp["hash"].as_str() {
            all_leaf_hashes.push(decode_hex_32(h_str));
        }
    }

    let root_str = tree_data["merkleRoot"].as_str().unwrap_or("");
    if root_str.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing merkleRoot").into_response();
    }
    
    // 建立共用的 MerkleInput
    let my_merkle_input = MerkleInput { 
        root: decode_hex_32(root_str), 
        all_leaf_hashes 
    };

    // 2. 建立一個暫存區，用來存放子套件的 Receipt
    // Key: 套件的 Hash (Hex字串), Value: RISC Zero Receipt
    let mut receipt_cache: HashMap<String, Receipt> = HashMap::new();
    let mut final_receipt: Option<Receipt> = None;

    // 3. 依序遍歷 Node.js 傳來的拓撲排序陣列 (由葉子節點到根節點)
    println!("[-] 開始處理套件證明，總套件數: {}", components.len());
    for comp in components {
        // 判別是否存在於 ipfs
        let cached_cid = ipfs_registry.lookup(comp.id);
        // 提取套件本身的資訊
        let comp_name = comp["name"].as_str().unwrap_or("unknown").to_string();
        let comp_hash_str = comp["hash"].as_str().unwrap();
        let comp_hash = decode_hex_32(comp_hash_str);
        
        // 解析這個套件的子依賴 Hash 陣列
        let mut dependency_hashes = Vec::new();
        if let Some(deps) = comp["dependencies"].as_array() {   
            for dep in deps {
                if let Some(dep_hash_str) = dep.as_str() {
                    dependency_hashes.push(decode_hex_32(dep_hash_str));
                }
            }
        }

        let comp_input = ComponentInput {
            name: comp_name.clone(),
            version: comp["version"].as_str().unwrap_or("").to_string(),
            hash: comp_hash,
            license: comp["license"].as_str().unwrap_or("").to_string(),
            severity: comp["severity"].as_str().unwrap_or("").to_string(),
            dependency_hashes: dependency_hashes.clone(),
        };

        println!("[-] 正在證明套件: {}", comp_name);


        // 【關鍵核心】：將子依賴的 Receipt 註冊為 Assumption
        let mut assumptions_to_add = Vec::new();
        for dep_hash in &comp_input.dependency_hashes {
            let dep_hex = hex::encode(dep_hash);
            if let Some(child_receipt) = receipt_cache.get(&dep_hex) {
                // 將已經算好的 Receipt 加入環境，這樣 Guest 的 env::verify 才會通過
                // env_builder.add_assumption(child_receipt.clone());
                assumptions_to_add.push(child_receipt.clone());
            } else {
                return (StatusCode::BAD_REQUEST, format!("Missing receipt for dependency {}", dep_hex)).into_response();
            }
        }

        let comp_input_clone = comp_input.clone();
        let merkle_input_clone = my_merkle_input.clone();
        // 5. 執行證明 (由於在迴圈內，這裡使用 blocking 等待)
        let receipt = match tokio::task::spawn_blocking(move || {
            let mut env_builder = ExecutorEnv::builder();

            // 寫入 Assumption (子節點的收據)
            for child_receipt in assumptions_to_add {
                env_builder.add_assumption(child_receipt);
            }

            // 寫入 Guest 需要的三大變數
            env_builder.write(&comp_input_clone).unwrap();
            env_builder.write(&GUEST_CODE_FOR_ZKP_ID).unwrap();
            env_builder.write(&merkle_input_clone).unwrap(); 

            let env = env_builder.build().unwrap();

            let prover = default_prover();
            prover.prove(env, GUEST_CODE_FOR_ZKP_ELF).map(|res| res.receipt)
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Prover error: {}", e)).into_response(),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Thread error: {}", e)).into_response(),
        };

        // 6. 將算出來的 Receipt 存入 Cache，供未來的父節點使用
        receipt_cache.insert(comp_hash_str.to_string(), receipt.clone());
        
        // 不斷覆寫 final_receipt，迴圈結束時它就會是整棵樹最頂層 (Root) 的收據
        final_receipt = Some(receipt);
        println!("[-] {} 證明完成", comp_name);
        
        // TODO: 輸出 proof 到 IPFS，並將 CID 註冊到 ipfs_registry 中
        // 這個 CID 要回傳給 node.js 這樣他才能在驗證時呼叫 zk-verifier 從 IPFS 下載證明來驗證
    }

    // 7. 取出最頂層的最終證明回傳給前端
    if let Some(receipt) = final_receipt {
        let proof_encoded = hex::encode(bincode::serialize(&receipt.inner).expect("Serialize failed"));
        let journal_encoded = hex::encode(receipt.journal.bytes.clone());
        let prove_duration_ms = start_calc.elapsed().as_millis();

        println!("✅ 遞歸證明完成，總耗時: {} ms", prove_duration_ms);

        Json(ProveResponse {
            proof: proof_encoded,
            journal: journal_encoded,
            prove_duration_ms,
        }).into_response()
    } else {
        (StatusCode::BAD_REQUEST, "No components to prove").into_response()
    }
}
#[tokio::main]
async fn main() {
    let image_id_hex = GUEST_CODE_FOR_ZKP_ID
        .iter()
        .flat_map(|n| n.to_le_bytes()) // 轉為大端序位元組
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    println!("========================================");
    println!("🚀 ZK Recursive Prover Server 啟動中...");
    println!("🔑 Current Image ID (Verification Key):");
    println!("0x{}", image_id_hex); // 這串就是下游開發者需要的 vk
    println!("========================================");
    // 初始化日誌
    tracing_subscriber::fmt::init();

    // 建立路由
    let app = Router::new()
        .route("/prove", post(handle_prove));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    println!("✅ ZK Recursive Prover Server (Axum)  運行在 {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
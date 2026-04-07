use shared_data::{ComponentInput, MerkleInput};
use axum::{routing::post, Json, Router, response::IntoResponse, http::StatusCode};
use methods::{GUEST_CODE_FOR_ZKP_ELF, GUEST_CODE_FOR_ZKP_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use std::time::Instant;
use std::collections::HashMap;
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient};
use std::sync::{Arc, RwLock};
use axum::extract::State;

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
    prove_duration_ms: u128,
    #[serde(rename = "rootCid")]
    root_cid: Option<String>, // 根節點的 IPFS CID
}

struct CompState {
    // RwLock 永許多個 trheads 同時讀取，但是只有一個可以寫入
    ipfs_map: RwLock<HashMap<String, String>>,
}


// #[derive(Clone)]
// struct IpfsRegistry {
//     map: HashMap<String, String>, // comp_hash -> cid
// }

// impl IpfsRegistry {
//     fn new() -> Self {
//         Self { map: HashMap::new() }        
//     }

//     fn lookup(&self, key: &str) -> Option<&String> {
//         self.map.get(key)
//     }

//     fn register(&mut self, key: String, cid: String) {
//         self.map.insert(key, cid);
//     }
// }

#[derive(Serialize, Deserialize)]
struct StoredProof {
    receipt: Receipt,
    image_id: [u32; 8],
}

// 輔助函式：Hex 轉換邏輯保持不變
fn decode_hex_32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s.replace("0x", "")).expect("Invalid hex");
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    array
}

async fn handle_prove(
    State(state): State<Arc<CompState>>,
    Json(payload): Json<ProveRequest> 
) -> axum::response::Response { // 修正 1: 明確回傳 Response 類型

    println!("✅ 開始處理遞歸證明任務: {}", payload.artifact_id);
    let start_calc = Instant::now();
    let tree_data = payload.tree_data;

    // let mut ipfs_registry = IpfsRegistry::new();
    // let mut ipfs_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    // let ipfs_client = IpfsClient::default();

    // 修正 2: 明確標註 components 為 &Vec<Value>，避免推導錯誤
    let components: &Vec<Value> = match tree_data["components"].as_array() {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "Invalid components array").into_response(),
    };

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
    
    let my_merkle_input = MerkleInput { 
        root: decode_hex_32(root_str), 
        all_leaf_hashes 
    };

    let mut receipt_cache: HashMap<String, Receipt> = HashMap::new();
    let mut final_receipt: Option<Receipt> = None;
    let mut root_cid: Option<String> = None;

    println!("[-] 開始處理套件證明，總套件數: {}", components.len());
    for comp in components {
        let comp_hash_str = match comp["hash"].as_str() {
            Some(s) => s,
            None => return (StatusCode::BAD_REQUEST, "Component hash missing").into_response(),
        };

        let cached_cid = {
            let map = state.ipfs_map.read().unwrap();
            map.get(comp_hash_str).cloned() // cloned 轉成 String 帶出作用域
        };

        let comp_name = comp["name"].as_str().unwrap_or("unknown").to_string();
        let comp_hash = decode_hex_32(comp_hash_str);
        
        if let Some(cid) = cached_cid {
            let cid_clone = cid.clone();
            // let receipt_stream = client.cat(cached_cid);
            // // 修正 4: 處理 Bytes 到 Vec<u8> 的收集
            // let chunks: Vec<risc0_zkvm::Bytes> = match receipt_stream.try_collect().await {
            //     Ok(data) => data,
            //     Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("IPFS cat error: {}", e)).into_response(),
            // };
            // let receipt_data: Vec<u8> = chunks.into_iter().flat_map(|b| b.to_vec()).collect();

            let receipt_data = tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                    
                rt.block_on(async {
                    let client = IpfsClient::default();
                    let mut stream = client.cat(&cid_clone);
                    let mut data = Vec::new();
                    use futures::StreamExt;
                    while let Some(chunk) = stream.next().await {
                        data.extend_from_slice(&chunk.unwrap());
                    }
                    data
                })
            }).await.unwrap();
            
            let stored_proof: StoredProof = match bincode::deserialize(&receipt_data) {
                Ok(sp) => sp,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Deserialize error: {}", e)).into_response(),
            };
            // 修正 5: 移除 &，直接傳入值
            if let Err(e) = stored_proof.receipt.verify(stored_proof.image_id) {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("Verify error: {}", e)).into_response();
            }
            receipt_cache.insert(comp_hash_str.to_string(), stored_proof.receipt.clone());
            final_receipt = Some(stored_proof.receipt);
            root_cid = Some(cid.to_string());
            println!("[-] {} 從 IPFS 驗證完成", comp_name);
            continue; 
        } else {
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

            let mut assumptions_to_add = Vec::new();
            for dep_hash in &comp_input.dependency_hashes {
                let dep_hex = hex::encode(dep_hash);
                if let Some(child_receipt) = receipt_cache.get(&dep_hex) {
                    assumptions_to_add.push(child_receipt.clone());
                } else {
                    return (StatusCode::BAD_REQUEST, format!("Missing receipt for dependency {}", dep_hex)).into_response();
                }
            }

            let comp_input_clone = comp_input.clone();
            let merkle_input_clone = my_merkle_input.clone();
            
            let receipt = match tokio::task::spawn_blocking(move || {
                let mut env_builder = ExecutorEnv::builder();
                for child_receipt in assumptions_to_add {
                    env_builder.add_assumption(child_receipt);
                }
                env_builder.write(&comp_input_clone).unwrap();
                env_builder.write(&GUEST_CODE_FOR_ZKP_ID).unwrap();
                env_builder.write(&merkle_input_clone).unwrap(); 

                let env = env_builder.build().unwrap();
                default_prover().prove(env, GUEST_CODE_FOR_ZKP_ELF).map(|res| res.receipt)
            }).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Prover error: {}", e)).into_response(),
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Thread error: {}", e)).into_response(),
            };

            let stored_proof = StoredProof {
                receipt: receipt.clone(),
                image_id: GUEST_CODE_FOR_ZKP_ID,
            };
            let receipt_data = bincode::serialize(&stored_proof).unwrap();
            let receipt_data_clone = receipt_data.clone(); // 這是 bincode 序列化後的 Vec<u8>
            let cid = tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                    
                rt.block_on(async {
                    let client = IpfsClient::default();
                    let res = client.add(std::io::Cursor::new(receipt_data_clone)).await.unwrap();
                    res.hash
                })
            }).await.unwrap();
            // 修正 6: 處理 IPFS Add 的非同步調用
            // let add_response = match client.add(Cursor::new(receipt_data)).await {
            //     Ok(res) => res,
            //     Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("IPFS add error: {}", e)).into_response(),
            // };

            // let cid = add_response.hash;
            receipt_cache.insert(comp_hash_str.to_string(), receipt.clone());
            final_receipt = Some(receipt);
            root_cid = Some(cid.clone());

            // ipfs_registry.register(comp_hash_str.to_string(), cid);
            // ipfs_map.insert(comp_hash_str.to_string(), cid);
            // 取得寫入鎻，更新 global map
            {
                let mut map = state.ipfs_map.write().unwrap();
                map.insert(comp_hash_str.to_string(), cid);
            }
            println!("[-] {} 證明完成並上傳到 IPFS", comp_name);
        }
    }

    if let Some(receipt) = final_receipt {
        let proof_encoded = hex::encode(bincode::serialize(&receipt.inner).expect("Serialize failed"));
        let journal_encoded = hex::encode(receipt.journal.bytes.clone());
        let prove_duration_ms = start_calc.elapsed().as_millis();

        println!("✅ 遞歸證明完成，總耗時: {} ms", prove_duration_ms);
        println!("CID: {}", root_cid.as_deref().unwrap_or("None"));

        Json(ProveResponse {
            proof: proof_encoded,
            journal: journal_encoded,
            prove_duration_ms,
            root_cid,
        }).into_response()
    } else {
        (StatusCode::BAD_REQUEST, "No components to prove").into_response()
    }
}


#[tokio::main]
async fn main() {

    let shared_state = Arc::new(CompState {
        ipfs_map: RwLock::new(HashMap::new()),
    });

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
        .route("/prove", post(handle_prove))
        .with_state(shared_state); //  注入狀態

    // let app = Router::new()
    // .route("/prove", post(|payload: Json<ProveRequest>| async move {
    //     handle_prove(payload).await
    // }));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    println!("✅ ZK Recursive Prover Server (Axum)  運行在 {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
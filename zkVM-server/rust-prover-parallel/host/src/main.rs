use shared_data::{ComponentInput, MerkleInput};
use axum::{routing::post, Json, Router, response::IntoResponse, http::StatusCode};
use methods::{GUEST_CODE_FOR_ZKP_ELF, GUEST_CODE_FOR_ZKP_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use std::time::Instant;
use std::collections::HashMap;
// use ipfs_api_backend_hyper::{IpfsApi, IpfsClient};
use reqwest::{Client, multipart};
use std::sync::{Arc, RwLock};
use axum::extract::{State, DefaultBodyLimit};
use async_recursion::async_recursion;

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

#[derive(Serialize, Deserialize)]
struct StoredProof {
    receipt: Receipt,
    image_id: [u32; 8],
}

struct CompState {
    // RwLock 允許多個 threads 同時讀取，但是只有一個可以寫入
    ipfs_map: RwLock<HashMap<String, String>>, // 以 component hash 為 key，IPFS CID 為 value 
}

// 輔助函式：Hex 轉換邏輯保持不變
fn decode_hex_32(s: &str) -> [u8; 32] {
    let clean_s = s.replace("0x", "");
    let bytes = hex::decode(&clean_s).expect("Invalid hex");
    let mut array = [0u8; 32];
    
    if bytes.len() == 32 {
        array.copy_from_slice(&bytes);
    } else if bytes.len() < 32 {
        // 如果不足 32 bytes，在前面補 0 (常見於 Ethereum address 轉 32 bytes word)
        let offset = 32 - bytes.len();
        array[offset..].copy_from_slice(&bytes);
        println!("[Warning] Hex string is only {} bytes, padded with zeros: {}", bytes.len(), s);
    } else {
        // 如果超過 32 bytes，則截斷
        array.copy_from_slice(&bytes[..32]);
        println!("[Warning] Hex string is {} bytes, truncated to 32 bytes: {}", bytes.len(), s);
    }
    array
}

async fn run_risc0_prover(
    comp_input: ComponentInput,
    merkle_input: MerkleInput,
    assumptions: Vec<Receipt>,
) -> Result<Receipt, (StatusCode, String)> {
    
    // 使用 spawn_blocking 因為 ZK 證明是 CPU 密集型任務，避免阻塞 Tokio Runtime
    let receipt = tokio::task::spawn_blocking(move || {
        let mut env_builder = ExecutorEnv::builder();

        // 1. 添加遞迴假設：讓 Guest 知道這些子節點已經被證明過了
        for child_receipt in assumptions {
            env_builder.add_assumption(child_receipt);
        }

        // 2. 寫入當前組件的私有輸入
        env_builder.write(&comp_input).unwrap();
        
        // 3. 寫入 Guest Code ID (用於內部 verify) 與 Merkle 驗證資料
        env_builder.write(&GUEST_CODE_FOR_ZKP_ID).unwrap();
        env_builder.write(&merkle_input).unwrap(); 

        let env = env_builder.build().unwrap();

        // 4. 呼叫你原本使用的 Prover
        default_prover()
            .prove(env, GUEST_CODE_FOR_ZKP_ELF)
            .map(|res| res.receipt)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Thread error: {}", e)))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Prover error: {}", e)))?;

    Ok(receipt)
}

async fn download_and_verify_receipt(cid: &str) -> Result<Receipt, (StatusCode, String)> {
    // 因為 ipfs-api 相關套件已經太老，前幾天 cores2 yanked 所以這個套件已經不行用了
    // 由於 ipfs-api 是基於 RUST API 去實作的，所以可以透過 reqwest 直接對 IPFS HTTP API 進行請求來實現下載功能
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:5001/api/v0/cat?arg={}", cid);

    let response = client.post(&url)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("IPFS cat connection error: {}", e)))?;
    
    if !response.status().is_success() {
        return Err((StatusCode::NOT_FOUND, format!("IPFS cat failed with status: {}", response.status())));
    }

    let receipt_data = response.bytes().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read IPFS data: {}", e)))?;

    if receipt_data.is_empty() {
        return Err((StatusCode::NOT_FOUND, "IPFS data is empty".to_string()));
    }

    // 2. 反序列化
    let stored_proof: StoredProof = bincode::deserialize(&receipt_data)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Deserialize error: {}", e)))?;

    // 3. 執行你原本的 Verify 邏輯
    // 這是確保遞迴安全性的關鍵：父節點只信任通過驗證的子收據
    if let Err(e) = stored_proof.receipt.verify(stored_proof.image_id) {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Verify error: {}", e)));
    }

    Ok(stored_proof.receipt)
}

async fn upload_receipt_to_ipfs(receipt: &Receipt) -> Result<String, (StatusCode, String)> {
    let stored_proof = StoredProof {
        receipt: receipt.clone(),
        image_id: GUEST_CODE_FOR_ZKP_ID,
    };
    
    let receipt_data = bincode::serialize(&stored_proof).unwrap();
    let client = reqwest::Client::new();
    let url = "http://127.0.0.1:5001/api/v0/add";

    let part = reqwest::multipart::Part::bytes(receipt_data)
        .file_name("receipt.bin");
    let form = reqwest::multipart::Form::new().part("file", part);
    
    let response = client.post(url)
        .multipart(form)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("IPFS upload connection error: {}", e)))?;

    let res_json: serde_json::Value = response.json().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to parse IPFS response: {}", e)))?;

    let cid = res_json["Hash"].as_str()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "No Hash found in IPFS response".to_string()))?
        .to_string();
    
    println!("[-] 證明上傳到 IPFS, CID: {}", cid);
    Ok(cid)
}

#[async_recursion]
async fn prove_component_recursive(
    comp_id: String, // 使用 bomRef 作為 key
    state: Arc<CompState>,
    tree_data: &Value,
    receipt_cache: &mut HashMap<String, Receipt>,
) -> Result<Receipt, (StatusCode, String)> {
    
    // 1. 取得組件詳細資料
    // println!("[Debug] tree_data keys: {:?}", tree_data.as_object().map(|m| m.keys().collect::<Vec<_>>()));
    
    let component_map = tree_data["componentMap"]
        .as_object()
        .ok_or((StatusCode::BAD_REQUEST, "componentMap is missing or not an object".to_string()))?;

    // println!("[Debug] comp_id = {:?}", comp_id);
    // println!("[Debug] component_map len = {}", component_map.len());
    // println!("[Debug] contains_key = {}", component_map.contains_key(&comp_id));
    // println!("[Debug] get = {:?}", component_map.get(&comp_id));

    let comp = component_map
        .get(&comp_id)
        .ok_or({
            let err_msg = format!("Component {} not found in componentMap", comp_id);
            println!("[Error] {}", err_msg); // 直接印出來
            (StatusCode::BAD_REQUEST, err_msg)
        })?;
    
    let comp_hash_str = comp["hash"].as_str().unwrap();
    let comp_name = comp["name"].as_str().unwrap_or("unknown");

    // 2. 檢查快取 (本輪任務快取或 IPFS 全域快取)
    if let Some(r) = receipt_cache.get(comp_hash_str) {
        return Ok(r.clone());
    }

    let cached_cid = {
        let map = state.ipfs_map.read().unwrap();
        map.get(comp_hash_str).cloned()
    };

    if let Some(cid) = cached_cid {
        println!("[-] {} 命中 IPFS 快取, CID: {}", comp_name, cid);
        let receipt = download_and_verify_receipt(&cid).await?;
        receipt_cache.insert(comp_hash_str.to_string(), receipt.clone());
        return Ok(receipt);
    }
    // 如果存在於快取，就直接 return receipt 否則就繼續進入到 recursive proof

    // 3. recursive proof for dependencies
    let mut assumptions_to_add = Vec::new();
    let mut children_hashes = Vec::new();

    if let Some(deps) = tree_data["dependencyMap"].get(&comp_id).and_then(|v| v.as_array()) {
        for dep_id_value in deps {
            let dep_id = dep_id_value.as_str().unwrap().to_string();
            
            // --- 遞迴呼叫：先證明兒子 ---
            let child_receipt = prove_component_recursive(
                dep_id.clone(), 
                state.clone(), 
                tree_data, 
                receipt_cache, 
            ).await?;
            
            assumptions_to_add.push(child_receipt);
            
            // 取得兒子的 hash 放入 input (ZK Guest 需要)
            let child_hash_str = tree_data["componentMap"][&dep_id]["hash"].as_str().unwrap();
            children_hashes.push(decode_hex_32(child_hash_str));
        }
    }

    // 4. 執行 Risc0 證明 (當前節點)
    let mut local_leaves = vec![decode_hex_32(comp_hash_str)];
    local_leaves.extend(children_hashes.clone());

    let local_merkle_root = comp["merkleData"]["merkleRoot"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, format!("Component {} missing merkleRoot", comp_name)))?;

    let local_merkle_input = MerkleInput {
        root: decode_hex_32(local_merkle_root),
        all_leaf_hashes: local_leaves,
    };

    let comp_input = ComponentInput {
        name: comp_name.to_string(),
        version: comp["version"].as_str().unwrap_or("").to_string(),
        hash: decode_hex_32(comp_hash_str),
        license: comp["license"].as_str().unwrap_or("").to_string(),
        severity: comp["severity"].as_str().unwrap_or("").to_string(),
        dependency_hashes: children_hashes,
    };

    println!("[-] 正在證明套件: {}", comp_name);
    let receipt = run_risc0_prover(comp_input, local_merkle_input.clone(), assumptions_to_add).await?;

    // 5. 上傳至 IPFS 並更新快取
    let cid = upload_receipt_to_ipfs(&receipt).await?;
    {
        let mut map = state.ipfs_map.write().unwrap();
        map.insert(comp_hash_str.to_string(), cid);
    }
    receipt_cache.insert(comp_hash_str.to_string(), receipt.clone());

    Ok(receipt)
}

async fn handle_prove(
    State(state): State<Arc<CompState>>,
    Json(payload): Json<ProveRequest> 
) -> axum::response::Response {
    // println!("[Debug] Received Tree Data Keys: {:?}", payload.tree_data.as_object().unwrap().keys());
    println!("✅ 開始遞迴證明任務: {}", payload.artifact_id);
    
    let start_calc = Instant::now();
    let tree_data = payload.tree_data;

    let components = match tree_data["components"].as_array() {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "Missing 'components' array").into_response(),
    };

    if components.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty components array").into_response();
    }

    let root_id = match components[0]["bomRef"].as_str() {
        Some(id) => id.to_string(),
        None => return (StatusCode::BAD_REQUEST, "Root component missing 'bomRef'").into_response(),
    };

    let start_node_id = root_id.clone();

    println!("[-] 起始證明節點: {}", start_node_id);

    let mut receipt_cache = HashMap::new();

    // 啟動遞迴證明 (從 lockfile 開始)
    match prove_component_recursive(start_node_id.clone(), state.clone(), &tree_data, &mut receipt_cache).await {
        Ok(final_receipt) => {
            let prove_duration_ms = start_calc.elapsed().as_millis();
            
            // 取得該起始節點的 hash 與 CID
            let start_node_hash_str = match tree_data["componentMap"].get(&start_node_id).and_then(|n| n["hash"].as_str()) {
                Some(h) => h,
                None => return (StatusCode::INTERNAL_SERVER_ERROR, "Start node hash missing or node not found").into_response(),
            };

            let root_cid = state.ipfs_map.read().unwrap().get(start_node_hash_str).cloned();

            println!("✅ 遞迴證明完成，總耗時: {} ms", prove_duration_ms);

            Json(ProveResponse {
                proof: hex::encode(bincode::serialize(&final_receipt.inner).unwrap()),
                journal: hex::encode(final_receipt.journal.bytes),
                prove_duration_ms,
                root_cid,
            }).into_response()
        },
        Err((status, msg)) => {
            eprintln!("[Error] 遞迴證明失敗: {} - {}", status, msg);
            (status, msg).into_response()
        }
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
        .layer(DefaultBodyLimit::disable())
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
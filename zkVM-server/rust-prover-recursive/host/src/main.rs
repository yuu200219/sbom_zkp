use shared_data::{ComponentInput, MerkleInput, Severity};
use axum::{routing::post, Json, Router, response::IntoResponse, http::StatusCode, extract::State, extract::DefaultBodyLimit};
use methods::{GUEST_CODE_FOR_ZKP_ELF, GUEST_CODE_FOR_ZKP_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use std::time::Instant;
use std::collections::HashMap;
use reqwest;
use std::sync::{Arc, RwLock};
use tokio::sync::Semaphore;
use async_recursion::async_recursion
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Deserialize)]
struct ProveRequest {
    #[serde(rename = "artifactId")]
    artifact_id: String,
    #[serde(rename = "treeData")]
    tree_data: Value, 
}

#[derive(Serialize)]
struct ProveResponse {
    proof: String,
    journal: String,
    #[serde(rename = "proveDurationMs")]
    prove_duration_ms: u128,
    #[serde(rename = "rootCid")]
    root_cid: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredProof {
    receipt: Receipt,
    image_id: [u32; 8],
}

struct CompState {
    ipfs_map: RwLock<HashMap<String, String>>,
    compress_semaphore: Arc<Semaphore>,
    prove_semaphore: Arc<Semaphore>,
}

fn decode_hex_32(s: &str) -> [u8; 32] {
    let clean_s = s.replace("0x", "");
    let bytes = hex::decode(&clean_s).expect("Invalid hex");
    let mut array = [0u8; 32];
    if bytes.len() == 32 {
        array.copy_from_slice(&bytes);
    } else if bytes.len() < 32 {
        let offset = 32 - bytes.len();
        array[offset..].copy_from_slice(&bytes);
    } else {
        array.copy_from_slice(&bytes[..32]);
    }
    array
}

fn map_severity(s: &str) -> Severity {
    match s {
        "Negligible" => Severity::Negligible,
        "Low" => Severity::Low,
        "Medium" => Severity::Medium,
        "High" => Severity::High,
        "Critical" => Severity::Critical,
        _ => Severity::Unknown,
    }
}

async fn run_risc0_prover(
    state: Arc<CompState>, // 傳入 state 以使用 semaphore
    comp_input: ComponentInput,
    merkle_input: MerkleInput,
    assumptions: Vec<Receipt>,
) -> Result<Receipt, (StatusCode, String)> {

    let _permit = if comp_input.comp_type == "virtual-batch" {
        state.compress_semaphore.acquire().await.unwrap()
    } else {
        state.prove_semaphore.acquire().await.unwrap()
    };

    let receipt = tokio::task::spawn_blocking(move || {
        let mut env_builder = ExecutorEnv::builder();
        for child_receipt in assumptions {
            env_builder.add_assumption(child_receipt);
        }
        env_builder.write(&comp_input).unwrap();
        env_builder.write(&GUEST_CODE_FOR_ZKP_ID).unwrap();
        env_builder.write(&merkle_input).unwrap(); 

        let env = env_builder.build().unwrap();
        let prover = default_prover();
        let prove_info = prover.prove(env, GUEST_CODE_FOR_ZKP_ELF)
            .map_err(|e| format!("Prover prove failed: {}", e))?;

        if comp_input.comp_type == "virtual-batch" {
            println!("[-] 聚合節點 ({})，執行證明壓縮...", comp_input.name);
            prover.compress(&risc0_zkvm::ProverOpts::succinct(), &prove_info.receipt)
                .map_err(|e| format!("Prover compression failed: {}", e))
        } else {
            Ok(prove_info.receipt)
        }
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Thread error: {}", e)))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Prover error: {}", e)))?;

    Ok(receipt)
}

async fn download_and_verify_receipt(cid: &str) -> Result<Receipt, (StatusCode, String)> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:5001/api/v0/cat?arg={}", cid);
    let response = client.post(&url).send().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("IPFS cat error: {}", e)))?;
    
    if !response.status().is_success() {
        return Err((StatusCode::NOT_FOUND, format!("IPFS cat failed: {}", response.status())));
    }

    let receipt_data = response.bytes().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read IPFS data: {}", e)))?;

    let stored_proof: StoredProof = bincode::deserialize(&receipt_data)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Deserialize error: {}", e)))?;

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

    let part = reqwest::multipart::Part::bytes(receipt_data).file_name("receipt.bin");
    let form = reqwest::multipart::Form::new().part("file", part);
    
    let response = client.post(url).multipart(form).send().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("IPFS upload error: {}", e)))?;

    let res_json: serde_json::Value = response.json().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to parse IPFS response: {}", e)))?;

    let cid = res_json["Hash"].as_str()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "No Hash found".to_string()))?.to_string();
    
    println!("[-] 證明上傳至 IPFS, CID: {}", cid);
    Ok(cid)
}

#[async_recursion]
async fn prove_component_recursive(
    comp_id: String,
    state: Arc<CompState>,
    tree_data: &Value,
    receipt_cache: &mut HashMap<String, Receipt>,
    pb: ProgressBar,
) -> Result<Receipt, (StatusCode, String)> {
    let component_map = tree_data["componentMap"].as_object()
        .ok_or((StatusCode::BAD_REQUEST, "componentMap missing".to_string()))?;

    let comp = component_map.get(&comp_id).ok_or((StatusCode::BAD_REQUEST, format!("Component {} not found", comp_id)))?;
    let comp_hash_str = comp["hash"].as_str().unwrap().to_string();
    let comp_name = comp["name"].as_str().unwrap_or("unknown");

    if let Some(r) = receipt_cache.get(&comp_hash_str) {
        pb.inc(1);
        return Ok(r.clone());
    }

    // checking lock and status
    loop {
        let current_status = {
            let map = state.ipfs_map.read().unwrap();
            map.get(&comp_hash_str).cloned()
        };

        if let Some(status) = current_status {
            if status == "PROCESSING" {
                // 如果別人在做了，我們就等一下再檢查，不要啟動新任務
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue; 
            } else {
                // 已完成，下載並回傳
                let receipt = download_and_verify_receipt(&status).await?;
                receipt_cache.insert(comp_hash_str.clone(), receipt.clone());
                pb.inc(1);
                return Ok(receipt);
            }
        } else {
            // 沒人在做，趕快佔位
            let mut map = state.ipfs_map.write().unwrap();
            // 佔位前再檢查一次，避免在等待寫鎖期間被別人搶先
            if map.contains_key(&comp_hash_str) { continue; } 
            map.insert(comp_hash_str.clone(), "PROCESSING".to_string());
            break; // 跳出 loop 開始執行證明
        }
    }

    let mut assumptions_to_add = Vec::new();
    let mut children_hashes = Vec::new();

    if let Some(deps) = tree_data["dependencyMap"].get(&comp_id).and_then(|v| v.as_array()) {
        for dep_id_value in deps {
            let dep_id = dep_id_value.as_str().unwrap().to_string();
            let child_receipt = prove_component_recursive(dep_id.clone(), state.clone(), tree_data, receipt_cache).await?;
            assumptions_to_add.push(child_receipt);
            let child_hash_str = tree_data["componentMap"][&dep_id]["hash"].as_str().unwrap();
            children_hashes.push(decode_hex_32(child_hash_str));
        }
    }

    let merkle_data = &comp["merkleData"];
    let root_str = merkle_data["merkleRoot"].as_str().unwrap();
    
    let path_elements = merkle_data["components"].as_array().unwrap().iter()
        .find(|c| c["hash"].as_str().unwrap() == &comp_hash_str)
        .and_then(|c| c["merklePath"]["pathElements"].as_array())
        .map(|arr| arr.iter().map(|v| decode_hex_32(v.as_str().unwrap())).collect::<Vec<_>>())
        .unwrap_or_default();

    let path_indices = merkle_data["components"].as_array().unwrap().iter()
        .find(|c| c["hash"].as_str().unwrap() == &comp_hash_str)
        .and_then(|c| c["merklePath"]["pathIndices"].as_array())
        .map(|arr| arr.iter().map(|v| v.as_u64().unwrap() as u32).collect::<Vec<_>>())
        .unwrap_or_default();

    let local_merkle_input = MerkleInput {
        root: decode_hex_32(root_str),
        path_elements,
        path_indices,
    };

    let comp_input = ComponentInput {
        name: comp_name.to_string(),
        version: comp["version"].as_str().unwrap_or("").to_string(),
        hash: decode_hex_32(&comp_hash_str),
        license: comp["license"].as_str().unwrap_or("").to_string(),
        severity: map_severity(comp["severity"].as_str().unwrap_or("Unknown")),
        comp_type: comp["type"].as_str().unwrap_or("unknown").to_string(),
        dependency_hashes: children_hashes,
    };

    // println!("[-] 正在證明套件: {}", comp_name);
    pb.set_message(format!("證明中: {}", comp_name));
    let receipt_result = run_risc0_prover(state.clone(), comp_input, local_merkle_input, assumptions_to_add).await;

    match receipt_result {
        Ok(receipt) => {
            // 證明成功，上傳並更新狀態
            let cid = upload_receipt_to_ipfs(&receipt).await?;
            {
                let mut map = state.ipfs_map.write().unwrap();
                map.insert(comp_hash_str.clone(), cid); // 用真正的 CID 替換 "PROCESSING"
            }
            receipt_cache.insert(comp_hash_str, receipt.clone());
            Ok(receipt)
        }
        Err(e) => {
            // 證明失敗，必須清除 "PROCESSING" 狀態，讓下次可以重試
            {
                let mut map = state.ipfs_map.write().unwrap();
                map.remove(&comp_hash_str);
            }
            Err(e)
        }
    }
}

async fn handle_prove(State(state): State<Arc<CompState>>, Json(payload): Json<ProveRequest>) -> axum::response::Response {
    println!("✅ 開始遞迴證明任務: {}", payload.artifact_id);
    let start_calc = Instant::now();
    let tree_data = payload.tree_data;

    let components = match tree_data["components"].as_array() {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "Missing components").into_response(),
    };

    if components.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty components").into_response();
    }

    let root_id = match components[0]["bomRef"].as_str() {
        Some(id) => id.to_string(),
        None => return (StatusCode::BAD_REQUEST, "Missing root bomRef").into_response(),
    };

    // 進度條初始化
    let total_count = components.len() as u64;
    let pb = ProgressBar::new(total_count);
    pb.set_style(ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta}) {msg}"
    ).unwrap().progress_chars("#>-"));
    pb.set_message("正在準備證明樹...");

    let mut receipt_cache = HashMap::new();
    match prove_component_recursive(root_id.clone(), state.clone(), &tree_data, &mut receipt_cache).await {
        Ok(final_receipt) => {
            pb.finish_with_message("證明生成完成！");
            let prove_duration_ms = start_calc.elapsed().as_millis();
            let root_hash = tree_data["componentMap"].get(&root_id).and_then(|n| n["hash"].as_str()).unwrap();
            let root_cid = state.ipfs_map.read().unwrap().get(root_hash).cloned();

            Json(ProveResponse {
                proof: hex::encode(bincode::serialize(&final_receipt.inner).unwrap()),
                journal: hex::encode(final_receipt.journal.bytes),
                prove_duration_ms,
                root_cid,
            }).into_response()
        },
        Err((status, msg)) => {
            pb.abandon_with_message("證明失敗");
            eprintln!("[Error] 遞迴證明失敗: {} - {}", status, msg);
            (status, msg).into_response()
        }
    }
}

#[tokio::main]
async fn main() {
    let prover_semaphore = Arc::new(Semaphore::new(1));
    let shared_state = Arc::new(CompState { 
        ipfs_map: RwLock::new(HashMap::new()),
        compress_semaphore: prover_semaphore.clone(),
        prove_semaphore: prover_semaphore,
    });
    let image_id_hex = GUEST_CODE_FOR_ZKP_ID.iter().flat_map(|n| n.to_le_bytes()).map(|b| format!("{:02x}", b)).collect::<String>();

    println!("========================================");
    println!("🚀 ZK Recursive Prover Server 啟動中...");
    println!("🔑 Image ID: 0x{}", image_id_hex);
    println!("========================================");

    tracing_subscriber::fmt::init();
    let app = Router::new()
        .route("/prove", post(handle_prove))
        .layer(DefaultBodyLimit::disable())
        .with_state(shared_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    println!("✅ 運行在 {}", addr);
    axum::Server::bind(&addr).serve(app.into_make_service()).await.unwrap();
}

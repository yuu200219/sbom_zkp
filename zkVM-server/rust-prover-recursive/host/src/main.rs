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
use async_recursion::async_recursion;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Mutex;
use std::collections::HashSet;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics::{histogram, counter, gauge};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;

// Wrapper to make Arc<Mutex<Vec<u8>>> implement Write
struct SharedStderr(Arc<Mutex<Vec<u8>>>);

impl Write for SharedStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

#[derive(Debug, Clone)]
struct ProveMetrics {
    total_cycles: u64,
    user_cycles: u64,
    segments: u64,
    depth: usize,
    pure_prove_duration: f64,
    children_count: usize,
    parent_count: usize,
    receipt_size_kb: f64,
    seal_size_kb: f64,
    compression_duration: f64,
    guest_io_read: u64,
    guest_dependency_check: u64,
    guest_severity_check: u64,
    guest_merkle_io_read: u64,
    guest_merkle_check: u64,
}

fn parse_guest_metrics(stderr_output: &str) -> (u64, u64, u64, u64, u64) {
    let mut io_read = 0u64;
    let mut dep_check = 0u64;
    let mut severity_check = 0u64;
    let mut merkle_io_read = 0u64;
    let mut merkle_check = 0u64;

    for line in stderr_output.lines() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() == 3 {
            if let Ok(cycles) = parts[2].trim().parse::<u64>() {
                match parts[1].trim() {
                    "IO_Read" => io_read = cycles,
                    "Dependency_Check" => dep_check = cycles,
                    "Severity_Check" => severity_check = cycles,
                    "Merkle_IO_Read" => merkle_io_read = cycles,
                    "Merkle_Check" => merkle_check = cycles,
                    _ => {}
                }
            }
        }
    }
    (io_read, dep_check, severity_check, merkle_io_read, merkle_check)
}

fn log_to_csv(
    metrics: &ProveMetrics,
    comp_name: &str,
    cid: &str,
) {
    let csv_path_str = format!("../../output/CSV/sequential/experiment_log.csv");
    let path = Path::new(&csv_path_str);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_default();
    }
    
    let file_exists = path.exists();
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path);

    if let Ok(file) = file {
        let mut wtr = csv::WriterBuilder::new()
            .has_headers(!file_exists)
            .from_writer(file);
        
        if !file_exists {
            wtr.write_record(&[
                "total_cycles", "user_cycles", "segments", "depth", "pure_prove_duration", 
                "children_count", "parent_count", "receipt_size_kb", "seal_size_kb", 
                "compression_duration", "guest_io_read", "guest_dependency_check", 
                "guest_severity_check", "guest_merkle_io_read", "guest_merkle_check",
                "comp_name", "cid"
            ]).unwrap_or_default();
        }
        
        wtr.write_record(&[
            metrics.total_cycles.to_string(),
            metrics.user_cycles.to_string(),
            metrics.segments.to_string(),
            metrics.depth.to_string(),
            metrics.pure_prove_duration.to_string(),
            metrics.children_count.to_string(),
            metrics.parent_count.to_string(),
            metrics.receipt_size_kb.to_string(),
            metrics.seal_size_kb.to_string(),
            metrics.compression_duration.to_string(),
            metrics.guest_io_read.to_string(),
            metrics.guest_dependency_check.to_string(),
            metrics.guest_severity_check.to_string(),
            metrics.guest_merkle_io_read.to_string(),
            metrics.guest_merkle_check.to_string(),
            comp_name.to_string(),
            cid.to_string(),
        ]).unwrap_or_default();
        wtr.flush().unwrap_or_default();
    }
}

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
    depth: usize,
) -> Result<(Receipt, ProveMetrics), (StatusCode, String)> {

    let _permit = if comp_input.comp_type == "virtual-batch" {
        state.compress_semaphore.acquire().await.unwrap()
    } else {
        state.prove_semaphore.acquire().await.unwrap()
    };

    let bom_ref = comp_input.bom_ref.clone();
    let children_count = comp_input.dependency_hashes.len();
    let parent_count = comp_input.parent_count;
    let labels = [
        ("component_name", comp_input.name.clone()), // 如果只是為了辨識，留 name 即可
        ("node_type", comp_input.comp_type.clone()), // "leaf" 或 "virtual-batch"
        ("severity", format!("{:?}", comp_input.severity)), 
        ("depth", depth.to_string()),                        
        ("children_count", children_count.to_string()),
        ("parent_count", parent_count.to_string()),
    ];
    let labels_for_task = labels.clone();

    let start_total_task = Instant::now();
    
    let (receipt, total_cycles, user_cycles, segments, pure_prove_duration, compression_duration, stderr_output) = tokio::task::spawn_blocking(move || -> Result<(Receipt, u64, u64, u64, f64, f64, Vec<u8>), String> {
        let stderr_buffer = Arc::new(Mutex::new(Vec::new()));
        
        let mut env_builder = ExecutorEnv::builder();
        for child_receipt in assumptions {
            env_builder.add_assumption(child_receipt);
        }
        env_builder.write(&comp_input).unwrap();
        env_builder.write(&GUEST_CODE_FOR_ZKP_ID).unwrap();
        env_builder.write(&merkle_input).unwrap();
        env_builder.stderr(SharedStderr(stderr_buffer.clone()));

        let env = env_builder.build().unwrap();
        let prover = default_prover();

        let prove_start = std::time::Instant::now();
        
        let prove_info = prover.prove(env, GUEST_CODE_FOR_ZKP_ELF)
            .map_err(|e| format!("Prover prove failed: {}", e))?;

        let pure_prove_duration = prove_start.elapsed().as_millis() as f64;
        let total_cycles = prove_info.stats.total_cycles as u64;
        let user_cycles = prove_info.stats.user_cycles as u64;
        let segments = prove_info.stats.segments as u64;

        if comp_input.comp_type == "virtual-batch" {
            println!("[-] 聚合節點 ({})，執行證明壓縮...", comp_input.name);
            
            let compress_start = std::time::Instant::now();

            let compressed_receipt = prover.compress(&risc0_zkvm::ProverOpts::succinct(), &prove_info.receipt)
                .map_err(|e| format!("Prover compression failed: {}", e))?;
            
            let compress_duration = compress_start.elapsed().as_millis() as f64;
            let captured_stderr = stderr_buffer.lock().unwrap().clone();
            Ok((compressed_receipt, total_cycles, user_cycles, segments, pure_prove_duration, compress_duration, captured_stderr))
        } else {
            let captured_stderr = stderr_buffer.lock().unwrap().clone();
            Ok((prove_info.receipt, total_cycles, user_cycles, segments, pure_prove_duration, 0.0, captured_stderr))
        }
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Thread error: {}", e)))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Prover error: {}", e)))?;

    let total_task_duration = start_total_task.elapsed().as_millis() as f64;

    // proof size
    let receipt_size = bincode::serialize(&receipt).unwrap();
    let receipt_size_kb = receipt_size.len() as f64 / 1024.0;

    let seal_bytes = bincode::serialize(&receipt.inner).unwrap_or_default();
    let seal_size_kb = seal_bytes.len() as f64 / 1024.0;

    // histogram!("risczero_receipt_size_kb", &labels).record(receipt_size_kb);
    // histogram!("risczero_receipt_seal_size_kb", &labels).record(seal_size_kb);
    // time metrics
    // histogram!("proving_duration_ms", &labels).record(pure_prove_duration);
    // gauge!("last_proving_duration_ms", &labels).set(pure_prove_duration);
    // histogram!("compression_duration_ms", &labels).record(compression_duration);
    // gauge!("last_compression_duration_ms", &labels).set(compression_duration);
    // histogram!("proving_node_depth", &labels).record(depth as f64);
    // histogram!("proving_node_children_count", &labels).record(children_count as f64);
    // counter!("risczero_cycles_total", &labels).absolute(cycles);
    // gauge!("last_proving_cycles", &labels).set(cycles as f64);

    // Extract guest metrics from stderr output
    let stderr_str = String::from_utf8_lossy(&stderr_output);
    let (guest_io_read, guest_dependency_check, guest_severity_check, guest_merkle_io_read, guest_merkle_check) = 
        parse_guest_metrics(&stderr_str);

    let metrics = ProveMetrics {
        total_cycles,
        user_cycles,
        segments,
        depth,
        pure_prove_duration,
        children_count,
        parent_count,
        receipt_size_kb,
        seal_size_kb,
        compression_duration,
        guest_io_read,
        guest_dependency_check,
        guest_severity_check,
        guest_merkle_io_read,
        guest_merkle_check,
    };

    Ok((receipt, metrics))
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
    visited_pb: Arc<Mutex<HashSet<String>>>,
) -> Result<Receipt, (StatusCode, String)> {
    let component_map = tree_data["componentMap"].as_object()
        .ok_or((StatusCode::BAD_REQUEST, "componentMap missing".to_string()))?;

    let comp = component_map.get(&comp_id).ok_or((StatusCode::BAD_REQUEST, format!("Component {} not found", comp_id)))?;
    let comp_identity_hash = comp["hash"].as_str().unwrap().to_string();
    let merkle_data = &comp["merkleData"];
    let comp_recursive_hash = merkle_data["merkleRoot"].as_str().unwrap().to_string();
    let comp_name = comp["name"].as_str().unwrap_or("unknown");

    let is_first_visit = {
        let mut visited = visited_pb.lock().unwrap();
        visited.insert(comp_recursive_hash.clone())
    };

    if let Some(r) = receipt_cache.get(&comp_recursive_hash) {
        if is_first_visit { pb.inc(1); }
        return Ok(r.clone());
    }

    // checking lock and status
    loop {
        let current_status = {
            let map = state.ipfs_map.read().unwrap();
            map.get(&comp_recursive_hash).cloned()
        };

        if let Some(status) = current_status {
            if status == "PROCESSING" {
                // 如果別人在做了，我們就等一下再檢查，不要啟動新任務
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue; 
            } else {
                // 已完成，下載並回傳
                let receipt = download_and_verify_receipt(&status).await?;
                receipt_cache.insert(comp_recursive_hash.clone(), receipt.clone());
                if is_first_visit { pb.inc(1); }
                return Ok(receipt);
            }
        } else {
            // 沒人在做，趕快佔位
            let mut map = state.ipfs_map.write().unwrap();
            // 佔位前再檢查一次，避免在等待寫鎖期間被別人搶先
            if map.contains_key(&comp_recursive_hash) { continue; } 
            map.insert(comp_recursive_hash.clone(), "PROCESSING".to_string());
            break; // 跳出 loop 開始執行證明
        }
    }

    let mut assumptions_to_add = Vec::new();
    let mut children_hashes = Vec::new();

    if let Some(deps) = tree_data["dependencyMap"].get(&comp_id).and_then(|v| v.as_array()) {
        for dep_id_value in deps {
            let dep_id = dep_id_value.as_str().unwrap().to_string();
            let child_receipt = prove_component_recursive(dep_id.clone(), state.clone(), tree_data, receipt_cache, pb.clone(), visited_pb.clone()).await?;
            
            // Virtual-batch 節點的收據也需要加入 assumption
            assumptions_to_add.push(child_receipt);
            
            let child_recursive_hash = tree_data["componentMap"][&dep_id]["merkleData"]["merkleRoot"].as_str().unwrap();
            children_hashes.push(decode_hex_32(child_recursive_hash));
        }
    }

    let root_str = merkle_data["merkleRoot"].as_str().unwrap();
    
    let path_elements = merkle_data["components"].as_array().unwrap().iter()
        .find(|c| c["hash"].as_str().unwrap() == &comp_identity_hash)
        .and_then(|c| c["merklePath"]["pathElements"].as_array())
        .map(|arr| arr.iter().map(|v| decode_hex_32(v.as_str().unwrap())).collect::<Vec<_>>())
        .unwrap_or_default();

    let path_indices = merkle_data["components"].as_array().unwrap().iter()
        .find(|c| c["hash"].as_str().unwrap() == &comp_identity_hash)
        .and_then(|c| c["merklePath"]["pathIndices"].as_array())
        .map(|arr| arr.iter().map(|v| v.as_u64().unwrap() as u32).collect::<Vec<_>>())
        .unwrap_or_default();

    let local_merkle_input = MerkleInput {
        root: decode_hex_32(root_str),
        path_elements,
        path_indices,
    };

    let comp_input = ComponentInput {
        bom_ref: comp_id.clone(),
        name: comp_name.to_string(),
        version: comp["version"].as_str().unwrap_or("").to_string(),
        hash: decode_hex_32(&comp_identity_hash),
        license: comp["license"].as_str().unwrap_or("").to_string(),
        severity: map_severity(comp["severity"].as_str().unwrap_or("Unknown")),
        comp_type: comp["type"].as_str().unwrap_or("unknown").to_string(),
        dependency_hashes: children_hashes,
        depth: comp["depth"].as_u64().unwrap_or(0) as usize,
        parent_count: comp["parent_count"].as_u64().unwrap_or(0) as usize,
    };

    // println!("[-] 正在證明套件: {}", comp_name);
    pb.set_message(format!("證明中: {} ({})", comp_name, &comp_recursive_hash[0..6]));
    let receipt_result = run_risc0_prover(state.clone(), comp_input.clone(), local_merkle_input, assumptions_to_add, comp_input.depth).await;

    match receipt_result {
        Ok((receipt, metrics)) => {
            // 證明成功，上傳並更新狀態
            let cid = upload_receipt_to_ipfs(&receipt).await?;
            {
                let mut map = state.ipfs_map.write().unwrap();
                map.insert(comp_recursive_hash.clone(), cid.clone()); // 用真正的 CID 替換 "PROCESSING"
            }
            // 在上傳完成後，記錄 CSV（包含 cid 和 comp_name）
            log_to_csv(&metrics, comp_name, &cid);
            receipt_cache.insert(comp_recursive_hash, receipt.clone());
            if is_first_visit { pb.inc(1); }
            Ok(receipt)
        }
        Err(e) => {
            // 證明失敗，必須清除 "PROCESSING" 狀態，讓下次可以重試
            {
                let mut map = state.ipfs_map.write().unwrap();
                map.remove(&comp_recursive_hash);
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

    let visited_pb = Arc::new(Mutex::new(HashSet::new()));

    let mut receipt_cache = HashMap::new();
    match prove_component_recursive(root_id.clone(), state.clone(), &tree_data, &mut receipt_cache, pb.clone(), visited_pb.clone()).await {
        Ok(final_receipt) => {
            pb.finish_with_message("證明生成完成！");
            let prove_duration_ms = start_calc.elapsed().as_millis();
            let root_hash = tree_data["componentMap"].get(&root_id).and_then(|n| n["merkleData"]["merkleRoot"].as_str()).unwrap();
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

    let builder = PrometheusBuilder::new();
    builder.with_http_listener(([0, 0, 0, 0], 3002))
           .install()
           .expect("failed to install Prometheus recorder");

    metrics::counter!("server_boot_test_total").increment(1);
    metrics::gauge!("server_status_ready").set(1.0);

    println!("📊 Prometheus Exporter 已啟動於 http://localhost:3002/metrics");

    let prover_semaphore = Arc::new(Semaphore::new(1));
    let shared_state = Arc::new(CompState { 
        ipfs_map: RwLock::new(HashMap::new()),
        compress_semaphore: prover_semaphore.clone(),
        prove_semaphore: prover_semaphore,
    });
    let image_id_hex = GUEST_CODE_FOR_ZKP_ID.iter().flat_map(|n| n.to_le_bytes()).map(|b| format!("{:02x}", b)).collect::<String>();

    // 將 Image ID 存入 .env.local 檔案，方便後續查詢
    let env_path = std::path::Path::new(".env.local");
    let image_id_entry = format!("IMAGE_ID=0x{}\n", image_id_hex);
    match std::fs::write(env_path, &image_id_entry) {
        Ok(_) => println!("✅ Image ID 已保存至 .env.local"),
        Err(e) => println!("⚠️  無法保存 Image ID 至 .env.local: {}", e),
    }

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

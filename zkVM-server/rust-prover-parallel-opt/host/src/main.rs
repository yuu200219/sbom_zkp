use shared_data::{ComponentInput, MerkleInput, Severity};
use axum::{routing::post, Json, Router, response::IntoResponse, http::StatusCode, extract::State};
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
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use sysinfo::{System, SystemExt, CpuExt};
use uuid::Uuid;
use chrono::Local;
use base64ct::Encoding;

const NUM_GROUPS: usize = 4;
const CORES_PER_GROUP: usize = 8;

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
    descendants_count: usize,
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
                "children_count", "parent_count", "descendants_count", "receipt_size_kb", "seal_size_kb", 
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
            metrics.descendants_count.to_string(),
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
    task_tracker: Arc<Mutex<HashMap<String, String>>>,
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

    let task_id = Uuid::new_v4().to_string();
    {
        let mut tracker = state.task_tracker.lock().unwrap();
        tracker.insert(task_id.clone(), format!("Wait Prove Semaphore: {}", comp_input.name));
    }

    let _permit = if comp_input.comp_type == "virtual-batch" {
        state.compress_semaphore.acquire().await.unwrap()
    } else {
        state.prove_semaphore.acquire().await.unwrap()
    };

    {
        let mut tracker = state.task_tracker.lock().unwrap();
        tracker.insert(task_id.clone(), format!("Proving: {}", comp_input.name));
    }

    // let bom_ref = comp_input.bom_ref.clone();
    let children_count = comp_input.dependency_hashes.len();
    let parent_count = comp_input.parent_count;
    let descendants_count = comp_input.descendants_count;
    // let labels = [
    //     ("component_name", comp_input.name.clone()), // 如果只是為了辨識，留 name 即可
    //     ("node_type", comp_input.comp_type.clone()), // "leaf" 或 "virtual-batch"
    //     ("severity", format!("{:?}", comp_input.severity)), 
    //     ("depth", depth.to_string()),                        
    //     ("children_count", children_count.to_string()),
    //     ("parent_count", parent_count.to_string()),
    //     ("descendants_count", descendants_count.to_string()),
    // ];
    // let labels_for_task = labels.clone();

    // let start_total_task = Instant::now();
    
    let (receipt, total_cycles, user_cycles, segments, pure_prove_duration, compression_duration, stderr_output) = tokio::task::spawn_blocking(move || -> Result<(Receipt, u64, u64, u64, f64, f64, Vec<u8>), String> {
        let stderr_buffer = Arc::new(Mutex::new(Vec::new()));
        
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(CORES_PER_GROUP)
            .build()
            .map_err(|e| format!("Failed to build rayon thread pool: {}", e))?;

        let is_leaf = comp_input.dependency_hashes.is_empty();
        let prove_start = std::time::Instant::now();
        
        let (prove_info, pure_prove_duration, compression_duration) = pool.install(|| {
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

            if is_leaf {
                let info = prover.prove(env, GUEST_CODE_FOR_ZKP_ELF)
                    .map_err(|e| format!("Prover prove failed: {}", e))?;
                let elapsed = prove_start.elapsed().as_millis() as f64;
                Ok::<_, String>((info, elapsed, 0.0))
            } else {
                let info = prover.prove_with_opts(env, GUEST_CODE_FOR_ZKP_ELF, &risc0_zkvm::ProverOpts::succinct())
                    .map_err(|e| format!("Prover prove_with_opts failed: {}", e))?;
                let elapsed = prove_start.elapsed().as_millis() as f64;
                Ok::<_, String>((info, 0.0, elapsed))
            }
        })?;

        let total_cycles = prove_info.stats.total_cycles as u64;
        let user_cycles = prove_info.stats.user_cycles as u64;
        let segments = prove_info.stats.segments as u64;

        let captured_stderr = stderr_buffer.lock().unwrap().clone();
        Ok((prove_info.receipt, total_cycles, user_cycles, segments, pure_prove_duration, compression_duration, captured_stderr))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Thread error: {}", e)))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Prover error: {}", e)))?;

    // let total_task_duration = start_total_task.elapsed().as_millis() as f64;

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
        descendants_count,
        receipt_size_kb,
        seal_size_kb,
        compression_duration,
        guest_io_read,
        guest_dependency_check,
        guest_severity_check,
        guest_merkle_io_read,
        guest_merkle_check,
    };

    {
        let mut tracker = state.task_tracker.lock().unwrap();
        tracker.remove(&task_id);
    }

    Ok((receipt, metrics))
}

async fn download_and_verify_receipt(cid: &str, state: Arc<CompState>) -> Result<Receipt, (StatusCode, String)> {
    let task_id = Uuid::new_v4().to_string();
    {
        let mut tracker = state.task_tracker.lock().unwrap();
        tracker.insert(task_id.clone(), format!("IPFS Down: {}", &cid[0..8]));
    }

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
        {
            let mut tracker = state.task_tracker.lock().unwrap();
            tracker.remove(&task_id);
        }
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Verify error: {}", e)));
    }
    
    {
        let mut tracker = state.task_tracker.lock().unwrap();
        tracker.remove(&task_id);
    }
    Ok(stored_proof.receipt)
}

async fn upload_receipt_to_ipfs(receipt: &Receipt, state: Arc<CompState>) -> Result<String, (StatusCode, String)> {
    let task_id = Uuid::new_v4().to_string();
    {
        let mut tracker = state.task_tracker.lock().unwrap();
        tracker.insert(task_id.clone(), "IPFS Up".to_string());
    }

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
        .map_err(|e| {
            let mut tracker = state.task_tracker.lock().unwrap();
            tracker.remove(&task_id);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to parse IPFS response: {}", e))
        })?;

    let cid = res_json["Hash"].as_str()
        .ok_or_else(|| {
            let mut tracker = state.task_tracker.lock().unwrap();
            tracker.remove(&task_id);
            (StatusCode::INTERNAL_SERVER_ERROR, "No Hash found".to_string())
        })?.to_string();
    
    println!("[-] 證明上傳至 IPFS, CID: {}", cid);
    
    {
        let mut tracker = state.task_tracker.lock().unwrap();
        tracker.remove(&task_id);
    }
    Ok(cid)
}

#[async_recursion]
async fn prove_component_recursive(
    comp_id: String,
    state: Arc<CompState>,
    tree_data: Arc<Value>,
    receipt_cache: Arc<RwLock<HashMap<String, Receipt>>>,
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

    {
        let cache = receipt_cache.read().unwrap();
        if let Some(r) = cache.get(&comp_recursive_hash) {
            if is_first_visit { pb.inc(1); }
            return Ok(r.clone());
        }
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
                let wait_task_id = Uuid::new_v4().to_string();
                {
                    let mut tracker = state.task_tracker.lock().unwrap();
                    tracker.insert(wait_task_id.clone(), format!("Wait IPFS Lock: {}", comp_name));
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                {
                    let mut tracker = state.task_tracker.lock().unwrap();
                    tracker.remove(&wait_task_id);
                }
                continue; 
            } else {
                // 已完成，下載並回傳
                let receipt = download_and_verify_receipt(&status, state.clone()).await?;
                {
                    let mut cache = receipt_cache.write().unwrap();
                    cache.insert(comp_recursive_hash.clone(), receipt.clone());
                }
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
        let mut child_futures = Vec::new();
        for dep_id_value in deps {
            let dep_id = dep_id_value.as_str().unwrap().to_string();
            let state_clone = state.clone();
            let tree_data_clone = tree_data.clone();
            let receipt_cache_clone = receipt_cache.clone();
            let pb_clone = pb.clone();
            let visited_pb_clone = visited_pb.clone();
            child_futures.push(async move {
                prove_component_recursive(
                    dep_id,
                    state_clone,
                    tree_data_clone,
                    receipt_cache_clone,
                    pb_clone,
                    visited_pb_clone,
                ).await
            });
        }
        let child_receipts = futures::future::try_join_all(child_futures).await?;
        for (i, dep_id_value) in deps.iter().enumerate() {
            let dep_id = dep_id_value.as_str().unwrap();
            assumptions_to_add.push(child_receipts[i].clone());
            let child_recursive_hash = tree_data["componentMap"][dep_id]["merkleData"]["merkleRoot"].as_str().unwrap();
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
        descendants_count: comp["descendants_count"].as_u64().unwrap_or(0) as usize,
    };

    // println!("[-] 正在證明套件: {}", comp_name);
    pb.set_message(format!("證明中: {} ({})", comp_name, &comp_recursive_hash[0..6]));

    let (receipt, metrics) = run_risc0_prover(
        state.clone(),
        comp_input,
        local_merkle_input,
        assumptions_to_add,
        comp["depth"].as_u64().unwrap_or(0) as usize,
    ).await?;

    let cid = upload_receipt_to_ipfs(&receipt, state.clone()).await?;
    log_to_csv(&metrics, comp_name, &cid);

    {
        let mut map = state.ipfs_map.write().unwrap();
        map.insert(comp_recursive_hash.clone(), cid);
    }
    
    {
        let mut cache = receipt_cache.write().unwrap();
        cache.insert(comp_recursive_hash.clone(), receipt.clone());
    }

    if is_first_visit { pb.inc(1); }
    Ok(receipt)
}

fn start_cpu_monitor(task_tracker: Arc<Mutex<HashMap<String, String>>>) {
    tokio::spawn(async move {
        let mut sys = System::new_all();
        // 初始化時先 refresh 一次，否則第一次的資料可能會是 0 或是非常奇怪的數字
        sys.refresh_cpu();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let csv_path_str = "../../output/CSV/parallel_opt/cpu_monitor.csv";
        let path = Path::new(csv_path_str);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap_or_default();
        }

        loop {
            sys.refresh_cpu();
            let mut cpu_usages = Vec::new();
            for cpu in sys.cpus() {
                cpu_usages.push(cpu.cpu_usage());
            }

            let running_tasks = {
                let tracker = task_tracker.lock().unwrap();
                let tasks: Vec<String> = tracker.values().cloned().collect();
                format!("[{}]", tasks.join(", "))
            };

            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

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
                    let mut headers = vec!["Timestamp".to_string()];
                    for i in 0..sys.cpus().len() {
                        headers.push(format!("Core_{}", i));
                    }
                    headers.push("Running_Tasks".to_string());
                    wtr.write_record(&headers).unwrap_or_default();
                }

                let mut record = vec![timestamp];
                for usage in cpu_usages {
                    record.push(format!("{:.1}", usage));
                }
                record.push(running_tasks);

                wtr.write_record(&record).unwrap_or_default();
                wtr.flush().unwrap_or_default();
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
}

// async fn prove_handler(
//     State(state): State<Arc<CompState>>,
//     Json(payload): Json<ProveRequest>,
// ) -> impl IntoResponse {
//     println!("✅ 開始遞迴證明任務: {}", payload.artifact_id);
//     let start_time = Instant::now(); 

//     // FIX: Keep tree_data as Arc<Value> for the recursive function
//     let shared_tree_data = Arc::new(payload.tree_data.clone());

//     let total_tasks = shared_tree_data["componentMap"]
//         .as_object()
//         .map_or(0, |m| m.len());

//     let receipt_cache = Arc::new(RwLock::new(HashMap::new()));
//     let visited_pb = Arc::new(Mutex::new(HashSet::new()));

//     let pb = ProgressBar::new(total_tasks as u64);
//     pb.set_style(ProgressStyle::default_bar()
//         .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) - {msg}")
//         .unwrap()
//         .progress_chars("#>-"));

//     let root_receipt = match prove_component_recursive(
//         payload.artifact_id.clone(),
//         state.clone(),
//         shared_tree_data.clone(), // Pass the Arc<Value> here
//         receipt_cache,
//         pb.clone(),
//         visited_pb,
//     ).await {
//         Ok(receipt) => receipt,
//         Err((code, msg)) => {
//             let mut tracker = state.task_tracker.lock().unwrap();
//             tracker.insert(payload.artifact_id.clone(), format!("Prove failed: {}", code));
//             return (code, msg).into_response();
//         }
//     };

//     let duration_ms = start_time.elapsed().as_millis();
    
//     // FIX: Traverse the JSON value properly to get the root hash
//     let root_cid = {
//         let root_hash = shared_tree_data["componentMap"][&payload.artifact_id]["merkleData"]["merkleRoot"]
//             .as_str()
//             .unwrap_or("")
//             .to_string();
//         let map = state.ipfs_map.read().unwrap();
//         map.get(&root_hash).cloned()
//     };

//     let response = ProveResponse {
//         proof: base64ct::Base64::encode_string(&bincode::serialize(&root_receipt).unwrap()),
//         journal: base64ct::Base64::encode_string(root_receipt.journal.bytes.as_slice()),
//         prove_duration_ms: duration_ms,
//         root_cid,
//     };

//     (StatusCode::OK, Json(response)).into_response()
// }

async fn handle_prove(State(state): State<Arc<CompState>>, Json(payload): Json<ProveRequest>) -> axum::response::Response {
    println!("✅ 開始遞迴證明任務: {}", payload.artifact_id);
    let start_calc = Instant::now();
    let tree_data = Arc::new(payload.tree_data.clone());

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

    let receipt_cache = Arc::new(RwLock::new(HashMap::new()));
    match prove_component_recursive(root_id.clone(), state.clone(), tree_data.clone(), receipt_cache, pb.clone(), visited_pb.clone()).await {
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
            let mut tracker = state.task_tracker.lock().unwrap();
            tracker.insert(payload.artifact_id.clone(), format!("Prove failed: {}", status));
            pb.abandon_with_message("證明失敗");
            eprintln!("[Error] 遞迴證明失敗: {} - {}", status, msg);
            (status, msg).into_response()
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = Arc::new(CompState {
        ipfs_map: RwLock::new(HashMap::new()),
        compress_semaphore: Arc::new(Semaphore::new(1)),
        prove_semaphore: Arc::new(Semaphore::new(NUM_GROUPS)),
        task_tracker: Arc::new(Mutex::new(HashMap::new())),
    });

    start_cpu_monitor(state.task_tracker.clone());

    let app = Router::new()
        .route("/prove", post(handle_prove))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    println!("✅ 運行在 {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

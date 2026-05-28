use clap::Parser;
use risc0_zkvm::Receipt;
use risc0_zkvm::sha::Digest;
use serde_json::Value;
use std::fs;
use std::time::Instant;
use csv::ReaderBuilder;
use std::path::Path;
use std::fs::OpenOptions;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
struct VerifyMetrics {
    cycle: u64,
    depth: usize,
    verify_duration: f64,
    children_count: usize,
    parent_count: usize,
    receipt_size_kb: f64,
    seal_size_kb: f64,
}

#[derive(Serialize, Deserialize)]
struct StoredProof {
    receipt: Receipt,
    image_id: [u32; 8],
}

#[derive(Debug, Deserialize)]
struct InputRow {
    cycle: u64,
    depth: usize,
    #[serde(rename = "pure_prove_duration")]
    pure_prove_duration: f64,
    children_count: usize,
    parent_count: usize,
    receipt_size_kb: f64,
    #[serde(rename = "seal_size_kb")]
    seal_size_kb: f64,
    #[serde(rename = "compression_duration")]
    compression_duration: f64,
    comp_name: String,
    cid: String,
}

#[derive(Parser)]
struct Args {
    /// 路徑：存放從 IPFS 下載的 receipt.bin
    #[arg(short, long)]
    receipt_path: Option<String>,

    /// 你的 Image ID (Verification Key)，格式為 0x...
    #[arg(short, long)]
    image_id: String,

    /// CSV 檔案路徑，用來批量驗證
    #[arg(short, long)]
    csv_path: Option<String>,
}

fn log_to_csv(
    metrics: &VerifyMetrics,
    comp_name: &str,
    cid: &str,
) {
    let csv_path_str = format!("../../output/CSV/recursive/never_seen/verification_log.csv");
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
            wtr.write_record(&["cycle", "depth", "verify_duration", "children_count", "parent_count", "receipt_size_kb", "seal_size_kb", "comp_name", "cid"]).unwrap_or_default();
        }
        
        wtr.write_record(&[
            metrics.cycle.to_string(),
            metrics.depth.to_string(),
            metrics.verify_duration.to_string(),
            metrics.children_count.to_string(),
            metrics.parent_count.to_string(),
            metrics.receipt_size_kb.to_string(),
            metrics.seal_size_kb.to_string(),
            comp_name.to_string(),
            cid.to_string(),
        ]).unwrap_or_default();
        wtr.flush().unwrap_or_default();
    }
}

fn download_from_ipfs(cid: &str) -> Result<Vec<u8>, String> {
    let url = format!("http://127.0.0.1:8080/ipfs/{}", cid);
    println!("[-] 正在從私有 IPFS 下載: {}", url);
    let response = reqwest::blocking::get(&url)
        .map_err(|e| format!("連線至 IPFS 失敗: {}", e))?
        .bytes()
        .map_err(|e| format!("讀取資料失敗: {}", e))?;

    Ok(response.to_vec())
}

fn read_csv_file(csv_path: &str) -> Result<Vec<InputRow>, Box<dyn std::error::Error>> {
    let file = fs::File::open(csv_path)?;
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(file);
    
    let mut rows = Vec::new();
    for result in reader.deserialize() {
        let row: InputRow = result?;
        rows.push(row);
    }
    
    Ok(rows)
}

fn verify_single(
    raw_data: &[u8],
    image_id: Digest,
    comp_name: &str,
    cid: &str,
) -> Result<VerifyMetrics, String> {
    let verify_start = Instant::now();
    
    // 首先尝试解析为 bincode 格式（Rust Prover 直接上传的格式）
    let receipt = match bincode::deserialize::<StoredProof>(raw_data) {
        Ok(stored_proof) => {
            println!("[-] {} - 偵測到 bincode 格式，直接使用。", comp_name);
            stored_proof.receipt
        }
        Err(_) => {
            // 如果 bincode 失败，尝试 JSON 格式（Node API 保存的格式）
            match serde_json::from_slice::<Value>(raw_data) {
                Ok(json) => {
                    println!("[-] {} - 偵測到 JSON 格式，正在解析...", comp_name);
                    let proof_hex = json["proof"].as_str()
                        .ok_or("JSON 中找不到 proof 欄位")?;

                    let proof_bytes = hex::decode(proof_hex)
                        .map_err(|e| format!("Proof Hex 解碼失敗: {}", e))?;

                    match bincode::deserialize::<Receipt>(&proof_bytes) {
                        Ok(r) => {
                            println!("[-] {} - JSON 中的 Receipt 格式有效", comp_name);
                            r
                        }
                        Err(_) => {
                            println!("[-] {} - JSON 中偵測到 InnerReceipt 格式，正在從 journal 重組...", comp_name);
                            let inner: risc0_zkvm::InnerReceipt = bincode::deserialize(&proof_bytes)
                                .map_err(|e| format!("無法解析 Proof: {}", e))?;

                            let journal_hex = json["journal"].as_str()
                                .ok_or("缺少 journal 欄位")?;
                            let journal_bytes = hex::decode(journal_hex)
                                .map_err(|e| format!("Journal Hex 解碼失敗: {}", e))?;

                            Receipt::new(inner, journal_bytes)
                        }
                    }
                }
                Err(e) => {
                    return Err(format!("無法解析資料：既不是 bincode 也不是 JSON - {}", e));
                }
            }
        }
    };

    // Get receipt size info
    let receipt_serialized = bincode::serialize(&receipt)
        .map_err(|e| format!("序列化 receipt 失敗: {}", e))?;
    let receipt_size_kb = receipt_serialized.len() as f64 / 1024.0;

    let seal_bytes = bincode::serialize(&receipt.inner)
        .unwrap_or_default();
    let seal_size_kb = seal_bytes.len() as f64 / 1024.0;

    // Perform verification
    receipt.verify(image_id)
        .map_err(|e| format!("驗證失敗: {}", e))?;

    let verify_duration = verify_start.elapsed().as_millis() as f64;

    // Note: Cycle information is not directly available from the receipt after verification
    // It's only available from the prover's output. Using 0 as placeholder.
    let cycle = 0u64;

    // Extract depth and children_count from the JSON journal if possible
    // For now, we'll use default values as these come from the input CSV
    let metrics = VerifyMetrics {
        cycle,
        depth: 0,  // Will be overridden by CSV data
        verify_duration,
        children_count: 0,  // Will be overridden by CSV data
        parent_count: 0,    // Will be overridden by CSV data
        receipt_size_kb,
        seal_size_kb,
    };

    println!("✅ {} - 驗證成功！耗時: {:.2} ms", comp_name, verify_duration);
    Ok(metrics)
}

fn main() {
    let args = Args::parse();

    // Parse Image ID
    let image_id_str = args.image_id.trim_start_matches("0x");
    let bytes = hex::decode(image_id_str).expect("Image ID Hex 解碼失敗");
    let image_id = Digest::from_bytes(bytes.try_into().expect("Image ID 長度不符"));

    // Batch verification from CSV
    if let Some(csv_path) = args.csv_path {
        println!("📋 從 CSV 文件批量驗證: {}", csv_path);
        match read_csv_file(&csv_path) {
            Ok(rows) => {
                println!("[-] 讀取 {} 個驗證任務", rows.len());
                let mut success_count = 0;
                let mut fail_count = 0;

                for (idx, row) in rows.iter().enumerate() {
                    println!("\n[{}/{}] 正在驗證: {} (CID: {})", idx + 1, rows.len(), row.comp_name, &row.cid[0..12]);
                    
                    match download_from_ipfs(&row.cid) {
                        Ok(raw_data) => {
                            match verify_single(&raw_data, image_id, &row.comp_name, &row.cid) {
                                Ok(mut metrics) => {
                                    // Override metrics with CSV data
                                    metrics.cycle = row.cycle;
                                    metrics.depth = row.depth;
                                    metrics.children_count = row.children_count;
                                    metrics.parent_count = row.parent_count;
                                    
                                    log_to_csv(&metrics, &row.comp_name, &row.cid);
                                    success_count += 1;
                                }
                                Err(e) => {
                                    println!("❌ {} - 驗證失敗: {}", row.comp_name, e);
                                    fail_count += 1;
                                }
                            }
                        }
                        Err(e) => {
                            println!("❌ {} - IPFS 下載失敗: {}", row.comp_name, e);
                            fail_count += 1;
                        }
                    }
                }

                println!("\n📊 批量驗證統計:");
                println!("成功: {}", success_count);
                println!("失敗: {}", fail_count);
                println!("驗證結果已保存至: ../../output/CSV/recursive/never_seen/verification_log.csv");
            }
            Err(e) => {
                eprintln!("❌ CSV 讀取失敗: {}", e);
                std::process::exit(1);
            }
        }
    } else if let Some(receipt_path) = args.receipt_path {
        // Single verification mode
        println!("🔍 單個驗證模式: {}", receipt_path);
        let verify_start = Instant::now();
        let raw_data = if receipt_path.starts_with("Qm") || receipt_path.starts_with("ba") {
            match download_from_ipfs(&receipt_path) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("❌ IPFS 下載失敗: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            fs::read(&receipt_path).expect("無法讀取文件")
        };

        let json: Value = serde_json::from_slice(&raw_data).expect("無法解析 JSON 資料");
        let proof_hex = json["proof"].as_str().expect("JSON 中找不到 proof 欄位");
        let proof_bytes = hex::decode(proof_hex).expect("Proof Hex 解碼失敗");

        let receipt: Receipt = match bincode::deserialize::<Receipt>(&proof_bytes) {
            Ok(r) => {
                println!("[-] 偵測到完整的 Receipt 格式，直接使用。");
                r
            }
            Err(_) => {
                println!("[-] 偵測到 InnerReceipt 格式，正在從 JSON 提取 journal 並重組...");
                let inner: risc0_zkvm::InnerReceipt = bincode::deserialize(&proof_bytes)
                    .expect("無法解析 Proof：格式既不符合 Receipt 也不符合 InnerReceipt");

                let journal_hex = json["journal"].as_str().expect("缺少 journal 欄位");
                let journal_bytes = hex::decode(journal_hex).expect("Journal Hex 解碼失敗");

                Receipt::new(inner, journal_bytes)
            }
        };

        match receipt.verify(image_id) {
            Ok(_) => {
                let verify_time = verify_start.elapsed().as_millis();
                println!("✅ [SUCCESS] 驗證成功！");
                println!("該證明確實由指定的 Guest Program 生成，且資料未經竄改。");
                println!("驗證耗時: {} ms", verify_time);
            }
            Err(e) => {
                println!("❌ [FAILED] 驗證失敗: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("❌ 必須提供 --receipt-path 或 --csv-path");
        std::process::exit(1);
    }
}

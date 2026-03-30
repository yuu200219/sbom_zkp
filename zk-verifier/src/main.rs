use clap::Parser;
use risc0_zkvm::Journal;
use risc0_zkvm::Receipt;
use serde_json::Value;
use std::fs;
use std::time::Instant;

#[derive(Parser)]
struct Args {
    /// 路徑：存放從 IPFS 下載的 receipt.bin
    #[arg(short, long)]
    receipt_path: String,

    /// 你的 Image ID (Verification Key)，格式為 0x...
    #[arg(short, long)]
    image_id: String,
}

fn download_from_ipfs(cid: &str) -> Vec<u8> {
    let url = format!("http://127.0.0.1:8080/ipfs/{}", cid);
    println!("[-] 正在從私有 IPFS 下載: {}", url);
    let response = reqwest::blocking::get(url)
        .expect("連線至 IPFS 失敗")
        .bytes()
        .expect("讀取資料失敗");

    response.to_vec()
}

fn main() {
    let args = Args::parse();
    let verify_start = Instant::now();
    let raw_data = if args.receipt_path.starts_with("Qm") || args.receipt_path.starts_with("ba") {
        download_from_ipfs(&args.receipt_path)
    } else {
        fs::read(&args.receipt_path).unwrap()
    };

    // --- 關鍵修正：先解析 JSON，再拿 Proof ---
    let json: Value = serde_json::from_slice(&raw_data).expect("無法解析 IPFS 下載的 JSON 資料");

    let proof_hex = json["proof"].as_str().expect("JSON 中找不到 proof 欄位");

    // 將 Hex 字串轉回 Bytes
    let proof_bytes = hex::decode(proof_hex).expect("Proof Hex 解碼失敗");
    // let inner_receipt: risc0_zkvm::InnerReceipt = bincode::deserialize(&proof_bytes)
    //     .expect("Proof 部分反序列化失敗，請確認 Prover 端的序列化對象");

    let receipt: Receipt = match bincode::deserialize::<Receipt>(&proof_bytes) {
        Ok(r) => {
            println!("[-] 偵測到完整的 Receipt 格式，直接使用。");
            r
        }
        Err(_) => {
            // 2. 如果失敗，嘗試解析為 InnerReceipt 並與 JSON 中的 journal 合併
            println!("[-] 偵測到 InnerReceipt 格式，正在從 JSON 提取 journal 並重組...");
            let inner: risc0_zkvm::InnerReceipt = bincode::deserialize(&proof_bytes)
                .expect("無法解析 Proof：格式既不符合 Receipt 也不符合 InnerReceipt");

            let journal_hex = json["journal"].as_str().expect("缺少 journal 欄位");
            let journal_bytes = hex::decode(journal_hex).expect("Journal Hex 解碼失敗");

            Receipt::new(inner, journal_bytes)
        }
    };
    // 2. 轉換 Image ID (vk)
    let image_id_str = args.image_id.trim_start_matches("0x");
    let image_id_bytes = hex::decode(image_id_str).expect("無效的 Image ID 格式");

    // RISC Zero 的 Image ID 是 [u32; 8]
    let mut image_id = [0u32; 8];
    for i in 0..8 {
        image_id[i] = u32::from_be_bytes(image_id_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    // 3. 執行驗證
    match receipt.verify(image_id) {
        Ok(_) => {
            let verifyTime = verify_start.elapsed().as_millis();
            println!("✅ [SUCCESS] 驗證成功！");
            println!("該證明確實由指定的 Guest Program 生成，且資料未經竄改。");
            println!("驗證耗時: {} ms", verifyTime);
            // 如果你想看 Merkle Root (x)，可以從 Journal 讀出
            // let root: String = receipt.journal.decode().unwrap();
            // println!("證明中的 Merkle Root 為: {}", root);
        }
        Err(e) => {
            println!("❌ [FAILED] 驗證失敗: {}", e);
            std::process::exit(1);
        }
    }
}

#![no_main]
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256, Digest};
use shared_data::{ComponentInput, MerkleInput, Severity};

risc0_zkvm::guest::entry!(main);

fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    let res = Impl::hash_bytes(&combined);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(res.as_bytes());
    arr
}

pub fn main() {
    let start = env::cycle_count();

    // 1. 讀取組件本身的資料
    let comp_input: ComponentInput = env::read();

    // 2. 讀取驗證金鑰 (Image ID)
    let my_image_id: [u32; 8] = env::read();

    // ==========================================
    // 驗證 1：遞歸驗證所有的子依賴
    // ==========================================
    for dep_hash in comp_input.dependency_hashes.iter() {
        env::verify(my_image_id, dep_hash)
            .expect("Dependency verification failed!");
    }

    // ==========================================
    // 驗證 2：驗證套件安全性 (Enum 比較速度快且資源消耗低)
    // ==========================================
    assert!(
        comp_input.severity <= Severity::Critical,
        "Severity check failed for {}", comp_input.name
    );

    // ==========================================
    // 驗證 3：使用 Merkle Path 檢查完整性
    // ==========================================
    let merkle_input: MerkleInput = env::read();
    
    let mut current_hash = comp_input.hash;
    
    for (i, sibling) in merkle_input.path_elements.iter().enumerate() {
        let is_right = merkle_input.path_indices[i] == 1;
        if is_right {
            current_hash = sha256_pair(sibling, &current_hash);
        } else {
            current_hash = sha256_pair(&current_hash, sibling);
        }
    }

    assert_eq!(
        current_hash, merkle_input.root,
        "Merkle root integrity verification failed!"
    );

    // ==========================================
    // 4. 檢查完畢，將自己的 Hash 寫入 Journal
    // ==========================================
    env::commit_slice(&comp_input.hash);

    let end = env::cycle_count();
    eprintln!("Component proven in cycles: {}", end - start);
}

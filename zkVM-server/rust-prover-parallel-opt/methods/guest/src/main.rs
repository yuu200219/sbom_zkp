#![no_main]
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256, Digest};
use shared_data::{ComponentInput, MerkleInput, Severity};

risc0_zkvm::guest::entry!(main);

#[inline(never)]
fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    let res = Impl::hash_bytes(&combined);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(res.as_bytes());
    arr
}

#[inline(never)]
fn check_dependency_hash(comp_input: &ComponentInput, my_image_id: [u32; 8]) {
    for dep_hash in comp_input.dependency_hashes.iter() {
        let mut expected_journal = [0u8; 64];
        expected_journal[..32].copy_from_slice(dep_hash);
        expected_journal[32..].copy_from_slice(&TARGET_HASH);
        env::verify(my_image_id, &expected_journal)
            .expect("Dependency verification failed!");
    }
}

#[inline(never)]
fn check_severity(severity: Severity) {
    assert!(
        severity <= Severity::Critical,
        "Severity check failed for severity level: {:?}", severity
    );
}

#[inline(never)]
fn check_merkle_path(comp_input: &ComponentInput, merkle_input: &MerkleInput) {
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
}

// simulate source hash for security testing (SHA-256 32-byte array)
const TARGET_HASH: [u8; 32] = [
    0x3c, 0xc8, 0x9f, 0xbf, 0x47, 0x46, 0x84, 0x27, 
    0xc3, 0xdb, 0xfa, 0x98, 0xc8, 0x12, 0x1a, 0x26, 
    0x65, 0xd5, 0x7d, 0x1c, 0x17, 0x38, 0x45, 0xc5, 
    0xd5, 0x68, 0xa9, 0x8c, 0x7e, 0xe7, 0xc5, 0xed
];

pub fn main() {
    let start = env::cycle_count();

    let io_start = env::cycle_count();
    // 1. 讀取組件本身的資料
    let comp_input: ComponentInput = env::read();
    // 2. 讀取驗證金鑰 (Image ID)
    let my_image_id: [u32; 8] = env::read();
    let io_end = env::cycle_count();

    eprintln!("{},IO_Read,{}", comp_input.name, io_end - io_start);

    // ==========================================
    // 驗證 1：遞歸驗證所有的子依賴
    // ==========================================
    let dep_start = env::cycle_count();
    check_dependency_hash(&comp_input, my_image_id);
    let dep_end = env::cycle_count();

    eprintln!("{},Dependency_Check,{}", comp_input.name, dep_end - dep_start);

    // ==========================================
    // 驗證 2：驗證套件安全性 (Enum 比較速度快且資源消耗低)
    // ==========================================
    let severity_start = env::cycle_count();
    check_severity(comp_input.severity);
    let severity_end = env::cycle_count();

    eprintln!("{},Severity_Check,{}", comp_input.name, severity_end - severity_start);

    // ==========================================
    // 驗證 3：使用 Merkle Path 檢查完整性
    // ==========================================
    let merkle_read_start = env::cycle_count();
    let merkle_input: MerkleInput = env::read();
    let merkle_read_end = env::cycle_count();
    eprintln!("{},Merkle_IO_Read,{}", comp_input.name, merkle_read_end - merkle_read_start);

    let merkle_check_start = env::cycle_count();
    check_merkle_path(&comp_input, &merkle_input);
    let merkle_check_end = env::cycle_count();
    eprintln!("{},Merkle_Check,{}", comp_input.name, merkle_check_end - merkle_check_start); 

    // ==========================================
    // 4. 檢查完畢，將自己的 Merkle Root 與 TARGET_HASH 寫入 Journal
    // 這是為了讓父節點能夠驗證遞歸證明，因為父節點預期驗證的是子節點的 Merkle Root 與 TARGET_HASH
    // ==========================================
    env::commit_slice(&merkle_input.root);
    env::commit_slice(&TARGET_HASH);

    let end = env::cycle_count();
    eprintln!("Component proven in cycles: {}", end - start);
}

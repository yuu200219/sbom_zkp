#![no_main]
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};
use shared_data::{ComponentInput, MerkleInput};

risc0_zkvm::guest::entry!(main);

const LICENSE_WHITELIST: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "BSD-3-Clause",
    "BSD-2-Clause",
    "ISC",
    "Unlicense",
    "CC0-1.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "MPL-2.0",
    "EPL-2.0",
];

fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    arr
}

fn next_pow2(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let mut p = 1usize;
    while p < n {
        p <<= 1;
    }
    p
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
        // 要求 Host 提供子節點的 Receipt，且其 Journal 必須正好是 dep_hash 的純位元組
        env::verify(my_image_id, dep_hash)
            .expect("Dependency verification failed! Child component missing or altered.");
    }

    // ==========================================
    // 驗證 2：驗證套件安全性
    // ==========================================
    let mut is_safe = false;
    if comp_input.severity == "Unknown" || comp_input.severity == "Low" {
        is_safe = true;
    }
    assert!(
        is_safe,
        "Component {} has unapproved vulnerability severity: {}",
        comp_input.name, comp_input.severity
    );

    // ==========================================
    // 驗證 3：驗證套件本身的授權條款
    // ==========================================
    // let mut is_legal = false;
    // for &allowed_license in LICENSE_WHITELIST {
    //     if comp_input.license.contains(allowed_license) {
    //         is_legal = true;
    //         break;
    //     }
    // }
    // assert!(
    //     is_legal,
    //     "Unapproved license in component: {}",
    //     comp_input.name
    // );

    // ==========================================
    // 驗證 4：檢查完整性 (Hash) 是否在 Merkle Tree 中
    // ==========================================
    let merkle_input: MerkleInput = env::read();

    let mut current_level = merkle_input.all_leaf_hashes;
    let real_leaf_count = current_level.len();
    let target = next_pow2(real_leaf_count);

    if target != real_leaf_count {
        while current_level.len() < target {
            current_level.push([0u8; 32]);
        }
    }

    while current_level.len() > 1 {
        let mut next_level: Vec<[u8; 32]> = Vec::new();
        for pair in current_level.chunks_exact(2) {
            next_level.push(sha256_pair(&pair[0], &pair[1]));
        }
        current_level = next_level;
    }

    assert_eq!(
        current_level[0], merkle_input.root,
        "Merkle root integrity verification failed!"
    );

    // ==========================================
    // 5. 檢查完畢，將自己的 Hash 作為純位元組寫入 Journal
    // ==========================================
    env::commit_slice(&comp_input.hash);

    let end = env::cycle_count();
    eprintln!("Component proven in cycles: {}", end - start);
}

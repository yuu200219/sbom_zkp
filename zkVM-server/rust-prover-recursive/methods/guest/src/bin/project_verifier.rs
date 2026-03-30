// methods/guest/src/bin/project_verifier.rs (或修改你原本的 main.rs)
#![no_main]
use risc0_zkvm::guest::env;
use core::MerkleInput; 
use sha2::{Digest, Sha256};

risc0_zkvm::guest::entry!(main);

// ... 保留原有的 sha256_pair 和 next_pow2 函數 ...

pub fn main() {
    let start = env::cycle_count();

    // 1. 讀取 Merkle 樹資料
    let input: MerkleInput = env::read();

    // 4. 計算 Merkle Tree (完全保留你原本的邏輯)
    let mut current_level = input.all_leaf_hashes;
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
        current_level[0], input.root,
        "Merkle root integrity verification failed!"
    );

    // 5. Commit 專案的 Merkle Root
    env::commit(&input.root);

    let end = env::cycle_count();
    eprintln!("Merkle tree verification cycles: {}", end - start);
}
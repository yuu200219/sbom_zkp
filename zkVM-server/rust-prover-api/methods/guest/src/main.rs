// methods/guest/src/main.rs
#![no_main]
use risc0_zkvm::guest::env; // 引入剛才的結構
                            // use risc0_zkvm::sha::{Impl, Sha256};
risc0_zkvm::guest::entry!(main);
use core::MerkleInput;

use sha2::{Digest, Sha256};

fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
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

    let input: MerkleInput = env::read();
    let leaves = input.all_leaf_hashes;

    let mut current_level: Vec<[u8; 32]> = leaves;

    let real_leaf_count = current_level.len();
    let target = next_pow2(real_leaf_count);

    if target != real_leaf_count {
        // padding 用 32 bytes 0，跟你 JS 的 PADDING_VALUE（64 個 '0'）一致
        while current_level.len() < target {
            current_level.push([0u8; 32]);
        }
    }

    // Check Root Hash Value
    while current_level.len() > 1 {
        let mut next_level: Vec<[u8; 32]> = Vec::new();
        for pair in current_level.chunks_exact(2) {
            let left = &pair[0];
            let right = &pair[1];
            next_level.push(sha256_pair(left, right));
        }
        current_level = next_level;
        // println!("Layer {} 完成，節點數: {}", depth, current_level.len());
    }

    let calculated_root = current_level[0];

    // if calculated_root != input.root {
    //     println!("期望的 Root: {}", hex::encode(input.root));
    //     println!("算出的 Root: {}", hex::encode(calculated_root));
    // }
    // 驗證計算出的 Root 是否等於宣稱的 Root
    assert_eq!(
        calculated_root, input.root,
        "Merkle root integrity verification failed!"
    );

    // 只要沒 panic，就代表驗證成功，把 Leaf Commit 到 Journal 證明它存在於這棵樹
    // env::commit(&input.leaf);
    // 為了匿名性，這邊在確認所有 components 都是 merkle tree member 後，commit Merkle root
    env::commit(&input.root);

    let end = env::cycle_count();
    eprintln!("Merkle tree verification cycles: {}", end - start);
    // Option: Check white/black list, according to CPE, license, etc.
}

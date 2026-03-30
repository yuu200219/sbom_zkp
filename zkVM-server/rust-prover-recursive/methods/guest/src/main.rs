// methods/guest/src/main.rs
#![no_main]
use risc0_zkvm::guest::env; // 引入剛才的結構
                            // use risc0_zkvm::sha::{Impl, Sha256};
risc0_zkvm::guest::entry!(main);

const LICENSE_WHITELIST: &[&str] = &["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", ];

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
    let leaves = input.all_leaf_hashes.clone();

    for proven_comp in input.assumptions.iter() {
        // 核心邏輯：驗證這個 ImageID 確實產生了這段 Journal
        // 只要這行不 panic，就代表底層的 ZK 證明是有效的
        env::verify(proven_comp.image_id, &proven_comp.journal)
            .expect("Assumption verification failed!");

        // 【重點安全檢查】：你需要確保這個被驗證的 Component，
        // 確實存在於你當前的 Merkle leaves 中。
        // 假設 sub-component 的 journal 就是它的 Root Hash ([u8; 32])
        let comp_hash: [u8; 32] = proven_comp.journal.as_slice().try_into().unwrap();
        assert!(
            leaves.contains(&comp_hash),
            "Proven component is not part of the current SBOM tree!"
        );
    }

    let mut current_level: Vec<[u8; 32]> = input.all_leaf_hashes;

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

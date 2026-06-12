#![no_main]
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};
use shared_data::MerkleInput;

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

pub fn main() {
    let input: MerkleInput = env::read();
    let mut current_level = input.all_leaf_hashes.clone();

    // 如果沒有任何 leaf hash，則 panic
    assert!(!current_level.is_empty(), "all_leaf_hashes cannot be empty");

    // 進行標準的兩兩雜湊，逐層往上計算，直到只剩下一個 Root 雜湊
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(sha256_pair(&chunk[0], &chunk[1]));
            } else {
                next_level.push(chunk[0]);
            }
        }
        current_level = next_level;
    }

    let computed_root = current_level.first().cloned().unwrap_or([0u8; 32]);
    assert_eq!(
        computed_root, input.root,
        "Merkle root integrity verification failed!"
    );

    // 將驗證通過的 Merkle Root 寫入 Journal，以便外部快速驗證
    env::commit_slice(&input.root);
}

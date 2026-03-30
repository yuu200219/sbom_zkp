// methods/guest/src/bin/component_verifier.rs
#![no_main]
use core::ComponentInput, MerkleInput;
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

risc0_zkvm::guest::entry!(main);

const LICENSE_WHITELIST: &[&str] = &[
    "MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", "Unlicense", "CC0-1.0", // 可以改任何程式碼，允許修改、商用、甚至閉源，唯一條件是保留原作者的版權聲明
    "LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-2.0" // 但如果你修改了該套件本身的原始碼，你就必須把修改的部分開源出來
];

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

    let input: ComponentInput = env::read();

    // 讀取 Component Verifier 自己的 Image ID (用來認證子依賴是不是也是自己這個程式產生的)
    let my_image_id: [u32; 8] = env::read();

    // ==========================================
    // 1. 遞歸驗證所有的子依賴 (Dependencies)
    // ==========================================
    for dep_hash in input.dependency_hashes.iter() {
        // 這行程式碼的意思是：「我要求底層系統證明，曾經有一個 ImageID 跟我一樣的程式，
        // 成功運行並輸出了這個 dep_hash 作為 Journal。」
        // 如果 Host 沒有把子依賴的 Receipt 傳進來，這裡就會 Panic！
        env::verify(my_image_id, dep_hash)
            .expect("Dependency verification failed! Child component is unsafe or missing.");
    }

    // ==========================================
    // 2. 驗證套件本身的安全性 (License 等)
    // ==========================================
    let mut is_legal = false;
    for &allowed_license in LICENSE_WHITELIST {
        if input.license.contains(allowed_license) {
            is_legal = true;
            break;
        }
    }
    assert!(is_legal, "Unapproved license in component: {}", input.name);

    // ==========================================
    // 3. 檢查完整性 (Hash) 是否在 Merkle Tree 中
    // ==========================================
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
    // ==========================================
    // 4. 檢查完畢，Commit 自己的 Hash
    // ==========================================
    // 當我 commit 出去後，依賴我的「父節點」就可以拿我的 Hash 去做 env::verify 了
    env::commit(&input.hash);

    let end = env::cycle_count();
    eprintln!("Merkle tree verification cycles: {}", end - start);
}

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MerkleInput {
    pub root: [u8; 32],                 // 宣稱的 Merkle Root
    pub all_leaf_hashes: Vec<[u8; 32]>, // SBOM 中所有的組件雜湊 (按順序)
    pub assumptions: Vec<ProvenComponent>,
}
pub struct ComponentInput {
    pub name: String,
    pub hash: [u8; 32], // 自己這個套件的 Hash
    pub license: String,
    // 新增：這個套件「所依賴的子套件」的 Hash 列表
    pub dependency_hashes: Vec<[u8; 32]>,
}

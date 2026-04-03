use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComponentInput {
    pub name: String,
    pub hash: [u8; 32],
    pub version: String,
    pub license: String,
    pub severity: String,
    pub dependency_hashes: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleInput {
    pub root: [u8; 32],                 // 宣稱的 Merkle Root
    pub all_leaf_hashes: Vec<[u8; 32]>, // SBOM 中所有的組件雜湊 (按順序)
}

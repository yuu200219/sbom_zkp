use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, PartialOrd)]
pub enum Severity {
    Unknown = 0,
    Negligible = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComponentInput {
    pub name: String,
    pub hash: [u8; 32],
    pub version: String,
    pub license: String,
    pub severity: Severity,
    pub comp_type: String,
    pub dependency_hashes: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleInput {
    pub root: [u8; 32],
    pub path_elements: Vec<[u8; 32]>,
    pub path_indices: Vec<u32>, // 0 for left, 1 for right
}

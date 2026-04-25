use sha2::{Digest as Sha2Digest, Sha256};

fn main() {
    let left = [1u8; 32];
    let right = [2u8; 32];
    
    let mut h = Sha256::new();
    h.update(&left);
    h.update(&right);
    let res1 = h.finalize();
    
    // We can't easily compile risc0_zkvm guest code on host for testing Impl::hash_bytes 
    // unless we use risc0-zkvm on host.
}

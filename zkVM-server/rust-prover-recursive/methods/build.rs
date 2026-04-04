use risc0_build::{embed_methods_with_options, DockerOptions, GuestOptions};
use std::collections::HashMap;
use std::path::PathBuf;

fn main() {
    // 取得專案根目錄的絕對路徑 (假設 methods 是根目錄下的一層)
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let root_dir = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();

    let mut docker_options = DockerOptions::default();
    // 關鍵點：將 Docker 的工作目錄設為整個專案的根目錄
    docker_options.root_dir = Some(root_dir);

    let mut guest_options = GuestOptions::default();
    guest_options.use_docker = Some(docker_options);

    embed_methods_with_options(HashMap::from([
        ("guest_code_for_zkp", guest_options),
    ]));
}
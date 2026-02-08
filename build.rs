use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-cfg=control_flow_flattening");
    println!("cargo:rustc-cfg=release_optimizations");
    println!("cargo:rustc-cfg=string_encryption");
    if env::var("PROFILE").unwrap_or_default() == "release" {
        println!("cargo:rustc-link-arg=-s");
        println!("cargo:rustc-link-arg=-Wl,--strip-all");
        println!("cargo:rustc-link-arg=-Wl,--build-id=none");
    }
    generate_build_metadata();
    apply_instruction_substitution();
}

fn generate_build_metadata() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let metadata_path = out_dir.join("build_metadata.rs");
    let timestamp = chrono::Utc::now().to_rfc3339();
    let git_hash = get_git_hash();
    let build_id = uuid::Uuid::new_v4().to_string();
    let metadata = format!(
        r#"
pub const BUILD_TIMESTAMP: &str = "{}";
pub const GIT_HASH: &str = "{}";
pub const BUILD_ID: &str = "{}";
"#,
        timestamp, git_hash, build_id
    );
    fs::write(metadata_path, metadata).expect("Failed to write build metadata");
}

fn get_git_hash() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn apply_instruction_substitution() {
    println!("cargo:rustc-cfg=aggressive_optimizations");
    println!("cargo:rustc-cfg=function_inlining");
    println!("cargo:rustc-cfg=loop_unrolling");
}

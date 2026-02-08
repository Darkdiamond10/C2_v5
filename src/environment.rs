use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone)]
pub struct EnvironmentFingerprint {
    machine_id: String,
    mac_address: String,
    username: String,
    inode: u64,
}

impl EnvironmentFingerprint {
    pub fn collect() -> Result<Self> {
        let machine_id = Self::get_machine_id()?;
        let mac_address = Self::get_mac_address()?;
        let username = Self::get_username()?;
        let inode = Self::get_inode()?;
        Ok(EnvironmentFingerprint {
            machine_id,
            mac_address,
            username,
            inode,
        })
    }
    
    fn get_machine_id() -> Result<String> {
        let content = fs::read_to_string("/etc/machine-id")
            .map_err(|e| anyhow!("Failed to read machine-id: {}", e))?;
        Ok(content.trim().to_string())
    }

    fn get_mac_address() -> Result<String> {
        let output = Command::new("sh")
            .arg("-c")
            .arg("cat /sys/class/net/eth0/address 2>/dev/null || cat /sys/class/net/enp0s3/address 2>/dev/null || cat /sys/class/net/ens33/address 2>/dev/null || echo '00:00:00:00:00:00'")
            .output()
            .map_err(|e| anyhow!("Failed to get MAC address: {}", e))?;
        let mac = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if mac.is_empty() || mac == "00:00:00:00:00:00" {
            return Err(anyhow!("No valid MAC address found"));
        }
        Ok(mac)
    }
    
    fn get_username() -> Result<String> {
        std::env::var("USER")
            .map_err(|e| anyhow!("Failed to get username: {}", e))
    }

    fn get_inode() -> Result<u64> {
        let metadata = fs::metadata("/etc/passwd")
            .map_err(|e| anyhow!("Failed to get /etc/passwd metadata: {}", e))?;
        #[cfg(unix)]
        {
            Ok(metadata.ino())
        }
        #[cfg(not(unix))]
        {
            Ok(0)
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.machine_id.as_bytes());
        hasher.update(self.mac_address.as_bytes());
        hasher.update(self.username.as_bytes());
        hasher.update(self.inode.to_le_bytes());
        hasher.finalize().to_vec()
    }
    
    pub fn verify(&self, expected_fingerprint: &[u8]) -> bool {
        let current = self.to_bytes();
        current == expected_fingerprint
    }
}

pub struct EnvironmentalLock {
    fingerprint: EnvironmentFingerprint,
    salt: [u8; 32],
}

impl EnvironmentalLock {
    pub fn new(salt: [u8; 32]) -> Result<Self> {
        let fingerprint = EnvironmentFingerprint::collect()?;
        Ok(EnvironmentalLock {
            fingerprint,
            salt,
        })
    }
    
    pub fn derive_key(&self) -> Result<[u8; 32]> {
        let fingerprint_bytes = self.fingerprint.to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(&fingerprint_bytes);
        let combined = hasher.finalize();
        let mut key_hasher = Sha256::new();
        key_hasher.update(&combined);
        key_hasher.update(b"SOPHIA_ENV_KEY_2024");
        let key_bytes = key_hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(key)
    }

    pub fn get_fingerprint(&self) -> &EnvironmentFingerprint {
        &self.fingerprint
    }
}

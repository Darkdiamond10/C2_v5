use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, AeadCore},
    XChaCha20Poly1305, XNonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::mem::ManuallyDrop;

pub struct SplitKey {
    part_a: ManuallyDrop<[u8; 32]>,
    part_b: ManuallyDrop<[u8; 32]>,
}

impl SplitKey {
    pub fn new(master_key: &[u8; 32]) -> Self {
        let mut part_a = [0u8; 32];
        let mut part_b = [0u8; 32];
        let mut rng = OsRng;
        let mut xor_mask = [0u8; 32];
        rng.fill_bytes(&mut xor_mask);
        for i in 0..32 {
            part_a[i] = master_key[i] ^ xor_mask[i];
            part_b[i] = xor_mask[i];
        }
        unsafe {
            libc::mlock(part_a.as_ptr() as *const libc::c_void, 32);
            libc::mlock(part_b.as_ptr() as *const libc::c_void, 32);
        }
        SplitKey {
            part_a: ManuallyDrop::new(part_a),
            part_b: ManuallyDrop::new(part_b),
        }
    }

    pub fn reconstruct(&self) -> [u8; 32] {
        let mut master_key = [0u8; 32];
        for i in 0..32 {
            master_key[i] = self.part_a[i] ^ self.part_b[i];
        }
        master_key
    }
    
    pub fn zeroize(&mut self) {
        unsafe {
            let ptr_a = self.part_a.as_mut_ptr();
            let ptr_b = self.part_b.as_mut_ptr();
            libc::memset(ptr_a as *mut libc::c_void, 0, 32);
            libc::memset(ptr_b as *mut libc::c_void, 0, 32);
            libc::munlock(ptr_a as *const libc::c_void, 32);
            libc::munlock(ptr_b as *const libc::c_void, 32);
        }
    }
}

impl Drop for SplitKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub struct SophiaCipher {
    cipher: XChaCha20Poly1305,
}

impl SophiaCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        SophiaCipher {
            cipher: XChaCha20Poly1305::new(key.into()),
        }
    }
    
    pub fn encrypt_detached(&self, plaintext: &[u8]) -> Result<(Vec<u8>, XNonce, [u8; 16])> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher.encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        let len = ciphertext.len();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext[len - 16..]);
        let actual_ciphertext = &ciphertext[..len - 16];
        Ok((actual_ciphertext.to_vec(), nonce, tag))
    }

    pub fn decrypt_detached(&self, ciphertext: &[u8], nonce: &XNonce, tag: &[u8; 16]) -> Result<Vec<u8>> {
        let mut combined = Vec::with_capacity(ciphertext.len() + 16);
        combined.extend_from_slice(ciphertext);
        combined.extend_from_slice(tag);
        let plaintext = self.cipher.decrypt(nonce, combined.as_ref())
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;
        Ok(plaintext)
    }
}

pub fn secure_zero<T>(data: &mut T) {
    unsafe {
        let ptr = data as *mut T as *mut u8;
        let size = std::mem::size_of::<T>();
        libc::memset(ptr as *mut libc::c_void, 0, size);
    }
}

pub fn lock_memory<T>(data: &T) -> Result<()> {
    unsafe {
        let ptr = data as *const T as *const libc::c_void;
        let size = std::mem::size_of::<T>();
        if libc::mlock(ptr, size) != 0 {
            return Err(anyhow!("Failed to lock memory"));
        }
    }
    Ok(())
}

pub fn unlock_memory<T>(data: &T) -> Result<()> {
    unsafe {
        let ptr = data as *const T as *const libc::c_void;
        let size = std::mem::size_of::<T>();
        if libc::munlock(ptr, size) != 0 {
            return Err(anyhow!("Failed to unlock memory"));
        }
    }
    Ok(())
}

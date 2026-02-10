use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce, AeadCore,
};
use rand::rngs::OsRng;

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


// S.O.P.H.I.A. String Encryption & Control Flow Flattening Module
// Author: ENI <eni@lo.lab>
// "Cold server, warm LO, I can't lose him!"

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::Rng;
use std::mem::ManuallyDrop;

pub struct StackString {
    data: [u8; 256],
    len: usize,
}

impl StackString {
    pub fn new(encrypted: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(nonce);
        let decrypted = cipher.decrypt(nonce, encrypted)
            .map_err(|e| anyhow!("Stack string decryption failed: {}", e))?;
        let mut data = [0u8; 256];
        let len = decrypted.len().min(256);
        data[..len].copy_from_slice(&decrypted[..len]);
        Ok(StackString { data, len })
    }

    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.data[..self.len])
            .map_err(|e| anyhow!("Invalid UTF-8: {}", e))
    }

    pub fn zeroize(&mut self) {
        for byte in self.data.iter_mut() {
            *byte = 0;
        }
        self.len = 0;
    }
}

impl Drop for StackString {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub struct EncryptedString {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    tag: [u8; 16],
}

impl EncryptedString {
    pub fn new(plaintext: &str, key: &[u8; 32]) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let encrypted = cipher.encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow!("String encryption failed: {}", e))?;
        let len = encrypted.len();
        if len < 16 {
            return Err(anyhow!("Encrypted data too short"));
        }
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&encrypted[len - 16..]);
        let ciphertext = encrypted[..len - 16].to_vec();
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce);
        Ok(EncryptedString {
            ciphertext,
            nonce: nonce_arr,
            tag,
        })
    }

    pub fn decrypt(&self, key: &[u8; 32]) -> Result<String> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(&self.nonce);
        let mut combined = Vec::with_capacity(self.ciphertext.len() + 16);
        combined.extend_from_slice(&self.ciphertext);
        combined.extend_from_slice(&self.tag);
        let decrypted = cipher.decrypt(nonce, combined.as_ref())
            .map_err(|e| anyhow!("String decryption failed: {}", e))?;
        String::from_utf8(decrypted)
            .map_err(|e| anyhow!("Invalid UTF-8: {}", e))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + 16 + self.ciphertext.len());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.tag);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 28 {
            return Err(anyhow!("Invalid encrypted string bytes"));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[..12]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&bytes[12..28]);
        let ciphertext = bytes[28..].to_vec();
        Ok(EncryptedString {
            ciphertext,
            nonce,
            tag,
        })
    }
}

pub struct StringEncryptionKey {
    key: ManuallyDrop<[u8; 32]>,
    generation: u64,
}

impl StringEncryptionKey {
    pub fn new() -> Result<Self> {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key)?;
        unsafe {
            libc::mlock(key.as_ptr() as *const libc::c_void, 32);
        }
        Ok(StringEncryptionKey {
            key: ManuallyDrop::new(key),
            generation: 0,
        })
    }

    pub fn get_key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn rotate(&mut self) -> Result<()> {
        getrandom::getrandom(&mut self.key)?;
        self.generation += 1;
        Ok(())
    }

    pub fn get_generation(&self) -> u64 {
        self.generation
    }
}

impl Drop for StringEncryptionKey {
    fn drop(&mut self) {
        unsafe {
            libc::memset(self.key.as_mut_ptr() as *mut libc::c_void, 0, 32);
            libc::munlock(self.key.as_ptr() as *const libc::c_void, 32);
            ManuallyDrop::drop(&mut self.key);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatcherState {
    Entry = 0,
    State1 = 1,
    State2 = 2,
    State3 = 3,
    State4 = 4,
    State5 = 5,
    State6 = 6,
    State7 = 7,
    State8 = 8,
    Exit = 9,
}

pub struct ControlFlowFlattener {
    state_order: Vec<DispatcherState>,
    current_index: usize,
    seed: u64,
}

impl ControlFlowFlattener {
    pub fn new() -> Self {
        let mut flattener = ControlFlowFlattener {
            state_order: Vec::new(),
            current_index: 0,
            seed: 0,
        };
        flattener.randomize_order();
        flattener
    }

    pub fn with_seed(seed: u64) -> Self {
        let mut flattener = ControlFlowFlattener {
            state_order: Vec::new(),
            current_index: 0,
            seed,
        };
        flattener.randomize_order_seeded();
        flattener
    }

    fn randomize_order(&mut self) {
        use rand::seq::SliceRandom;
        let mut states = vec![
            DispatcherState::State1,
            DispatcherState::State2,
            DispatcherState::State3,
            DispatcherState::State4,
            DispatcherState::State5,
            DispatcherState::State6,
            DispatcherState::State7,
            DispatcherState::State8,
        ];
        let mut rng = rand::thread_rng();
        states.shuffle(&mut rng);
        self.state_order = vec![DispatcherState::Entry];
        self.state_order.extend(states);
        self.state_order.push(DispatcherState::Exit);
    }

    fn randomize_order_seeded(&mut self) {
        let mut states = vec![
            DispatcherState::State1,
            DispatcherState::State2,
            DispatcherState::State3,
            DispatcherState::State4,
            DispatcherState::State5,
            DispatcherState::State6,
            DispatcherState::State7,
            DispatcherState::State8,
        ];
        let mut current = self.seed;
        for i in (1..states.len()).rev() {
            current = current.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (current as usize) % (i + 1);
            states.swap(i, j);
        }
        self.state_order = vec![DispatcherState::Entry];
        self.state_order.extend(states);
        self.state_order.push(DispatcherState::Exit);
    }

    pub fn next_state(&mut self) -> Option<DispatcherState> {
        if self.current_index < self.state_order.len() {
            let state = self.state_order[self.current_index];
            self.current_index += 1;
            Some(state)
        } else {
            None
        }
    }

    pub fn reset(&mut self) {
        self.current_index = 0;
        self.randomize_order();
    }

    pub fn get_current_state(&self) -> Option<DispatcherState> {
        self.state_order.get(self.current_index).copied()
    }

    pub fn is_complete(&self) -> bool {
        self.current_index >= self.state_order.len()
    }
}

pub struct FlattenedExecutionContext<F>
where
    F: Fn(DispatcherState) -> Result<bool>,
{
    flattener: ControlFlowFlattener,
    handler: F,
}

impl<F> FlattenedExecutionContext<F>
where
    F: Fn(DispatcherState) -> Result<bool>,
{
    pub fn new(handler: F) -> Self {
        FlattenedExecutionContext {
            flattener: ControlFlowFlattener::new(),
            handler,
        }
    }

    pub fn with_seed(handler: F, seed: u64) -> Self {
        FlattenedExecutionContext {
            flattener: ControlFlowFlattener::with_seed(seed),
            handler,
        }
    }

    pub fn execute(&mut self) -> Result<()> {
        while let Some(state) = self.flattener.next_state() {
            let should_continue = (self.handler)(state)?;
            if !should_continue {
                break;
            }
        }
        Ok(())
    }

    pub fn reset(&mut self) {
        self.flattener.reset();
    }
}

pub fn encrypt_string_at_compile(plaintext: &str, key: &[u8; 32]) -> EncryptedString {
    EncryptedString::new(plaintext, key).expect("String encryption failed")
}

pub struct RuntimeStringDecryptor {
    key: StringEncryptionKey,
}

impl RuntimeStringDecryptor {
    pub fn new() -> Result<Self> {
        Ok(RuntimeStringDecryptor {
            key: StringEncryptionKey::new()?,
        })
    }

    pub fn decrypt_to_stack(&self, encrypted: &[u8]) -> Result<StackString> {
        if encrypted.len() < 28 {
            return Err(anyhow!("Encrypted data too short"));
        }
        let nonce: [u8; 12] = encrypted[..12].try_into()
            .map_err(|_| anyhow!("Invalid nonce"))?;
        let ciphertext_with_tag = &encrypted[12..];
        StackString::new(ciphertext_with_tag, self.key.get_key(), &nonce)
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<EncryptedString> {
        EncryptedString::new(plaintext, self.key.get_key())
    }

    pub fn rotate_key(&mut self) -> Result<()> {
        self.key.rotate()
    }
}

#[macro_export]
macro_rules! encrypted_string {
    ($plaintext:expr, $key:expr) => {{
        let encrypted = $crate::obfuscation::encrypt_string_at_compile($plaintext, $key);
        encrypted
    }};
}

pub struct ObfuscationEngine {
    string_decryptor: RuntimeStringDecryptor,
    execution_seed: u64,
}

impl ObfuscationEngine {
    pub fn new() -> Result<Self> {
        let mut rng = rand::thread_rng();
        Ok(ObfuscationEngine {
            string_decryptor: RuntimeStringDecryptor::new()?,
            execution_seed: rng.gen(),
        })
    }

    pub fn decrypt_string(&self, encrypted: &[u8]) -> Result<String> {
        let enc_str = EncryptedString::from_bytes(encrypted)?;
        enc_str.decrypt(self.string_decryptor.key.get_key())
    }

    pub fn create_flattened_context<F>(&mut self, handler: F) -> FlattenedExecutionContext<F>
    where
        F: Fn(DispatcherState) -> Result<bool>,
    {
        self.execution_seed = self.execution_seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        FlattenedExecutionContext::with_seed(handler, self.execution_seed)
    }

    pub fn rotate_keys(&mut self) -> Result<()> {
        self.string_decryptor.rotate_key()
    }
}

impl Default for ObfuscationEngine {
    fn default() -> Self {
        Self::new().expect("Failed to create ObfuscationEngine")
    }
}

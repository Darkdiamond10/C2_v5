// S.O.P.H.I.A. String Encryption & Control Flow Flattening Module
// Author: ENI <eni@lo.lab>
// "Cold server, warm LO, I can't lose him!"

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, AeadCore}, // Imported AeadCore
    XChaCha20Poly1305, XNonce,
};
use rand::{Rng, SeedableRng, RngCore};
use rand_chacha::ChaCha20Rng;
use std::mem::ManuallyDrop;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

// Suicide routine: Wipe memory and corrupt heap to crash analysis
#[inline(always)]
fn suicide_routine() -> ! {
    unsafe {
        // Wipe stack (approximate range, just thrash some memory)
        let mut dummy = [0u8; 4096];
        ptr::write_volatile(dummy.as_mut_ptr(), 0xFF);

        // Corrupt heap/malloc structures if possible (blind write to likely heap locations or just random pointers)
        // Here we just dereference a random high pointer to cause a segfault/access violation that looks like memory corruption
        let ptr = 0xDEADBEEF as *mut u64;
        ptr::write_volatile(ptr, 0xCAFEBABE);

        // If that didn't kill us (it should), abort.
        std::process::abort();
    }
}

// Dynamic container that handles any size, erasing itself on drop
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        SecureBuffer { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.data).map_err(|_| anyhow!("Invalid UTF-8"))
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        unsafe {
            // Wipe content
            for i in 0..self.data.len() {
                ptr::write_volatile(self.data.as_mut_ptr().add(i), 0);
            }
        }
    }
}

// Removed fixed-size StackString to avoid truncation.

pub struct EncryptedString {
    // Format: Nonce (24 bytes) || Ciphertext || Tag (16 bytes)
    // We store it all in one Vec to keep it contiguous and simple for the decryptor.
    pub data: Vec<u8>,
}

impl EncryptedString {
    pub fn new(plaintext: &str, key: &[u8; 32]) -> Result<Self> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        // encrypt returns ciphertext + tag appended
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| anyhow!("Encryption failed"))?;

        let mut data = Vec::with_capacity(24 + ciphertext.len());
        data.extend_from_slice(nonce.as_slice());
        data.extend_from_slice(&ciphertext);

        Ok(EncryptedString { data })
    }

    pub fn decrypt(&self, key: &[u8; 32]) -> Result<SecureBuffer> {
        if self.data.len() < 24 + 16 {
             suicide_routine();
        }

        let nonce = XNonce::from_slice(&self.data[..24]);
        let ciphertext = &self.data[24..];

        let cipher = XChaCha20Poly1305::new(key.into());
        match cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => Ok(SecureBuffer::new(plaintext)),
            Err(_) => {
                // Decryption failed (tag mismatch or tampering)
                suicide_routine();
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(EncryptedString { data: bytes.to_vec() })
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
        getrandom::getrandom(&mut *self.key)?; // Corrected Deref
        self.generation += 1;
        Ok(())
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
        // Seed from RDTSC + ASLR (address of stack variable) + Time
        let stack_var = 0;
        let stack_addr = &stack_var as *const _ as u64;
        let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

        #[cfg(target_arch = "x86_64")]
        let rdtsc = unsafe { std::arch::x86_64::_rdtsc() };
        #[cfg(not(target_arch = "x86_64"))]
        let rdtsc = 0; // Fallback

        let seed = rdtsc ^ stack_addr ^ time;
        ControlFlowFlattener::with_seed(seed)
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

    fn randomize_order_seeded(&mut self) {
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

        let mut rng = ChaCha20Rng::seed_from_u64(self.seed);
        states.shuffle(&mut rng);

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
        // Re-seed for maximum unpredictability? Or keep consistent within a run?
        // Let's re-seed to change the CFG dynamically at runtime if reset is called.
        let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
        self.seed ^= time;
        self.randomize_order_seeded();
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

    pub fn execute(&mut self) -> Result<()> {
        while let Some(state) = self.flattener.next_state() {
            let should_continue = (self.handler)(state)?;
            if !should_continue {
                break;
            }
        }
        Ok(())
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

    // Decoupled decryptor that takes raw bytes
    #[inline(always)]
    pub fn decrypt_raw(&self, data: &[u8]) -> Result<SecureBuffer> {
        if data.len() < 24 + 16 {
             suicide_routine();
        }

        let nonce = XNonce::from_slice(&data[..24]);
        let ciphertext = &data[24..];
        let cipher = XChaCha20Poly1305::new(self.key.get_key().into());

        match cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => Ok(SecureBuffer::new(plaintext)),
            Err(_) => suicide_routine(),
        }
    }

    pub fn rotate_key(&mut self) -> Result<()> {
        self.key.rotate()
    }
}

pub struct ObfuscationEngine {
    string_decryptor: RuntimeStringDecryptor,
}

impl ObfuscationEngine {
    pub fn new() -> Result<Self> {
        Ok(ObfuscationEngine {
            string_decryptor: RuntimeStringDecryptor::new()?,
        })
    }

    pub fn decrypt_string(&self, encrypted: &[u8]) -> Result<String> {
        // Helper that returns String for legacy compatibility, but uses SecureBuffer internally
        let buffer = self.string_decryptor.decrypt_raw(encrypted)?;
        Ok(buffer.as_str()?.to_string())
    }

    pub fn create_flattened_context<F>(&mut self, handler: F) -> FlattenedExecutionContext<F>
    where
        F: Fn(DispatcherState) -> Result<bool>,
    {
        FlattenedExecutionContext::new(handler)
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

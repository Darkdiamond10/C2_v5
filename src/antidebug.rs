use anyhow::{anyhow, Result};
use libc::{pid_t, prctl, PR_GET_DUMPABLE, PR_SET_DUMPABLE, PR_SET_PTRACER};
use nix::sys::ptrace;
use nix::unistd::{fork, ForkResult, Pid};
use std::process;
use std::thread;
use std::time::Duration;
use rand::Rng;

pub struct AntiDebugConfig {
    pub enable_ptrace_check: bool,
    pub enable_parent_check: bool,
    pub enable_tracer_check: bool,
    pub enable_dumpable_check: bool,
    pub suicide_on_detection: bool,
}
impl Default for AntiDebugConfig {
    fn default() -> Self {
        AntiDebugConfig {
            enable_ptrace_check: true,
            enable_parent_check: true,
            enable_tracer_check: true,
            enable_dumpable_check: true,
            suicide_on_detection: true,
        }
    }
}
pub struct AntiDebugMonitor {
    config: AntiDebugConfig,
    child_pid: Option<Pid>,
}

impl AntiDebugMonitor {
    pub fn new(config: AntiDebugConfig) -> Self {
        AntiDebugMonitor {
            config,
            child_pid: None,
        }
    }
    
    pub fn start(&mut self) -> Result<()> {
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                self.child_pid = Some(child);
                self.monitor_child()?;
                Ok(())
            }
            Ok(ForkResult::Child) => {
                self.run_child_checks()?;
                Ok(())
            }
            Err(e) => Err(anyhow!("Fork failed: {}", e)),
        }
    }
    
    fn monitor_child(&self) -> Result<()> {
        if let Some(child_pid) = self.child_pid {
            loop {
                match nix::sys::wait::waitpid(Some(child_pid), None) {
                    Ok(_) => {
                        break;
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        }
        Ok(())
    }

    fn run_child_checks(&self) -> Result<()> {
        if self.config.enable_ptrace_check {
            self.check_ptrace()?;
        }
        if self.config.enable_parent_check {
            self.check_parent()?;
        }
        if self.config.enable_tracer_check {
            self.check_tracer()?;
        }
        if self.config.enable_dumpable_check {
            self.check_dumpable()?;
        }
        Ok(())
    }
    
    fn check_ptrace(&self) -> Result<()> {
        match ptrace::attach(Pid::from_raw(process::id() as i32)) {
            Ok(_) => {
                ptrace::detach(Pid::from_raw(process::id() as i32), None)?;
                Ok(())
            }
            Err(_) => {
                if self.config.suicide_on_detection {
                    self.suicide("ptrace check failed");
                }
                Err(anyhow!("ptrace check failed"))
            }
        }
    }
    
    fn check_parent(&self) -> Result<()> {
        let ppid = unsafe { libc::getppid() };
        let parent_name = self.get_process_name(ppid)?;
        let debuggers = vec![
            "gdb",
            "lldb",
            "strace",
            "ltrace",
            "valgrind",
            "rr",
        ];
        if debuggers.iter().any(|d| parent_name.contains(d)) {
            if self.config.suicide_on_detection {
                self.suicide("debugger detected in parent");
            }
            return Err(anyhow!("Debugger detected in parent: {}", parent_name));
        }
        Ok(())
    }
    
    fn check_tracer(&self) -> Result<()> {
        let tracer = unsafe { prctl(PR_SET_PTRACER, 0, 0, 0, 0) };
        if tracer < 0 {
            if self.config.suicide_on_detection {
                self.suicide("tracer detected");
            }
            return Err(anyhow!("Tracer detected"));
        }
        Ok(())
    }

    fn check_dumpable(&self) -> Result<()> {
        let dumpable = unsafe { prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) };
        if dumpable == 0 {
            if self.config.suicide_on_detection {
                self.suicide("core dumps disabled");
            }
            return Err(anyhow!("Core dumps disabled"));
        }
        Ok(())
    }
    
    fn get_process_name(&self, pid: pid_t) -> Result<String> {
        let path = format!("/proc/{}/comm", pid);
        let content = std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("Failed to read {}: {}", path, e))?;
        Ok(content.trim().to_string())
    }
    
    fn suicide(&self, reason: &str) {
        self.perform_random_tasks();
        eprintln!("Suicide: {}", reason);
        process::exit(1);
    }

    fn perform_random_tasks(&self) {
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let size = rng.gen_range(1024..65536);
            let _vec: Vec<u8> = vec![0; size];
        }
        for _ in 0..5 {
            let temp_path = format!("/tmp/sophia_temp_{}", rng.gen::<u32>());
            let _ = std::fs::write(&temp_path, b"random data");
            let _ = std::fs::remove_file(&temp_path);
        }
        let duration = Duration::from_millis(rng.gen_range(100..1000));
        thread::sleep(duration);
    }
}

pub fn disable_core_dumps() -> Result<()> {
    unsafe {
        if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0 {
            return Err(anyhow!("Failed to disable core dumps"));
        }
    }
    Ok(())
}
pub fn check_vm_environment() -> Result<()> {
    let vm_indicators = vec![
        "/proc/vz",
        "/proc/xen",
        "/sys/class/dmi/id/product_name",
    ];
    for indicator in &vm_indicators {
        if std::path::Path::new(indicator).exists() {
            if let Ok(content) = std::fs::read_to_string(indicator) {
                let content_lower = content.to_lowercase();
                if content_lower.contains("vmware") ||
                   content_lower.contains("virtualbox") ||
                   content_lower.contains("qemu") ||
                   content_lower.contains("kvm") ||
                   content_lower.contains("xen") ||
                   content_lower.contains("parallels") {
                    return Err(anyhow!("VM environment detected"));
                }
            }
        }
    }
    Ok(())
}

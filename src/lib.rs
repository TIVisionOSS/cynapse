//! # Cynapse — Binary Memory Integrity Monitor
//!
//! **Real-time, memory-resident binary integrity verification for Rust applications.**
//!
//! Cynapse continuously validates executable memory segments to detect runtime injection,
//! tampering, or in-memory patching — providing a self-defending layer for secure,
//! high-assurance software.
//!
//! ## Overview
//!
//! Modern attacks often target live memory: code injection, API hooking, shellcode placement,
//! or silent function patching. **Cynapse** is designed to **detect and mitigate in-memory
//! tampering** at runtime.
//!
//! It works by:
//! 1. Mapping executable memory regions of your process
//! 2. Computing a Merkle-tree-based checksum baseline
//! 3. Continuously verifying page integrity while your application runs
//! 4. Executing callbacks (alert, self-heal, or terminate) when tampering is detected
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use cynapse::Monitor;
//! use std::time::Duration;
//!
//! let mut monitor = Monitor::new()
//!     .with_interval(Duration::from_secs(3))
//!     .on_tamper(|segment, diff| {
//!         eprintln!("[ALERT] Tampering detected in {:?}", segment);
//!     });
//!
//! monitor.start();
//!
//! // Your application logic continues...
//! loop {
//!     std::thread::sleep(Duration::from_secs(1));
//! }
//! ```
//!
//! ## Advanced Configuration
//!
//! ```rust,no_run
//! use cynapse::{Monitor, TamperResponse, WhitelistPolicy};
//! use std::time::Duration;
//!
//! let monitor = Monitor::builder()
//!     .interval(Duration::from_secs(2))
//!     .enable_merkle_trees(true)
//!     .adaptive_sampling(true)
//!     .whitelist_jit_regions(WhitelistPolicy::ByPattern(vec![".jit".to_string()]))
//!     .enable_forensics(true)
//!     .build()
//!     .expect("Failed to initialize monitor");
//!
//! monitor.start();
//! ```
//!
//! ## Security Model
//!
//! Cynapse detects and mitigates:
//! - Code injection and patching
//! - DLL/SO injection
//! - ROP chains and shellcode execution
//! - Inline API hooking (depending on page granularity)
//!
//! It explicitly allows:
//! - JIT compilation (when whitelisted)
//! - Self-modifying code (when whitelisted)
//!
//! ## Platform Support
//!
//! - **Linux**: Via `/proc/self/maps` and direct memory reading
//! - **Windows**: Via `VirtualQuery` and memory APIs
//! - **macOS**: Via Mach kernel APIs
//!
//! ## Safety
//!
//! This crate contains minimal `unsafe` code, isolated to platform-specific memory reading.
//! All unsafe blocks are documented with safety invariants and have been validated with Miri.

#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(dead_code)] // Remove after full implementation

use std::time::Duration;
use thiserror::Error;

// Core modules
pub mod core;
pub use core::{monitor::Monitor, monitor::MonitorBuilder};

// Platform abstraction
mod platform;

// Optional modules
#[cfg(feature = "remote-attestation")]
pub mod attestation;

pub mod utils;

// Re-exports
pub use core::{
    forensics::ForensicSnapshot,
    hasher::{HashAlgorithm, MerkleTree},
    mapper::{MemorySegment, SegmentPermissions},
    monitor::MonitorHandle,
};

/// Errors that can occur during monitor operations
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to initialize the monitor
    #[error("Monitor initialization failed: {0}")]
    InitializationFailed(String),

    /// Failed to map memory segments
    #[error("Memory mapping failed: {0}")]
    MappingFailed(String),

    /// Failed to compute hash
    #[error("Hashing failed: {0}")]
    HashingFailed(String),

    /// Tampering detected
    #[error("Tampering detected in segment: {0}")]
    TamperingDetected(String),

    /// Platform-specific error
    #[error("Platform error: {0}")]
    PlatformError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Monitor already running
    #[error("Monitor is already running")]
    AlreadyRunning,

    /// Monitor not running
    #[error("Monitor is not running")]
    NotRunning,
}

/// Result type for cynapse operations
pub type Result<T> = std::result::Result<T, Error>;

/// Configuration for the integrity monitor
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Verification interval (how often to check for tampering)
    pub interval: Duration,

    /// Enable Merkle tree optimization for faster verification
    pub use_merkle: bool,

    /// Hash algorithm to use
    pub hash_algorithm: HashAlgorithm,

    /// Enable adaptive sampling (adjust interval based on risk)
    pub adaptive: bool,

    /// JIT region whitelist policy
    pub whitelist_policy: WhitelistPolicy,

    /// Enable forensic snapshots on tampering detection
    pub enable_forensics: bool,

    /// Maximum snapshot size in bytes
    pub max_snapshot_size: usize,

    /// Tamper response strategy
    pub response: TamperResponse,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(3),
            use_merkle: true,
            hash_algorithm: HashAlgorithm::Blake3,
            adaptive: false,
            whitelist_policy: WhitelistPolicy::None,
            enable_forensics: false,
            max_snapshot_size: 10 * 1024 * 1024, // 10 MB
            response: TamperResponse::Alert,
        }
    }
}

/// Policy for whitelisting legitimate self-modifying code
#[derive(Debug, Clone)]
pub enum WhitelistPolicy {
    /// No whitelisting
    None,

    /// Whitelist segments matching specific patterns (e.g., ".jit", ".v8")
    ByPattern(Vec<String>),

    /// Whitelist specific address ranges
    ByAddressRange(Vec<(usize, usize)>),

    /// Custom whitelist function
    Custom,
}

/// Response action when tampering is detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamperResponse {
    /// Log the event and continue
    Log,

    /// Alert (log + invoke callbacks) and continue
    Alert,

    /// Attempt to restore from baseline
    Restore,

    /// Terminate the process immediately
    Terminate,
}

/// Information about detected tampering
#[derive(Debug, Clone)]
pub struct TamperInfo {
    /// The affected memory segment
    pub segment: MemorySegment,

    /// Byte positions that differ from baseline
    pub differences: Vec<u8>,

    /// Original hash
    pub original_hash: Vec<u8>,

    /// Current hash
    pub current_hash: Vec<u8>,

    /// Timestamp of detection
    pub timestamp: std::time::SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MonitorConfig::default();
        assert_eq!(config.interval, Duration::from_secs(3));
        assert!(config.use_merkle);
        assert_eq!(config.response, TamperResponse::Alert);
    }

    #[test]
    fn test_tamper_response_variants() {
        assert_eq!(TamperResponse::Log, TamperResponse::Log);
        assert_ne!(TamperResponse::Log, TamperResponse::Alert);
    }
}

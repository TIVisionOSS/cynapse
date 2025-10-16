//! Core functionality for memory integrity monitoring
//!
//! This module contains the fundamental building blocks:
//! - `mapper`: Memory segment enumeration and mapping
//! - `hasher`: Page hashing and Merkle tree construction
//! - `monitor`: Integrity monitoring and verification loop
//! - `signals`: Signal and exception handling
//! - `forensics`: Snapshot and analysis tools

pub mod hasher;
pub mod mapper;
pub mod monitor;
pub mod signals;

#[cfg(feature = "forensics")]
pub mod forensics;

#[cfg(not(feature = "forensics"))]
pub mod forensics {
    //! Stub for forensics when feature is disabled

    /// Placeholder forensic snapshot type
    #[derive(Debug, Clone)]
    pub struct ForensicSnapshot;
}

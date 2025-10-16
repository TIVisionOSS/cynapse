//! Remote attestation and cryptographic proof generation
//!
//! This module provides optional remote attestation capabilities for distributed systems.

#[cfg(feature = "remote-attestation")]
pub mod crypto;

#[cfg(feature = "remote-attestation")]
pub mod remote;

#[cfg(not(feature = "remote-attestation"))]
pub mod crypto {
    //! Stub for crypto when feature is disabled
}

#[cfg(not(feature = "remote-attestation"))]
pub mod remote {
    //! Stub for remote attestation when feature is disabled
}

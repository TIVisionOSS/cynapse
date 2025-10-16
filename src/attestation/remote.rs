//! Remote attestation protocol
//!
//! Provides mechanisms for generating and verifying cryptographic proofs of integrity.

#[cfg(feature = "remote-attestation")]
use crate::{attestation::crypto::AttestationKeys, core::hasher::MerkleTree, Error, Result};

#[cfg(feature = "remote-attestation")]
use serde::{Deserialize, Serialize};

/// An attestation proof that can be verified remotely
#[cfg(feature = "remote-attestation")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationProof {
    /// Merkle root hash
    pub root_hash: Vec<u8>,

    /// Timestamp of attestation
    pub timestamp: u64,

    /// Signature over (root_hash || timestamp)
    pub signature: Vec<u8>,

    /// Public key used for signing
    pub public_key: Vec<u8>,

    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
}

#[cfg(feature = "remote-attestation")]
impl AttestationProof {
    /// Create a new attestation proof from a Merkle tree
    pub fn new(tree: &MerkleTree, keys: &AttestationKeys) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut message = tree.root_hash().to_vec();
        message.extend_from_slice(&timestamp.to_le_bytes());

        let signature = keys.sign(&message);
        let public_key = keys.public_key();

        Self {
            root_hash: tree.root_hash().to_vec(),
            timestamp,
            signature,
            public_key,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Verify the proof signature
    pub fn verify(&self, keys: &AttestationKeys) -> Result<()> {
        let mut message = self.root_hash.clone();
        message.extend_from_slice(&self.timestamp.to_le_bytes());

        keys.verify(&message, &self.signature)
    }

    /// Add metadata to the proof
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| Error::PlatformError(format!("Failed to serialize proof: {}", e)))
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| Error::PlatformError(format!("Failed to deserialize proof: {}", e)))
    }
}

#[cfg(test)]
#[cfg(feature = "remote-attestation")]
mod tests {
    use super::*;
    use crate::core::hasher::{HashAlgorithm, MerkleTree};

    #[test]
    fn test_create_proof() {
        let hashes = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let tree = MerkleTree::from_hashes(hashes, HashAlgorithm::Blake3);
        let keys = AttestationKeys::generate();

        let proof = AttestationProof::new(&tree, &keys);
        assert!(!proof.root_hash.is_empty());
        assert!(!proof.signature.is_empty());
    }

    #[test]
    fn test_verify_proof() {
        let hashes = vec![vec![1, 2, 3]];
        let tree = MerkleTree::from_hashes(hashes, HashAlgorithm::Blake3);
        let keys = AttestationKeys::generate();

        let proof = AttestationProof::new(&tree, &keys);
        assert!(proof.verify(&keys).is_ok());
    }

    #[test]
    fn test_json_serialization() {
        let hashes = vec![vec![1, 2, 3]];
        let tree = MerkleTree::from_hashes(hashes, HashAlgorithm::Blake3);
        let keys = AttestationKeys::generate();

        let proof = AttestationProof::new(&tree, &keys);
        let json = proof.to_json().unwrap();
        let deserialized = AttestationProof::from_json(&json).unwrap();

        assert_eq!(proof.root_hash, deserialized.root_hash);
        assert_eq!(proof.timestamp, deserialized.timestamp);
    }
}

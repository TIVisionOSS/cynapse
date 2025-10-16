//! Page hashing and Merkle tree construction
//!
//! This module provides:
//! - Efficient page-by-page hashing
//! - Merkle tree construction for hierarchical verification
//! - Differential hashing for change detection

use crate::{Error, Result};
use std::fmt;

/// Hash algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// BLAKE3 (default, fastest)
    Blake3,
    /// SHA-256 (widely compatible)
    Sha256,
}

impl HashAlgorithm {
    /// Hash data using the selected algorithm
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            #[cfg(feature = "blake3-hash")]
            HashAlgorithm::Blake3 => {
                let hash = blake3::hash(data);
                hash.as_bytes().to_vec()
            }
            #[cfg(not(feature = "blake3-hash"))]
            HashAlgorithm::Blake3 => {
                panic!("BLAKE3 feature not enabled");
            }

            #[cfg(feature = "sha256-hash")]
            HashAlgorithm::Sha256 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            #[cfg(not(feature = "sha256-hash"))]
            HashAlgorithm::Sha256 => {
                panic!("SHA-256 feature not enabled");
            }
        }
    }

    /// Get the output size in bytes
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Blake3 => 32,
            HashAlgorithm::Sha256 => 32,
        }
    }

    /// Get the algorithm name
    pub fn name(&self) -> &'static str {
        match self {
            HashAlgorithm::Blake3 => "BLAKE3",
            HashAlgorithm::Sha256 => "SHA-256",
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Page size for hashing (4KB standard)
pub const PAGE_SIZE: usize = 4096;

/// A hashed memory page
#[derive(Debug, Clone)]
pub struct HashedPage {
    /// Page address
    pub address: usize,

    /// Hash of page contents
    pub hash: Vec<u8>,

    /// Size of the page
    pub size: usize,
}

impl HashedPage {
    /// Create a new hashed page
    pub fn new(address: usize, hash: Vec<u8>, size: usize) -> Self {
        Self {
            address,
            hash,
            size,
        }
    }

    /// Compare with another hash
    pub fn matches(&self, other_hash: &[u8]) -> bool {
        self.hash == other_hash
    }
}

/// Merkle tree for hierarchical hash verification
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Root hash
    pub root: Vec<u8>,

    /// Leaf hashes (bottom level)
    pub leaves: Vec<Vec<u8>>,

    /// Internal nodes (organized by level)
    pub nodes: Vec<Vec<Vec<u8>>>,

    /// Algorithm used
    pub algorithm: HashAlgorithm,
}

impl MerkleTree {
    /// Build a Merkle tree from page hashes
    pub fn from_hashes(hashes: Vec<Vec<u8>>, algorithm: HashAlgorithm) -> Self {
        if hashes.is_empty() {
            return Self {
                root: vec![0; algorithm.output_size()],
                leaves: Vec::new(),
                nodes: Vec::new(),
                algorithm,
            };
        }

        let mut current_level = hashes.clone();
        let mut all_nodes = Vec::new();

        // Build tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    [&chunk[0][..], &chunk[1][..]].concat()
                } else {
                    // Odd number, duplicate last hash
                    [&chunk[0][..], &chunk[0][..]].concat()
                };

                next_level.push(algorithm.hash(&combined));
            }

            all_nodes.push(current_level.clone());
            current_level = next_level;
        }

        let root = current_level
            .into_iter()
            .next()
            .unwrap_or_else(|| vec![0; algorithm.output_size()]);

        Self {
            root,
            leaves: hashes,
            nodes: all_nodes,
            algorithm,
        }
    }

    /// Verify a leaf hash is part of the tree
    pub fn verify_leaf(&self, index: usize, hash: &[u8]) -> bool {
        if index >= self.leaves.len() {
            return false;
        }
        self.leaves[index] == hash
    }

    /// Get the root hash
    pub fn root_hash(&self) -> &[u8] {
        &self.root
    }

    /// Total number of leaves
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
}

/// Hash engine for computing page hashes
pub struct HashEngine {
    algorithm: HashAlgorithm,
    page_size: usize,
}

impl HashEngine {
    /// Create a new hash engine
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            page_size: PAGE_SIZE,
        }
    }

    /// Hash a single page
    pub fn hash_page(&self, data: &[u8], address: usize) -> Result<HashedPage> {
        if data.is_empty() {
            return Err(Error::HashingFailed("Empty data".to_string()));
        }

        let hash = self.algorithm.hash(data);
        Ok(HashedPage::new(address, hash, data.len()))
    }

    /// Hash multiple pages from a memory region
    pub fn hash_pages(&self, data: &[u8], start_address: usize) -> Result<Vec<HashedPage>> {
        let mut pages = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let chunk_size = std::cmp::min(self.page_size, data.len() - offset);
            let chunk = &data[offset..offset + chunk_size];
            let address = start_address + offset;

            let page = self.hash_page(chunk, address)?;
            pages.push(page);

            offset += chunk_size;
        }

        Ok(pages)
    }

    /// Build a Merkle tree from memory data
    pub fn build_merkle_tree(&self, pages: &[HashedPage]) -> MerkleTree {
        let hashes: Vec<Vec<u8>> = pages.iter().map(|p| p.hash.clone()).collect();
        MerkleTree::from_hashes(hashes, self.algorithm)
    }

    /// Compare two sets of pages and find differences
    pub fn find_differences(&self, baseline: &[HashedPage], current: &[HashedPage]) -> Vec<usize> {
        let mut differences = Vec::new();

        for (i, (base, curr)) in baseline.iter().zip(current.iter()).enumerate() {
            if base.address == curr.address && !base.matches(&curr.hash) {
                differences.push(i);
            }
        }

        differences
    }

    /// Get the hash algorithm
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
}

impl Default for HashEngine {
    fn default() -> Self {
        Self::new(HashAlgorithm::Blake3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm() {
        let algo = HashAlgorithm::Blake3;
        let data = b"test data";
        let hash1 = algo.hash(data);
        let hash2 = algo.hash(data);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), algo.output_size());
    }

    #[test]
    fn test_hash_page() {
        let engine = HashEngine::new(HashAlgorithm::Blake3);
        let data = vec![0u8; 4096];
        let page = engine.hash_page(&data, 0x1000).unwrap();

        assert_eq!(page.address, 0x1000);
        assert_eq!(page.size, 4096);
        assert!(!page.hash.is_empty());
    }

    #[test]
    fn test_merkle_tree_empty() {
        let tree = MerkleTree::from_hashes(vec![], HashAlgorithm::Blake3);
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn test_merkle_tree_single() {
        let hash = vec![1, 2, 3, 4];
        let tree = MerkleTree::from_hashes(vec![hash.clone()], HashAlgorithm::Blake3);
        assert_eq!(tree.leaf_count(), 1);
        assert!(tree.verify_leaf(0, &hash));
    }

    #[test]
    fn test_merkle_tree_multiple() {
        let hashes = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]];
        let tree = MerkleTree::from_hashes(hashes.clone(), HashAlgorithm::Blake3);

        assert_eq!(tree.leaf_count(), 3);
        assert!(tree.verify_leaf(0, &hashes[0]));
        assert!(tree.verify_leaf(1, &hashes[1]));
        assert!(tree.verify_leaf(2, &hashes[2]));
    }

    #[test]
    fn test_find_differences() {
        let engine = HashEngine::new(HashAlgorithm::Blake3);
        let data1 = vec![0u8; 4096];
        let data2 = vec![1u8; 4096];

        let page1 = engine.hash_page(&data1, 0x1000).unwrap();
        let page2 = engine.hash_page(&data2, 0x1000).unwrap();

        let diffs = engine.find_differences(&[page1.clone()], &[page2]);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0], 0);

        let no_diffs = engine.find_differences(&[page1.clone()], &[page1]);
        assert_eq!(no_diffs.len(), 0);
    }
}

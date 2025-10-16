//! Memory operation integration tests

use cynapse::core::{
    mapper::{MemoryMapper, SegmentPermissions},
    hasher::{HashEngine, HashAlgorithm},
};

#[test]
fn test_enumerate_segments() {
    let mut mapper = MemoryMapper::new().unwrap();
    let segments = mapper.enumerate_executable_segments();

    assert!(segments.is_ok());
    let segs = segments.unwrap();
    
    // Should have at least one executable segment
    assert!(!segs.is_empty());
    
    // All returned segments should be executable
    for seg in segs {
        assert!(seg.is_executable());
    }
}

#[test]
fn test_read_memory_from_segment() {
    // Read from a safe stack variable instead of arbitrary memory
    let test_data: [u8; 64] = [0x42; 64];
    let address = test_data.as_ptr() as usize;
    
    let mapper = MemoryMapper::new().unwrap();
    let result = mapper.read_page(address, 64);
    
    assert!(result.is_ok());
    let data = result.unwrap();
    assert_eq!(data.len(), 64);
    assert_eq!(&data[..], &test_data[..]);
}

#[test]
fn test_hash_memory_pages() {
    let engine = HashEngine::new(HashAlgorithm::Blake3);
    let data = vec![0u8; 8192]; // Two pages
    
    let pages = engine.hash_pages(&data, 0x1000).unwrap();
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].address, 0x1000);
    assert_eq!(pages[1].address, 0x2000);
}

#[test]
fn test_merkle_tree_construction() {
    let engine = HashEngine::new(HashAlgorithm::Blake3);
    let data = vec![0xAA; 16384]; // 4 pages
    
    let pages = engine.hash_pages(&data, 0x1000).unwrap();
    let tree = engine.build_merkle_tree(&pages);
    
    assert_eq!(tree.leaf_count(), 4);
    assert!(!tree.root_hash().is_empty());
}

#[test]
fn test_detect_modifications() {
    let engine = HashEngine::new(HashAlgorithm::Blake3);
    
    let original_data = vec![0u8; 4096];
    let modified_data = vec![1u8; 4096];
    
    let original_pages = engine.hash_pages(&original_data, 0x1000).unwrap();
    let modified_pages = engine.hash_pages(&modified_data, 0x1000).unwrap();
    
    let differences = engine.find_differences(&original_pages, &modified_pages);
    
    // Should detect that the page was modified
    assert!(!differences.is_empty());
}

#[test]
fn test_segment_permissions() {
    let perms = SegmentPermissions::executable();
    assert!(perms.read);
    assert!(perms.execute);
    assert!(!perms.write);
}

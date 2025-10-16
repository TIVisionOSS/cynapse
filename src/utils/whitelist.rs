//! Whitelist utilities for legitimate self-modifying code
//!
//! Provides helpers for managing whitelists of JIT regions and dynamic code.

use crate::core::mapper::MemorySegment;
use std::collections::HashSet;

/// Whitelist manager for segments that should not be monitored
pub struct WhitelistManager {
    patterns: HashSet<String>,
    address_ranges: Vec<(usize, usize)>,
}

impl WhitelistManager {
    /// Create a new whitelist manager
    pub fn new() -> Self {
        Self {
            patterns: HashSet::new(),
            address_ranges: Vec::new(),
        }
    }

    /// Add a pattern to whitelist (e.g., ".jit", ".v8")
    pub fn add_pattern(&mut self, pattern: String) {
        self.patterns.insert(pattern);
    }

    /// Add an address range to whitelist
    pub fn add_address_range(&mut self, start: usize, end: usize) {
        self.address_ranges.push((start, end));
    }

    /// Check if a segment should be whitelisted
    pub fn should_whitelist(&self, segment: &MemorySegment) -> bool {
        // Check pattern matches
        for pattern in &self.patterns {
            if segment.name.contains(pattern) {
                return true;
            }
        }

        // Check address range matches
        for (start, end) in &self.address_ranges {
            if segment.start >= *start && segment.end <= *end {
                return true;
            }
        }

        false
    }

    /// Add common JIT patterns (V8, JVM, etc.)
    pub fn add_common_jit_patterns(&mut self) {
        let patterns = vec![
            ".jit", "jit", "v8", ".v8", "java", "jvm", "dotnet", "mono", "node", "deno",
        ];

        for pattern in patterns {
            self.add_pattern(pattern.to_string());
        }
    }

    /// Clear all whitelists
    pub fn clear(&mut self) {
        self.patterns.clear();
        self.address_ranges.clear();
    }

    /// Get count of whitelist entries
    pub fn entry_count(&self) -> usize {
        self.patterns.len() + self.address_ranges.len()
    }
}

impl Default for WhitelistManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mapper::SegmentPermissions;

    fn create_segment(name: &str, start: usize, end: usize) -> MemorySegment {
        MemorySegment::new(
            start,
            end,
            SegmentPermissions::executable(),
            name.to_string(),
            0,
        )
    }

    #[test]
    fn test_pattern_whitelist() {
        let mut manager = WhitelistManager::new();
        manager.add_pattern(".jit".to_string());

        let jit_segment = create_segment("module.jit.code", 0x1000, 0x2000);
        let normal_segment = create_segment("module.text", 0x3000, 0x4000);

        assert!(manager.should_whitelist(&jit_segment));
        assert!(!manager.should_whitelist(&normal_segment));
    }

    #[test]
    fn test_address_range_whitelist() {
        let mut manager = WhitelistManager::new();
        manager.add_address_range(0x1000, 0x2000);

        let inside_segment = create_segment("test", 0x1500, 0x1800);
        let outside_segment = create_segment("test", 0x3000, 0x4000);

        assert!(manager.should_whitelist(&inside_segment));
        assert!(!manager.should_whitelist(&outside_segment));
    }

    #[test]
    fn test_common_jit_patterns() {
        let mut manager = WhitelistManager::new();
        manager.add_common_jit_patterns();

        let v8_segment = create_segment("v8.code", 0x1000, 0x2000);
        let jvm_segment = create_segment("java.hotspot", 0x3000, 0x4000);

        assert!(manager.should_whitelist(&v8_segment));
        assert!(manager.should_whitelist(&jvm_segment));
    }

    #[test]
    fn test_clear() {
        let mut manager = WhitelistManager::new();
        manager.add_pattern(".jit".to_string());
        manager.add_address_range(0x1000, 0x2000);

        assert_eq!(manager.entry_count(), 2);

        manager.clear();
        assert_eq!(manager.entry_count(), 0);
    }
}

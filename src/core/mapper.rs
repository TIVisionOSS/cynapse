//! Memory segment mapping and enumeration
//!
//! This module provides cross-platform abstractions for:
//! - Enumerating executable memory regions
//! - Reading memory contents
//! - Tracking segment metadata

use crate::Result;
use std::fmt;

/// Represents a mapped memory segment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemorySegment {
    /// Start address
    pub start: usize,

    /// End address (exclusive)
    pub end: usize,

    /// Memory permissions
    pub permissions: SegmentPermissions,

    /// Segment name/path (e.g., binary name, library path)
    pub name: String,

    /// Offset in file (if mapped from file)
    pub offset: usize,
}

impl MemorySegment {
    /// Create a new memory segment
    pub fn new(
        start: usize,
        end: usize,
        permissions: SegmentPermissions,
        name: String,
        offset: usize,
    ) -> Self {
        Self {
            start,
            end,
            permissions,
            name,
            offset,
        }
    }

    /// Size of the segment in bytes
    pub fn size(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Check if the segment is executable
    pub fn is_executable(&self) -> bool {
        self.permissions.execute
    }

    /// Check if address is within this segment
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Get page-aligned start address
    pub fn page_aligned_start(&self) -> usize {
        self.start & !0xFFF // Align to 4KB pages
    }

    /// Get page-aligned size
    pub fn page_aligned_size(&self) -> usize {
        let aligned_start = self.page_aligned_start();
        let aligned_end = (self.end + 0xFFF) & !0xFFF;
        aligned_end - aligned_start
    }
}

impl fmt::Display for MemorySegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:016x}-{:016x} {} {}",
            self.start, self.end, self.permissions, self.name
        )
    }
}

/// Memory permissions for a segment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentPermissions {
    /// Readable
    pub read: bool,

    /// Writable
    pub write: bool,

    /// Executable
    pub execute: bool,

    /// Shared mapping
    pub shared: bool,
}

impl SegmentPermissions {
    /// Create new permissions
    pub fn new(read: bool, write: bool, execute: bool, shared: bool) -> Self {
        Self {
            read,
            write,
            execute,
            shared,
        }
    }

    /// Permissions for typical executable code (.text)
    pub fn executable() -> Self {
        Self::new(true, false, true, false)
    }

    /// Parse from Linux-style permission string (e.g., "r-xp")
    pub fn from_linux_string(s: &str) -> Self {
        let chars: Vec<char> = s.chars().collect();
        Self {
            read: chars.first() == Some(&'r'),
            write: chars.get(1) == Some(&'w'),
            execute: chars.get(2) == Some(&'x'),
            shared: chars.get(3) == Some(&'s'),
        }
    }
}

impl fmt::Display for SegmentPermissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' },
            if self.shared { 's' } else { 'p' }
        )
    }
}

/// Memory mapper for enumerating and reading memory segments
#[derive(Default)]
pub struct MemoryMapper {
    segments: Vec<MemorySegment>,
}

impl MemoryMapper {
    /// Create a new memory mapper
    pub fn new() -> Result<Self> {
        Ok(Self {
            segments: Vec::new(),
        })
    }

    /// Enumerate all executable memory segments
    pub fn enumerate_executable_segments(&mut self) -> Result<Vec<MemorySegment>> {
        log::debug!("Enumerating executable memory segments");

        self.segments = crate::platform::enumerate_segments()?
            .into_iter()
            .filter(|seg| seg.is_executable())
            .collect();

        log::info!("Found {} executable segments", self.segments.len());
        Ok(self.segments.clone())
    }

    /// Get all mapped segments
    pub fn segments(&self) -> &[MemorySegment] {
        &self.segments
    }

    /// Read memory from a segment
    pub fn read_segment(&self, segment: &MemorySegment) -> Result<Vec<u8>> {
        crate::platform::read_memory(segment.start, segment.size())
    }

    /// Read a specific page from memory
    pub fn read_page(&self, address: usize, size: usize) -> Result<Vec<u8>> {
        crate::platform::read_memory(address, size)
    }

    /// Get segment containing the given address
    pub fn segment_at(&self, address: usize) -> Option<&MemorySegment> {
        self.segments.iter().find(|seg| seg.contains(address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_creation() {
        let seg = MemorySegment::new(
            0x1000,
            0x2000,
            SegmentPermissions::executable(),
            "test".to_string(),
            0,
        );

        assert_eq!(seg.size(), 0x1000);
        assert!(seg.is_executable());
        assert!(seg.contains(0x1500));
        assert!(!seg.contains(0x2000));
    }

    #[test]
    fn test_permissions_parsing() {
        let perms = SegmentPermissions::from_linux_string("r-xp");
        assert!(perms.read);
        assert!(!perms.write);
        assert!(perms.execute);
        assert!(!perms.shared);

        assert_eq!(perms.to_string(), "r-xp");
    }

    #[test]
    fn test_page_alignment() {
        let seg = MemorySegment::new(
            0x1234,
            0x3456,
            SegmentPermissions::executable(),
            "test".to_string(),
            0,
        );

        assert_eq!(seg.page_aligned_start(), 0x1000);
        assert!(seg.page_aligned_size() >= seg.size());
    }
}

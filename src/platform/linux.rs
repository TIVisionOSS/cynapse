//! Linux-specific memory operations using /proc/self/maps
//!
//! This module implements memory enumeration and reading for Linux systems.

use crate::{
    core::mapper::{MemorySegment, SegmentPermissions},
    Error, Result,
};
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

/// Parse a single line from /proc/self/maps
///
/// Format: address perms offset dev inode pathname
/// Example: 00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/dbus-daemon
fn parse_maps_line(line: &str) -> Option<MemorySegment> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    // Parse address range
    let addr_parts: Vec<&str> = parts[0].split('-').collect();
    if addr_parts.len() != 2 {
        return None;
    }

    let start = usize::from_str_radix(addr_parts[0], 16).ok()?;
    let end = usize::from_str_radix(addr_parts[1], 16).ok()?;

    // Parse permissions
    let permissions = SegmentPermissions::from_linux_string(parts[1]);

    // Parse offset
    let offset = usize::from_str_radix(parts[2], 16).ok()?;

    // Get pathname (if exists)
    let name = if parts.len() > 5 {
        parts[5..].join(" ")
    } else {
        "[anonymous]".to_string()
    };

    Some(MemorySegment::new(start, end, permissions, name, offset))
}

/// Enumerate all memory segments by reading /proc/self/maps
pub fn enumerate_segments() -> Result<Vec<MemorySegment>> {
    let file = File::open("/proc/self/maps")
        .map_err(|e| Error::PlatformError(format!("Failed to open /proc/self/maps: {}", e)))?;

    let reader = BufReader::new(file);
    let mut segments = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if let Some(segment) = parse_maps_line(&line) {
            segments.push(segment);
        }
    }

    log::debug!("Enumerated {} memory segments on Linux", segments.len());
    Ok(segments)
}

/// Read memory directly from the current process
///
/// # Safety
///
/// This reads from arbitrary memory addresses within our own process.
/// The address must be valid and readable, or this will cause a segfault.
pub fn read_memory(address: usize, size: usize) -> Result<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0u8; size];

    // SAFETY: We're reading from our own process memory.
    // The caller must ensure the address range is valid and readable.
    // If not, this will segfault, but that's the expected behavior for invalid reads.
    unsafe {
        let src = address as *const u8;
        std::ptr::copy_nonoverlapping(src, buffer.as_mut_ptr(), size);
    }

    Ok(buffer)
}

/// Alternative implementation using /proc/self/mem
/// This is safer as it goes through the kernel, but requires appropriate permissions
#[allow(dead_code)]
pub fn read_memory_via_proc(address: usize, size: usize) -> Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = File::open("/proc/self/mem")
        .map_err(|e| Error::PlatformError(format!("Failed to open /proc/self/mem: {}", e)))?;

    file.seek(SeekFrom::Start(address as u64))?;

    let mut buffer = vec![0u8; size];
    file.read_exact(&mut buffer)?;

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_maps_line() {
        let line = "00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/test";
        let segment = parse_maps_line(line).unwrap();

        assert_eq!(segment.start, 0x00400000);
        assert_eq!(segment.end, 0x00452000);
        assert!(segment.permissions.read);
        assert!(!segment.permissions.write);
        assert!(segment.permissions.execute);
        assert_eq!(segment.name, "/usr/bin/test");
    }

    #[test]
    fn test_parse_maps_line_anonymous() {
        let line = "7ffff7dd7000-7ffff7dfc000 r--p 00000000 00:00 0";
        let segment = parse_maps_line(line).unwrap();

        assert_eq!(segment.start, 0x7ffff7dd7000);
        assert_eq!(segment.name, "[anonymous]");
    }

    #[test]
    fn test_enumerate_segments() {
        let result = enumerate_segments();
        assert!(result.is_ok());

        let segments = result.unwrap();
        assert!(!segments.is_empty());

        // At least one segment should be executable (our own code)
        let has_executable = segments.iter().any(|s| s.is_executable());
        assert!(has_executable);
    }

    #[test]
    fn test_read_memory() {
        // Read from a known safe location (stack variable)
        let test_data: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let address = test_data.as_ptr() as usize;

        let result = read_memory(address, 16);
        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data.len(), 16);
        assert_eq!(&data[..], &test_data[..]);
    }
}

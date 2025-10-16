//! Platform-specific memory access implementations
//!
//! This module provides a unified interface for platform-specific operations:
//! - Memory segment enumeration
//! - Direct memory reading
//! - Platform-specific initialization

use crate::{core::mapper::MemorySegment, Result};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "macos")]
mod macos;

/// Enumerate all memory segments for the current process
pub fn enumerate_segments() -> Result<Vec<MemorySegment>> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "linux")] {
            linux::enumerate_segments()
        } else if #[cfg(target_os = "windows")] {
            windows::enumerate_segments()
        } else if #[cfg(target_os = "macos")] {
            macos::enumerate_segments()
        } else {
            Err(crate::Error::PlatformError("Unsupported platform".into()))
        }
    }
}

/// Read memory from the specified address
///
/// # Safety
///
/// This function reads from arbitrary memory addresses. The caller must ensure:
/// - The address range is valid and readable
/// - The memory is not being concurrently modified in an unsafe way
/// - The size does not cause overflow
pub fn read_memory(address: usize, size: usize) -> Result<Vec<u8>> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "linux")] {
            linux::read_memory(address, size)
        } else if #[cfg(target_os = "windows")] {
            windows::read_memory(address, size)
        } else if #[cfg(target_os = "macos")] {
            macos::read_memory(address, size)
        } else {
            Err(crate::Error::PlatformError("Unsupported platform".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_segments() {
        let segments = enumerate_segments();
        // Should succeed or fail gracefully
        match segments {
            Ok(segs) => {
                // On most platforms, we should have at least one executable segment
                assert!(!segs.is_empty(), "Expected at least one memory segment");
            }
            Err(_) => {
                // Some platforms might not support this
            }
        }
    }
}

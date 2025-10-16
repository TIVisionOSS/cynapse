//! Windows-specific memory operations using VirtualQuery
//!
//! This module implements memory enumeration and reading for Windows systems.

use crate::{
    core::mapper::{MemorySegment, SegmentPermissions},
    Error, Result,
};

#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::{GetLastError, HANDLE},
    System::{
        Diagnostics::Debug::{ReadProcessMemory, MEMORY_BASIC_INFORMATION},
        Memory::{
            VirtualQuery, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS,
        },
        Threading::{GetCurrentProcess, GetModuleFileNameA},
    },
};

/// Convert Windows page protection flags to our SegmentPermissions
#[cfg(target_os = "windows")]
fn permissions_from_protect(protect: PAGE_PROTECTION_FLAGS) -> SegmentPermissions {
    let value = protect.0;

    let execute = (value & PAGE_EXECUTE.0) != 0
        || (value & PAGE_EXECUTE_READ.0) != 0
        || (value & PAGE_EXECUTE_READWRITE.0) != 0
        || (value & PAGE_EXECUTE_WRITECOPY.0) != 0;

    let write = (value & PAGE_EXECUTE_READWRITE.0) != 0 || (value & PAGE_EXECUTE_WRITECOPY.0) != 0;

    let read = (value & PAGE_EXECUTE_READ.0) != 0
        || (value & PAGE_EXECUTE_READWRITE.0) != 0
        || (value & PAGE_EXECUTE_WRITECOPY.0) != 0;

    SegmentPermissions::new(read, write, execute, false)
}

/// Enumerate all memory segments using VirtualQuery
#[cfg(target_os = "windows")]
pub fn enumerate_segments() -> Result<Vec<MemorySegment>> {
    let mut segments = Vec::new();
    let mut address: usize = 0;

    unsafe {
        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQuery(
                Some(address as *const std::ffi::c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                break;
            }

            let start = mbi.BaseAddress as usize;
            let size = mbi.RegionSize;
            let end = start + size;
            let permissions = permissions_from_protect(mbi.Protect);

            // Get module name if available
            let mut module_name = vec![0u8; 260];
            let name = if GetModuleFileNameA(
                windows::Win32::Foundation::HINSTANCE(mbi.AllocationBase as isize),
                &mut module_name,
            ) > 0
            {
                String::from_utf8_lossy(&module_name)
                    .trim_end_matches('\0')
                    .to_string()
            } else {
                format!("[{:016x}]", start)
            };

            segments.push(MemorySegment::new(start, end, permissions, name, 0));

            address = end;

            // Prevent infinite loop
            if address == 0 || address >= usize::MAX - size {
                break;
            }
        }
    }

    log::debug!("Enumerated {} memory segments on Windows", segments.len());
    Ok(segments)
}

/// Read memory using ReadProcessMemory
#[cfg(target_os = "windows")]
pub fn read_memory(address: usize, size: usize) -> Result<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0;

    unsafe {
        let process = GetCurrentProcess();
        let result = ReadProcessMemory(
            process,
            address as *const std::ffi::c_void,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            size,
            Some(&mut bytes_read),
        );

        if result.is_err() {
            let error = GetLastError();
            return Err(Error::PlatformError(format!(
                "ReadProcessMemory failed: {:?}",
                error
            )));
        }

        if bytes_read != size {
            return Err(Error::PlatformError(format!(
                "Partial read: {} of {} bytes",
                bytes_read, size
            )));
        }
    }

    Ok(buffer)
}

// Stub implementations for non-Windows platforms
#[cfg(not(target_os = "windows"))]
pub fn enumerate_segments() -> Result<Vec<MemorySegment>> {
    Err(Error::PlatformError(
        "Windows-only function called on non-Windows platform".into(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn read_memory(_address: usize, _size: usize) -> Result<Vec<u8>> {
    Err(Error::PlatformError(
        "Windows-only function called on non-Windows platform".into(),
    ))
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_segments_windows() {
        let result = enumerate_segments();
        assert!(result.is_ok());

        let segments = result.unwrap();
        assert!(!segments.is_empty());
    }

    #[test]
    fn test_read_memory_windows() {
        let segments = enumerate_segments().unwrap();
        let executable = segments.iter().find(|s| s.is_executable());

        if let Some(segment) = executable {
            let result = read_memory(segment.start, 16);
            assert!(result.is_ok());
        }
    }
}

//! macOS-specific memory operations using Mach kernel APIs
//!
//! This module implements memory enumeration and reading for macOS systems.

use crate::{
    core::mapper::{MemorySegment, SegmentPermissions},
    Error, Result,
};

#[cfg(target_os = "macos")]
use mach2::{
    kern_return::KERN_SUCCESS,
    mach_types::{vm_address_t, vm_size_t},
    vm::{mach_vm_read, mach_vm_region_recurse},
    vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE},
    vm_region::{
        vm_region_submap_info_64, vm_region_submap_short_info_64, VM_REGION_SUBMAP_INFO_COUNT_64,
    },
};

/// Convert Mach VM protection flags to our SegmentPermissions
#[cfg(target_os = "macos")]
fn permissions_from_vm_prot(prot: i32) -> SegmentPermissions {
    SegmentPermissions::new(
        (prot & VM_PROT_READ) != 0,
        (prot & VM_PROT_WRITE) != 0,
        (prot & VM_PROT_EXECUTE) != 0,
        false,
    )
}

/// Enumerate all memory segments using mach_vm_region_recurse
#[cfg(target_os = "macos")]
pub fn enumerate_segments() -> Result<Vec<MemorySegment>> {
    use mach2::traps::mach_task_self;

    let mut segments = Vec::new();
    let task = unsafe { mach_task_self() };
    let mut address: vm_address_t = 0;

    loop {
        let mut size: vm_size_t = 0;
        let mut depth: u32 = 0;
        let mut info = unsafe { std::mem::zeroed::<vm_region_submap_info_64>() };
        let mut count = VM_REGION_SUBMAP_INFO_COUNT_64;

        let kr = unsafe {
            mach_vm_region_recurse(
                task,
                &mut address,
                &mut size,
                &mut depth,
                &mut info as *mut _ as *mut i32,
                &mut count,
            )
        };

        if kr != KERN_SUCCESS {
            break;
        }

        let start = address as usize;
        let end = start + (size as usize);
        let permissions = permissions_from_vm_prot(info.protection);

        // Generate a name based on address (we could enhance this with dyld info)
        let name = format!("[{:016x}]", start);

        segments.push(MemorySegment::new(
            start,
            end,
            permissions,
            name,
            info.offset as usize,
        ));

        // Move to next region
        address += size;
        if address == 0 {
            break;
        }
    }

    log::debug!("Enumerated {} memory segments on macOS", segments.len());
    Ok(segments)
}

/// Read memory using mach_vm_read
#[cfg(target_os = "macos")]
pub fn read_memory(address: usize, size: usize) -> Result<Vec<u8>> {
    use mach2::traps::mach_task_self;

    if size == 0 {
        return Ok(Vec::new());
    }

    let task = unsafe { mach_task_self() };
    let mut data: vm_address_t = 0;
    let mut data_count: u32 = 0;

    let kr = unsafe {
        mach_vm_read(
            task,
            address as vm_address_t,
            size as vm_size_t,
            &mut data,
            &mut data_count,
        )
    };

    if kr != KERN_SUCCESS {
        return Err(Error::PlatformError(format!(
            "mach_vm_read failed with code: {}",
            kr
        )));
    }

    // Copy the data
    let mut buffer = vec![0u8; size];
    unsafe {
        std::ptr::copy_nonoverlapping(
            data as *const u8,
            buffer.as_mut_ptr(),
            std::cmp::min(size, data_count as usize),
        );
    }

    Ok(buffer)
}

// Stub implementations for non-macOS platforms
#[cfg(not(target_os = "macos"))]
pub fn enumerate_segments() -> Result<Vec<MemorySegment>> {
    Err(Error::PlatformError(
        "macOS-only function called on non-macOS platform".into(),
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn read_memory(_address: usize, _size: usize) -> Result<Vec<u8>> {
    Err(Error::PlatformError(
        "macOS-only function called on non-macOS platform".into(),
    ))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_segments_macos() {
        let result = enumerate_segments();
        assert!(result.is_ok());

        let segments = result.unwrap();
        assert!(!segments.is_empty());
    }

    #[test]
    fn test_read_memory_macos() {
        let segments = enumerate_segments().unwrap();
        let executable = segments.iter().find(|s| s.is_executable());

        if let Some(segment) = executable {
            let result = read_memory(segment.start, 16);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_permissions() {
        use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ};

        let perms = permissions_from_vm_prot(VM_PROT_READ | VM_PROT_EXECUTE);
        assert!(perms.read);
        assert!(!perms.write);
        assert!(perms.execute);
    }
}

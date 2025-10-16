//! Platform-specific tests

#[cfg(target_os = "linux")]
mod linux_tests {
    use cynapse::platform;

    #[test]
    fn test_linux_enumerate() {
        let segments = platform::enumerate_segments();
        assert!(segments.is_ok());
        
        let segs = segments.unwrap();
        assert!(!segs.is_empty());

        // Should find some executable segments
        let exe_count = segs.iter().filter(|s| s.is_executable()).count();
        assert!(exe_count > 0);
    }

    #[test]
    fn test_linux_read_memory() {
        // Read from a safe location (our own stack)
        let stack_var: u64 = 0x4142434445464748;
        let address = &stack_var as *const u64 as usize;
        
        let result = platform::read_memory(address, 8);
        assert!(result.is_ok());
        
        let data = result.unwrap();
        assert_eq!(data.len(), 8);
    }
}

#[cfg(target_os = "windows")]
mod windows_tests {
    use cynapse::platform;

    #[test]
    fn test_windows_enumerate() {
        let segments = platform::enumerate_segments();
        assert!(segments.is_ok());
        
        let segs = segments.unwrap();
        assert!(!segs.is_empty());
    }

    #[test]
    fn test_windows_read_memory() {
        let stack_var: u64 = 0x4142434445464748;
        let address = &stack_var as *const u64 as usize;
        
        let result = platform::read_memory(address, 8);
        assert!(result.is_ok());
    }
}

#[cfg(target_os = "macos")]
mod macos_tests {
    use cynapse::platform;

    #[test]
    fn test_macos_enumerate() {
        let segments = platform::enumerate_segments();
        assert!(segments.is_ok());
        
        let segs = segments.unwrap();
        assert!(!segs.is_empty());
    }

    #[test]
    fn test_macos_read_memory() {
        let stack_var: u64 = 0x4142434445464748;
        let address = &stack_var as *const u64 as usize;
        
        let result = platform::read_memory(address, 8);
        assert!(result.is_ok());
    }
}

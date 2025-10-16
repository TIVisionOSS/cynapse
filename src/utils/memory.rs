//! Memory utility functions
//!
//! Helper functions for memory operations and analysis.

/// Page size constant (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Align an address down to page boundary
pub fn align_down(addr: usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}

/// Align an address up to page boundary
pub fn align_up(addr: usize) -> usize {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Calculate the number of pages needed for a given size
pub fn pages_needed(size: usize) -> usize {
    size.div_ceil(PAGE_SIZE)
}

/// Check if an address is page-aligned
pub fn is_page_aligned(addr: usize) -> bool {
    (addr & (PAGE_SIZE - 1)) == 0
}

/// Calculate the page index for an address
pub fn page_index(addr: usize, base: usize) -> usize {
    (addr - base) / PAGE_SIZE
}

/// Format memory size in human-readable form
pub fn format_size(bytes: usize) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

/// Compare two byte slices and find differences
pub fn find_byte_differences(original: &[u8], current: &[u8]) -> Vec<usize> {
    let min_len = std::cmp::min(original.len(), current.len());
    let mut differences = Vec::new();

    for i in 0..min_len {
        if original[i] != current[i] {
            differences.push(i);
        }
    }

    differences
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_down() {
        assert_eq!(align_down(0x1000), 0x1000);
        assert_eq!(align_down(0x1234), 0x1000);
        assert_eq!(align_down(0x1fff), 0x1000);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0x1000), 0x1000);
        assert_eq!(align_up(0x1001), 0x2000);
        assert_eq!(align_up(0x1fff), 0x2000);
    }

    #[test]
    fn test_pages_needed() {
        assert_eq!(pages_needed(0), 0);
        assert_eq!(pages_needed(1), 1);
        assert_eq!(pages_needed(4096), 1);
        assert_eq!(pages_needed(4097), 2);
        assert_eq!(pages_needed(8192), 2);
    }

    #[test]
    fn test_is_page_aligned() {
        assert!(is_page_aligned(0x0));
        assert!(is_page_aligned(0x1000));
        assert!(is_page_aligned(0x2000));
        assert!(!is_page_aligned(0x1001));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1048576), "1.00 MB");
    }

    #[test]
    fn test_find_byte_differences() {
        let original = vec![1, 2, 3, 4, 5];
        let current = vec![1, 9, 3, 8, 5];
        let diffs = find_byte_differences(&original, &current);

        assert_eq!(diffs.len(), 2);
        assert_eq!(diffs[0], 1);
        assert_eq!(diffs[1], 3);
    }
}

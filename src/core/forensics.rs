//! Forensic snapshot and analysis tools
//!
//! This module provides capabilities for:
//! - Capturing memory snapshots when tampering is detected
//! - Storing tampered regions for post-incident analysis
//! - Generating forensic reports

use crate::{core::mapper::MemorySegment, Result, TamperInfo};
use std::{collections::HashMap, time::SystemTime};

/// A forensic snapshot of a tampering event
#[derive(Debug, Clone)]
pub struct ForensicSnapshot {
    /// Unique snapshot ID
    pub id: String,

    /// Timestamp when snapshot was created
    pub timestamp: SystemTime,

    /// Affected memory segment
    pub segment: MemorySegment,

    /// Original memory contents (from baseline)
    pub original_data: Vec<u8>,

    /// Current memory contents (tampered)
    pub tampered_data: Vec<u8>,

    /// Tamper information
    pub tamper_info: TamperInfo,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl ForensicSnapshot {
    /// Create a new forensic snapshot
    pub fn new(
        segment: MemorySegment,
        original_data: Vec<u8>,
        tampered_data: Vec<u8>,
        tamper_info: TamperInfo,
    ) -> Self {
        let id = format!(
            "snapshot_{:016x}_{}",
            segment.start,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );

        Self {
            id,
            timestamp: SystemTime::now(),
            segment,
            original_data,
            tampered_data,
            tamper_info,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata to the snapshot
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Get the differences between original and tampered data
    pub fn get_differences(&self) -> Vec<DiffEntry> {
        let mut diffs = Vec::new();
        let min_len = std::cmp::min(self.original_data.len(), self.tampered_data.len());

        for i in 0..min_len {
            if self.original_data[i] != self.tampered_data[i] {
                diffs.push(DiffEntry {
                    offset: i,
                    original: self.original_data[i],
                    tampered: self.tampered_data[i],
                });
            }
        }

        diffs
    }

    /// Generate a human-readable report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== Forensic Snapshot Report ===\n");
        report.push_str(&format!("ID: {}\n", self.id));
        report.push_str(&format!("Timestamp: {:?}\n", self.timestamp));
        report.push_str(&format!("Segment: {}\n", self.segment));
        report.push('\n');

        let diffs = self.get_differences();
        report.push_str(&format!("Total differences: {}\n", diffs.len()));
        report.push('\n');

        if !diffs.is_empty() {
            report.push_str("First 20 differences:\n");
            for (i, diff) in diffs.iter().take(20).enumerate() {
                report.push_str(&format!(
                    "  [{:04}] Offset 0x{:08x}: 0x{:02x} -> 0x{:02x}\n",
                    i, diff.offset, diff.original, diff.tampered
                ));
            }
        }

        if !self.metadata.is_empty() {
            report.push_str("\nMetadata:\n");
            for (key, value) in &self.metadata {
                report.push_str(&format!("  {}: {}\n", key, value));
            }
        }

        report
    }

    /// Save snapshot to a file
    #[cfg(feature = "forensics")]
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        use std::io::Write;

        let report = self.generate_report();
        let mut file = std::fs::File::create(path)?;
        file.write_all(report.as_bytes())?;

        log::info!("Forensic snapshot saved to {:?}", path);
        Ok(())
    }
}

/// A single byte difference in memory
#[derive(Debug, Clone, Copy)]
pub struct DiffEntry {
    /// Offset within the segment
    pub offset: usize,

    /// Original byte value
    pub original: u8,

    /// Tampered byte value
    pub tampered: u8,
}

impl DiffEntry {
    /// Format as hex string
    pub fn format_hex(&self) -> String {
        format!(
            "0x{:08x}: 0x{:02x} -> 0x{:02x}",
            self.offset, self.original, self.tampered
        )
    }
}

/// Manager for forensic snapshots
pub struct ForensicsManager {
    snapshots: Vec<ForensicSnapshot>,
    max_snapshots: usize,
}

impl ForensicsManager {
    /// Create a new forensics manager
    pub fn new(max_snapshots: usize) -> Self {
        Self {
            snapshots: Vec::new(),
            max_snapshots,
        }
    }

    /// Add a snapshot
    pub fn add_snapshot(&mut self, snapshot: ForensicSnapshot) {
        self.snapshots.push(snapshot);

        // Keep only the most recent snapshots
        if self.snapshots.len() > self.max_snapshots {
            self.snapshots.remove(0);
        }

        log::info!("Forensic snapshot added (total: {})", self.snapshots.len());
    }

    /// Get all snapshots
    pub fn snapshots(&self) -> &[ForensicSnapshot] {
        &self.snapshots
    }

    /// Get snapshot by ID
    pub fn get_snapshot(&self, id: &str) -> Option<&ForensicSnapshot> {
        self.snapshots.iter().find(|s| s.id == id)
    }

    /// Clear all snapshots
    pub fn clear(&mut self) {
        self.snapshots.clear();
        log::info!("All forensic snapshots cleared");
    }

    /// Get total snapshot count
    pub fn count(&self) -> usize {
        self.snapshots.len()
    }
}

impl Default for ForensicsManager {
    fn default() -> Self {
        Self::new(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mapper::SegmentPermissions;

    fn create_test_segment() -> MemorySegment {
        MemorySegment::new(
            0x1000,
            0x2000,
            SegmentPermissions::executable(),
            "test".to_string(),
            0,
        )
    }

    fn create_test_tamper_info() -> TamperInfo {
        TamperInfo {
            segment: create_test_segment(),
            differences: vec![],
            original_hash: vec![1, 2, 3],
            current_hash: vec![4, 5, 6],
            timestamp: SystemTime::now(),
        }
    }

    #[test]
    fn test_snapshot_creation() {
        let segment = create_test_segment();
        let original = vec![0, 1, 2, 3];
        let tampered = vec![0, 9, 2, 8];
        let info = create_test_tamper_info();

        let snapshot = ForensicSnapshot::new(segment, original, tampered, info);

        assert!(!snapshot.id.is_empty());
        assert_eq!(snapshot.original_data.len(), 4);
        assert_eq!(snapshot.tampered_data.len(), 4);
    }

    #[test]
    fn test_get_differences() {
        let segment = create_test_segment();
        let original = vec![0, 1, 2, 3, 4];
        let tampered = vec![0, 9, 2, 8, 4];
        let info = create_test_tamper_info();

        let snapshot = ForensicSnapshot::new(segment, original, tampered, info);
        let diffs = snapshot.get_differences();

        assert_eq!(diffs.len(), 2);
        assert_eq!(diffs[0].offset, 1);
        assert_eq!(diffs[0].original, 1);
        assert_eq!(diffs[0].tampered, 9);
    }

    #[test]
    fn test_forensics_manager() {
        let mut manager = ForensicsManager::new(5);

        for i in 0..7 {
            let segment = create_test_segment();
            let original = vec![i; 10];
            let tampered = vec![i + 1; 10];
            let info = create_test_tamper_info();
            let snapshot = ForensicSnapshot::new(segment, original, tampered, info);

            manager.add_snapshot(snapshot);
        }

        assert_eq!(manager.count(), 5); // Should keep only 5
    }

    #[test]
    fn test_generate_report() {
        let segment = create_test_segment();
        let original = vec![0, 1, 2];
        let tampered = vec![9, 8, 7];
        let info = create_test_tamper_info();

        let snapshot = ForensicSnapshot::new(segment, original, tampered, info);
        let report = snapshot.generate_report();

        assert!(report.contains("Forensic Snapshot Report"));
        assert!(report.contains("Total differences: 3"));
    }
}

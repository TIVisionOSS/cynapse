//! Integrity monitoring and verification
//!
//! This module provides the main `Monitor` type that orchestrates:
//! - Baseline establishment
//! - Continuous verification
//! - Tamper detection and response

use crate::{
    core::{
        hasher::{HashEngine, HashedPage, MerkleTree},
        mapper::{MemoryMapper, MemorySegment},
    },
    Error, MonitorConfig, Result, TamperInfo, TamperResponse, WhitelistPolicy,
};
use parking_lot::{Mutex, RwLock};
use std::{
    sync::Arc,
    thread::{self, JoinHandle},
    time::{Duration, SystemTime},
};

/// Callback function type for tamper detection
pub type TamperCallback = Box<dyn Fn(&MemorySegment, &TamperInfo) + Send + Sync>;

/// Handle to a running monitor
pub struct MonitorHandle {
    thread: Option<JoinHandle<()>>,
    running: Arc<Mutex<bool>>,
}

impl MonitorHandle {
    /// Stop the monitor
    pub fn stop(mut self) -> Result<()> {
        *self.running.lock() = false;
        if let Some(handle) = self.thread.take() {
            handle
                .join()
                .map_err(|_| Error::InitializationFailed("Failed to join monitor thread".into()))?;
        }
        Ok(())
    }

    /// Check if the monitor is running
    pub fn is_running(&self) -> bool {
        *self.running.lock()
    }
}

/// Main integrity monitor
pub struct Monitor {
    config: MonitorConfig,
    mapper: MemoryMapper,
    hash_engine: HashEngine,
    baseline: Arc<RwLock<Option<Baseline>>>,
    callbacks: Arc<Mutex<Vec<TamperCallback>>>,
    running: Arc<Mutex<bool>>,
}

/// Baseline snapshot of memory state
#[derive(Debug, Clone)]
struct Baseline {
    segments: Vec<MemorySegment>,
    pages: Vec<HashedPage>,
    merkle_tree: Option<MerkleTree>,
    timestamp: SystemTime,
}

impl Monitor {
    /// Create a new monitor with default configuration
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> MonitorBuilder {
        MonitorBuilder::new()
    }

    /// Create a monitor builder for advanced configuration
    pub fn builder() -> MonitorBuilder {
        MonitorBuilder::new()
    }

    /// Start monitoring in the background
    pub fn start(self) -> MonitorHandle {
        let running = Arc::new(Mutex::new(true));
        let running_clone = running.clone();

        let thread = thread::spawn(move || {
            if let Err(e) = self.run_monitor_loop(running_clone) {
                log::error!("Monitor loop failed: {}", e);
            }
        });

        MonitorHandle {
            thread: Some(thread),
            running,
        }
    }

    /// Main monitoring loop
    fn run_monitor_loop(&self, running: Arc<Mutex<bool>>) -> Result<()> {
        log::info!("Starting integrity monitor");

        // Establish baseline
        self.establish_baseline()?;
        log::info!("Baseline established");

        let mut interval = self.config.interval;
        let mut consecutive_clean = 0u32;

        while *running.lock() {
            thread::sleep(interval);

            // Perform verification
            match self.verify_integrity() {
                Ok(true) => {
                    log::debug!("Integrity check passed");
                    consecutive_clean += 1;

                    // Adaptive sampling: increase interval if clean
                    if self.config.adaptive && consecutive_clean > 10 {
                        interval = std::cmp::min(
                            interval + Duration::from_secs(1),
                            Duration::from_secs(30),
                        );
                    }
                }
                Ok(false) => {
                    log::warn!("Integrity violation detected");
                    consecutive_clean = 0;

                    // Adaptive sampling: decrease interval on detection
                    if self.config.adaptive {
                        interval = std::cmp::max(Duration::from_secs(1), interval / 2);
                    }

                    // Handle according to response policy
                    if self.config.response == TamperResponse::Terminate {
                        log::error!("Terminating process due to tampering");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    log::error!("Verification error: {}", e);
                }
            }
        }

        log::info!("Monitor stopped");
        Ok(())
    }

    /// Establish the baseline by hashing all executable segments
    fn establish_baseline(&self) -> Result<()> {
        let mut mapper = MemoryMapper::new()?;
        let segments = mapper.enumerate_executable_segments()?;

        if segments.is_empty() {
            return Err(Error::InitializationFailed(
                "No executable segments found".into(),
            ));
        }

        let mut all_pages = Vec::new();

        for segment in &segments {
            // Skip whitelisted segments
            if self.should_whitelist(segment) {
                log::debug!("Whitelisting segment: {}", segment.name);
                continue;
            }

            // Read and hash the segment
            match mapper.read_segment(segment) {
                Ok(data) => {
                    let pages = self.hash_engine.hash_pages(&data, segment.start)?;
                    all_pages.extend(pages);
                }
                Err(e) => {
                    log::warn!("Failed to read segment {}: {}", segment.name, e);
                }
            }
        }

        // Build Merkle tree if enabled
        let merkle_tree = if self.config.use_merkle {
            Some(self.hash_engine.build_merkle_tree(&all_pages))
        } else {
            None
        };

        let baseline = Baseline {
            segments,
            pages: all_pages,
            merkle_tree,
            timestamp: SystemTime::now(),
        };

        *self.baseline.write() = Some(baseline);
        Ok(())
    }

    /// Verify integrity against baseline
    fn verify_integrity(&self) -> Result<bool> {
        let baseline_guard = self.baseline.read();
        let baseline = baseline_guard
            .as_ref()
            .ok_or_else(|| Error::InitializationFailed("No baseline established".into()))?;

        let mut mapper = MemoryMapper::new()?;
        mapper.enumerate_executable_segments()?;

        // Sample pages for verification
        let sample_indices = self.select_sample_indices(baseline.pages.len());

        for &idx in &sample_indices {
            if idx >= baseline.pages.len() {
                continue;
            }

            let baseline_page = &baseline.pages[idx];

            // Read current page
            match mapper.read_page(baseline_page.address, baseline_page.size) {
                Ok(current_data) => {
                    let current_page = self
                        .hash_engine
                        .hash_page(&current_data, baseline_page.address)?;

                    if !baseline_page.matches(&current_page.hash) {
                        // Tampering detected!
                        self.handle_tampering(baseline_page, &current_page)?;
                        return Ok(false);
                    }
                }
                Err(e) => {
                    log::warn!(
                        "Failed to read page at 0x{:x}: {}",
                        baseline_page.address,
                        e
                    );
                }
            }
        }

        Ok(true)
    }

    /// Select sample indices for verification
    fn select_sample_indices(&self, total: usize) -> Vec<usize> {
        // For now, check all pages. In production, this could be optimized
        // with random sampling or adaptive strategies
        (0..total).collect()
    }

    /// Handle detected tampering
    fn handle_tampering(
        &self,
        baseline_page: &HashedPage,
        current_page: &HashedPage,
    ) -> Result<()> {
        let baseline_guard = self.baseline.read();
        let baseline = baseline_guard.as_ref().unwrap();

        // Find the affected segment
        let segment = baseline
            .segments
            .iter()
            .find(|s| s.contains(baseline_page.address))
            .cloned()
            .unwrap_or_else(|| {
                MemorySegment::new(
                    baseline_page.address,
                    baseline_page.address + baseline_page.size,
                    crate::core::mapper::SegmentPermissions::executable(),
                    "unknown".to_string(),
                    0,
                )
            });

        let tamper_info = TamperInfo {
            segment: segment.clone(),
            differences: vec![], // Could compute actual byte differences
            original_hash: baseline_page.hash.clone(),
            current_hash: current_page.hash.clone(),
            timestamp: SystemTime::now(),
        };

        // Invoke callbacks
        let callbacks = self.callbacks.lock();
        for callback in callbacks.iter() {
            callback(&segment, &tamper_info);
        }

        // Log the event
        log::error!(
            "Tampering detected in segment {} at address 0x{:x}",
            segment.name,
            baseline_page.address
        );

        Ok(())
    }

    /// Check if segment should be whitelisted
    fn should_whitelist(&self, segment: &MemorySegment) -> bool {
        match &self.config.whitelist_policy {
            WhitelistPolicy::None => false,
            WhitelistPolicy::ByPattern(patterns) => {
                patterns.iter().any(|p| segment.name.contains(p))
            }
            WhitelistPolicy::ByAddressRange(ranges) => ranges
                .iter()
                .any(|(start, end)| segment.start >= *start && segment.end <= *end),
            WhitelistPolicy::Custom => false, // Placeholder
        }
    }
}

impl Default for Monitor {
    fn default() -> Self {
        MonitorBuilder::new().build().unwrap()
    }
}

/// Builder for Monitor configuration
pub struct MonitorBuilder {
    config: MonitorConfig,
    callbacks: Vec<TamperCallback>,
}

impl MonitorBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: MonitorConfig::default(),
            callbacks: Vec::new(),
        }
    }

    /// Set verification interval
    pub fn interval(mut self, interval: Duration) -> Self {
        self.config.interval = interval;
        self
    }

    /// Set interval using convenient method
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.config.interval = interval;
        self
    }

    /// Enable Merkle tree optimization
    pub fn enable_merkle_trees(mut self, enable: bool) -> Self {
        self.config.use_merkle = enable;
        self
    }

    /// Enable adaptive sampling
    pub fn adaptive_sampling(mut self, enable: bool) -> Self {
        self.config.adaptive = enable;
        self
    }

    /// Set whitelist policy
    pub fn whitelist_jit_regions(mut self, policy: WhitelistPolicy) -> Self {
        self.config.whitelist_policy = policy;
        self
    }

    /// Enable forensic snapshots
    pub fn enable_forensics(mut self, enable: bool) -> Self {
        self.config.enable_forensics = enable;
        self
    }

    /// Set tamper response
    pub fn response(mut self, response: TamperResponse) -> Self {
        self.config.response = response;
        self
    }

    /// Add a tamper detection callback
    pub fn on_tamper<F>(mut self, callback: F) -> Self
    where
        F: Fn(&MemorySegment, &TamperInfo) + Send + Sync + 'static,
    {
        self.callbacks.push(Box::new(callback));
        self
    }

    /// Build the monitor
    pub fn build(self) -> Result<Monitor> {
        let hash_engine = HashEngine::new(self.config.hash_algorithm);

        Ok(Monitor {
            config: self.config,
            mapper: MemoryMapper::new()?,
            hash_engine,
            baseline: Arc::new(RwLock::new(None)),
            callbacks: Arc::new(Mutex::new(self.callbacks)),
            running: Arc::new(Mutex::new(false)),
        })
    }
}

impl Default for MonitorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_builder() {
        let monitor = Monitor::builder()
            .interval(Duration::from_secs(5))
            .enable_merkle_trees(true)
            .adaptive_sampling(true)
            .build();

        assert!(monitor.is_ok());
        let m = monitor.unwrap();
        assert_eq!(m.config.interval, Duration::from_secs(5));
        assert!(m.config.use_merkle);
        assert!(m.config.adaptive);
    }

    #[test]
    #[ignore] // Ignore by default as it requires reading executable memory
    fn test_monitor_handle() {
        let monitor = Monitor::builder()
            .interval(Duration::from_millis(100))
            .build()
            .unwrap();

        let handle = monitor.start();
        assert!(handle.is_running());

        thread::sleep(Duration::from_millis(50));
        handle.stop().unwrap();
    }
}

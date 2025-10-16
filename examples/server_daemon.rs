//! Server daemon with advanced monitoring
//!
//! This example shows how to use Cynapse to protect a long-running server process
//! with advanced features like adaptive sampling and forensics.

use cynapse::{Monitor, TamperResponse, WhitelistPolicy};
use std::time::Duration;

fn main() {
    // Initialize logging
    env_logger::init();

    println!("🧠 Cynapse Server Daemon Demo");
    println!("==============================\n");

    // Create an advanced monitor configuration
    let monitor = Monitor::builder()
        .interval(Duration::from_secs(2))
        .enable_merkle_trees(true)
        .adaptive_sampling(true)
        .whitelist_jit_regions(WhitelistPolicy::ByPattern(vec![
            ".jit".to_string(),
            ".v8".to_string(),
            "java".to_string(),
        ]))
        .enable_forensics(true)
        .response(TamperResponse::Alert)
        .on_tamper(|segment, info| {
            // Custom handler - in production, this would send alerts to monitoring systems
            log::error!("🚨 Integrity violation detected!");
            log::error!("   Segment: {}", segment.name);
            log::error!(
                "   Address range: 0x{:016x} - 0x{:016x}",
                segment.start,
                segment.end
            );
            log::error!("   Size: {} bytes", segment.size());
            log::error!("   Timestamp: {:?}", info.timestamp);

            // In production, you might:
            // - Send alert to SIEM
            // - Trigger incident response workflow
            // - Capture forensic snapshot
            // - Notify security team
        })
        .build()
        .expect("Failed to initialize monitor");

    println!("✓ Advanced monitor configured:");
    println!("  • Merkle tree optimization: enabled");
    println!("  • Adaptive sampling: enabled");
    println!("  • JIT whitelisting: enabled");
    println!("  • Forensics: enabled");
    println!("  • Response: Alert\n");

    println!("✓ Starting monitoring...\n");

    // Start the monitor
    let handle = monitor.start();

    // Simulate server operations
    println!("Server running. Press Ctrl+C to stop.\n");

    let mut counter = 0;
    loop {
        std::thread::sleep(Duration::from_secs(5));
        counter += 1;

        println!("[{}] Server health check: OK", counter);

        // For demo purposes, stop after 1 minute
        if counter >= 12 {
            break;
        }
    }

    println!("\n✓ Shutting down gracefully...");
    handle.stop().expect("Failed to stop monitor");
    println!("✓ Server stopped");
}

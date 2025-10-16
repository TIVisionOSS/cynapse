//! Forensic analysis example
//!
//! This example demonstrates how to capture and analyze forensic snapshots
//! when tampering is detected.

#[cfg(feature = "forensics")]
use cynapse::{Monitor, TamperResponse};
#[cfg(feature = "forensics")]
use std::time::Duration;

#[cfg(feature = "forensics")]
fn main() {
    // Initialize logging
    env_logger::init();

    println!("🧠 Cynapse Forensic Analysis Demo");
    println!("==================================\n");

    // Create a monitor with forensics enabled
    let monitor = Monitor::builder()
        .interval(Duration::from_secs(2))
        .enable_forensics(true)
        .response(TamperResponse::Alert)
        .on_tamper(|segment, info| {
            println!("\n📸 Forensic Snapshot Captured");
            println!("==============================");
            println!("Segment: {}", segment.name);
            println!("Address: 0x{:016x} - 0x{:016x}", segment.start, segment.end);
            println!("Size: {} bytes", segment.size());
            println!("Timestamp: {:?}", info.timestamp);
            println!();

            // Display hash differences
            println!("Hash Comparison:");
            println!("  Original: {:02x?}", &info.original_hash[..16]);
            println!("  Current:  {:02x?}", &info.current_hash[..16]);
            println!();

            // In production, you would:
            // 1. Save the snapshot to disk
            // 2. Upload to forensic analysis system
            // 3. Generate detailed reports
            // 4. Preserve evidence for investigation
        })
        .build()
        .expect("Failed to initialize monitor");

    println!("✓ Forensic monitor initialized");
    println!("✓ Monitoring for tampering...\n");

    let handle = monitor.start();

    // Run for demonstration
    let mut counter = 0;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        counter += 1;

        if counter % 5 == 0 {
            println!("[{}s] No tampering detected", counter);
        }

        if counter >= 20 {
            break;
        }
    }

    println!("\n✓ Demo complete");
    handle.stop().expect("Failed to stop monitor");
}

#[cfg(not(feature = "forensics"))]
fn main() {
    eprintln!("This example requires the 'forensics' feature.");
    eprintln!("Run with: cargo run --example forensic_analysis --features forensics");
    std::process::exit(1);
}

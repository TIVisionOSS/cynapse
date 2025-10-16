//! Basic self-protection example
//!
//! This example demonstrates how to use Cynapse to protect a simple application
//! from runtime code tampering.

use cynapse::{Monitor, TamperResponse};
use std::time::Duration;

fn main() {
    // Initialize logging
    env_logger::init();

    println!("🧠 Cynapse Self-Protection Demo");
    println!("================================\n");

    // Create a monitor with basic configuration
    let monitor = Monitor::new()
        .with_interval(Duration::from_secs(3))
        .on_tamper(|segment, info| {
            eprintln!("\n🚨 [ALERT] Tampering detected!");
            eprintln!("   Segment: {}", segment);
            eprintln!("   Address: 0x{:016x}", info.segment.start);
            eprintln!("   Original hash: {:02x?}", &info.original_hash[..8]);
            eprintln!("   Current hash:  {:02x?}", &info.current_hash[..8]);
            eprintln!();
        })
        .build()
        .expect("Failed to initialize monitor");

    println!("✓ Monitor initialized");
    println!("✓ Starting integrity checks every 3 seconds...\n");

    // Start the monitor in the background
    let handle = monitor.start();

    // Simulate application work
    let mut counter = 0;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        counter += 1;

        if counter % 5 == 0 {
            println!("Application running... ({} seconds)", counter);
        }

        // Stop after 30 seconds for demo purposes
        if counter >= 30 {
            break;
        }
    }

    println!("\n✓ Demo complete. Stopping monitor...");
    handle.stop().expect("Failed to stop monitor");
    println!("✓ Monitor stopped cleanly");
}

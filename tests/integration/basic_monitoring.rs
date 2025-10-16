//! Basic monitoring integration tests

use cynapse::{Monitor, TamperResponse};
use std::time::Duration;

#[test]
fn test_monitor_initialization() {
    let monitor = Monitor::builder()
        .interval(Duration::from_millis(100))
        .build();

    assert!(monitor.is_ok());
}

#[test]
#[ignore] // Requires reading executable memory
fn test_monitor_start_stop() {
    let monitor = Monitor::builder()
        .interval(Duration::from_millis(100))
        .build()
        .unwrap();

    let handle = monitor.start();
    assert!(handle.is_running());

    std::thread::sleep(Duration::from_millis(200));
    
    handle.stop().unwrap();
}

#[test]
#[ignore] // Requires reading executable memory
fn test_monitor_with_callback() {
    use std::sync::{Arc, Mutex};

    let called = Arc::new(Mutex::new(false));
    let called_clone = called.clone();

    let monitor = Monitor::builder()
        .interval(Duration::from_millis(100))
        .on_tamper(move |_seg, _info| {
            *called_clone.lock().unwrap() = true;
        })
        .build()
        .unwrap();

    let handle = monitor.start();
    std::thread::sleep(Duration::from_millis(200));
    handle.stop().unwrap();

    // Callback should not have been called (no tampering)
    // This is just verifying the monitor runs without panicking
}

#[test]
#[ignore] // Requires reading executable memory
fn test_monitor_merkle_enabled() {
    let monitor = Monitor::builder()
        .interval(Duration::from_millis(100))
        .enable_merkle_trees(true)
        .build()
        .unwrap();

    let handle = monitor.start();
    std::thread::sleep(Duration::from_millis(200));
    handle.stop().unwrap();
}

#[test]
#[ignore] // Requires reading executable memory
fn test_monitor_adaptive_sampling() {
    let monitor = Monitor::builder()
        .interval(Duration::from_millis(100))
        .adaptive_sampling(true)
        .build()
        .unwrap();

    let handle = monitor.start();
    std::thread::sleep(Duration::from_millis(200));
    handle.stop().unwrap();
}

#[test]
#[ignore] // Requires reading executable memory
fn test_monitor_response_strategies() {
    for response in &[
        TamperResponse::Log,
        TamperResponse::Alert,
        TamperResponse::Restore,
    ] {
        let monitor = Monitor::builder()
            .interval(Duration::from_millis(100))
            .response(*response)
            .build()
            .unwrap();

        let handle = monitor.start();
        std::thread::sleep(Duration::from_millis(50));
        handle.stop().unwrap();
    }
}

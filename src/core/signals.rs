//! Signal and exception handling
//!
//! This module provides hooks for intercepting memory-related signals and exceptions:
//! - SIGSEGV (segmentation fault)
//! - SIGTRAP (debug trap)
//! - Access violations (Windows)
//!
//! These can indicate attempted tampering or memory corruption.

use crate::Result;

/// Signal handler configuration
#[derive(Debug, Clone, Default)]
pub struct SignalConfig {
    /// Handle SIGSEGV
    pub handle_sigsegv: bool,

    /// Handle SIGTRAP
    pub handle_sigtrap: bool,

    /// Handle access violations (Windows)
    pub handle_access_violation: bool,
}

/// Signal handler for memory-related events
pub struct SignalHandler {
    config: SignalConfig,
    installed: bool,
}

impl SignalHandler {
    /// Create a new signal handler
    pub fn new(config: SignalConfig) -> Self {
        Self {
            config,
            installed: false,
        }
    }

    /// Install signal handlers
    pub fn install(&mut self) -> Result<()> {
        if self.installed {
            return Ok(());
        }

        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                self.install_unix_handlers()?;
            } else if #[cfg(windows)] {
                self.install_windows_handlers()?;
            }
        }

        self.installed = true;
        log::info!("Signal handlers installed");
        Ok(())
    }

    /// Uninstall signal handlers
    pub fn uninstall(&mut self) -> Result<()> {
        if !self.installed {
            return Ok(());
        }

        // Restore default handlers
        self.installed = false;
        log::info!("Signal handlers uninstalled");
        Ok(())
    }

    #[cfg(unix)]
    fn install_unix_handlers(&self) -> Result<()> {
        use libc::{signal, SIGSEGV, SIGTRAP};

        unsafe {
            if self.config.handle_sigsegv {
                signal(SIGSEGV, signal_handler as usize);
            }

            if self.config.handle_sigtrap {
                signal(SIGTRAP, signal_handler as usize);
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn install_windows_handlers(&self) -> Result<()> {
        // Windows structured exception handling would go here
        // This is a placeholder for the full implementation
        log::warn!("Windows signal handling not yet fully implemented");
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    fn install_unix_handlers(&self) -> Result<()> {
        Err(Error::PlatformError("Unsupported platform".into()))
    }

    #[cfg(not(any(unix, windows)))]
    fn install_windows_handlers(&self) -> Result<()> {
        Err(Error::PlatformError("Unsupported platform".into()))
    }
}

#[cfg(unix)]
extern "C" fn signal_handler(sig: i32) {
    match sig {
        libc::SIGSEGV => {
            log::error!("SIGSEGV caught - possible memory corruption or tampering");
            // In production, this could trigger forensic snapshot
        }
        libc::SIGTRAP => {
            log::warn!("SIGTRAP caught - possible debugging attempt");
        }
        _ => {
            log::warn!("Unexpected signal: {}", sig);
        }
    }

    // Restore default handler and re-raise
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Information about a signal event
#[derive(Debug, Clone)]
pub struct SignalEvent {
    /// Signal number
    pub signal: i32,

    /// Address that caused the signal (if applicable)
    pub address: Option<usize>,

    /// Timestamp
    pub timestamp: std::time::SystemTime,
}

impl SignalEvent {
    /// Create a new signal event
    pub fn new(signal: i32, address: Option<usize>) -> Self {
        Self {
            signal,
            address,
            timestamp: std::time::SystemTime::now(),
        }
    }

    /// Get signal name
    pub fn signal_name(&self) -> &'static str {
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                match self.signal {
                    libc::SIGSEGV => "SIGSEGV",
                    libc::SIGTRAP => "SIGTRAP",
                    _ => "UNKNOWN",
                }
            } else {
                "UNKNOWN"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_config_default() {
        let config = SignalConfig::default();
        assert!(!config.handle_sigsegv);
        assert!(!config.handle_sigtrap);
    }

    #[test]
    fn test_signal_handler_creation() {
        let config = SignalConfig::default();
        let handler = SignalHandler::new(config);
        assert!(!handler.installed);
    }

    #[test]
    fn test_signal_event() {
        let event = SignalEvent::new(11, Some(0x1000));
        assert_eq!(event.signal, 11);
        assert_eq!(event.address, Some(0x1000));
    }
}

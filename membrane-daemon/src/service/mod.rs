//! OS service management.
//!
//! Exposes install / start / stop / status / uninstall as platform-
//! agnostic operations. The actual mechanism (systemd, launchd, Windows
//! services) is selected at compile time via cfg gates.
//!
//! v1 installs the daemon as a **user-level** service:
//! - Linux: `~/.config/systemd/user/membrane-daemon.service`
//! - macOS: `~/Library/LaunchAgents/com.membrane.daemon.plist`
//! - Windows: a user-scoped service via the Service Control Manager
//!
//! User-level keeps the daemon's process privileges aligned with the
//! customer who installed it. System-wide install can be added later
//! for enterprise deployments that demand it.

#[allow(unused_imports)]
use anyhow::Result;

/// Outcome of a service-management call. Variants are deliberately
/// loose because each platform reports state differently.
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceStatus {
    /// Service is installed and running.
    Running,
    /// Installed but stopped.
    Stopped,
    /// Not installed at all.
    NotInstalled,
    /// Installed; precise state unknown.
    Unknown(String),
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceStatus::Running => write!(f, "running"),
            ServiceStatus::Stopped => write!(f, "stopped"),
            ServiceStatus::NotInstalled => write!(f, "not installed"),
            ServiceStatus::Unknown(s) => write!(f, "unknown ({s})"),
        }
    }
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod unsupported {
    use super::*;
    pub fn install(_exe: &std::path::Path) -> Result<()> {
        anyhow::bail!("service install not supported on this platform")
    }
    pub fn uninstall() -> Result<()> {
        anyhow::bail!("service uninstall not supported on this platform")
    }
    pub fn start() -> Result<()> {
        anyhow::bail!("service start not supported on this platform")
    }
    pub fn stop() -> Result<()> {
        anyhow::bail!("service stop not supported on this platform")
    }
    pub fn status() -> Result<ServiceStatus> {
        Ok(ServiceStatus::NotInstalled)
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub use unsupported::*;

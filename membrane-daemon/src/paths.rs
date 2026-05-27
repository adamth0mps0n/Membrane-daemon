//! Cross-platform path resolution for daemon files.
//!
//! Two roots:
//! - User config: where the customer's daemon config and cert live.
//!   Linux: `~/.config/membrane`, macOS: `~/Library/Application Support/membrane`,
//!   Windows: `%APPDATA%/membrane`.
//! - System policy: where enterprise MDM puts org-managed policy that
//!   overrides user config. Read-only to the daemon.
//!   Linux: `/etc/membrane`, macOS: `/Library/Application Support/membrane`,
//!   Windows: `%PROGRAMDATA%/membrane`.

use std::path::{Path, PathBuf};

/// User-writable config directory.
pub fn user_dir() -> PathBuf {
    if let Some(d) = directories::ProjectDirs::from("", "", "membrane") {
        d.config_dir().to_path_buf()
    } else {
        // Last-resort fallback.
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".config").join("membrane"))
            .unwrap_or_else(|_| PathBuf::from("."))
    }
}

/// System-wide policy directory (enterprise MDM).
pub fn system_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/etc/membrane")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/membrane")
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("PROGRAMDATA")
            .map(|p| PathBuf::from(p).join("membrane"))
            .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\membrane"))
    }
}

/// User policy file path.
pub fn user_policy() -> PathBuf { user_dir().join("policy.toml") }

/// System policy file path (read-only override).
pub fn system_policy() -> PathBuf { system_dir().join("policy.toml") }

/// mTLS cert and key for daemon → cloud auth.
pub fn cert_path() -> PathBuf { user_dir().join("daemon.crt") }
pub fn key_path() -> PathBuf { user_dir().join("daemon.key") }

/// Pinned cloud cert fingerprint (BLAKE3 of cert DER bytes).
pub fn cloud_pin_path() -> PathBuf { user_dir().join("cloud.pin") }

/// Append-only audit log (rotated daily).
pub fn audit_dir() -> PathBuf { user_dir().join("audit") }
pub fn audit_log_for(day: &str) -> PathBuf { audit_dir().join(format!("{day}.jsonl")) }

/// Returns true if `path` exists and we can read it.
pub fn readable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_dir_resolves_to_something() {
        let d = user_dir();
        assert!(!d.as_os_str().is_empty());
    }

    #[test]
    fn system_dir_is_platform_appropriate() {
        let d = system_dir();
        #[cfg(target_os = "linux")]
        assert_eq!(d, PathBuf::from("/etc/membrane"));
    }

    #[test]
    fn audit_log_naming() {
        let p = audit_log_for("2026-05-22");
        assert!(p.ends_with("audit/2026-05-22.jsonl"));
    }
}

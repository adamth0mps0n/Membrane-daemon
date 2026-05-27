//! Linux systemd-user integration.
//!
//! Installs `~/.config/systemd/user/membrane-daemon.service` and uses
//! `systemctl --user` to control it. `systemctl` is available on every
//! mainstream Linux distro that uses systemd (most do); on others the
//! customer can run the daemon directly from their shell.
//!
//! The service is enabled with `linger` left to the customer's choice:
//! by default it runs when they log in. If they want it to run while
//! they're logged out they enable lingering separately (loginctl
//! enable-linger), which we don't touch.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::ServiceStatus;

const SERVICE_NAME: &str = "membrane-daemon.service";

fn unit_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config/systemd/user").join(SERVICE_NAME)
}

fn render_unit(exe: &Path) -> String {
    // Restart=on-failure with a 5s delay covers transient crashes
    // (e.g. cloud connection refused) without hammering the cloud
    // when something is broken upstream. Network-online is best-effort.
    format!(
        r#"[Unit]
Description=Membrane daemon
Documentation=https://membrane.example.com/docs
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={exe} run
Restart=on-failure
RestartSec=5
# Daemon is interactive-grade; cap memory + CPU so a misbehaving build
# can't take down the customer's session.
MemoryHigh=512M
MemoryMax=1G
# Inherit the user's environment for HOME, PATH, etc.
PassEnvironment=HOME PATH

[Install]
WantedBy=default.target
"#,
        exe = exe.display(),
    )
}

pub fn install(exe: &Path) -> Result<()> {
    let path = unit_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    let body = render_unit(exe);
    std::fs::write(&path, body)
        .with_context(|| format!("write {}", path.display()))?;
    eprintln!("wrote {}", path.display());

    run_systemctl(&["daemon-reload"])?;
    run_systemctl(&["enable", SERVICE_NAME])?;
    eprintln!("service installed. Use `systemctl --user start {SERVICE_NAME}` or");
    eprintln!("`membrane-daemon start` to start it now.");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let _ = run_systemctl(&["stop", SERVICE_NAME]);
    let _ = run_systemctl(&["disable", SERVICE_NAME]);
    let path = unit_path();
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("remove {}", path.display()))?;
        eprintln!("removed {}", path.display());
    }
    let _ = run_systemctl(&["daemon-reload"]);
    Ok(())
}

pub fn start() -> Result<()> { run_systemctl(&["start", SERVICE_NAME]) }
pub fn stop() -> Result<()> { run_systemctl(&["stop", SERVICE_NAME]) }

pub fn status() -> Result<ServiceStatus> {
    if !unit_path().exists() { return Ok(ServiceStatus::NotInstalled); }
    // `is-active` exits 0 if active, non-zero otherwise. Plain text.
    let output = Command::new("systemctl")
        .args(["--user", "is-active", SERVICE_NAME])
        .output()
        .context("run systemctl is-active")?;
    let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(match state.as_str() {
        "active" => ServiceStatus::Running,
        "inactive" | "failed" => ServiceStatus::Stopped,
        other => ServiceStatus::Unknown(other.to_string()),
    })
}

fn run_systemctl(args: &[&str]) -> Result<()> {
    let mut cmd = Command::new("systemctl");
    cmd.arg("--user");
    cmd.args(args);
    let output = cmd.output()
        .with_context(|| format!("run: systemctl --user {}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "systemctl --user {} failed: {}",
            args.join(" "),
            stderr.trim(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn unit_renders_with_exe_path() {
        let exe = PathBuf::from("/usr/local/bin/membrane-daemon");
        let body = render_unit(&exe);
        assert!(body.contains("ExecStart=/usr/local/bin/membrane-daemon run"));
        assert!(body.contains("Restart=on-failure"));
        assert!(body.contains("WantedBy=default.target"));
        assert!(body.contains("After=network-online.target"));
    }

    #[test]
    #[serial]
    fn unit_path_under_user_systemd_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", dir.path());
        let p = unit_path();
        assert!(p.ends_with(".config/systemd/user/membrane-daemon.service"));
    }
}

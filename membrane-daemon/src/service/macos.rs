//! macOS launchd integration.
//!
//! Installs `~/Library/LaunchAgents/com.membrane.daemon.plist` and uses
//! `launchctl` to control it. Per Apple's modern guidance we use the
//! `bootstrap`/`bootout`/`kickstart`/`print` verbs targeting the user's
//! GUI domain (`gui/$UID`).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::ServiceStatus;

const LABEL: &str = "com.membrane.daemon";

fn uid() -> u32 {
    // SAFETY: getuid is a non-failing syscall.
    unsafe { libc::getuid() }
}

fn domain() -> String { format!("gui/{}", uid()) }
fn service_target() -> String { format!("{}/{}", domain(), LABEL) }

fn plist_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join("Library/LaunchAgents").join(format!("{LABEL}.plist"))
}

fn log_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join("Library/Logs/membrane")
}

fn render_plist(exe: &Path) -> String {
    let logs = log_dir();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>StandardOutPath</key>
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>
</dict>
</plist>
"#,
        exe = exe.display(),
        stdout = logs.join("daemon.out").display(),
        stderr = logs.join("daemon.err").display(),
    )
}

pub fn install(exe: &Path) -> Result<()> {
    let path = plist_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::create_dir_all(log_dir())
        .with_context(|| format!("create {}", log_dir().display()))?;
    std::fs::write(&path, render_plist(exe))
        .with_context(|| format!("write {}", path.display()))?;
    eprintln!("wrote {}", path.display());

    // bootstrap into the GUI domain. If already bootstrapped (e.g. a
    // re-install), bootout first.
    let _ = launchctl(&["bootout", &service_target()]);
    launchctl(&["bootstrap", &domain(), &path.to_string_lossy()])?;
    eprintln!("service installed and bootstrapped");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let _ = launchctl(&["bootout", &service_target()]);
    let path = plist_path();
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("remove {}", path.display()))?;
        eprintln!("removed {}", path.display());
    }
    Ok(())
}

pub fn start() -> Result<()> { launchctl(&["kickstart", &service_target()]) }
pub fn stop() -> Result<()> { launchctl(&["kill", "SIGTERM", &service_target()]) }

pub fn status() -> Result<ServiceStatus> {
    if !plist_path().exists() { return Ok(ServiceStatus::NotInstalled); }
    let output = Command::new("launchctl")
        .args(["print", &service_target()])
        .output()
        .context("run launchctl print")?;
    if !output.status.success() {
        return Ok(ServiceStatus::Stopped);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // launchctl print includes "state = running" when active.
    if text.contains("state = running") {
        Ok(ServiceStatus::Running)
    } else if text.contains("state = ") {
        let line = text.lines()
            .find(|l| l.trim_start().starts_with("state ="))
            .unwrap_or("state = unknown");
        Ok(ServiceStatus::Unknown(line.trim().to_string()))
    } else {
        Ok(ServiceStatus::Stopped)
    }
}

fn launchctl(args: &[&str]) -> Result<()> {
    let output = Command::new("launchctl")
        .args(args)
        .output()
        .with_context(|| format!("launchctl {}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "launchctl {} failed: {}",
            args.join(" "),
            stderr.trim(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_contains_exe_and_logs() {
        let exe = PathBuf::from("/usr/local/bin/membrane-daemon");
        let body = render_plist(&exe);
        assert!(body.contains("<string>com.membrane.daemon</string>"));
        assert!(body.contains("/usr/local/bin/membrane-daemon"));
        assert!(body.contains("<string>run</string>"));
        assert!(body.contains("KeepAlive"));
    }

    #[test]
    #[serial_test::serial]
    fn plist_path_under_launch_agents() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", dir.path());
        let p = plist_path();
        assert!(p.ends_with("Library/LaunchAgents/com.membrane.daemon.plist"));
    }
}

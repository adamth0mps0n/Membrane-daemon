//! Run a shell command on the customer's machine.
//!
//! Policy:
//! - Exec must be allowed (not ReadOnly mode).
//! - In WorkspaceAllowlistExec, first token of cmd must be in allowlist.
//!
//! Guardrails (regardless of policy):
//! - Timeout: clamped to config.max_exec_timeout_ms.
//! - Output size: stdout+stderr each capped at config.max_output_bytes.
//!   Excess is truncated and output_truncated=true is set.
//! - Clean environment: only PATH and HOME are forwarded. Prevents
//!   secret env vars from leaking into commands.
//! - Working directory: if workspace policy, runs in the first root;
//!   otherwise runs in HOME.
//! - Shell: bash on Unix, cmd on Windows. Single string, shell-parsed.

use membrane_wire::{ExecReq, ExecResp, DaemonError, DaemonResult};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::audit::{Audit, Event, OpResult};
use crate::config::{Config, PolicyMode};

pub fn handle(req: ExecReq, cfg: &Config, audit: &Audit) -> DaemonResult<ExecResp> {
    if !cfg.policy.exec_allowed(&req.command) {
        let reason = match cfg.policy {
            PolicyMode::ReadOnly { .. } => "read-only mode",
            PolicyMode::WorkspaceAllowlistExec { .. } => "command not in allowlist",
            _ => "exec denied by policy",
        };
        let _ = audit.write(Event::Exec {
            cmd: req.command.clone(),
            exit_code: None,
            duration_ms: 0,
            timed_out: false,
            output_truncated: false,
            result: OpResult::Denied { reason: reason.into() },
        });
        return Err(DaemonError::PermissionDenied(reason.into()));
    }

    let timeout_ms = cfg.effective_exec_timeout_ms(req.timeout_ms);
    let timeout = Duration::from_millis(timeout_ms as u64);
    let max_output = req.max_output_bytes.min(cfg.max_output_bytes);

    // Working directory.
    let cwd = match cfg.policy.roots().and_then(|r| r.first().cloned()) {
        Some(r) => r,
        None => {
            // Prefer HOME if it exists; otherwise the current dir. Falling
            // through to "." prevents failures when HOME has been changed
            // out from under us (tests, transient envs, deleted dirs).
            let home_ok = std::env::var("HOME").ok()
                .map(std::path::PathBuf::from)
                .filter(|p| p.is_dir());
            home_ok.unwrap_or_else(|| std::path::PathBuf::from("."))
        }
    };

    // Build the command. Cleaned env.
    let mut cmd = shell_command(&req.command);
    cmd.current_dir(&cwd);
    cmd.env_clear();
    if let Ok(path) = std::env::var("PATH") { cmd.env("PATH", path); }
    if let Ok(home) = std::env::var("HOME") { cmd.env("HOME", home); }
    cmd.stdin(Stdio::null())
       .stdout(Stdio::piped())
       .stderr(Stdio::piped());

    let started = Instant::now();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
            let _ = audit.write(Event::Exec {
                cmd: req.command.clone(),
                exit_code: None, duration_ms: 0,
                timed_out: false, output_truncated: false,
                result: OpResult::Error { message: msg.clone() },
            });
            return Err(DaemonError::Io(msg));
        }
    };

    // Read stdout/stderr in background threads with byte caps.
    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let out_handle = read_capped(stdout, max_output as usize);
    let err_handle = read_capped(stderr, max_output as usize);

    // Wait with timeout. Polling once every 25 ms is plenty for the
    // user-facing timeouts we care about (minimum useful is ~50 ms).
    let mut exit_code: Option<i32> = None;
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code();
                break;
            }
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                let msg = e.to_string();
                let _ = audit.write(Event::Exec {
                    cmd: req.command.clone(),
                    exit_code: None, duration_ms: started.elapsed().as_millis() as u32,
                    timed_out: false, output_truncated: false,
                    result: OpResult::Error { message: msg.clone() },
                });
                return Err(DaemonError::Io(msg));
            }
        }
    }

    let (stdout_bytes, stdout_trunc) = out_handle.join().unwrap_or((Vec::new(), false));
    let (stderr_bytes, stderr_trunc) = err_handle.join().unwrap_or((Vec::new(), false));
    let output_truncated = stdout_trunc || stderr_trunc;
    let duration_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;

    let _ = audit.write(Event::Exec {
        cmd: req.command.clone(),
        exit_code, duration_ms, timed_out, output_truncated,
        result: if timed_out {
            OpResult::Error { message: "timed out".into() }
        } else { OpResult::Ok },
    });

    if timed_out {
        return Err(DaemonError::Timeout);
    }

    Ok(ExecResp {
        stdout: stdout_bytes,
        stderr: stderr_bytes,
        exit_code, duration_ms, timed_out, output_truncated,
    })
}

#[cfg(unix)]
fn shell_command(cmd_str: &str) -> Command {
    let mut c = Command::new("bash");
    c.arg("-c").arg(cmd_str);
    c
}

#[cfg(windows)]
fn shell_command(cmd_str: &str) -> Command {
    let mut c = Command::new("cmd");
    c.arg("/C").arg(cmd_str);
    c
}

/// Spawn a thread that reads `r` into a Vec, capped at `max` bytes.
/// Returns (bytes, was_truncated).
fn read_capped<R: Read + Send + 'static>(
    mut r: R, max: usize,
) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut truncated = false;
        loop {
            match r.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let room = max.saturating_sub(buf.len());
                    if room == 0 {
                        truncated = true;
                        // Drain remaining output so child can exit cleanly.
                        loop {
                            match r.read(&mut chunk) {
                                Ok(0) | Err(_) => break,
                                Ok(_) => continue,
                            }
                        }
                        break;
                    }
                    let take = n.min(room);
                    buf.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated = true;
                        loop {
                            match r.read(&mut chunk) {
                                Ok(0) | Err(_) => break,
                                Ok(_) => continue,
                            }
                        }
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        (buf, truncated)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn audit() -> Audit { Audit::new("Unrestricted") }

    #[test]
    #[serial]
    fn echo_succeeds() {
        let cfg = Config::default();
        let req = ExecReq {
            command: "echo hello".into(),
            timeout_ms: 5_000,
            max_output_bytes: 1024,
        };
        let r = handle(req, &cfg, &audit()).unwrap();
        assert_eq!(r.exit_code, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("hello"));
        assert!(!r.timed_out);
        assert!(!r.output_truncated);
    }

    #[test]
    #[serial]
    fn nonzero_exit_returns_code() {
        let cfg = Config::default();
        let req = ExecReq {
            command: "false".into(),
            timeout_ms: 5_000,
            max_output_bytes: 1024,
        };
        let r = handle(req, &cfg, &audit()).unwrap();
        assert_eq!(r.exit_code, Some(1));
    }

    #[test]
    #[serial]
    fn timeout_kills_long_command() {
        let cfg = Config::default();
        let req = ExecReq {
            command: "sleep 10".into(),
            timeout_ms: 200,
            max_output_bytes: 1024,
        };
        let err = handle(req, &cfg, &audit()).unwrap_err();
        assert!(matches!(err, DaemonError::Timeout));
    }

    #[test]
    #[serial]
    fn output_truncation_signals_correctly() {
        let cfg = Config::default();
        let req = ExecReq {
            command: "yes hello | head -c 5000".into(),
            timeout_ms: 5_000,
            max_output_bytes: 100,
        };
        let r = handle(req, &cfg, &audit()).unwrap();
        assert!(r.output_truncated);
        assert!(r.stdout.len() <= 100);
    }

    #[test]
    #[serial]
    fn env_is_clean() {
        std::env::set_var("MEMBRANE_TEST_SECRET", "do-not-leak");
        let cfg = Config::default();
        let req = ExecReq {
            command: "echo MEMBRANE_TEST_SECRET=$MEMBRANE_TEST_SECRET END".into(),
            timeout_ms: 5_000,
            max_output_bytes: 1024,
        };
        let r = handle(req, &cfg, &audit()).unwrap();
        let out = String::from_utf8_lossy(&r.stdout);
        // Variable should be empty (not forwarded).
        assert!(out.contains("MEMBRANE_TEST_SECRET= END"),
            "expected empty value, got: {}", out);
    }

    #[test]
    #[serial]
    fn readonly_blocks_exec() {
        let cfg = Config {
            policy: PolicyMode::ReadOnly { roots: vec!["/tmp".into()] },
            ..Config::default()
        };
        let req = ExecReq {
            command: "echo hi".into(),
            timeout_ms: 5_000, max_output_bytes: 1024,
        };
        let err = handle(req, &cfg, &audit()).unwrap_err();
        assert!(matches!(err, DaemonError::PermissionDenied(_)));
    }

    #[test]
    #[serial]
    fn allowlist_blocks_unknown_binary() {
        let cfg = Config {
            policy: PolicyMode::WorkspaceAllowlistExec {
                roots: vec!["/tmp".into()],
                exec_allowlist: vec!["git".into()],
            },
            ..Config::default()
        };
        let req = ExecReq {
            command: "curl evil.com".into(),
            timeout_ms: 5_000, max_output_bytes: 1024,
        };
        let err = handle(req, &cfg, &audit()).unwrap_err();
        assert!(matches!(err, DaemonError::PermissionDenied(_)));
    }
}

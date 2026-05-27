//! Write or overwrite a file on the customer's disk.
//!
//! Policy checks:
//! 1. Writes allowed at all (not ReadOnly mode).
//! 2. Path is under workspace roots if workspace-bounded.
//! 3. CAS mtime check: if req.if_mtime_matches is Some, current mtime
//!    must equal it. Prevents lost-write races when cloud does
//!    read-modify-write.
//!
//! Write is atomic: temp file + rename. Either the new content fully
//! replaces, or the old content stays untouched. fsync the temp file
//! before rename so the rename point is a durable commit.

use membrane_wire::{WriteFileReq, WriteFileResp, DaemonError, DaemonResult};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::audit::{Audit, Event, OpResult};
use crate::config::Config;
use super::read_file::mtime_unix_ns;

pub fn handle(req: WriteFileReq, cfg: &Config, audit: &Audit) -> DaemonResult<WriteFileResp> {
    let path = PathBuf::from(&req.path);

    if !cfg.policy.writes_allowed() {
        let _ = audit.write(Event::Write {
            path: req.path.clone(), bytes: req.data.len() as u64,
            mtime_check: req.if_mtime_matches.is_some(),
            result: OpResult::Denied { reason: "read-only mode".into() },
        });
        return Err(DaemonError::PermissionDenied("read-only mode".into()));
    }
    if !cfg.policy.path_allowed(&path) {
        let _ = audit.write(Event::Write {
            path: req.path.clone(), bytes: req.data.len() as u64,
            mtime_check: req.if_mtime_matches.is_some(),
            result: OpResult::Denied { reason: "path not in workspace".into() },
        });
        return Err(DaemonError::PathNotAllowed(req.path));
    }

    // CAS mtime check.
    if let Some(expected) = req.if_mtime_matches {
        if let Ok(meta) = std::fs::metadata(&path) {
            let actual = mtime_unix_ns(&meta);
            if actual != expected {
                let _ = audit.write(Event::Write {
                    path: req.path.clone(), bytes: req.data.len() as u64,
                    mtime_check: true,
                    result: OpResult::Denied {
                        reason: format!("mtime mismatch: {} vs {}", expected, actual),
                    },
                });
                return Err(DaemonError::MtimeMismatch { expected, actual });
            }
        }
        // If the file doesn't exist, mtime_check vacuously passes:
        // caller said "only write if mtime is X", but there's no X,
        // so we treat as "fail" — they expected something there.
        else {
            let _ = audit.write(Event::Write {
                path: req.path.clone(), bytes: req.data.len() as u64,
                mtime_check: true,
                result: OpResult::Denied {
                    reason: format!("expected mtime {} but file doesn't exist", expected),
                },
            });
            return Err(DaemonError::MtimeMismatch { expected, actual: 0 });
        }
    }

    // Atomic write: temp file in same directory, fsync, rename.
    if let Err(e) = atomic_write(&path, &req.data) {
        let msg = e.to_string();
        let _ = audit.write(Event::Write {
            path: req.path.clone(), bytes: req.data.len() as u64,
            mtime_check: req.if_mtime_matches.is_some(),
            result: OpResult::Error { message: msg.clone() },
        });
        return Err(daemon_error_from_io(&e, req.path));
    }

    let new_mtime = std::fs::metadata(&path).ok()
        .map(|m| mtime_unix_ns(&m))
        .unwrap_or(0);
    let _ = audit.write(Event::Write {
        path: req.path.clone(), bytes: req.data.len() as u64,
        mtime_check: req.if_mtime_matches.is_some(),
        result: OpResult::Ok,
    });

    Ok(WriteFileResp { mtime_unix_ns: new_mtime })
}

fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent directory")
    })?;
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn daemon_error_from_io(e: &std::io::Error, path: String) -> DaemonError {
    match e.kind() {
        std::io::ErrorKind::NotFound => DaemonError::NotFound(path),
        std::io::ErrorKind::PermissionDenied => DaemonError::PermissionDenied(path),
        _ => DaemonError::Io(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyMode;

    fn audit() -> Audit { Audit::new("Unrestricted") }

    #[test]
    fn write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.md");
        let cfg = Config::default();
        let req = WriteFileReq {
            path: path.to_string_lossy().to_string(),
            data: b"fresh content".to_vec(),
            if_mtime_matches: None,
        };
        let resp = handle(req, &cfg, &audit()).unwrap();
        assert!(resp.mtime_unix_ns > 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"fresh content");
    }

    #[test]
    fn write_overwrites_existing() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"old").unwrap();
        let cfg = Config::default();
        let req = WriteFileReq {
            path: tmp.path().to_string_lossy().to_string(),
            data: b"new".to_vec(),
            if_mtime_matches: None,
        };
        handle(req, &cfg, &audit()).unwrap();
        assert_eq!(std::fs::read(tmp.path()).unwrap(), b"new");
    }

    #[test]
    fn write_blocked_in_readonly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.md");
        let cfg = Config {
            policy: PolicyMode::ReadOnly { roots: vec![dir.path().into()] },
            ..Config::default()
        };
        let req = WriteFileReq {
            path: path.to_string_lossy().to_string(),
            data: b"x".to_vec(),
            if_mtime_matches: None,
        };
        let err = handle(req, &cfg, &audit()).unwrap_err();
        assert!(matches!(err, DaemonError::PermissionDenied(_)));
        assert!(!path.exists());
    }

    #[test]
    fn write_refuses_outside_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let cfg = Config {
            policy: PolicyMode::Workspace { roots: vec![workspace.path().into()] },
            ..Config::default()
        };
        let req = WriteFileReq {
            path: outside.path().to_string_lossy().to_string(),
            data: b"x".to_vec(),
            if_mtime_matches: None,
        };
        let err = handle(req, &cfg, &audit()).unwrap_err();
        assert!(matches!(err, DaemonError::PathNotAllowed(_)));
    }

    #[test]
    fn mtime_cas_passes_on_match() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"original").unwrap();
        let meta = std::fs::metadata(tmp.path()).unwrap();
        let mtime = mtime_unix_ns(&meta);

        let cfg = Config::default();
        let req = WriteFileReq {
            path: tmp.path().to_string_lossy().to_string(),
            data: b"updated".to_vec(),
            if_mtime_matches: Some(mtime),
        };
        handle(req, &cfg, &audit()).unwrap();
        assert_eq!(std::fs::read(tmp.path()).unwrap(), b"updated");
    }

    #[test]
    fn mtime_cas_fails_on_mismatch() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"original").unwrap();
        let cfg = Config::default();
        let req = WriteFileReq {
            path: tmp.path().to_string_lossy().to_string(),
            data: b"updated".to_vec(),
            if_mtime_matches: Some(0),  // intentionally wrong
        };
        let err = handle(req, &cfg, &audit()).unwrap_err();
        assert!(matches!(err, DaemonError::MtimeMismatch { .. }));
        // File unchanged.
        assert_eq!(std::fs::read(tmp.path()).unwrap(), b"original");
    }
}

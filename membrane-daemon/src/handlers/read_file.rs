//! Read a file from the customer's disk.
//!
//! Policy checks (in order):
//! 1. Path is under workspace roots if policy is workspace-bounded.
//! 2. File exists and is readable.
//! 3. File size ≤ min(req.max_bytes, config.max_read_bytes).
//!
//! Audit: one Read entry with bytes read and result status.

use membrane_wire::{ReadFileReq, ReadFileResp, DaemonError, DaemonResult};
use std::path::PathBuf;
use std::time::SystemTime;

use crate::audit::{Audit, Event, OpResult};
use crate::config::Config;

pub fn handle(req: ReadFileReq, cfg: &Config, audit: &Audit) -> DaemonResult<ReadFileResp> {
    let path = PathBuf::from(&req.path);

    // Policy check.
    if !cfg.policy.path_allowed(&path) {
        let _ = audit.write(Event::Read {
            path: req.path.clone(),
            bytes: 0,
            result: OpResult::Denied { reason: "path not in workspace".into() },
        });
        return Err(DaemonError::PathNotAllowed(req.path));
    }

    // Cap requested bytes against daemon's hard limit.
    let cap = req.max_bytes.min(cfg.max_read_bytes);

    // Stat first to size-check without reading.
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = audit.write(Event::Read {
                path: req.path.clone(), bytes: 0,
                result: OpResult::Error { message: "not found".into() },
            });
            return Err(DaemonError::NotFound(req.path));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let _ = audit.write(Event::Read {
                path: req.path.clone(), bytes: 0,
                result: OpResult::Error { message: "permission denied".into() },
            });
            return Err(DaemonError::PermissionDenied(req.path));
        }
        Err(e) => {
            let msg = e.to_string();
            let _ = audit.write(Event::Read {
                path: req.path.clone(), bytes: 0,
                result: OpResult::Error { message: msg.clone() },
            });
            return Err(DaemonError::Io(msg));
        }
    };
    let size = meta.len();
    if size > cap {
        let _ = audit.write(Event::Read {
            path: req.path.clone(), bytes: 0,
            result: OpResult::Denied { reason: format!("size {} > cap {}", size, cap) },
        });
        return Err(DaemonError::SizeLimitExceeded { requested: size, max: cap });
    }

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            let msg = e.to_string();
            let _ = audit.write(Event::Read {
                path: req.path.clone(), bytes: 0,
                result: OpResult::Error { message: msg.clone() },
            });
            return Err(DaemonError::Io(msg));
        }
    };

    let mtime_ns = mtime_unix_ns(&meta);
    let bytes = data.len() as u64;
    let _ = audit.write(Event::Read {
        path: req.path.clone(),
        bytes,
        result: OpResult::Ok,
    });

    Ok(ReadFileResp {
        data,
        mtime_unix_ns: mtime_ns,
        size_bytes: bytes,
    })
}

/// Best-effort conversion from std::fs metadata to nanoseconds since
/// the UNIX epoch. Returns 0 on platforms or filesystems that don't
/// expose mtime.
pub(crate) fn mtime_unix_ns(meta: &std::fs::Metadata) -> i64 {
    let Ok(m) = meta.modified() else { return 0; };
    let Ok(d) = m.duration_since(SystemTime::UNIX_EPOCH) else { return 0; };
    d.as_nanos() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyMode;

    fn audit() -> Audit { Audit::new("Unrestricted") }

    #[test]
    fn read_existing_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello world").unwrap();
        let cfg = Config::default();
        let req = ReadFileReq {
            path: tmp.path().to_string_lossy().to_string(),
            max_bytes: 1 << 20,
        };
        let resp = handle(req, &cfg, &audit()).unwrap();
        assert_eq!(resp.data, b"hello world");
        assert_eq!(resp.size_bytes, 11);
    }

    #[test]
    fn read_refuses_oversized() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), vec![0u8; 2000]).unwrap();
        let cfg = Config::default();
        let req = ReadFileReq {
            path: tmp.path().to_string_lossy().to_string(),
            max_bytes: 100, // smaller than file
        };
        let err = handle(req, &cfg, &audit()).unwrap_err();
        match err {
            DaemonError::SizeLimitExceeded { requested, max } => {
                assert_eq!(requested, 2000);
                assert_eq!(max, 100);
            }
            _ => panic!("wrong error"),
        }
    }

    #[test]
    fn read_refuses_outside_workspace() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"secret").unwrap();
        // Workspace policy with a root that does NOT include the temp file.
        let workspace = tempfile::tempdir().unwrap();
        let cfg = Config {
            policy: PolicyMode::Workspace { roots: vec![workspace.path().into()] },
            ..Config::default()
        };
        let req = ReadFileReq {
            path: tmp.path().to_string_lossy().to_string(),
            max_bytes: 1 << 20,
        };
        let err = handle(req, &cfg, &audit()).unwrap_err();
        assert!(matches!(err, DaemonError::PathNotAllowed(_)));
    }

    #[test]
    fn read_missing_file_returns_not_found() {
        let cfg = Config::default();
        let req = ReadFileReq {
            path: "/tmp/definitely-does-not-exist-12345".into(),
            max_bytes: 1 << 20,
        };
        let err = handle(req, &cfg, &audit()).unwrap_err();
        assert!(matches!(err, DaemonError::NotFound(_)));
    }
}

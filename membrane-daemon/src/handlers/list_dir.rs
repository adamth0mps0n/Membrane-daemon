//! List a directory's contents.
//!
//! Policy: directory must be under workspace roots if workspace-bounded.
//! No size limit on the response — directories with millions of entries
//! are pathological but not blocked here (the network layer enforces
//! its own message-size cap).
//!
//! Skips hidden entries (starting with '.'). Cloud can request them
//! later if needed via a config flag.

use membrane_wire::{ListDirReq, ListDirResp, DirEntry, DaemonError, DaemonResult};
use std::path::PathBuf;

use crate::audit::{Audit, Event, OpResult};
use crate::config::Config;

pub fn handle(req: ListDirReq, cfg: &Config, audit: &Audit) -> DaemonResult<ListDirResp> {
    let path = PathBuf::from(&req.path);

    if !cfg.policy.path_allowed(&path) {
        let _ = audit.write(Event::List {
            path: req.path.clone(), entries: 0,
            result: OpResult::Denied { reason: "path not in workspace".into() },
        });
        return Err(DaemonError::PathNotAllowed(req.path));
    }

    let read_dir = match std::fs::read_dir(&path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = audit.write(Event::List {
                path: req.path.clone(), entries: 0,
                result: OpResult::Error { message: "not found".into() },
            });
            return Err(DaemonError::NotFound(req.path));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let _ = audit.write(Event::List {
                path: req.path.clone(), entries: 0,
                result: OpResult::Error { message: "permission denied".into() },
            });
            return Err(DaemonError::PermissionDenied(req.path));
        }
        Err(e) => {
            let msg = e.to_string();
            let _ = audit.write(Event::List {
                path: req.path.clone(), entries: 0,
                result: OpResult::Error { message: msg.clone() },
            });
            return Err(DaemonError::Io(msg));
        }
    };

    let mut entries = Vec::new();
    for entry in read_dir.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        let name = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue, // non-UTF8 name; skip silently
        };
        if name.starts_with('.') { continue; }
        entries.push(DirEntry {
            name,
            is_dir: meta.is_dir(),
            size_bytes: if meta.is_dir() { 0 } else { meta.len() },
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let _ = audit.write(Event::List {
        path: req.path.clone(),
        entries: entries.len(),
        result: OpResult::Ok,
    });

    Ok(ListDirResp { entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyMode;

    fn audit() -> Audit { Audit::new("Unrestricted") }

    #[test]
    fn list_existing_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.md"), b"x").unwrap();
        std::fs::write(dir.path().join("b.md"), b"yy").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        // hidden — should be filtered
        std::fs::write(dir.path().join(".hidden"), b"z").unwrap();

        let cfg = Config::default();
        let req = ListDirReq { path: dir.path().to_string_lossy().to_string() };
        let resp = handle(req, &cfg, &audit()).unwrap();
        assert_eq!(resp.entries.len(), 3);
        // Sorted alphabetically.
        assert_eq!(resp.entries[0].name, "a.md");
        assert!(!resp.entries[0].is_dir);
        assert_eq!(resp.entries[0].size_bytes, 1);
        assert_eq!(resp.entries[1].name, "b.md");
        assert_eq!(resp.entries[1].size_bytes, 2);
        assert_eq!(resp.entries[2].name, "sub");
        assert!(resp.entries[2].is_dir);
    }

    #[test]
    fn list_missing_returns_not_found() {
        let cfg = Config::default();
        let req = ListDirReq { path: "/tmp/no-such-dir-xyz".into() };
        let err = handle(req, &cfg, &audit()).unwrap_err();
        assert!(matches!(err, DaemonError::NotFound(_)));
    }

    #[test]
    fn list_refuses_outside_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let cfg = Config {
            policy: PolicyMode::Workspace { roots: vec![workspace.path().into()] },
            ..Config::default()
        };
        let req = ListDirReq { path: outside.path().to_string_lossy().to_string() };
        let err = handle(req, &cfg, &audit()).unwrap_err();
        assert!(matches!(err, DaemonError::PathNotAllowed(_)));
    }
}

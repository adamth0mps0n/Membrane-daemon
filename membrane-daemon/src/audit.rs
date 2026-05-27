//! Audit log: every read, write, exec, and policy-deny is appended to
//! a daily JSONL file under `audit_dir()`. The customer can grep,
//! `jq`, tail, or forward these to a SIEM.
//!
//! Daily rotation: a new file `YYYY-MM-DD.jsonl` per UTC day. Old files
//! kept indefinitely (customer's disk, customer's choice when to delete).
//!
//! Format: one JSON object per line. Fields are forward-compatible —
//! readers must tolerate unknown fields. Common envelope:
//!
//! ```json
//! {"ts":"2026-05-22T20:18:33.123Z","op":"read","mode":"Unrestricted", ...op-specific...}
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Event {
    Read {
        path: String,
        bytes: u64,
        result: OpResult,
    },
    Write {
        path: String,
        bytes: u64,
        /// Was a CAS mtime check requested?
        mtime_check: bool,
        result: OpResult,
    },
    List {
        path: String,
        entries: usize,
        result: OpResult,
    },
    Exec {
        cmd: String,
        exit_code: Option<i32>,
        duration_ms: u32,
        timed_out: bool,
        output_truncated: bool,
        result: OpResult,
    },
    /// Daemon lifecycle events.
    Lifecycle {
        event: String,
        detail: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum OpResult {
    Ok,
    Denied { reason: String },
    Error { message: String },
}

/// Wrapper that adds the common envelope (timestamp + mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub ts: DateTime<Utc>,
    /// Policy mode name at the time of the event.
    pub mode: String,
    #[serde(flatten)]
    pub event: Event,
}

/// Audit log writer. Cheap to construct; opens the daily file lazily.
#[derive(Clone)]
pub struct Audit {
    mode_name: String,
}

impl Audit {
    pub fn new(mode_name: impl Into<String>) -> Self {
        Self { mode_name: mode_name.into() }
    }

    /// Append an event to the day's log file.
    pub fn write(&self, event: Event) -> std::io::Result<()> {
        let entry = Entry { ts: Utc::now(), mode: self.mode_name.clone(), event };
        let line = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let day = entry.ts.format("%Y-%m-%d").to_string();
        let path = crate::paths::audit_log_for(&day);
        if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
        append_line(&path, &line)
    }
}

fn append_line(path: &Path, line: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true).append(true).open(path)?;
    writeln!(f, "{line}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Override HOME so paths::user_dir() resolves into a temp dir.
    ///
    /// HOME is process-global; tests that call this must be marked
    /// `#[serial]` or they race each other.
    fn isolate_user_dir() -> tempfile::TempDir {
        let dir = tempfile::Builder::new()
            .prefix("membrane-audit-test-")
            .tempdir().unwrap();
        std::env::set_var("HOME", dir.path());
        dir
    }

    #[test]
    fn write_event_roundtrip() {
        let event = Event::Read {
            path: "/home/adam/test.md".into(),
            bytes: 1024,
            result: OpResult::Ok,
        };
        let entry = Entry {
            ts: Utc::now(),
            mode: "Unrestricted".into(),
            event,
        };
        let line = serde_json::to_string(&entry).unwrap();
        let parsed: Entry = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed.mode, "Unrestricted");
        match parsed.event {
            Event::Read { bytes, .. } => assert_eq!(bytes, 1024),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_result_variants_round_trip() {
        let cases = vec![
            OpResult::Ok,
            OpResult::Denied { reason: "read-only".into() },
            OpResult::Error { message: "io".into() },
        ];
        for r in cases {
            let s = serde_json::to_string(&r).unwrap();
            let _: OpResult = serde_json::from_str(&s).unwrap();
        }
    }

    #[test]
    #[serial]
    fn audit_writes_jsonl_to_daily_file() {
        let _guard = isolate_user_dir();
        let audit = Audit::new("Unrestricted");
        audit.write(Event::Lifecycle {
            event: "startup".into(),
            detail: "test boot".into(),
        }).unwrap();
        audit.write(Event::Read {
            path: "/x".into(),
            bytes: 0,
            result: OpResult::Ok,
        }).unwrap();

        let day = Utc::now().format("%Y-%m-%d").to_string();
        let log = crate::paths::audit_log_for(&day);
        let body = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        let l0: Entry = serde_json::from_str(lines[0]).unwrap();
        assert!(matches!(l0.event, Event::Lifecycle { .. }));
    }

    #[test]
    #[serial]
    fn denied_exec_recorded_correctly() {
        let _guard = isolate_user_dir();
        let audit = Audit::new("WorkspaceAllowlistExec");
        audit.write(Event::Exec {
            cmd: "curl evil.com".into(),
            exit_code: None,
            duration_ms: 0,
            timed_out: false,
            output_truncated: false,
            result: OpResult::Denied { reason: "not in allowlist".into() },
        }).unwrap();
        let day = Utc::now().format("%Y-%m-%d").to_string();
        let body = std::fs::read_to_string(crate::paths::audit_log_for(&day)).unwrap();
        assert!(body.contains("\"status\":\"denied\""));
        assert!(body.contains("\"reason\":\"not in allowlist\""));
    }
}

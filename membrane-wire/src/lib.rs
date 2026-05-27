//! Wire protocol shared between the membrane cloud server and the
//! customer-side daemon.
//!
//! ## Connection model
//!
//! - One QUIC connection per session.
//! - One QUIC stream per RPC: client (cloud) sends one `Request`, daemon
//!   replies with one `Response`, then closes the stream.
//! - All RPCs are request/response. No streaming.
//!
//! ## Framing
//!
//! Each message on a stream is length-prefixed (u32 little-endian) and
//! bincode-encoded. There is no version header in v1; cloud and daemon
//! ship together.
//!
//! ## Trust model
//!
//! - The substrate lives in the cloud. The daemon's job is purely to
//!   serve customer-machine files and run shell commands when asked.
//! - The daemon enforces what filesystem paths it serves via its
//!   allowlist config. The cloud does not pass policy; the daemon
//!   refuses paths outside its allowlist.
//! - All four data-touching RPCs (ReadFile, WriteFile, ListDir, Exec)
//!   are logged daemon-side to a local audit log the customer controls.

use serde::{Deserialize, Serialize};

// ── Filesystem ──────────────────────────────────────────────────────

/// Read a file from the customer's disk.
///
/// Used by the cloud to:
/// - `absorb://path` — ingest a file into the substrate
/// - `view://path` — show the user file contents in chat
/// - `documents` / `context` queries — rescan source files for passages
///   around query-word occurrences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFileReq {
    pub path: String,
    /// Daemon refuses if file exceeds this. Cloud should set a sane cap
    /// (typically a few MB) to prevent runaway reads.
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFileResp {
    pub data: Vec<u8>,
    pub mtime_unix_ns: i64,
    pub size_bytes: u64,
}

/// Write or overwrite a file on the customer's disk.
///
/// Used by the cloud to:
/// - `write://path` — create or overwrite a file with `data`
/// - `edit://path` — apply a unique-anchor replacement, served by the
///   cloud as a write of the new full contents (cloud handles the
///   anchor-matching using a prior ReadFile)
///
/// For `edit://` the cloud sets `if_mtime_matches` to the mtime it read
/// earlier; daemon refuses if the file changed under us, preventing
/// lost-write races.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteFileReq {
    pub path: String,
    pub data: Vec<u8>,
    pub if_mtime_matches: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteFileResp {
    pub mtime_unix_ns: i64,
}

/// List a directory on the customer's disk.
///
/// Used by the cloud to:
/// - `batch://absorb dir=...` — enumerate files for bulk ingest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDirReq {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDirResp {
    pub entries: Vec<DirEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u64,
}

// ── Exec ────────────────────────────────────────────────────────────

/// Run a shell command on the customer's machine.
///
/// Used by the cloud for `exec://command`.
///
/// Daemon enforces:
/// - timeout in seconds; cloud's `timeout_ms` clamped to daemon's max
/// - output capped at `max_output_bytes`; oversized output truncated
///   with a marker
/// - command runs as the same user the daemon runs as
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecReq {
    pub command: String,
    pub timeout_ms: u32,
    pub max_output_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResp {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub duration_ms: u32,
    pub timed_out: bool,
    /// True if stdout or stderr was truncated to fit `max_output_bytes`.
    pub output_truncated: bool,
}

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonError {
    /// Path not under the daemon's allowlist.
    PathNotAllowed(String),
    /// Path doesn't exist on the customer's disk.
    NotFound(String),
    /// Path exists but daemon can't access it (permissions, etc.).
    PermissionDenied(String),
    /// Generic underlying IO failure (with message).
    Io(String),
    /// Request asked for more bytes than the daemon allows.
    SizeLimitExceeded { requested: u64, max: u64 },
    /// Operation exceeded the deadline.
    Timeout,
    /// CAS-style mtime check failed for `WriteFile`.
    MtimeMismatch { expected: i64, actual: i64 },
    /// Anything else that doesn't fit the categories above.
    Other(String),
}

pub type DaemonResult<T> = Result<T, DaemonError>;

// ── Top-level envelopes ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    ReadFile(ReadFileReq),
    WriteFile(WriteFileReq),
    ListDir(ListDirReq),
    Exec(ExecReq),
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    ReadFile(DaemonResult<ReadFileResp>),
    WriteFile(DaemonResult<WriteFileResp>),
    ListDir(DaemonResult<ListDirResp>),
    Exec(DaemonResult<ExecResp>),
    Pong,
}

// ── Framing helpers ────────────────────────────────────────────────

/// Encode a message with a u32 little-endian length prefix.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, bincode::Error> {
    let body = bincode::serialize(msg)?;
    let len = body.len() as u32;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a length-prefixed message from a buffer. Returns the decoded
/// message and how many bytes were consumed.
///
/// `Err(NeedMore(n))` means `n` more bytes are required before a full
/// message can be decoded.
pub fn decode<T: for<'de> Deserialize<'de>>(buf: &[u8]) -> Result<(T, usize), DecodeError> {
    if buf.len() < 4 {
        return Err(DecodeError::NeedMore(4 - buf.len()));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&buf[..4]);
    let len = u32::from_le_bytes(len_bytes) as usize;
    if buf.len() < 4 + len {
        return Err(DecodeError::NeedMore(4 + len - buf.len()));
    }
    let msg: T = bincode::deserialize(&buf[4..4 + len])
        .map_err(|e| DecodeError::Bincode(e.to_string()))?;
    Ok((msg, 4 + len))
}

#[derive(Debug)]
pub enum DecodeError {
    NeedMore(usize),
    Bincode(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::NeedMore(n) => write!(f, "need {n} more bytes"),
            DecodeError::Bincode(e) => write!(f, "decode error: {e}"),
        }
    }
}

impl std::error::Error for DecodeError {}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_file_roundtrip() {
        let req = Request::ReadFile(ReadFileReq {
            path: "/home/adam/Documents/notes.md".into(),
            max_bytes: 1 << 20,
        });
        let encoded = encode(&req).unwrap();
        let (decoded, n): (Request, usize) = decode(&encoded).unwrap();
        assert_eq!(n, encoded.len());
        assert!(matches!(decoded, Request::ReadFile(_)));
    }

    #[test]
    fn write_file_with_mtime_check() {
        let req = Request::WriteFile(WriteFileReq {
            path: "/tmp/test.md".into(),
            data: b"new content".to_vec(),
            if_mtime_matches: Some(1234567890),
        });
        let encoded = encode(&req).unwrap();
        let (decoded, _): (Request, usize) = decode(&encoded).unwrap();
        match decoded {
            Request::WriteFile(w) => {
                assert_eq!(w.if_mtime_matches, Some(1234567890));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn exec_response_with_truncation() {
        let resp = Response::Exec(Ok(ExecResp {
            stdout: vec![0; 1024],
            stderr: vec![],
            exit_code: Some(0),
            duration_ms: 42,
            timed_out: false,
            output_truncated: true,
        }));
        let encoded = encode(&resp).unwrap();
        let (decoded, _): (Response, usize) = decode(&encoded).unwrap();
        match decoded {
            Response::Exec(Ok(r)) => {
                assert!(r.output_truncated);
                assert_eq!(r.stdout.len(), 1024);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn need_more_signals_partial_buffer() {
        let req = Request::Ping;
        let encoded = encode(&req).unwrap();
        let result: Result<(Request, usize), DecodeError> =
            decode(&encoded[..encoded.len() - 1]);
        match result {
            Err(DecodeError::NeedMore(n)) => assert_eq!(n, 1),
            _ => panic!("expected NeedMore(1)"),
        }
    }

    #[test]
    fn daemon_error_variants_roundtrip() {
        let errors = vec![
            DaemonError::PathNotAllowed("/etc/shadow".into()),
            DaemonError::NotFound("/nope".into()),
            DaemonError::SizeLimitExceeded { requested: 1 << 30, max: 1 << 20 },
            DaemonError::MtimeMismatch { expected: 0, actual: 1 },
            DaemonError::Timeout,
        ];
        for e in errors {
            let resp = Response::ReadFile(Err(e.clone()));
            let encoded = encode(&resp).unwrap();
            let (decoded, _): (Response, usize) = decode(&encoded).unwrap();
            assert_eq!(format!("{:?}", decoded), format!("{:?}", resp));
        }
    }

    #[test]
    fn list_dir_with_entries() {
        let resp = Response::ListDir(Ok(ListDirResp {
            entries: vec![
                DirEntry { name: "a.md".into(), is_dir: false, size_bytes: 1024 },
                DirEntry { name: "subdir".into(), is_dir: true, size_bytes: 4096 },
            ],
        }));
        let encoded = encode(&resp).unwrap();
        let (decoded, _): (Response, usize) = decode(&encoded).unwrap();
        match decoded {
            Response::ListDir(Ok(r)) => {
                assert_eq!(r.entries.len(), 2);
                assert!(r.entries[1].is_dir);
            }
            _ => panic!("wrong variant"),
        }
    }
}

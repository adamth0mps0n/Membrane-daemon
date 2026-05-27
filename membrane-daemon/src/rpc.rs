//! RPC server loop. Reads length-prefixed Request frames from a Read,
//! dispatches via `handlers::dispatch`, writes length-prefixed Response
//! frames to a Write.
//!
//! The function is generic over Read+Write so the same loop drives:
//! - stdio (this step's main use, easy to test with shell pipelines)
//! - QUIC bidirectional streams (step 3 — quinn streams implement
//!   AsyncRead+AsyncWrite, which we'll wrap to fit this signature)

use membrane_wire::{encode, decode, DecodeError, Request};
use std::io::{Read, Write};

use crate::audit::Audit;
use crate::config::Config;
use crate::handlers;

/// Run the RPC loop synchronously: read one Request, dispatch, write
/// one Response, repeat until stream closes or a framing error is
/// unrecoverable. Returns Ok(()) on clean EOF.
pub fn serve(mut input: impl Read, mut output: impl Write, cfg: &Config, audit: &Audit)
    -> std::io::Result<()>
{
    let mut buf: Vec<u8> = Vec::with_capacity(4096);

    loop {
        // Read frames out of `buf`, requesting more from `input` as needed.
        match decode::<Request>(&buf) {
            Ok((req, consumed)) => {
                buf.drain(..consumed);
                let resp = handlers::dispatch(req, cfg, audit);
                let frame = encode(&resp).map_err(io_err)?;
                output.write_all(&frame)?;
                output.flush()?;
            }
            Err(DecodeError::NeedMore(_)) => {
                let mut chunk = [0u8; 4096];
                let n = input.read(&mut chunk)?;
                if n == 0 {
                    // Clean EOF if nothing partial buffered.
                    return if buf.is_empty() { Ok(()) }
                    else { Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "stream ended mid-frame",
                    )) };
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(DecodeError::Bincode(msg)) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("frame decode error: {msg}"),
                ));
            }
        }
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use membrane_wire::{ReadFileReq, WriteFileReq, ListDirReq, ExecReq, Request, Response};
    use serial_test::serial;

    fn fixture_cfg() -> Config { Config::default() }
    fn fixture_audit() -> Audit { Audit::new("Unrestricted") }

    /// Round-trip a single request through the dispatcher.
    fn one_round(req: Request) -> Response {
        let frame = encode(&req).unwrap();
        let mut output: Vec<u8> = Vec::new();
        // Run the loop — it returns Ok(()) when input EOFs cleanly.
        let cfg = fixture_cfg();
        let audit = fixture_audit();
        serve(&frame[..], &mut output, &cfg, &audit).unwrap();
        let (resp, _): (Response, usize) = decode(&output).unwrap();
        resp
    }

    #[test]
    #[serial]
    fn ping_dispatches() {
        let resp = one_round(Request::Ping);
        assert!(matches!(resp, Response::Pong));
    }

    #[test]
    #[serial]
    fn read_file_dispatches() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello stdio").unwrap();
        let resp = one_round(Request::ReadFile(ReadFileReq {
            path: tmp.path().to_string_lossy().to_string(),
            max_bytes: 1 << 20,
        }));
        match resp {
            Response::ReadFile(Ok(r)) => assert_eq!(r.data, b"hello stdio"),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    #[serial]
    fn write_file_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.md");
        let resp = one_round(Request::WriteFile(WriteFileReq {
            path: path.to_string_lossy().to_string(),
            data: b"written via rpc loop".to_vec(),
            if_mtime_matches: None,
        }));
        assert!(matches!(resp, Response::WriteFile(Ok(_))));
        assert_eq!(std::fs::read(&path).unwrap(), b"written via rpc loop");
    }

    #[test]
    #[serial]
    fn list_dir_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.md"), b"x").unwrap();
        let resp = one_round(Request::ListDir(ListDirReq {
            path: dir.path().to_string_lossy().to_string(),
        }));
        match resp {
            Response::ListDir(Ok(r)) => {
                assert_eq!(r.entries.len(), 1);
                assert_eq!(r.entries[0].name, "a.md");
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    #[serial]
    fn exec_dispatches() {
        let resp = one_round(Request::Exec(ExecReq {
            command: "echo via-rpc".into(),
            timeout_ms: 5_000,
            max_output_bytes: 1024,
        }));
        match resp {
            Response::Exec(Ok(r)) => {
                assert!(String::from_utf8_lossy(&r.stdout).contains("via-rpc"));
                assert_eq!(r.exit_code, Some(0));
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    #[serial]
    fn multiple_requests_in_one_stream() {
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(&encode(&Request::Ping).unwrap());
        input.extend_from_slice(&encode(&Request::Ping).unwrap());
        input.extend_from_slice(&encode(&Request::Ping).unwrap());

        let mut output: Vec<u8> = Vec::new();
        let cfg = fixture_cfg();
        let audit = fixture_audit();
        serve(&input[..], &mut output, &cfg, &audit).unwrap();

        // Should have three Pong responses back-to-back.
        let mut cursor = 0;
        for _ in 0..3 {
            let (resp, n): (Response, usize) = decode(&output[cursor..]).unwrap();
            assert!(matches!(resp, Response::Pong));
            cursor += n;
        }
        assert_eq!(cursor, output.len());
    }

    #[test]
    #[serial]
    fn partial_frame_then_eof_is_error() {
        // First 4 bytes of a frame (the length prefix) but no body.
        let prefix = [10u8, 0, 0, 0]; // claims 10 bytes
        let mut output: Vec<u8> = Vec::new();
        let cfg = fixture_cfg();
        let audit = fixture_audit();
        let err = serve(&prefix[..], &mut output, &cfg, &audit).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    #[serial]
    fn corrupt_frame_is_error() {
        // Valid 5-byte body, but the bytes aren't a valid bincode-encoded Request.
        let body = [0xFFu8; 5];
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&body);
        let mut output: Vec<u8> = Vec::new();
        let cfg = fixture_cfg();
        let audit = fixture_audit();
        let err = serve(&frame[..], &mut output, &cfg, &audit).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}

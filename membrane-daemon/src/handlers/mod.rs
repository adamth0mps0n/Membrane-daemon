//! RPC handlers. Each function takes a typed request, the daemon's
//! policy/config, and the audit writer; returns a typed response with
//! every operation already recorded in the audit log.
//!
//! Handlers are pure functions of (request, policy, audit) — no shared
//! mutable state. This means many can run concurrently without locks
//! once the QUIC layer is added.

pub mod read_file;
pub mod write_file;
pub mod list_dir;
pub mod exec;
pub mod ping;

use membrane_wire::{Request, Response};

use crate::audit::Audit;
use crate::config::Config;

/// Dispatch a single request to its handler. Returns the response.
pub fn dispatch(req: Request, cfg: &Config, audit: &Audit) -> Response {
    match req {
        Request::ReadFile(r) => Response::ReadFile(read_file::handle(r, cfg, audit)),
        Request::WriteFile(r) => Response::WriteFile(write_file::handle(r, cfg, audit)),
        Request::ListDir(r) => Response::ListDir(list_dir::handle(r, cfg, audit)),
        Request::Exec(r) => Response::Exec(exec::handle(r, cfg, audit)),
        Request::Ping => { ping::handle(); Response::Pong }
    }
}

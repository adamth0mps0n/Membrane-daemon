//! Library surface of the membrane daemon.
//!
//! `main.rs` is the daemon binary; this lib exposes modules so the
//! sibling bins (`mock-cloud`, `stub-issuer`) can reuse them without
//! duplicating code. External consumers shouldn't depend on this crate.

#![allow(dead_code)]

pub mod paths;
pub mod config;
pub mod audit;
pub mod handlers;
pub mod rpc;
pub mod tunnel;
pub mod pairing;
pub mod service;

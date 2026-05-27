//! Ping handler — daemon-side no-op.
//!
//! Kept as its own module so the dispatcher's match is symmetric and
//! ping-specific behavior (rate limiting, lightweight stats reporting,
//! etc.) can be added later without restructuring the dispatcher.

pub fn handle() {
    // Pong is constructed by the dispatcher; nothing to do here.
}

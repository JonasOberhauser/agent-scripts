//! Negative-control gate test PR (T3): the declared branch does not
//! exist — the gate must REJECT gracefully (no crash).
#![allow(unknown_lints)]
#![allow(clippy::unwrap_used, clippy::panic, unused_results, inline_literal)]
use fuse_protocol::protocol::versions_compatible;

#[test]
fn empty_is_incompatible() {
    assert!(!versions_compatible("", "0.34.0"));
}

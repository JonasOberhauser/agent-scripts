//! Gate self-test T10: the declaration block contains EMPTY lines and
//! a non-branch line — the parser must take only the /-prefixed
//! branch entries.
#![allow(unknown_lints)]
#![allow(clippy::unwrap_used, clippy::panic, unused_results, inline_literal)]
use fuse_protocol::protocol::versions_compatible;

#[test]
fn t10_marker_resilience() {
    assert!(!versions_compatible("", "0.34.0"), "empty fails closed");
}

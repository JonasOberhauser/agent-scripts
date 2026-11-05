//! Negative-control gate test PR (T4): the declared branch does not
//! BUILD (library syntax error) — the gate must REJECT (a broken
//! control proves nothing).
#![allow(unknown_lints)]
#![allow(clippy::unwrap_used, clippy::panic, unused_results, inline_literal)]
use fuse_protocol::protocol::versions_compatible;

#[test]
fn major_skew_is_incompatible() {
    assert!(!versions_compatible("1.0.0", "0.34.0"));
}

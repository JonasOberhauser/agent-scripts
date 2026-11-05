//! Negative-control gate test PR (T1): this test passes on the
//! declared fault branch (the fault is unrelated) — the gate MUST
//! reject the PR.
#![allow(unknown_lints)]
#![allow(clippy::unwrap_used, clippy::panic, unused_results, inline_literal)]
use fuse_protocol::protocol::versions_compatible;

#[test]
fn minor_skew_is_incompatible() {
    assert!(!versions_compatible("0.34.0", "0.35.0"));
}

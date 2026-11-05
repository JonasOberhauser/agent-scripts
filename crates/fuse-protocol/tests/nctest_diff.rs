//! Negative-control gate test PR (T2): the declared branch MODIFIES
//! this test file — rule 1 must REJECT.
#![allow(unknown_lints)]
#![allow(clippy::unwrap_used, clippy::panic, unused_results, inline_literal)]
use fuse_protocol::protocol::versions_compatible;

#[test]
fn garbage_version_is_incompatible() {
    assert!(!versions_compatible("banana", "0.34.0"));
}

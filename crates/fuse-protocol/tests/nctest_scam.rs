//! S2: the SCAM shape — commit 1 adds a WRONG failing test, commit 2
//! fixes the TEST (not the library). The last touch passes → no
//! self-control → REJECT (no branches declared either).
#![allow(unknown_lints)]
#![allow(clippy::unwrap_used, clippy::panic, unused_results, inline_literal)]
use fuse_protocol::protocol::versions_compatible;

#[test]
fn s2_wrong_expectation() {
    assert!(versions_compatible("0.34.0", "9.9.9"), "deliberately wrong");
}

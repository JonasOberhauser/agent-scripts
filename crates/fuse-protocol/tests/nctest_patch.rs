//! Gate self-test T6: file-granularity branch (one test target per
//! fault branch to catch).
#![allow(unknown_lints)]
#![allow(clippy::unwrap_used, clippy::panic, unused_results, inline_literal)]
use fuse_protocol::protocol::versions_compatible;
#[test]
fn t6_patch_tolerance() {
    assert!(versions_compatible("0.34.0", "0.34.7"), "patch skew is fine");
}

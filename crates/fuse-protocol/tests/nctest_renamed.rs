//! Gate self-test T9: a test file RENAMED by the PR (delete + add in
//! one diff) — the added side must be caught like any touched test.
#![allow(unknown_lints)]
#![allow(clippy::unwrap_used, clippy::panic, unused_results, inline_literal)]
use fuse_protocol::protocol::versions_compatible;

#[test]
fn t9_renamed_still_checks_the_contract() {
    assert!(versions_compatible("0.34.0", "0.34.7"));
}

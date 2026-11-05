//! Gate self-test T7: a second touched test that NO declared branch
//! catches — the gate must REJECT even though one test IS caught.
#![allow(unknown_lints)]
#![allow(clippy::unwrap_used, clippy::panic, unused_results, inline_literal)]
use fuse_protocol::protocol::versions_compatible;

#[test]
fn t7_major_axis() {
    assert!(!versions_compatible("1.0.0", "0.34.0"), "major is incompatible");
}

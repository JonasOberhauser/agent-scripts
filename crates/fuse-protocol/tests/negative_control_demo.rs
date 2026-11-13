//! A REAL test doubling as the negative-control gate's self-test
//! (#145 review: "can you also test this CI somehow?"). It exercises
//! the gate end-to-end: this file is a touched test on the gate's
//! own PR, the declared fault branch faults `versions_compatible`
//! (patch-component comparison — a real bug class), and the gate
//! must see THIS test fail on that branch to pass.
#![allow(unknown_lints)]
#![allow(clippy::unwrap_used, clippy::panic, unused_results, inline_literal)]

use fuse_protocol::protocol::versions_compatible;

/// The versioning contract (AGENTS.md): the handshake ignores the
/// patch component — patch releases never force a server restart.
#[test]
fn patch_differences_are_compatible() {
    assert!(versions_compatible("0.34.0", "0.34.9"), "patch skew is fine");
    assert!(versions_compatible("0.34.9", "0.34.0"), "either direction");
    assert!(!versions_compatible("0.34.0", "0.35.0"), "minor is the axis");
}

// gate-probe touch: the aggregation validation is the point of this draft

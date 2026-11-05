//! S1: a genuine test-first RED — the stub below returns the WRONG
//! answer on purpose; the next commit fixes the implementation. The
//! test's own last-touch commit is runtime-red: self-control.
#![allow(unknown_lints)]
#![allow(clippy::unwrap_used, clippy::panic, unused_results, inline_literal)]
use fuse_protocol::protocol::major_of;

#[test]
fn major_of_parses_the_leading_component() {
    assert_eq!(major_of("0.34.7"), Some(0), "major of 0.x is 0");
    assert_eq!(major_of("2.1.0"), Some(2), "major of 2.x is 2");
    assert_eq!(major_of("banana"), None, "garbage has no major");
}

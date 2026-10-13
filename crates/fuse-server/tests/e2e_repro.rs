//! The live-report restart flow (2026-10-13), end to end and kernel-
//! free: the REAL fuse-client restarting a REAL supervised stack whose
//! daemon cannot surrender (the real fused until #103 lands) — the
//! exact production shape of the #93 F2 fallback.
//!
//! Two live failures are pinned here:
//! 1. round 1: the OrphanBySocket kill was a `pkill -f "--socket …"`
//!    child — a `--`-leading pattern parses as an OPTION (rc 2, kills
//!    nothing), the old server survived, and the successor died on
//!    its "another server is running" probe ("Server did not start
//!    within 10s");
//! 2. round 2: the restart never recorded the successor's pid, so
//!    every later restart walked the same broken orphan path.
//!
//! Now: both rounds refuse handoff honestly, kill the old server
//! precisely (exact argv tokens, never a substring sweep), WAIT for
//! its death, record the successor, and serve.

#![allow(clippy::unwrap_used, clippy::panic, unused_results)]

use gatekeeper_testkit::{bin, Stack};

fn restart_via_client(stack: &gatekeeper_testkit::SupervisedStack) -> String {
    let out = std::process::Command::new(bin("fuse-client"))
        .arg("--socket")
        .arg(stack.socket())
        .arg("restart")
        .env(fuse_protocol::ENV_STATE_FILE, stack.state_file())
        .output()
        .expect("run fuse-client restart");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn the_live_report_flow_two_rounds_of_fallback_restarts() {
    let stack = Stack::new()
        .pending_timeout(std::time::Duration::from_secs(5))
        .fused_binary(std::path::Path::new("/bin/sleep"))
        .spawn_supervised();
    for round in 1..=2 {
        let text = restart_via_client(&stack);
        assert!(
            text.contains("Handoff refused") || text.contains("does not speak handoff"),
            "round {round}: the honest refusal must precede the fallback: {text}"
        );
        assert!(
            !text.contains("Server did not start"),
            "round {round}: the successor never served — {text}"
        );
        assert!(
            text.contains("Server ready"),
            "round {round}: the restart must complete: {text}"
        );
        stack.wait_serving();
    }
}

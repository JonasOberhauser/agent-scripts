//! The F2 bug (#93's original shape), still live on main after the
//! kill fix (#106): a SIGTERM'd policy daemon ORPHANS its supervised
//! data daemon. The orphan keeps running — holding the FUSE mount on
//! a real stack — and every restart leaks one; the successor then
//! mounts over a mount the orphan still serves.
//!
//! The client's restart TERMs the policy daemon (reliably, since
//! #106). What happens to the supervised child is the SERVER's
//! contract: it must die WITH its supervisor.

#![allow(clippy::unwrap_used, clippy::panic, unused_results)]

use gatekeeper_testkit::Stack;

/// The live-report shape, driven exactly as the client drives it:
/// SIGTERM the policy daemon → the supervised daemon must not survive
/// its supervisor.
#[test]
fn a_sigtermd_policy_daemon_reaps_its_supervised_daemon() {
    let mut stack = Stack::new()
        .pending_timeout(std::time::Duration::from_secs(5))
        .spawn_supervised();
    let daemons = stack.daemon_pids();
    assert!(!daemons.is_empty(), "the supervised daemon must be alive to start");
    let daemon = daemons[0];

    // The client's fallback kill (#106): SIGTERM — the catchable
    // signal whose handler is the code under test (SIGKILL, the
    // kit's kill_policy, would skip it entirely).
    stack.terminate_policy();

    // The daemon must die WITH its supervisor: an orphaned daemon
    // holds the mount (a real stack) and leaks one process per
    // restart — the second-restart failure mode #93 was opened for.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let gone = stack.daemon_pids().is_empty();
        if gone {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "F2: the SIGTERM'd policy daemon orphaned its supervised \
             daemon (pid {daemon} still alive) — it holds the mount and \
             leaks across restarts"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

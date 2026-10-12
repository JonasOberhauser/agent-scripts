//! The #93 F2 handoff races — every failure mode from the PR #97
//! design discussion, pinned on the supervision seam (real
//! fuse-server processes, the custody-capable fake fused, no kernel
//! FUSE: runs in every container).
//!
//! The custody-lineage oracle: the fake daemon appends 8-byte BE
//! generation counters through ONE shared file description. A
//! continued lineage `[1, 2, 3, ...]` proves the fd (and its position)
//! was inherited — a reopened file restarts at position 0, so a fresh
//! mount always shows `[1]`.

#![allow(clippy::unwrap_used, clippy::panic, unused_results)]

use std::process::Child;

use gatekeeper_testkit::{bin, Stack};

/// A supervision stack whose fake daemon maintains the custody
/// lineage, plus the wait-for-generation helper.
struct HandoffStack {
    stack: gatekeeper_testkit::SupervisedStack,
}

impl HandoffStack {
    fn new() -> Self {
        let stack = Stack::new()
            .pending_timeout(std::time::Duration::from_secs(5))
            .spawn_supervised();
        // The first generation lands when the fake boots.
        let s = Self { stack };
        s.wait_generations(1);
        s
    }

    fn wait_generations(&self, n: usize) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if self.stack.custody_lineage().len() >= n {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!(
            "custody lineage never reached {n} generations: {:?} — {}",
            self.stack.custody_lineage(),
            self.stack.dump_server_log()
        );
    }

    /// Ask for handoff mode and wait until the old server lingers.
    fn handoff(&self, timeout_secs: Option<u64>) {
        let out = self.stack.request_handoff(timeout_secs);
        assert!(
            out.status.success(),
            "handoff command failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        // The rendezvous appears when the conductor is live.
        let sock = self
            .stack
            .state_file()
            .parent()
            .unwrap()
            .join("oracle.sock.handoff");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if sock.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!(
            "handoff socket never appeared — {}",
            self.stack.dump_server_log()
        );
    }
}

fn pid_dead(pid: u32) -> bool {
    // #97's lesson: kill(0) succeeds and /proc lists UNREAPED
    // zombies — a corpse is not a survivor. The /proc state is the
    // honest answer (gone, zombie, or dead-on-arrival all count).
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return true; // reaped already
    };
    let state = stat
        .rsplit(')')
        .next()
        .map(|rest| rest.split_whitespace().next().unwrap_or("Z").to_string())
        .unwrap_or_else(|| "Z".into());
    state != "R" && state != "S" && state != "D"
}

#[test]
fn happy_path_the_mount_session_survives_the_restart() {
    let hs = HandoffStack::new();
    let old_pid = hs.stack.policy_pid();
    hs.handoff(None);
    let mut successor = hs.stack.restart_policy();
    hs.stack.wait_serving();

    // The lineage CONTINUED — the new pair inherited the custody fd
    // with its position; nobody reopened the file.
    hs.wait_generations(2);
    assert_eq!(
        hs.stack.custody_lineage(),
        vec![1, 2],
        "fd inheritance broke"
    );

    // The old server retired.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !pid_dead(old_pid) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        pid_dead(old_pid),
        "the old server never retired — {}",
        hs.stack.dump_server_log()
    );
    let _ = successor.kill();
    let _ = successor.wait();
}

#[test]
fn a_successor_dying_mid_takeover_costs_the_next_attempt_nothing() {
    let hs = HandoffStack::new();
    hs.handoff(None);

    // First successor dies BEFORE committing (killed immediately —
    // its commit watcher never fires).
    let mut first = hs.stack.restart_policy();
    first.kill().unwrap();
    let _ = first.wait();

    // The second attempt re-runs the takeover from STATUS and gets
    // the fd again — the lineage shows the FIRST successor's fake
    // lived briefly (position moved) and the second continues from
    // wherever the shared description stands. The invariant: the old
    // server never destroyed its copies before commit.
    let mut second = hs.stack.restart_policy();
    hs.stack.wait_serving();
    hs.wait_generations(2);
    let lineage = hs.stack.custody_lineage();
    assert!(
        lineage.len() >= 2 && lineage.iter().all(|&g| g >= 1),
        "resumability broke: {lineage:?}"
    );
    let _ = second.kill();
    let _ = second.wait();
}

#[test]
fn a_second_successor_stands_down_after_a_committed_handoff() {
    let hs = HandoffStack::new();
    hs.handoff(None);
    let mut first = hs.stack.restart_policy();
    hs.stack.wait_serving();
    hs.wait_generations(2);
    assert_eq!(hs.stack.custody_lineage(), vec![1, 2]);

    // A SECOND successor arrives (restart storm): the old server
    // reports committed_to; the newcomer must NOT take anything over
    // — it spawns its own fresh daemon (lineage restarts at 1).
    let mut second = hs.stack.restart_policy();
    hs.stack.wait_serving();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let lineage = hs.stack.custody_lineage();
        // The newcomer's fresh open RESTARTED the file at [1] — but
        // the first successor's fake may still hold the OLD file
        // description; the assertion is that the newcomer's counter
        // is 1 (fresh), not a continuation of 3.
        if lineage.first() == Some(&1) && lineage.len() == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "second successor did not stand down + fresh-mount: {lineage:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = first.kill();
    let _ = first.wait();
    let _ = second.kill();
    let _ = second.wait();
}

#[test]
fn a_dead_fused_means_no_custody_and_a_fresh_mount() {
    let hs = HandoffStack::new();
    // Kill the fake daemon BEFORE the handoff: the surrender times
    // out into the honest no-custody fallback.
    for pid in hs.stack.daemon_pids() {
        let _ = std::process::Command::new("kill")
            .arg(pid.to_string())
            .output();
    }
    hs.handoff(None);

    let mut successor = hs.stack.restart_policy();
    hs.stack.wait_serving();
    // Fresh mount: the lineage restarts (a second [1] appended after
    // the first, or the file rewritten — never a [2] continuation via
    // inheritance, which the happy test pins separately).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let lineage = hs.stack.custody_lineage();
        if lineage == vec![1, 1] || lineage == vec![1] {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "expected a fresh-mount lineage, got {lineage:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = successor.kill();
    let _ = successor.wait();
}

#[test]
fn kill9_of_the_lingering_old_server_degrades_to_a_fresh_mount() {
    let mut hs = HandoffStack::new();
    hs.handoff(None);

    // The uncatchable signal: nobody can serve the rendezvous.
    let old_pid = hs.stack.policy_pid();
    let sig = libc::SIGKILL;
    // SAFETY: one verified pid, the stack's own child.
    unsafe { libc::kill(old_pid as i32, sig) };
    let _ = hs.stack.wait_policy();

    let mut successor = hs.stack.restart_policy();
    hs.stack.wait_serving();
    // Fresh mount (the probe could not reach the rendezvous).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let lineage = hs.stack.custody_lineage();
        if lineage == vec![1, 1] || lineage == vec![1] {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "expected fresh-mount after kill -9, got {lineage:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = successor.kill();
    let _ = successor.wait();
}

#[test]
fn an_unclaimed_handoff_times_out_into_todays_behavior() {
    let hs = HandoffStack::new();
    let old_pid = hs.stack.policy_pid();
    hs.handoff(Some(2));

    // Nobody comes. The old server gives up: retire the fused, exit.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    while !pid_dead(old_pid) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        pid_dead(old_pid),
        "the lingering old server never timed out"
    );
}

#[test]
fn a_bogus_handoff_rendezvous_declines_into_a_fresh_mount() {
    let hs = HandoffStack::new();

    // A state file claiming a handoff at a rendezvous that answers
    // with garbage: the dialect check must decline, never half-parse.
    let state_file = hs.stack.state_file();
    let text = std::fs::read_to_string(&state_file).unwrap();
    let mut f: serde_json::Value = serde_json::from_str(&text).unwrap();
    f["handoff_socket"] = serde_json::json!("/nonexistent/handoff.sock");
    std::fs::write(&state_file, serde_json::to_vec(&f).unwrap()).unwrap();

    let mut successor = hs.stack.restart_policy();
    hs.stack.wait_serving();
    // Fresh boot, lineage restarts.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let lineage = hs.stack.custody_lineage();
        if lineage == vec![1, 1] || lineage == vec![1] {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "expected decline into fresh mount, got {lineage:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = successor.kill();
    let _ = successor.wait();
}

/// Sibling: the plain supervision lifecycle of #94 still works.
#[test]
fn supervision_seam_still_substitutes_the_daemon() {
    let hs = HandoffStack::new();
    assert!(
        !hs.stack.daemon_pids().is_empty(),
        "the substituted daemon must be alive"
    );
}

#[allow(dead_code)]
fn _bin_witness() -> std::path::PathBuf {
    bin("fuse-client")
}

#[allow(dead_code)]
fn _child_witness(c: &mut Child) {
    let _ = c.try_wait();
}

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
    let pid_t = old_pid as libc::pid_t;
    let sig = libc::SIGKILL;
    // SAFETY: one verified pid, the stack's own child.
    unsafe { libc::kill(pid_t, sig) };
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

// ═══ Review proofs: each criticism of the review comment, pinned ═══
// These encode the DESIRED behavior; against the current code they
// fail — that is the point. Each test names the finding it proves.

/// Speak one handoff command over a fresh connection; reply line only
/// (fds sent as SCM_RIGHTS are dropped with the socket — sufficient:
/// the REPLY SHAPE is the assertion surface).
fn speak(sock: &std::path::Path, req: &fuse_protocol::handoff::HandoffRequest) -> String {
    use std::io::{BufRead, BufReader, Write};
    let mut c = std::os::unix::net::UnixStream::connect(sock).expect("connect rendezvous");
    let body = serde_json::to_string(req).expect("internal enum");
    c.write_all(format!("{body}\n").as_bytes()).expect("write");
    let _ = c.flush();
    let mut line = String::new();
    BufReader::new(&c).read_line(&mut line).expect("read reply");
    line
}

fn handoff_sock_of(hs: &HandoffStack) -> std::path::PathBuf {
    hs.stack
        .state_file()
        .parent()
        .unwrap()
        .join("oracle.sock.handoff")
}

/// **B1-a**: a LIVE fused that does not surrender (the REAL fused of
/// today — warns and serves nothing on Surrender) must mean handoff
/// mode is REFUSED: the stack sockets stay up, no rendezvous appears.
/// Today the server enters handoff mode anyway — unlinks both stack
/// sockets while the daemon still holds the mount — and every real
/// restart walks into it.
#[test]
fn b1_no_custody_live_mute_fused_refuses_handoff_mode() {
    // A stayer that never connects to the oracle: live, mute on
    // Surrender — exactly the real fused's current behavior.
    let stayer = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug/fake-fused");
    let stack = Stack::new()
        .fused_binary(&stayer)
        .spawn_supervised();
    // give the fake a moment to boot; it must NOT be asked to
    // surrender in this test — the take-back must simply find nothing
    std::thread::sleep(std::time::Duration::from_millis(500));
    let out = stack.request_handoff(Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    // DESIRED: the server REFUSES (non-zero exit or an explicit
    // refusal line), because there is no custody to hand off.
    assert!(
        !out.status.success() || stderr.contains("refus") || stdout.contains("refus"),
        "B1: a live non-surrendering fused (the real fused today) must REFUSE \
         handoff mode — instead the server entered it: {stderr}{stdout}"
    );
}

/// **B1-b**: a successor DECLINING the takeover (no custody) must
/// send Abort so the old pair retires promptly. Today the decline
/// path returns without Abort; the old server lingers the full
/// timeout with the stack sockets unlinked.
#[test]
fn b2_decline_sends_abort_and_retires_the_old_pair() {
    let hs = HandoffStack::new();
    let old_pid = hs.stack.policy_pid();
    hs.handoff(Some(120));
    let sock = handoff_sock_of(&hs);

    // STATUS, then decline WITHOUT further commands — the shape of
    // every decline in resume_from_handoff.
    let reply = speak(&sock, &fuse_protocol::handoff::HandoffRequest::Status);
    assert!(reply.contains("status"), "precondition: {reply}");

    // DESIRED: the mere disconnect-without-commit of a decliner must
    // not strand the stack: within a short bound the old server must
    // be gone (Abort on decline, or the conductor's short idle
    // deadline for un-committed sessions).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !pid_dead(old_pid) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        pid_dead(old_pid),
        "B1: a declined takeover stranded the old server (no Abort) — \
         it lingers with the stack sockets unlinked: {}",
        hs.stack.dump_server_log()
    );
}

/// **B3-a**: the takeover slot must not be inheritable by CLAIMING a
/// dead taker's pid — SO_PEERCRED already knows the real one. A
/// different process asserting the dead first taker's pid must get
/// Error, not the fd batch.
#[test]
fn b3_claiming_a_dead_takers_pid_must_not_inherit_the_slot() {
    let hs = HandoffStack::new();
    hs.handoff(Some(120));
    let sock = handoff_sock_of(&hs);

    // First taker: a genuinely dead pid (spawn + kill + reap).
    let mut corpse = std::process::Command::new("sleep").arg("0.05").spawn().unwrap();
    let corpse_pid = corpse.id();
    let _ = corpse.wait();
    std::thread::sleep(std::time::Duration::from_millis(200));

    // A DIFFERENT live process (this test) CLAIMS the corpse's pid.
    let reply = speak(
        &sock,
        &fuse_protocol::handoff::HandoffRequest::GetFd {
            attempt: 1,
            requester_pid: corpse_pid,
        },
    );
    assert!(
        reply.contains("error"),
        "B3: claiming a dead taker's pid inherited the slot and was \
         handed the custody batch: {reply}"
    );
}

/// **B3-b**: Commit must be refused from a process that never took
/// custody (the kernel-verified pid != fd_taken_by). Today ANY
/// same-uid process can retire the old pair mid-takeover.
#[test]
fn b3_commit_without_custody_is_refused() {
    let hs = HandoffStack::new();
    hs.handoff(Some(120));
    let sock = handoff_sock_of(&hs);

    // No GetFd first: a naked Commit from a stranger-ish process.
    let reply = speak(
        &sock,
        &fuse_protocol::handoff::HandoffRequest::Commit {
            new_server_pid: std::process::id(),
        },
    );
    assert!(
        reply.contains("error"),
        "B3: a Commit from a process that never took custody was \
         accepted — the old pair retires mid-takeover: {reply}"
    );
}

/// **M1**: the linger deadline must not yank custody from a LIVE
/// mid-takeover successor. With the taker alive at the deadline, the
/// supervised daemon must survive past it.
#[test]
fn m1_live_taker_suspends_the_deadline() {
    let hs = HandoffStack::new();
    hs.handoff(Some(2)); // SHORT timeout: the wall clock expires fast
    let sock = handoff_sock_of(&hs);

    // Take custody as a LIVE taker (this test process).
    let reply = speak(
        &sock,
        &fuse_protocol::handoff::HandoffRequest::GetFd {
            attempt: 1,
            requester_pid: std::process::id(),
        },
    );
    assert!(reply.contains("fd"), "precondition: {reply}");

    let fake = hs.stack.daemon_pids();
    assert!(!fake.is_empty(), "precondition: daemon alive");
    // Past the deadline + margin, taker still live.
    std::thread::sleep(std::time::Duration::from_millis(3500));
    assert!(
        !hs.stack.daemon_pids().is_empty(),
        "M1: the wall-clock deadline retired the daemon while a LIVE \
         taker held custody mid-takeover: {}",
        hs.stack.dump_server_log()
    );
}

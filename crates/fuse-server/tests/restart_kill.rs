//! The live-report restart failure (2026-10-13), end to end and
//! kernel-free: the REAL `fuse-client` restarting a REAL supervised
//! stack — twice, because round 2 is where the live machine failed.
//!
//! The bug chain (both links broken independently):
//! 1. the orphan kill was a `pkill -f "--socket <path>"` child — a
//!    `--`-leading argument parses as an OPTION ("unrecognized
//!    option", rc 2), NOTHING is signaled, the old server survives,
//!    and the successor dies on its stale-socket probe ("Server did
//!    not start within 10s");
//! 2. the restart never recorded the successor's pid, so round 2's
//!    state file named a dead pid and walked the same broken orphan
//!    path (round 1 had taken the working NamedPid kill by luck of
//!    the old state file still naming a live pid).
//!
//! Both rounds must now complete: honest kill, waited-out death,
//! successor serving, state file naming the successor.

#![allow(clippy::unwrap_used, clippy::panic, unused_results)]

use std::path::PathBuf;

use gatekeeper_testkit::{bin, Stack};

/// A supervised stack plus the state file the client restarts from
/// (written by the test: the orchestrator's role in this flow).
struct LiveStack {
    stack: gatekeeper_testkit::supervised::SupervisedStack,
    state_file: PathBuf,
    policy: PathBuf,
}

impl LiveStack {
    fn new() -> Self {
        let stack = Stack::new()
            .pending_timeout(std::time::Duration::from_secs(5))
            .spawn_supervised();
        let socket = stack.socket().to_path_buf();
        let root = socket.parent().unwrap().to_path_buf();
        let state_file = root.join("state.json");
        let policy = root.join("policy.json");
        write_state(&state_file, &socket, &root, &policy, 0);
        let s = Self {
            stack,
            state_file,
            policy,
        };
        s.wait_cmd_socket();
        s
    }

    fn socket(&self) -> PathBuf {
        self.stack.socket().to_path_buf()
    }

    fn restart(&self) -> String {
        let out = std::process::Command::new(bin("fuse-client"))
            .arg("--socket")
            .arg(self.socket())
            .arg("restart")
            .env(fuse_protocol::ENV_STATE_FILE, &self.state_file)
            .env(fuse_protocol::ENV_POLICY_FILE, &self.policy)
            .output()
            .expect("run fuse-client restart");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    fn recorded_pid(&self) -> u32 {
        let text = std::fs::read_to_string(&self.state_file).unwrap();
        serde_json::from_str::<fuse_protocol::ServerStateFile>(&text)
            .unwrap()
            .server_pid
    }

    /// The command socket accepts again (the successor is serving).
    fn wait_cmd_socket(&self) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if std::os::unix::net::UnixStream::connect(self.socket()).is_ok() {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the successor never served — {:#?}",
                self.stack.daemon_pids()
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

fn write_state(
    path: &std::path::Path,
    socket: &std::path::Path,
    root: &std::path::Path,
    policy: &std::path::Path,
    server_pid: u32,
) {
    let f = fuse_protocol::ServerStateFile {
        version: fuse_protocol::VERSION.to_string(),
        server_pid,
        server_binary: bin("fuse-server").display().to_string(),
        mount_point: root.join("mnt").display().to_string(),
        socket: socket.display().to_string(),
        log_level: "info".into(),
        pending_timeout: 5,
        runtime_wrapper: None,
        oracle_socket: Some(root.join("oracle.sock").display().to_string()),
        env: [(
            "FUSE_GATEKEEPER_POLICY".to_string(),
            policy.display().to_string(),
        )]
        .into(),
        secrets: Vec::new(),
    };
    std::fs::write(path, serde_json::to_vec(&f).unwrap()).unwrap();
}

#[test]
fn two_rounds_of_restarts_complete_the_live_report_flow() {
    let live = LiveStack::new();

    // Round 1: the state file names NO live pid (server_pid 0) — the
    // orphan path, the exact broken link. Must complete anyway.
    let text = live.restart();
    assert!(
        text.contains("Server ready"),
        "round 1 must complete (the live report's round 1 did): {text}"
    );
    live.wait_cmd_socket();
    let successor_pid = live.recorded_pid();
    assert!(
        successor_pid != 0,
        "the successor's pid must be recorded: {text}"
    );

    // Round 2: the live machine's failing round — the state file now
    // names the round-1 successor (the precise path); and if it had
    // still named a dead pid, the orphan path must work too.
    let text2 = live.restart();
    assert!(
        text2.contains("Server ready"),
        "round 2 must complete (the live report's failure): {text2}"
    );
    live.wait_cmd_socket();
    assert!(live.recorded_pid() != 0);
    assert_ne!(live.recorded_pid(), successor_pid);
}

//! The SUPERVISION tier (#94): the real `fuse-server` supervising a
//! SUBSTITUTED data daemon — by default the kit's `fake-fused` — via
//! the `--fused-binary` seam. No kernel FUSE, no libfuse: runs in
//! every container, built for supervise/reap/respawn lifecycle tests
//! (#93 F2).

use std::path::PathBuf;
use std::process::{Child, Command};

use crate::{Stack, bin};

/// A live supervision stack: the policy daemon child plus everything
/// needed to observe and drive the supervision lifecycle. Dropping it
/// kills the policy daemon and any surviving substituted daemon.
/// The live daemons for this binary+mountpoint (root-scoped pattern;
/// zombies count as dead — #97's lesson in kit form).
fn pgrep_daemons(daemon_binary: &std::path::Path, mount: &std::path::Path) -> Vec<u32> {
    let out = Command::new("pgrep")
        .arg("-f")
        .arg(format!("{}.*{}", daemon_binary.display(), mount.display()))
        .output()
        .expect("testkit: pgrep");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|p| p.parse().ok())
        .filter(|&pid| {
            // ZOMBIES ARE DEAD: kill(0) succeeds and pgrep lists
            // unreaped corpses; the scheduler state is the answer.
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|s| {
                    s.rsplit(')')
                        .next()
                        .and_then(|rest| rest.split_whitespace().next().map(|f| f.to_string()))
                })
                .is_some_and(|state| state != "Z" && state != "X")
        })
        .collect()
}

pub struct SupervisedStack {
    policy: Child,
    daemon_binary: PathBuf,
    mount: PathBuf,
    socket: PathBuf,
    /// Respawns driven by tests (adoption tiers): killed at teardown
    /// so no policy daemon outlives the stack.
    respawns: std::cell::RefCell<Vec<u32>>,
    _root: tempfile::TempDir,
}

impl SupervisedStack {
    pub(crate) fn spawn(stack: Stack) -> Self {
        let root = stack.root;
        let socket = root.path().join("cmd.sock");
        let oracle = root.path().join("oracle.sock");
        let mount = root.path().join("mnt");
        std::fs::create_dir_all(&mount).expect("testkit: mount dir");

        let daemon_binary = stack
            .fused_binary
            .clone()
            .unwrap_or_else(|| bin("fake-fused"));
        assert!(
            daemon_binary.exists(),
            "testkit: substituted daemon {} not built (cargo build --workspace)",
            daemon_binary.display()
        );

        let log = std::fs::File::create(root.path().join("server.log"))
            .expect("testkit: create server.log");
        let mut policy = Command::new(bin("fuse-server"));
        {
            let _a = policy
                .arg("--socket").arg(&socket)
                .arg("--oracle-socket").arg(&oracle)
                .arg("--mount-point").arg(&mount)
                .arg("--fused-binary").arg(&daemon_binary)
                .arg("--pending-timeout")
                .arg(stack.pending_timeout.as_secs().max(1).to_string());
        }
        if let Some(w) = stack.adopt_window {
            let _win = policy.arg("--adopt-window").arg(w.to_string());
        }
        {
            let _b = policy
                .env(fuse_protocol::ENV_POLICY_FILE, root.path().join("policy.json"))
                .env("RUST_LOG", "fuse_server=info")
                .envs(&stack.envs)
                .stdout(log.try_clone().expect("testkit: clone log"))
                .stderr(log);
        }
        let mut policy = policy
            .spawn()
            .expect("testkit: spawn fuse-server — is target/debug built?");

        crate::wait_connect_pub(&socket, "policy daemon (supervision tier)", root.path());
        let _ = &mut policy;

        // With an adoption window the gate may hold the spawn for its
        // duration (fresh boot) — the daemon appears at the latest
        // when the window expires. Wait for the DECISION so callers
        // see the steady state, not the gate mid-flight.
        if stack.adopt_window.is_some() {
            let deadline = std::time::Instant::now()
                + std::time::Duration::from_secs(stack.adopt_window.unwrap_or(0) + 10);
            let this_mount = mount.clone();
            while std::time::Instant::now() < deadline {
                let _ = &this_mount;
                let has_daemon = pgrep_daemons(&daemon_binary, &mount).len() == 1;
                let log = std::fs::read_to_string(root.path().join("server.log"))
                    .unwrap_or_default();
                let decided = log.contains("ADOPTED the surviving") || has_daemon;
                if decided {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }

        Self {
            policy,
            daemon_binary,
            mount,
            socket,
            respawns: std::cell::RefCell::new(Vec::new()),
            _root: root,
        }
    }

    /// The policy daemon's pid (the supervisor).
    pub fn policy_pid(&self) -> u32 {
        self.policy.id()
    }

    /// The stack's private root (sockets, logs, policy store).
    pub fn root(&self) -> &std::path::Path {
        self._root.path()
    }

    /// The raw server log (adoption-gate assertions).
    pub fn server_log(&self) -> String {
        std::fs::read_to_string(self._root.path().join("server.log"))
            .unwrap_or_default()
    }

    /// Log containment (the gate's decisions are log-lined).
    pub fn server_log_contains(&self, needle: &str) -> bool {
        self.server_log().contains(needle)
    }

    /// Record a test-driven respawn pid for teardown.
    pub fn register_respawn(&self, pid: u32) {
        self.respawns.borrow_mut().push(pid);
    }

    /// The substituted daemon's pid(s), discovered by binary path
    /// scoped to this stack's mount (unique per stack root).
    ///
    /// # Panics
    ///
    /// Panics only if pgrep itself cannot be executed (never on a
    /// missing daemon — that is the empty result this returns).
    pub fn daemon_pids(&self) -> Vec<u32> {
        pgrep_daemons(&self.daemon_binary, &self.mount)
    }

    /// SIGTERM the policy daemon — the #93 F2 move: what happens to
    /// the supervised child is the assertion's business.
    pub fn kill_policy(&mut self) {
        let _ = self.policy.kill();
        let _ = self.policy.wait();
    }

    /// The command socket path.
    pub fn socket(&self) -> &std::path::Path {
        &self.socket
    }
}

impl Drop for SupervisedStack {
    fn drop(&mut self) {
        self.kill_policy();
        for pid in self.respawns.borrow().iter() {
            let _ = Command::new("kill").arg(pid.to_string()).output();
        }
        for pid in self.daemon_pids() {
            let _ = Command::new("kill").arg(pid.to_string()).output();
        }
    }
}

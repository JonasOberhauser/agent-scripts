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
pub struct SupervisedStack {
    policy: Child,
    daemon_binary: PathBuf,
    mount: PathBuf,
    socket: PathBuf,
    _root: tempfile::TempDir,
}

/// kill(2) by pid — std offers no non-Child variant and the kit needs
/// the exact signal.
fn kill_pid(pid: u32, sig: i32) -> bool {
    let pid_t = pid as libc::pid_t;
    // SAFETY: a plain signal to one known pid; the comparison lives
    // outside the block (one op per unsafe block).
    let rc = unsafe { libc::kill(pid_t, sig) };
    rc == 0
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
        let mut policy = Command::new(bin("fuse-server"))
            .arg("--socket").arg(&socket)
            .arg("--oracle-socket").arg(&oracle)
            .arg("--mount-point").arg(&mount)
            .arg("--fused-binary").arg(&daemon_binary)
            .arg("--pending-timeout")
            .arg(stack.pending_timeout.as_secs().max(1).to_string())
            .env(fuse_protocol::ENV_POLICY_FILE, root.path().join("policy.json"))
            .env("RUST_LOG", "fuse_server=info")
            .stdout(log.try_clone().expect("testkit: clone log"))
            .stderr(log)
            .spawn()
            .expect("testkit: spawn fuse-server — is target/debug built?");

        crate::wait_connect_pub(&socket, "policy daemon (supervision tier)", root.path());
        let _ = &mut policy;

        Self {
            policy,
            daemon_binary,
            mount,
            socket,
            _root: root,
        }
    }

    /// The policy daemon's pid (the supervisor).
    pub fn policy_pid(&self) -> u32 {
        self.policy.id()
    }

    /// The substituted daemon's pid(s), discovered by binary path
    /// scoped to this stack's mount (unique per stack root).
    ///
    /// # Panics
    ///
    /// Panics only if pgrep itself cannot be executed (never on a
    /// missing daemon — that is the empty result this returns).
    pub fn daemon_pids(&self) -> Vec<u32> {
        let out = Command::new("pgrep")
            .arg("-f")
            .arg(format!(
                "{}.*{}",
                self.daemon_binary.display(),
                self.mount.display()
            ))
            .output()
            .expect("testkit: pgrep");
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .filter_map(|p| p.parse().ok())
            // ZOMBIES ARE DEAD: kill(0) succeeds and pgrep lists them,
            // but an unreaped entry is not a live daemon (this filter
            // is what makes reap assertions honest).
            .filter(|&pid| {
                std::fs::read_to_string(format!("/proc/{pid}/stat"))
                    .ok()
                    // state is the field after the (comm) — read the
                    // char after the last ')'
                    .and_then(|s| {
                        s.rsplit(')').next()
                            .and_then(|rest| rest.split_whitespace().next().map(|f| f.to_string()))
                    })
                    .is_some_and(|state| state != "Z" && state != "X")
            })
            .collect()
    }

    /// SIGTERM the policy daemon — the signal `fuse-client restart`
    /// actually sends (#93 F2): the shutdown handler (and with it the
    /// supervised-daemon reaping) runs. What happens to the daemon is
    /// the assertion's business.
    pub fn kill_policy(&mut self) {
        // NOT Child::kill() — that is SIGKILL, which no handler can
        // catch; the restart path uses TERM and the test must model
        // the real signal.
        let _ = kill_pid(self.policy.id(), libc::SIGTERM);
        let _ = self.policy.wait();
    }

    /// SIGKILL the policy daemon — the uncatchable variant (kill -9):
    /// NO handler runs, so the supervised daemon is orphaned by
    /// construction; recovery from THIS shape is the restart path's
    /// business, not the server's.
    pub fn kill_policy_9(&mut self) {
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
        for pid in self.daemon_pids() {
            let _ = Command::new("kill").arg(pid.to_string()).output();
        }
    }
}

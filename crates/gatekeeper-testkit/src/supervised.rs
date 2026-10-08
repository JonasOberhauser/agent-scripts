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
            .collect()
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
        for pid in self.daemon_pids() {
            let _ = Command::new("kill").arg(pid.to_string()).output();
        }
    }
}

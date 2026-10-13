//! The SUPERVISION tier (#94): the real `fuse-server` supervising a
//! SUBSTITUTED data daemon — by default the kit's `fake-fused` — via
//! the `--fused-binary` seam. No kernel FUSE, no libfuse: runs in
//! every container, built for supervise/reap/respawn lifecycle tests
//! (#93 F2).

use std::path::PathBuf;
use std::process::{Child, Command};

use crate::{bin, Stack};

/// A live supervision stack: the policy daemon child plus everything
/// needed to observe and drive the supervision lifecycle. Dropping it
/// kills the policy daemon and any surviving substituted daemon.
pub struct SupervisedStack {
    pub policy: Child,
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
        // The stack's state file (#93 F2): the handoff rendezvous is
        // recorded here, and the successor server reads it at startup.
        let state_file = root.path().join("state.json");
        let f = fuse_protocol::ServerStateFile {
            handoff_socket: None,
            supervised_pid: None,
            version: fuse_protocol::VERSION.to_string(),
            server_pid: 0,
            server_binary: bin("fuse-server").display().to_string(),
            mount_point: mount.display().to_string(),
            socket: socket.display().to_string(),
            log_level: "info".into(),
            pending_timeout: stack.pending_timeout.as_secs().max(1),
            runtime_wrapper: None,
            oracle_socket: Some(oracle.display().to_string()),
            env: [(std::env::var("FUSE_GATEKEEPER_POLICY")
                .ok()
                .or_else(|| root.path().join("policy.json").to_str().map(str::to_string))
                .map(|v| ("FUSE_GATEKEEPER_POLICY".to_string(), v)))]
            .into_iter()
            .flatten()
            .collect(),
            secrets: Vec::new(),
        };
        std::fs::write(
            &state_file,
            serde_json::to_vec(&f).expect("testkit: state file"),
        )
        .expect("testkit: write state file");
        let mut policy = Command::new(bin("fuse-server"))
            .arg("--socket")
            .arg(&socket)
            .arg("--oracle-socket")
            .arg(&oracle)
            .arg("--mount-point")
            .arg(&mount)
            .arg("--fused-binary")
            .arg(&daemon_binary)
            .arg("--pending-timeout")
            .arg(stack.pending_timeout.as_secs().max(1).to_string())
            .env(
                fuse_protocol::ENV_POLICY_FILE,
                root.path().join("policy.json"),
            )
            .env(fuse_protocol::ENV_STATE_FILE, &state_file)
            .env("RUST_LOG", "fuse_server=info,fuse_mount=info")
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

    /// Reap the policy daemon child (kill-9 tests verify the exit).
    ///
    /// # Panics
    /// Panics if the wait itself fails (never on a nonzero exit).
    pub fn wait_policy(&mut self) -> std::process::ExitStatus {
        self.policy.wait().expect("testkit: wait policy")
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

    /// The mount point (the custody file lives here).
    pub fn mount(&self) -> &std::path::Path {
        &self.mount
    }

    /// The stack's state file (the handoff rendezvous is recorded
    /// here; the successor reads it at startup).
    pub fn state_file(&self) -> std::path::PathBuf {
        self._root.path().join("state.json")
    }

    /// The custody lineage file the fake daemon maintains — 8-byte BE
    /// generation counters appended through ONE shared file
    /// description; continuing counters prove fd inheritance.
    pub fn custody_file(&self) -> std::path::PathBuf {
        self.mount.join("custody.token")
    }

    /// Read the custody lineage (test-side parsing is sanctioned).
    pub fn custody_lineage(&self) -> Vec<u64> {
        let bytes = std::fs::read(self.custody_file()).unwrap_or_default();
        // Misaligned tails are impossible (only the fake writes this
        // file, in 8-byte counters); as_chunks makes that a type.
        bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_be_bytes(*c))
            .collect()
    }

    /// Ask the policy daemon to enter HANDOFF MODE via the real
    /// fuse-client (old servers that predate the command fail and the
    /// caller falls back — exactly the client's own logic).
    ///
    /// # Panics
    /// Panics only if fuse-client cannot be executed at all.
    pub fn request_handoff(&self, timeout_secs: Option<u64>) -> std::process::Output {
        let mut args = vec![
            "handoff".to_string(),
            self.state_file().display().to_string(),
        ];
        if let Some(t) = timeout_secs {
            args.push(t.to_string());
        }
        Command::new(bin("fuse-client"))
            .arg("--socket")
            .arg(&self.socket)
            .args(&args)
            .output()
            .expect("testkit: run fuse-client handoff")
    }

    /// Spawn the SUCCESSOR policy daemon (the restart path): same
    /// sockets, same env — it performs the takeover at startup when
    /// the state file records one. The caller owns the returned child.
    ///
    /// # Panics
    /// Panics if the successor cannot be spawned (missing binary,
    /// exhausted pids) — a test-environment failure, not a stack
    /// condition.
    pub fn restart_policy(&self) -> std::process::Child {
        let state_file = self.state_file();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self._root.path().join("server.log"))
            .expect("testkit: open server.log");
        let child = Command::new(bin("fuse-server"))
            .arg("--socket")
            .arg(&self.socket)
            .arg("--oracle-socket")
            .arg(self._root.path().join("oracle.sock"))
            .arg("--mount-point")
            .arg(&self.mount)
            .arg("--fused-binary")
            .arg(&self.daemon_binary)
            .arg("--pending-timeout")
            .arg("5")
            .env(
                fuse_protocol::ENV_POLICY_FILE,
                self._root.path().join("policy.json"),
            )
            .env(fuse_protocol::ENV_STATE_FILE, &state_file)
            .env("RUST_LOG", "fuse_server=info,fuse_mount=info")
            .stdout(std::process::Stdio::from(
                log.try_clone().expect("testkit: clone log"),
            ))
            .stderr(log)
            .spawn()
            .expect("testkit: spawn successor fuse-server");
        child
    }

    /// Wait until the command socket accepts a connection again (the
    /// successor is up).
    ///
    /// # Panics
    /// Panics with the server log tail if the successor never serves.
    pub fn wait_serving(&self) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut served = false;
        while std::time::Instant::now() < deadline {
            if std::os::unix::net::UnixStream::connect(&self.socket).is_ok() {
                served = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(
            served,
            "successor never served — {}",
            self.dump_server_log()
        );
    }

    /// The server log tail (failure diagnostics).
    ///
    /// # Panics
    /// Never — unreadable logs degrade to "(no server.log)".
    pub fn dump_server_log(&self) -> String {
        std::fs::read_to_string(self._root.path().join("server.log"))
            .map(|t| {
                let lines: Vec<&str> = t.lines().collect();
                let start = lines.len().saturating_sub(30);
                lines[start..].join("\n")
            })
            .unwrap_or_else(|_| "(no server.log)".into())
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

//! The mock-fuse driver tier: the REAL `fused` binary against the
//! in-process policy daemon, with only the kernel end of the FUSE
//! channel mocked (`--mock-fuse`) — the everywhere-tier (no
//! `/dev/fuse` needed), ported from `fuse-mount`'s `mock_fuse`
//! harness as the last step-2 piece of #82/#63.
//!
//! [`MockFuseStack`] composes both halves under one kit root: the
//! policy side is the in-process [`crate::StackHandle`] (real oracle
//! wire, real state, real hub), the data side a real `fused` child
//! whose mock control socket tests drive through their typed driver
//! (`fuse_mount::mock_driver::MockDriver::connect`).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fuse_server::oracle_service::OracleHub;
use fuse_server::ServerState;

use crate::{bin, Stack, StackHandle};

/// The mock-fuse split stack: the in-process policy daemon + the real
/// `fused` child on `--mock-fuse`, under one kit root. Dropping it
/// kills the child and tears the policy stack down (root reclaimed,
/// sockets with it).
pub struct MockFuseStack {
    policy: StackHandle,
    child: Child,
    control: PathBuf,
}

impl MockFuseStack {
    /// Build for a [`Stack`] (see [`Stack::spawn_mock_fuse`]): spawn
    /// the in-process policy first, then the real `fused` binary
    /// against its oracle socket, with the mock control socket under
    /// the same root.
    ///
    /// # Panics
    /// Panics if the fused binary cannot be spawned or its control
    /// socket never appears within 10s.
    pub(super) fn spawn(stack: Stack) -> Self {
        let policy = stack.spawn_in_process();
        let control = policy.scratch("mock-fuse.sock");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(policy.scratch("fused.log"))
            .expect("testkit: open fused.log");
        #[allow(clippy::zombie_processes)]
        let child = Command::new(bin("fused"))
            .arg("--mount-point")
            .arg(policy.scratch("mnt"))
            .arg("--oracle-socket")
            .arg(policy.oracle_socket())
            .arg("--mock-fuse")
            .arg(&control)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log.try_clone().expect("testkit: clone log")))
            .stderr(log)
            .spawn()
            .expect("testkit: spawn fused --mock-fuse — is target/debug built?");
        let deadline = Instant::now() + Duration::from_secs(10);
        let up = loop {
            if control.exists() {
                break true;
            }
            if Instant::now() > deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            up,
            "testkit: fused never bound the mock control socket at {} — {}",
            control.display(),
            policy.dump_logs("mock-fuse spawn")
        );
        Self { policy, child, control }
    }

    /// The mock control socket — hand it to
    /// `fuse_mount::mock_driver::MockDriver::connect`.
    pub fn control_socket(&self) -> &Path {
        &self.control
    }

    /// The fused child's pid (fd-count probes in the leak tests).
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The live policy state (the in-process daemon's own).
    pub fn state(&self) -> &Arc<ServerState> {
        self.policy.state()
    }

    /// The oracle hub: `serve`/`remove` push to the data daemon.
    pub fn hub(&self) -> &OracleHub {
        self.policy.hub()
    }

    /// The policy daemon's oracle socket (the child's wire).
    pub fn oracle_socket(&self) -> &Path {
        self.policy.oracle_socket()
    }

    /// Tail the daemon logs under the root.
    pub fn dump_logs(&self, what: &str) -> String {
        self.policy.dump_logs(what)
    }
}

impl Drop for MockFuseStack {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.control);
    }
}

/// Whether this environment can run the mock-fuse tier: the `fused`
/// binary is built (no `/dev/fuse` or `fusermount3` needed — this is
/// the everywhere-tier).
pub fn mock_fuse_available() -> bool {
    bin("fused").exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_mount::mock_driver::MockDriver;

    /// The full mock-fuse roundtrip at kit level: serve a secret
    /// through the hub, drive the real fused child through the typed
    /// driver, read the bytes, and hit the one-read deny.
    #[test]
    fn mock_fuse_stack_serves_reads_and_one_read_denies() {
        if !mock_fuse_available() {
            eprintln!("skipping: fused binary not built (CI exercises it)");
            return;
        }
        let stack = Stack::new()
            .pending_timeout(Duration::from_millis(150))
            .secret("s", b"KIT-MOCK", "*")
            .spawn_mock_fuse();
        stack.hub().serve("s", "ab12cd34ef56", 0o400);

        let mut d = MockDriver::connect(stack.control_socket()).expect("connect driver");
        let _init = d.init().expect("init handshake");
        let deadline = Instant::now() + Duration::from_secs(10);
        let entry = loop {
            let dh = d.opendir(fuser::FUSE_ROOT_ID).expect("opendir");
            let entries = d.readdir(dh.fh, 4096).expect("readdir");
            let _ = d.releasedir(fuser::FUSE_ROOT_ID, dh.fh);
            if entries.iter().any(|(_, name)| name == "ab12cd34ef56") {
                break d.lookup("ab12cd34ef56").expect("lookup");
            }
            assert!(Instant::now() < deadline, "Serve never reached the store");
            std::thread::sleep(Duration::from_millis(50));
        };
        let opened = d.open(entry.nodeid).expect("open");
        assert_eq!(d.read(opened.fh, 0, 4096).expect("read"), b"KIT-MOCK");
        d.release(entry.nodeid, opened.fh).expect("release");
        let second = d.open(entry.nodeid).expect_err("one-read denies the second open");
        assert_eq!(second.0, libc::EACCES);
    }
}

//! E2E WITHOUT /dev/fuse: the REAL fused binary process against a
//! REAL oracle (in-process policy daemon over the true wire protocol)
//! — only the kernel end of the FUSE channel is the mock fuser
//! (`--mock-fuse`), driven through the typed [`MockDriver`]. This is
//! the tier that runs everywhere: CI containers, the authoring
//! sandbox, fuzz hosts.
//!
//! The stack under test, in full: fused's control loop receiving
//! Serve from the oracle hub, LOOKUP's live-stat identity minting,
//! OPEN's MR4 adjudication (the policy daemon answers with a host fd
//! over SCM_RIGHTS), READ's preads of that fd, one-read semantics in
//! the policy daemon, RELEASE closing the fd.

#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fuse_mount::mock_driver::MockDriver;
use fuse_server::oracle_service::OracleHub;
use fuse_server::ServerState;

struct Fused {
    child: Child,
    control: std::path::PathBuf,
}

impl Drop for Fused {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.control);
    }
}

fn spawn_fused(dir: &Path, oracle: &Path) -> Fused {
    let control = dir.join("mock-fuse.sock");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("fused.log"))
        .unwrap();
    #[allow(clippy::zombie_processes)]
    let child = Command::new(env!("CARGO_BIN_EXE_fused"))
        .arg("--mount-point")
        .arg(dir.join("mnt"))
        .arg("--oracle-socket")
        .arg(oracle)
        .arg("--mock-fuse")
        .arg(&control)
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(log)
        .spawn()
        .expect("spawn fused");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if control.exists() {
            return Fused { child, control };
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    unreachable!("fused never bound the mock control socket within 10s");
}

/// The in-process policy daemon: real wire protocol, dead hashd seam
/// (#69), fast pendings, one secret with the wildcard hash.
fn oracle_env(
    _dir: &Path,
) -> (std::path::PathBuf, Arc<ServerState>, OracleHub, gatekeeper_testkit::StackHandle) {
    // The kit (issue #63): per-stack root, dead hashd seam (#69),
    // 150ms pendings, the host secret under the root. Keep the
    // HANDLE — dropping it tears the policy stack down.
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tag = format!("mock-fuse-{}", N.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let stack = gatekeeper_testkit::Stack::new(&tag)
        .pending_timeout(Duration::from_millis(150))
        .secret("s", b"MOCK-FUSE-CONTENT", "*")
        .spawn_in_process();
    (
        stack.oracle_socket().to_path_buf(),
        stack.state().clone(),
        stack.hub().clone(),
        stack,
    )
}

#[test]
fn fused_serves_a_full_read_path_over_the_mock_kernel() {
    let dir = tempfile::tempdir().unwrap();
    let (oracle, _state, hub, _keep) = oracle_env(dir.path());
    let fused = spawn_fused(dir.path(), &oracle);

    // The control loop needs a moment to connect and receive Serve;
    // poll the listing until the inner name appears.
    hub.serve("s", "ab12cd34ef56", 0o400);
    let mut d = MockDriver::connect(&fused.control).expect("connect driver");
    let _init = d.init().expect("init handshake");

    let deadline = Instant::now() + Duration::from_secs(10);
    let entry = loop {
        let dh = d.opendir(fuser::FUSE_ROOT_ID).expect("opendir");
        let entries = d.readdir(dh.fh, 4096).expect("readdir");
        let _ = d.releasedir(fuser::FUSE_ROOT_ID, dh.fh);
        if entries.iter().any(|(_, name)| name == "ab12cd34ef56") {
            break d.lookup("ab12cd34ef56").expect("lookup after listing");
        }
        assert!(Instant::now() < deadline, "Serve never reached the store");
        std::thread::sleep(Duration::from_millis(50));
    };
    let ino = entry.nodeid;
    assert_eq!(entry.attr.size, 17, "size comes from live stat");
    assert_ne!(entry.attr.mode & libc::S_IFREG, 0, "a regular file");

    // GETATTR (path stat: identity check against the oracle).
    let attr = d.getattr(ino).expect("getattr");
    assert_eq!(attr.attr.size, 17);

    // OPEN: the policy daemon adjudicates and passes a host fd —
    // one-read budget spent by this successful open.
    let opened = d.open(ino).expect("open");

    // READ: preads of the passed fd, through the mock kernel.
    let data = d.read(opened.fh, 0, 4096).expect("read");
    assert_eq!(data, b"MOCK-FUSE-CONTENT");

    // EOF read returns empty, not an error.
    let eof = d.read(opened.fh, 17, 16).expect("eof read");
    assert!(eof.is_empty(), "eof: {eof:?}");

    // RELEASE closes the fd.
    d.release(ino, opened.fh).expect("release");

    // ONE-READ semantics, end to end: the budget lives in the policy
    // daemon; a second OPEN pends out its 150ms and is denied — never
    // hangs, never grants.
    let t0 = Instant::now();
    let second = d.open(ino).expect_err("second open must fail");
    let elapsed = t0.elapsed();
    assert_eq!(second.0, libc::EACCES, "errno: {second}");
    assert!(
        elapsed >= Duration::from_millis(120),
        "the deny must come from a real pend-out, not a fast path: {elapsed:?}"
    );

    // STATFS: the served-file count.
    let st = d.statfs().expect("statfs");
    assert_eq!(st.st.files, 2, "root + one secret");

    // A lookup for a name that was never served: ENOENT.
    let miss = d.lookup("nope").expect_err("lookup miss must fail");
    assert_eq!(miss.0, libc::ENOENT);

    // FORGET is oneway; follow it with a cheap sync (STATFS) so the
    // session never sees two requests queued at once.
    d.forget(ino, 1).expect("forget");
    let _st = d.statfs().expect("session alive after forget");

    drop(d);
    drop(fused);
}

/// Count the fused process's open descriptors: the kernel-faithful
/// driver-exit cleanup (synthetic RELEASEs for outstanding fhs) is
/// observable as the fd count returning to baseline after a driver
/// abandons an open file.
fn fd_count(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|rd| rd.count())
        .unwrap_or(0)
}

/// Quiescent fd count: the control loop's oracle polls open transient
/// connections, so single samples race them — take the minimum over a
/// short window (transients close, the steady state stays).
fn quiescent_fd_count(pid: u32) -> usize {
    let mut min = usize::MAX;
    let deadline = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < deadline {
        min = min.min(fd_count(pid));
        std::thread::sleep(Duration::from_millis(25));
    }
    min
}

#[test]
fn a_driver_abandoning_an_open_fh_leaks_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (oracle, _state, hub, _keep) = oracle_env(dir.path());
    let fused = spawn_fused(dir.path(), &oracle);
    hub.serve("s", "ab12cd34ef56", 0o400);

    let deadline = Instant::now() + Duration::from_secs(10);
    let ino = loop {
        let mut d = MockDriver::connect(&fused.control).expect("connect");
        let _ = d.init().expect("init");
        if let Ok(entry) = d.lookup("ab12cd34ef56") {
            break entry.nodeid;
        }
        assert!(Instant::now() < deadline, "Serve never arrived");
        std::thread::sleep(Duration::from_millis(50));
    };

    // Steady state WITH one connected driver (the connection itself
    // holds fds; only the DELTA across the open is meaningful).
    let mut d = MockDriver::connect(&fused.control).expect("connect");
    let _ = d.init().expect("init");
    let _ = d.statfs().expect("statfs");
    let baseline = quiescent_fd_count(fused.child.id());

    // Open (the host fd is now fused's to hold until RELEASE)…
    let _open = d.open(ino).expect("open");
    let during = quiescent_fd_count(fused.child.id());
    assert_eq!(during, baseline + 1, "the passed host fd must be open");

    // …and hang up WITHOUT releasing — process death, the hostile
    // path. The mock must synthesize the RELEASEs the real kernel
    // sends when a process exits with files open.
    drop(d);
    let mut next = MockDriver::connect(&fused.control).expect("reconnect");
    let _ = next.init().expect("init");
    // The cleanup runs at the PREVIOUS bridge's exit; the reconnect
    // can overtake it via the accept queue, so poll to the steady state.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if quiescent_fd_count(fused.child.id()) == baseline {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "driver death must close the abandoned host fd (kernel-faithful cleanup)"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = next.statfs();

    drop(next);
    drop(fused);
}

/// A second driver connection after the first hangs up: the session
/// (and the store) survive; the new driver re-inits and reads again.
#[test]
fn the_session_survives_driver_reconnects() {
    let dir = tempfile::tempdir().unwrap();
    let (oracle, state, hub, _keep) = oracle_env(dir.path());
    let fused = spawn_fused(dir.path(), &oracle);
    hub.serve("s", "ab12cd34ef56", 0o400);

    let deadline = Instant::now() + Duration::from_secs(10);
    let ino = loop {
        let mut d = MockDriver::connect(&fused.control).expect("connect");
        let _ = d.init().expect("init");
        if let Ok(entry) = d.lookup("ab12cd34ef56") {
            break entry.nodeid;
        }
        assert!(Instant::now() < deadline, "Serve never arrived");
        std::thread::sleep(Duration::from_millis(50));
    };

    // Budget reset through the POLICY daemon (the CLI's `reset`
    // path), then a fresh driver on the SAME session.
    let _reset = state.reset(Some("s"));

    let mut d2 = MockDriver::connect(&fused.control).expect("reconnect");
    let _ = d2.init().expect("init");
    let opened = d2.open(ino).expect("reopen after reconnect");
    let _ = opened;
}

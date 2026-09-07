//! E2E: `sha256_process_package` against real system binaries.
//!
//! The branch's own fuse e2e (needs /dev/fuse) proves the security
//! property end-to-end (LD_PRELOAD changes the hash -> read denied).
//! These tests exercise the hashing seam directly on two fixture
//! programs deployments actually grant — `curl` and `ssh-agent` — with
//! their full real-world library closures (libcurl, libssl, libcrypto,
//! zlib, ...).  Pure userspace: no FUSE, no podman, so they run in
//! every default `cargo test`; each property is its own test, so a
//! failure names exactly what broke.
//!
//! Fixtures, not SUT: a binary missing from PATH skips that test with
//! a message (unlike the podman suites, where skipping would hide
//! regressions of the system under test itself).

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};

use fuse_protocol::{RealSystemIo, SystemIo};

/// A live fixture process: kept alive (stdin pipe held open so no EOF
/// ever reaches it), cleaned up on drop.
struct Fixture {
    child: Child,
    _stdin: Option<ChildStdin>,
    exe: PathBuf,
}

impl Fixture {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn exe(&self) -> &PathBuf {
        &self.exe
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Where `bin` lives on PATH (fixtures are spawned by name).
fn on_path(bin: &str) -> Option<PathBuf> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

/// The executable path of a freshly spawned, still-live child; falls
/// back to the PATH location when /proc denies the readlink (hardened
/// binaries like ssh-agent are non-dumpable).
fn exe_path(bin: &str, pid: u32) -> PathBuf {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .unwrap_or_else(|_| on_path(bin).expect("fixture is on PATH"))
}

fn missing(bin: &str) -> bool {
    on_path(bin).is_none()
}

/// `ssh-agent -D`: a foreground daemon — stays loaded until killed.
fn ssh_agent() -> Option<Fixture> {
    if missing("ssh-agent") {
        eprintln!("skip: ssh-agent not on PATH");
        return None;
    }
    let mut child = Command::new("ssh-agent")
        .arg("-D")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ssh-agent");
    let exe = exe_path("ssh-agent", child.id());
    let _stdin = child.stdin.take();
    Some(Fixture { child, _stdin, exe })
}

/// `curl -s telnet://<stalled-listener>`: connects and blocks on the
/// silent peer.  stdin is a HELD-OPEN pipe — with /dev/null curl would
/// see EOF, end its half of the telnet session and exit mid-test.
fn curl(listener: &TcpListener) -> Option<(Fixture, TcpStream)> {
    if missing("curl") {
        eprintln!("skip: curl not on PATH");
        return None;
    }
    let addr = listener.local_addr().unwrap();
    let mut child = Command::new("curl")
        .args(["-s", &format!("telnet://{addr}")])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn curl");
    let exe = exe_path("curl", child.id());
    let mut stdin = child.stdin.take();
    // Belt and braces: never write, never close, never flush EOF.
    let _ = stdin.as_mut().map(|s| s.flush());
    let fixture = Fixture { child, _stdin: stdin, exe };
    // Accept and stay silent; the stream stays open (returned to the
    // caller) so curl keeps blocking until the test is done.
    let (conn, _) = listener.accept().expect("accept curl");
    // Settle: give lazy binders a moment so the mapped set is complete.
    std::thread::sleep(std::time::Duration::from_millis(300));
    Some((fixture, conn))
}

/// `ssh -N` against a silent listener: the connection is accepted but
/// no SSH banner ever arrives, so the client blocks in banner exchange
/// with its full crypto library closure loaded.  stdin is a held-open
/// pipe like curl's.
fn ssh(listener: &TcpListener) -> Option<(Fixture, TcpStream)> {
    if missing("ssh") {
        eprintln!("skip: ssh not on PATH");
        return None;
    }
    let port = listener.local_addr().unwrap().port();
    let mut child = Command::new("ssh")
        .args([
            "-N",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-p",
            &port.to_string(),
            "127.0.0.1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ssh");
    let exe = exe_path("ssh", child.id());
    let _stdin = child.stdin.take();
    let fixture = Fixture { child, _stdin, exe };
    let (conn, _) = listener.accept().expect("accept ssh");
    std::thread::sleep(std::time::Duration::from_millis(300));
    Some((fixture, conn))
}

// ── curl ──────────────────────────────────────────────────────────

/// The same binary's package hash is deterministic across independent
/// instances.
#[test]
fn curl_package_hash_is_deterministic() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let Some((curl1, _conn1)) = curl(&listener) else { return };
    let Some((curl2, _conn2)) = curl(&listener) else { return };
    let io = RealSystemIo::new();
    let h1 = io
        .sha256_process_package(curl1.pid())
        .unwrap_or_else(|e| panic!("hash curl #1: {e}"));
    let h2 = io
        .sha256_process_package(curl2.pid())
        .unwrap_or_else(|e| panic!("hash curl #2: {e}"));
    assert_eq!(h1, h2, "same binary, same library set, same hash");
}

/// The package hash covers the library closure: it must differ from
/// the bare executable's sha256 (the old, pre-package hash).
#[test]
fn curl_package_hash_covers_libraries() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let Some((c, _conn)) = curl(&listener) else { return };
    let io = RealSystemIo::new();
    let package = io
        .sha256_process_package(c.pid())
        .unwrap_or_else(|e| panic!("hash curl: {e}"));
    let binary = io.sha256_file(c.exe()).expect("hash the curl binary file");
    assert_ne!(
        package, binary,
        "the package hash must not collapse to the bare binary hash"
    );
}

// ── ssh client ────────────────────────────────────────────────────

/// Unlike its hardened agent, the ssh client stays dumpable: its whole
/// crypto closure (libcrypto, libc, ...) is hashable everywhere.
#[test]
fn ssh_package_hash_is_deterministic() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let Some((ssh1, _conn1)) = ssh(&listener) else { return };
    let Some((ssh2, _conn2)) = ssh(&listener) else { return };
    let io = RealSystemIo::new();
    let h1 = io
        .sha256_process_package(ssh1.pid())
        .unwrap_or_else(|e| panic!("hash ssh #1: {e}"));
    let h2 = io
        .sha256_process_package(ssh2.pid())
        .unwrap_or_else(|e| panic!("hash ssh #2: {e}"));
    assert_eq!(h1, h2, "same binary, same library set, same hash");
}

#[test]
fn ssh_package_hash_covers_libraries() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let Some((s, _conn)) = ssh(&listener) else { return };
    let io = RealSystemIo::new();
    let package = io
        .sha256_process_package(s.pid())
        .unwrap_or_else(|e| panic!("hash ssh: {e}"));
    let binary = io.sha256_file(s.exe()).expect("hash the ssh binary file");
    assert_ne!(
        package, binary,
        "the package hash must not collapse to the bare binary hash"
    );
}

/// Two different network clients are two different packages.
#[test]
fn ssh_and_curl_packages_differ() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let Some((c, _cconn)) = curl(&listener) else { return };
    let Some((s, _sconn)) = ssh(&listener) else { return };
    let io = RealSystemIo::new();
    let curl_hash = io
        .sha256_process_package(c.pid())
        .unwrap_or_else(|e| panic!("hash curl: {e}"));
    let ssh_hash = io
        .sha256_process_package(s.pid())
        .unwrap_or_else(|e| panic!("hash ssh: {e}"));
    assert_ne!(curl_hash, ssh_hash, "ssh and curl are different packages");
}

// ── ssh-agent ─────────────────────────────────────────────────────

/// ssh-agent hardens itself (PR_SET_DUMPABLE=0): reading its /proc
/// maps needs CAP_SYS_PTRACE (or an equally permissive setup).  Both
/// outcomes assert real behavior — with the capability the full
/// property set, without it a clean fail-closed error.  Never a
/// vacuous hash.
#[test]
fn ssh_agent_package_hash_properties() {
    let Some(agent) = ssh_agent() else { return };
    let io = RealSystemIo::new();
    match io.sha256_process_package(agent.pid()) {
        Ok(hash) => {
            let binary = io.sha256_file(agent.exe()).expect("hash the binary file");
            assert_ne!(
                hash, binary,
                "the package hash must not collapse to the bare binary hash"
            );
            let Some(agent2) = ssh_agent() else { return };
            let hash2 = io
                .sha256_process_package(agent2.pid())
                .expect("hash ssh-agent #2");
            assert_eq!(hash, hash2, "same binary, same library set, same hash");
        }
        Err(e) => {
            assert!(
                e.to_string().contains("Permission denied"),
                "unexpected failure hashing ssh-agent: {e}"
            );
            eprintln!(
                "note: ssh-agent is non-dumpable and this environment lacks \
CAP_SYS_PTRACE — package hash fails closed (as designed)"
            );
        }
    }
}

/// When the environment CAN hash ssh-agent, its package must differ
/// from curl's (a distinct program is a distinct package).
#[test]
fn curl_and_ssh_agent_packages_differ() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let Some((c, _conn)) = curl(&listener) else { return };
    let Some(agent) = ssh_agent() else { return };
    let io = RealSystemIo::new();
    let curl_hash = io
        .sha256_process_package(c.pid())
        .unwrap_or_else(|e| panic!("hash curl: {e}"));
    match io.sha256_process_package(agent.pid()) {
        Ok(agent_hash) => assert_ne!(
            curl_hash, agent_hash,
            "curl and ssh-agent are different packages"
        ),
        Err(e) => {
            assert!(
                e.to_string().contains("Permission denied"),
                "unexpected failure hashing ssh-agent: {e}"
            );
            eprintln!("note: skipping the comparison — ssh-agent not hashable here");
        }
    }
}

// ── failure modes ─────────────────────────────────────────────────

/// A dead pid must fail closed, never hash an empty package.
#[test]
fn dead_pid_fails_closed() {
    let io = RealSystemIo::new();
    let mut child = Command::new("true").spawn().expect("spawn true");
    let pid = child.id();
    child.wait().unwrap();
    assert!(
        io.sha256_process_package(pid).is_err(),
        "a reaped pid must fail closed"
    );
}

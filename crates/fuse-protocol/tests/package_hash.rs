//! E2E: `sha256_process_package` against real system binaries.
//!
//! The branch's own fuse e2e (needs /dev/fuse) proves the security
//! property end-to-end (LD_PRELOAD changes the hash -> read denied).
//! These tests exercise the hashing seam directly on two fixture
//! programs deployments actually grant — `curl` and `ssh-agent` — with
//! their full real-world library closures (libcurl, libssl, libcrypto,
//! zlib, ...).  Pure userspace: no FUSE, no podman, so they run in
//! every default `cargo test`.
//!
//! Fixtures, not SUT: if a binary is missing from PATH the test skips
//! with a message (unlike the podman suites, where skipping would hide
//! regressions of the system under test itself).

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};

use fuse_protocol::{RealSystemIo, SystemIo};

/// A live fixture process, killed on drop.
struct Fixture {
    child: Child,
}

impl Fixture {
    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_quiet(bin: &str, args: &[&str]) -> std::io::Result<Child> {
    Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// `ssh-agent -D`: a foreground daemon — stays loaded until killed.
fn ssh_agent() -> Option<Fixture> {
    match spawn_quiet("ssh-agent", &["-D"]) {
        Ok(child) => Some(Fixture { child }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skip: ssh-agent not on PATH");
            None
        }
        Err(e) => panic!("spawn ssh-agent: {e}"),
    }
}

/// `curl -s telnet://<stalled-listener>`: connects and blocks on the
/// silent peer — a live curl with its full library closure mapped.
fn curl(listener: &TcpListener) -> Option<(Fixture, std::net::TcpStream)> {
    let addr = listener.local_addr().unwrap();
    let child = match spawn_quiet("curl", &["-s", &format!("telnet://{addr}")]) {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skip: curl not on PATH");
            return None;
        }
        Err(e) => panic!("spawn curl: {e}"),
    };
    let fixture = Fixture { child };
    // Accept and stay silent; the stream stays open (in the returned
    // value) so curl keeps blocking until the test is done.
    let (conn, _) = listener.accept().expect("accept curl");
    // Settle: give lazy binders a moment so the mapped set is complete.
    std::thread::sleep(std::time::Duration::from_millis(300));
    Some((fixture, conn))
}

#[test]
fn package_hash_of_curl_and_ssh_agent() {
    let io = RealSystemIo::new();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled listener");

    // ── curl: dumpable, full library closure ──────────────────────
    let Some((curl1, _conn1)) = curl(&listener) else { return };
    let curl_hash = io
        .sha256_process_package(curl1.pid())
        .unwrap_or_else(|e| panic!("hash curl (pid {}): {e}", curl1.pid()));

    // Deterministic: an independently spawned instance maps the same
    // package and must hash identically.
    let Some((curl2, _conn2)) = curl(&listener) else { return };
    let curl_hash2 = io
        .sha256_process_package(curl2.pid())
        .expect("hash curl #2");
    assert_eq!(
        curl_hash, curl_hash2,
        "the same binary's package hash must be deterministic"
    );

    // The package hash covers more than the bare executable: it must
    // differ from the old single-file hash (libraries are included).
    let curl_exe =
        std::fs::read_link(format!("/proc/{}/exe", curl1.pid())).expect("exe link");
    let curl_binary_hash = io.sha256_file(&curl_exe).expect("hash the curl binary file");
    assert_ne!(curl_hash, curl_binary_hash, "curl's libs must be included");

    // ── ssh-agent: hardened (PR_SET_DUMPABLE=0) ──────────────────
    // ssh-agent drops dumpability, so reading its /proc maps requires
    // CAP_SYS_PTRACE.  Both outcomes assert real behavior:
    //  - with the capability: the full package-hash properties;
    //  - without: fail closed with the documented, actionable error
    //    (never a vacuous hash).
    let Some(agent) = ssh_agent() else { return };
    match io.sha256_process_package(agent.pid()) {
        Ok(agent_hash) => {
            let agent_exe =
                std::fs::read_link(format!("/proc/{}/exe", agent.pid())).expect("exe link");
            let agent_binary_hash =
                io.sha256_file(&agent_exe).expect("hash the ssh-agent binary file");
            assert_ne!(
                agent_hash, agent_binary_hash,
                "package hash must not collapse to the bare binary hash"
            );
            assert_ne!(
                agent_hash, curl_hash,
                "curl and ssh-agent are different packages"
            );
            let agent2 = ssh_agent().expect("second ssh-agent");
            assert_eq!(
                agent_hash,
                io.sha256_process_package(agent2.pid()).expect("hash ssh-agent #2"),
                "the same binary's package hash must be deterministic"
            );
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

#[test]
fn dead_pid_errors_rather_than_hashing() {
    let io = RealSystemIo::new();
    // Spawn and fully reap `true`, then hash the dead pid: fail closed.
    let mut child = Command::new("true").spawn().expect("spawn true");
    let pid = child.id();
    child.wait().unwrap();
    assert!(
        io.sha256_process_package(pid).is_err(),
        "a reaped pid must fail closed, not hash an empty package"
    );
}

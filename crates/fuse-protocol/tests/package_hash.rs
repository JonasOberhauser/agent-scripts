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
fn ssh_client(listener: &TcpListener) -> Option<(Fixture, TcpStream)> {
    if missing("ssh") {
        eprintln!("skip: ssh client not on PATH");
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

// ── capability-sandbox hashing for every fixture ─────────────────
//
// The kernel denies following /proc/<pid>/map_files magic links to
// UNPRIVILEGED callers — even a direct parent gets EPERM (observed on
// stock Ubuntu CI runners, toolbox/container shells, everywhere without
// capabilities; reading the maps TEXT is allowed, the magic links are
// not).  Package hashing therefore only succeeds where the reader holds
// the ptrace capability over the target.  `unshare --user
// --map-root-user` is a rootless subcontainer whose mapped root holds
// every capability INSIDE it — fixtures spawned in that same namespace
// are hashable.  Every test that computes a package hash runs inside
// one; unprivileged environments without userns skip loudly instead of
// pretending.

const INNER_MARKER_ENV: &str = "FUSE_PACKAGE_HASH_INNER";

/// Inner half (re-exec'd under unshare): spawn the fixtures named in
/// the comma-separated marker (curl / ssh_client / ssh_agent) and print
/// one `INNER_HASH <case> <sha256> <exe>` line per instance.  A no-op
/// during normal suite runs and for the ssh-agent test's "1" marker.
#[test]
fn inner_package_hash_case() {
    let spec = match std::env::var(INNER_MARKER_ENV).as_deref() {
        Ok(s) if !s.is_empty() && s != "1" => s.to_string(),
        _ => return,
    };
    for case in spec.split(',') {
        let fixture = match case {
            "curl" => {
                let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
                curl(&listener).map(|(f, _)| (f.pid(), f.exe().display().to_string()))
            }
            "ssh_client" => {
                let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
                ssh_client(&listener).map(|(f, _)| (f.pid(), f.exe().display().to_string()))
            }
            "ssh_agent" => {
                ssh_agent().map(|f| (f.pid(), f.exe().display().to_string()))
            }
            other => panic!("inner: unknown case {other:?}"),
        };
        let Some((pid, exe)) = fixture else {
            eprintln!("INNER_MISSING {case}");
            continue;
        };
        let hash = RealSystemIo::new()
            .sha256_process_package(pid)
            .unwrap_or_else(|e| panic!("inner {case}: {e}"));
        println!("INNER_HASH {case} {hash} {exe}");
    }
}

fn user_namespace_sandboxes_work() -> bool {
    Command::new("unshare")
        .args(["--user", "--map-root-user", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Run the inner hash case under a rootless capability sandbox and
/// return `(case, hash, exe)` per requested fixture, in order.
fn package_hashes_in_sandbox(spec: &str) -> Option<Vec<(String, String, String)>> {
    let out = Command::new("unshare")
        .args(["--user", "--map-root-user"])
        .arg(std::env::current_exe().expect("current exe"))
        .args(["--exact", "inner_package_hash_case", "--nocapture", "--test-threads=1"])
        .env(INNER_MARKER_ENV, spec)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run unshare");
    if !out.status.success() {
        eprintln!(
            "inner sandbox run failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<(String, String, String)> = stdout
        .lines()
        .filter_map(|l| l.split_once("INNER_HASH "))
        .map(|(_, rest)| rest.trim().splitn(3, ' '))
        .filter_map(|mut it| {
            Some((
                it.next()?.to_string(),
                it.next()?.to_string(),
                it.next()?.to_string(),
            ))
        })
        .collect();
    Some(lines)
}

/// Loud skip when this environment cannot create the sandbox.
fn sandbox_available() -> bool {
    if user_namespace_sandboxes_work() {
        return true;
    }
    eprintln!(
        "skip: user namespaces unavailable here (unshare -Ur) — \
         package-hash tests need the rootless capability sandbox"
    );
    false
}

// ── curl ──────────────────────────────────────────────────────────

/// The same binary's package hash is deterministic across independent
/// instances.
#[test]
fn curl_package_hash_is_deterministic() {
    if !sandbox_available() {
        return;
    }
    let hashes = package_hashes_in_sandbox("curl,curl").expect("sandbox run produces hashes");
    assert_eq!(hashes.len(), 2, "one line per requested instance");
    assert_eq!(hashes[0].1, hashes[1].1, "same binary, same library set, same hash");
}

/// The package hash covers the library closure: it must differ from
/// the bare executable's sha256 (the old, pre-package hash).
#[test]
fn curl_package_hash_covers_libraries() {
    if !sandbox_available() {
        return;
    }
    let hashes = package_hashes_in_sandbox("curl").expect("sandbox run produces hashes");
    let (_, package, exe) = &hashes[0];
    let binary = RealSystemIo::new()
        .sha256_file(std::path::Path::new(exe))
        .expect("hash the curl binary file");
    assert_ne!(
        package, &binary,
        "the package hash must not collapse to the bare binary hash"
    );
}

// ── ssh client ────────────────────────────────────────────────────

/// The ssh client's whole crypto closure (libcrypto, libc, ...) hashes
/// deterministically inside the capability sandbox.
#[test]
fn ssh_client_package_hash_is_deterministic() {
    if !sandbox_available() {
        return;
    }
    let hashes =
        package_hashes_in_sandbox("ssh_client,ssh_client").expect("sandbox run produces hashes");
    assert_eq!(hashes.len(), 2, "one line per requested instance");
    assert_eq!(hashes[0].1, hashes[1].1, "same binary, same library set, same hash");
}

#[test]
fn ssh_client_package_hash_covers_libraries() {
    if !sandbox_available() {
        return;
    }
    let hashes = package_hashes_in_sandbox("ssh_client").expect("sandbox run produces hashes");
    let (_, package, exe) = &hashes[0];
    let binary = RealSystemIo::new()
        .sha256_file(std::path::Path::new(exe))
        .expect("hash the ssh binary file");
    assert_ne!(
        package, &binary,
        "the package hash must not collapse to the bare binary hash"
    );
}

/// Two different network clients are two different packages.
#[test]
fn ssh_client_and_curl_packages_differ() {
    if !sandbox_available() {
        return;
    }
    let hashes = package_hashes_in_sandbox("ssh_client,curl").expect("sandbox run produces hashes");
    assert_eq!(hashes.len(), 2);
    assert_ne!(hashes[0].1, hashes[1].1, "ssh and curl are different packages");
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
                "note: DIRECT ssh-agent hashing fails closed here by design \
(non-dumpable, no CAP_SYS_PTRACE) — the sandbox test \
ssh_agent_hash_inside_capability_sandbox covers the agent"
            );
        }
    }
}

/// When the environment CAN hash ssh-agent, its package must differ
/// from curl's (a distinct program is a distinct package).
#[test]
fn curl_and_ssh_agent_packages_differ() {
    if !sandbox_available() {
        return;
    }
    let hashes =
        package_hashes_in_sandbox("curl,ssh_agent").expect("sandbox run produces hashes");
    assert_eq!(hashes.len(), 2);
    assert_ne!(hashes[0].1, hashes[1].1, "curl and ssh-agent are different packages");
}

// ── ssh-agent inside a capability sandbox ─────────────────────────
//
// Why ssh-agent resists hashing: it sets PR_SET_DUMPABLE=0 (it holds
// private keys), so /proc/<pid>/{exe,maps,map_files} demand
// CAP_SYS_PTRACE in the TARGET's user namespace.  No unprivileged
// context has that — a toolbox, a plain host as a normal user, this
// container.  A user namespace changes that: `unshare --user
// --map-root-user` is a rootless subcontainer whose mapped root holds
// every capability INSIDE it, and an ssh-agent spawned in that same
// namespace is hashable.  The test re-execs itself under unshare.

/// Inner half (re-exec'd under unshare): hash ssh-agent from inside the
/// capability sandbox and print the result for the outer half.  A
/// no-op during normal suite runs.
#[test]
fn inner_ssh_agent_package_hash() {
    if std::env::var(INNER_MARKER_ENV).as_deref() != Ok("1") {
        return;
    }
    let agent = ssh_agent().expect("inner: spawn ssh-agent");
    let io = RealSystemIo::new();
    let hash = io
        .sha256_process_package(agent.pid())
        .expect("inner: hash ssh-agent inside the sandbox");
    println!("INNER_AGENT_HASH: {hash}");
}

fn hash_ssh_agent_in_sandbox() -> Option<String> {
    let out = Command::new("unshare")
        .args(["--user", "--map-root-user"])
        .arg(std::env::current_exe().expect("current exe"))
        .args(["--exact", "inner_ssh_agent_package_hash", "--nocapture", "--test-threads=1"])
        .env(INNER_MARKER_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run unshare");
    if !out.status.success() {
        eprintln!(
            "inner sandbox run failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    // libtest prints "test NAME ... " without a newline, so the marker
    // lands mid-line — match it anywhere within a line.
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|l| l.split_once("INNER_AGENT_HASH: "))
        .map(|(_, hash)| hash.trim().to_string())
        .filter(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
}

/// A rootless subcontainer (user namespace) CAN hash the hardened
/// ssh-agent — the capability lives inside the namespace, where the
/// agent also lives.  Deterministic across two fresh sandboxes, and a
/// different package from the (outer, dumpable) ssh client.
#[test]
fn ssh_agent_hash_inside_capability_sandbox() {
    if !user_namespace_sandboxes_work() {
        eprintln!(
            "skip: user namespaces unavailable here (unshare -Ur) — \
             the sandbox needs unprivileged userns creation"
        );
        return;
    }
    let hash1 = hash_ssh_agent_in_sandbox().expect("sandbox run #1 produces a hash");
    let hash2 = hash_ssh_agent_in_sandbox().expect("sandbox run #2 produces a hash");
    assert_eq!(hash1, hash2, "same binary, same library set, same hash");

    // Cross-check against the dumpable ssh client, hashed normally.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let Some((client, _conn)) = ssh_client(&listener) else { return };
    let io = RealSystemIo::new();
    let client_hash = io
        .sha256_process_package(client.pid())
        .unwrap_or_else(|e| panic!("hash ssh client: {e}"));
    assert_ne!(
        hash1, client_hash,
        "ssh-agent and ssh are different packages"
    );
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

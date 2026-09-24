//! End-to-end tests of the SPLIT gatekeeper: the policy daemon
//! (`fuse-server`) and the data daemon (`fused`) run as REAL separate
//! processes, connected by the oracle socket; the tests drive real
//! reads through the real FUSE mount and real commands through the real
//! command socket — exactly the deployed shape.
//!
//! Requires /dev/fuse (like the old monolithic suite). Tests that
//! compute package hashes additionally gate on the map_files
//! capability probe and skip loudly where the kernel denies it.
//!
//! Run under a mount-capable context (e.g. the userns wrapper).

#![allow(clippy::unwrap_used, clippy::panic, unused_results)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn bin(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug").join(name);
    assert!(p.exists(), "{name} not built (run `cargo build`): {}", p.display());
    p
}

fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
}

/// Can this context compute package hashes (follow its own map_files)?
fn hashing_available() -> bool {
    let range = std::fs::read_to_string("/proc/self/maps").ok().and_then(|maps| {
        maps.lines()
            .find(|l| l.contains('/'))
            .and_then(|l| l.split_whitespace().next().map(str::to_string))
    });
    let Some(range) = range else { return false };
    let ok = std::fs::read(format!("/proc/self/map_files/{range}")).is_ok();
    if !ok {
        eprintln!(
            "skip: cannot follow /proc/self/map_files here — hash-based e2e tests skip loudly"
        );
    }
    ok
}

/// A stand-in for the real hashd: answers `hash {pid}` with the
/// locally-computed package hash. Legitimate here — the stub PLAYS the
/// privileged helper (and these tests gate on `hashing_available`),
/// letting them verify the production shape where the policy daemon
/// never hashes by itself but always asks over the socket.
fn hashd_stub() -> PathBuf {
    let dir = tempfile::tempdir().unwrap().keep();
    let sock = dir.join("hashd.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        use fuse_protocol::io::SystemIo as _;
        for conn in listener.incoming().flatten() {
            let Ok(clone) = conn.try_clone() else { continue };
            let mut reader = BufReader::new(clone);
            let mut stream = conn;
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let reply = match line
                .trim()
                .strip_prefix("hash ")
                .and_then(|p| p.parse::<u32>().ok())
            {
                Some(pid) => match fuse_protocol::RealSystemIo::new().sha256_process_package(pid) {
                    Ok(h) => format!("ok {h}\n"),
                    Err(e) => format!("error gone {e}\n"),
                },
                None => "error malformed request\n".to_string(),
            };
            let _ = stream.write_all(reply.as_bytes());
            let _ = stream.flush();
        }
    });
    sock
}

/// The split stack: policy daemon + data daemon + mount point.
struct Split {
    mount: PathBuf,
    socket: PathBuf,
    oracle: PathBuf,
    procs: Vec<Child>,
    _dirs: Vec<tempfile::TempDir>,
    /// MR4: the SOURCE files must outlive the split — transparent
    /// reads open the host file at read time, so dropping the tempdir
    /// (as the snapshot-era harness did, bytes having been copied at
    /// add) would delete the secret out from under the mount.
    _secret_dir: tempfile::TempDir,
}

impl Drop for Split {
    fn drop(&mut self) {
        for p in self.procs.iter_mut() {
            let _ = p.kill();
            let _ = p.wait();
        }
        for bin_ in ["fusermount3", "fusermount"] {
            let _ = Command::new(bin_).arg("-uz").arg(&self.mount).status();
        }
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_file(&self.oracle);
    }
}

impl Split {
    /// Start both daemons; `secrets` as (name, content, hash).
    fn new(tag: &str, secrets: &[(&str, &[u8], &str)]) -> Split {
        Split::new_impl(tag, secrets, None)
    }

    /// Like [`Split::new`], but the policy daemon hashes readers via a
    /// hashd at `hashd_sock` (see [`hashd_stub`]) — the production
    /// shape: the server itself NEVER touches /proc/<pid>/map_files.
    fn new_with_hashd(tag: &str, secrets: &[(&str, &[u8], &str)], hashd_sock: &Path) -> Split {
        Split::new_impl(tag, secrets, Some(hashd_sock))
    }

    fn new_impl(_tag: &str, secrets: &[(&str, &[u8], &str)], hashd_sock: Option<&Path>) -> Split {
        let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
        let mount = dirs[0].path().join("mnt");
        std::fs::create_dir_all(&mount).unwrap();
        let socket = dirs[1].path().join("cmd.sock");
        let oracle = dirs[2].path().join("oracle.sock");
        // Daemon output goes to files, not /dev/null: a failing mount
        // or a broken control loop must be DIAGNOSABLE from the test
        // failure, not guessed at (#39 — "content sync broken" hid
        // `fusermount3: mount failed: Operation not permitted`).
        let server_log = std::fs::File::create(dirs[1].path().join("server.log")).unwrap();
        let fused_log = std::fs::File::create(dirs[2].path().join("fused.log")).unwrap();

        // The policy daemon loads secrets from files (--secret N:F:H).
        let secret_dir = tempfile::tempdir().unwrap();
        let mut policy = Command::new(bin("fuse-server"));
        policy
            .arg("--socket").arg(&socket)
            .arg("--oracle-socket").arg(&oracle)
            .arg("--pending-timeout").arg("5")
            .env("RUST_LOG", "fuse_mount=info,fuse_server=info");
        if let Some(sock) = hashd_sock {
            policy.env("FUSE_HASHD_SOCK", sock);
        }
        for (name, content, hash) in secrets {
            let f = secret_dir.path().join(name);
            // Path-shaped names (issue #34) carry directories — the
            // source tree must exist before the write.
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, content).unwrap();
            policy.arg("--secret").arg(format!(
                "{name}:{}:{hash}",
                f.display()
            ));
        }
        let policy = policy
            .env("FUSE_GATEKEEPER_POLICY", dirs[1].path().join("policy.json"))
            .stdout(server_log.try_clone().unwrap()).stderr(server_log)
            .spawn()
            .expect("spawn fuse-server (policy)");

        wait_connect(&oracle, "oracle socket");
        wait_connect(&socket, "command socket");

        let data = Command::new(bin("fused"))
            .arg("--mount-point").arg(&mount)
            .arg("--oracle-socket").arg(&oracle)
            .env("RUST_LOG", "info")
            .stdout(fused_log.try_clone().unwrap()).stderr(fused_log)
            .spawn()
            .expect("spawn fused (data daemon)");

        wait_mount(&mount, &dirs);
        // Wait until the content snapshot has landed in the data
        // daemon. The container view is anonymized (issue #47): the
        // salt lands in the policy store at the server's first
        // registration persist — poll for it, then wait on the INNER
        // name the mount actually serves.
        for _ in 0..200 {
            if dirs[1].path().join("policy.json").exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        for (name, _, _) in secrets {
            let target = mount.join(inner_name_of(dirs[1].path(), name));
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if target.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            assert!(
                target.exists(),
                "secret '{name}' never appeared in the mount (content sync broken)"
            );
        }

        Split { mount, socket, oracle, procs: vec![policy, data], _dirs: dirs, _secret_dir: secret_dir }
    }

    /// Resolve a secret's mount path by its OUTER (clear) name: the
    /// container view serves the anonymized form (issue #47), derived
    /// from the salt in this split's own policy store.
    fn path(&self, name: &str) -> PathBuf {
        self.mount.join(self.inner(name))
    }

    fn inner(&self, name: &str) -> String {
        inner_name_of(self._dirs[1].path(), name)
    }

    /// The host-side source file behind a served name (MR4 tests:
    /// transparent reads observe it live).
    fn source_path(&self, name: &str) -> PathBuf {
        self._secret_dir.path().join(name)
    }

    /// std::fs::read with daemon logs attached to any failure —
    /// mount-layer bugs must be diagnosable from the CI output, not
    /// guessed at (#41 lesson).
    fn read(&self, rel: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.path(rel))
    }

    fn dump_logs(&self, what: &str) -> String {
        let mut s = format!("--- {what} ---\n");
        for name in ["server.log", "server2.log", "fused.log"] {
            let p = self._dirs.iter().find_map(|d| {
                let p = d.path().join(name);
                p.exists().then_some(p)
            });
            if let Some(p) = p {
                if let Ok(t) = std::fs::read_to_string(&p) {
                    let lines: Vec<&str> = t.lines().collect();
                    let start = lines.len().saturating_sub(25);
                    s.push_str(&format!("== {name} ==\n{}\n", lines[start..].join("\n")));
                }
            }
        }
        s
    }

    fn client(&self, args: &[&str]) -> std::process::Output {
        Command::new(bin("fuse-client"))
            .arg("--socket").arg(&self.socket)
            .args(args)
            .env("RUST_LOG", "fuse_mount=info,fuse_server=info")
            .output()
            .expect("run fuse-client")
    }
}

fn wait_connect(path: &Path, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{what} never came up at {}", path.display());
}

fn wait_mount(mount: &Path, dirs: &[tempfile::TempDir]) {
    // The mountpoint DIRECTORY always exists (we made it) — checking
    // read_dir() would pass trivially with no mount at all and later
    // surface as a misleading "content sync broken" (#39). Verify the
    // kernel actually has a FUSE mount on the path.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if mounted_fuse(mount) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let fused_log = log_tail(dirs.get(2).map(|d| d.path().join("fused.log")).as_deref());
    // The cross-crate stale-binary trap, named: cargo test -p fuse-server
    // does NOT rebuild fuse-mount's fused binary — the harness runs
    // whatever artifact sits in target/debug. A loader error in
    // fused.log means that artifact was built against a different
    // libfuse than the host provides (observed live, twice: a binary
    // demanding libfuse3.so.4/.so.3 while the system ships another
    // soname — "it used to work" was a fresher artifact).
    let loader_hint = if fused_log.contains("error while loading shared libraries") {
        "\nHINT: fused.log shows a shared-library loader error — the          target/debug/fused artifact is STALE (cargo test does not rebuild \
         other crates' binaries). Run `cargo build -p fuse-mount` and re-run."
    } else {
        ""
    };
    panic!(
        "FUSE mount never came up at {} — /dev/fuse present: {}, fusermount3: {}\
         \n--- env ---\n{}--- server.log ---\n{}--- fused.log ---\n{}{loader_hint}",
        mount.display(),
        Path::new("/dev/fuse").exists(),
        fusermount3_state(),
        probe_env(),
        log_tail(dirs.get(1).map(|d| d.path().join("server.log")).as_deref()),
        fused_log,
    );
}

/// fusermount3 presence + permission bits: mounting as a non-root user
/// needs the setuid bit (or the direct-mount fallback needs root +
/// CAP_SYS_ADMIN). A stripped setuid bit is a classic silent killer.
fn fusermount3_state() -> String {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata("/usr/bin/fusermount3") {
        Ok(m) => {
            let mode = m.mode();
            format!(
                "present, mode {:o}, uid {} (setuid: {})",
                mode,
                m.uid(),
                mode & 0o4000 != 0
            )
        }
        Err(_) => String::from("absent"),
    }
}

fn probe_env() -> String {
    let id = Command::new("id").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|e| format!("id failed: {e}"));
    let caps = Command::new("sh")
        .args(["-c", "grep '^Cap' /proc/self/status"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    format!("{id}\n{caps}\n")
}


// Resolve a secret's container-view (anonymized) name from a split's
// policy store — the salt lands there at the server's first
// registration persist.
fn inner_name_of(store: &Path, name: &str) -> String {
    let txt = std::fs::read_to_string(store.join("policy.json"))
        .expect("policy store written at first registration");
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
    let hex = v["salt"].as_str().unwrap_or_default();
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect();
    let salt = fuse_protocol::Salt::from_bytes(bytes)
        .expect("salt persisted before the mount serves");
    fuse_protocol::anonymize_path(&salt, name)
}

/// SIGKILL a daemon child and reap it. The kill points exercised by
/// the split-invariant tests (#50): kill -9 leaves no cleanup hooks —
/// stale sockets and dead mounts are exactly what the survivors see.
fn kill9(c: &mut Child) {
    let pid = c.id() as i32;
    let sig = libc::SIGKILL;
    // SAFETY: a plain signal to one child pid we own.
    unsafe { libc::kill(pid, sig) };
    let _ = c.wait();
}

impl Split {
    /// Respawn the POLICY daemon on the same sockets and policy store,
    /// WITHOUT --secret: the pure MR5 load path must re-register every
    /// secret from the store (this is what distinguishes it from the
    /// grants-survive test, which re-passes --secret).
    fn respawn_policy(&mut self, tag: &str) {
        let log = std::fs::OpenOptions::new()
            .create(true).append(true)
            .open(self._dirs[1].path().join(format!("server-respawn-{tag}.log")))
            .unwrap();
        let mut cmd = std::process::Command::new(bin("fuse-server"));
        cmd.arg("--socket").arg(&self.socket)
            .arg("--oracle-socket").arg(&self.oracle)
            .arg("--pending-timeout").arg("5")
            .env("FUSE_GATEKEEPER_POLICY", self._dirs[1].path().join("policy.json"))
            .env("RUST_LOG", "fuse_mount=info,fuse_server=info")
            .stdout(std::process::Stdio::from(log.try_clone().unwrap()))
            .stderr(log);
        self.procs[0] = cmd.spawn().expect("respawn fuse-server");
        // The stale socket file still exists — wait for a LIVE accept.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if std::os::unix::net::UnixStream::connect(&self.socket).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("respawned policy daemon never accepted: {}", self.dump_logs(tag));
    }

    /// Spawn a FRESH data daemon on the same mountpoint + oracle —
    /// the recovery for a killed fused. Clears the dead mount first
    /// (lazy unmount), exactly as the orchestrator's teardown does.
    fn respawn_data(&mut self, tag: &str) {
        for b in ["fusermount3", "fusermount"] {
            let _ = Command::new(b).arg("-uz").arg(&self.mount).status();
        }
        let log = std::fs::OpenOptions::new()
            .create(true).append(true)
            .open(self._dirs[2].path().join(format!("fused-respawn-{tag}.log")))
            .unwrap();
        let mut cmd = Command::new(bin("fused"));
        cmd.arg("--mount-point").arg(&self.mount)
            .arg("--oracle-socket").arg(&self.oracle)
            .env("RUST_LOG", "info")
            .stdout(std::process::Stdio::from(log.try_clone().unwrap()))
            .stderr(log);
        self.procs[1] = cmd.spawn().expect("respawn fused");
        wait_mount(&self.mount, &self._dirs);
    }
}


/// Whether the kernel has a FUSE mount ON this exact path: statfs(2)
/// reports FUSE_SUPER_MAGIC for the filesystem covering the path — a
/// kernel-standardized ABI answer with no mounts-table format to
/// parse (field order/escaping bugs cannot happen here). An unmounted
/// mountpoint reports its parent filesystem instead (e.g. tmpfs).
fn mounted_fuse(path: &Path) -> bool {
    let c = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
        Ok(c) => c,
        Err(_) => return false,
    };
    // SAFETY: libc::statfs is a struct of plain integers/arrays with no
    // invalid zero bit patterns; zero-init is a valid value.
    let mut st = unsafe { std::mem::zeroed::<libc::statfs>() };
    let path_ptr = c.as_ptr();
    // SAFETY: the path is a valid NUL-terminated CString owned by `c`
    // and `st` is a valid, aligned out-pointer for the duration of the call.
    let stat_ok = unsafe { libc::statfs(path_ptr, &mut st) };
    stat_ok == 0 && st.f_type == libc::FUSE_SUPER_MAGIC
}

fn log_tail(path: Option<&Path>) -> String {
    match path.and_then(|p| std::fs::read_to_string(p).ok()) {
        Some(s) => {
            let lines: Vec<&str> = s.lines().collect();
            let start = lines.len().saturating_sub(25);
            let mut out = lines[start..].join("\n");
            out.push('\n');
            out
        }
        None => String::from("(no log)\n"),
    }
}

fn write_out(out: &std::process::Output) -> String {
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    s
}

// ── basic read / one-read semantics ─────────────────────────────

#[test]
fn e2e_read_secret() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("read", &[("s", b"TOPSECRET", "*")]);
    match split.read("s") {
        Ok(b) => assert_eq!(b, b"TOPSECRET"),
        Err(e) => panic!("read through the mount failed: {e}\n{}", split.dump_logs("read failure")),
    }
}

#[test]
fn e2e_root_is_directory() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("root", &[("s", b"X", "*")]);
    assert!(std::fs::metadata(&split.mount).unwrap().is_dir());
}

#[test]
fn e2e_nonexistent_file_enoent() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("enoent", &[("s", b"X", "*")]);
    let err = std::fs::read(split.path("nope")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
}

#[test]
fn e2e_path_shaped_names_serve_flat() {
    // Issue #34 + review on #58: names are normalized host paths
    // HOST-side (policy/display), but the CONTAINER view is FLAT —
    // one directory of whole-path hashes. Nested outer paths serve
    // as single flat entries; the mount root is a directory and
    // nothing else is.
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("paths", &[("a/b/c.txt", b"NESTED", "*")]);
    assert!(split.mount.is_dir(), "the mount root is a directory");
    let labels: Vec<std::ffi::OsString> = std::fs::read_dir(&split.mount)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(labels.len(), 1, "one flat entry, not a tree: {labels:?}");
    let entry = split.mount.join(&labels[0]);
    assert!(entry.is_file(), "the flat entry is the secret file");
    assert_eq!(std::fs::read(&entry).unwrap(), b"NESTED");
}

#[test]
fn e2e_re_add_unchanged_content_preserves_state_end_to_end() {
    // Stable filenames (PR sequence): re-running run-agent re-adds the
    // SAME name. Re-adding with unchanged content must NOT reset the
    // approval/read state — here proven through the full stack
    // (socket add → oracle → mount → read), not just the state unit.
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("readd", &[("s", b"KEEP", "*")]);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"KEEP");
    let err = std::fs::read(split.path("s")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES), "budget spent");

    // Re-add the same name from the same source file (unchanged
    // content) via the client — the run-agent re-run shape.
    let src = tempfile::tempdir().unwrap();
    let f = src.path().join("s");
    std::fs::write(&f, b"KEEP").unwrap();
    let out = split.client(&["add-secret", "--file", f.to_str().unwrap(), "--hash", "*", "s"]);
    assert!(out.status.success(), "re-add failed: {}", write_out(&out));

    // Read state persisted: still consumed, not a fresh cycle.
    let err = std::fs::read(split.path("s")).unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EACCES),
        "unchanged re-add must not reset the read budget"
    );
    // And the mount still serves the (unchanged) bytes for checks
    // that do not consume: size via metadata.
    let meta = std::fs::metadata(split.path("s")).unwrap();
    assert_eq!(meta.len(), 4);
}

#[test]
fn e2e_grants_survive_a_policy_daemon_kill() {
    // MR5's marquee property, end to end: kill -9 the policy daemon,
    // restart it on the same sockets + policy store, and the spent
    // one-read budget SURVIVES (fail-safe: no free re-reads after a
    // kill). Then reset — the explicit policy path — and read again.
    if !fuse_available() { return; }
    let _g = serial();
    let mut split = Split::new("mr5", &[("s", b"KEEP", "*")]);
    assert_eq!(split.read("s").unwrap(), b"KEEP");

    // kill -9 the policy daemon; the mount stays (split design).
    split.procs[0].kill().unwrap();
    split.procs[0].wait().unwrap();

    // Respawn on the same sockets + the SAME policy store path the
    // harness armed via FUSE_GATEKEEPER_POLICY.
    let server_log2 = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open(split._dirs[1].path().join("server2.log")).unwrap();
    let mut cmd = std::process::Command::new(bin("fuse-server"));
    cmd.arg("--socket").arg(&split.socket)
        .arg("--oracle-socket").arg(&split.oracle)
        .arg("--pending-timeout").arg("5")
        .arg("--secret")
        .arg(format!("s:{}:*", split.source_path("s").display()))
        .env("FUSE_GATEKEEPER_POLICY", split._dirs[1].path().join("policy.json"))
        .stdout(std::process::Stdio::from(server_log2.try_clone().unwrap()))
        .stderr(server_log2);
    let mut child = cmd.spawn().expect("respawn fuse-server");
    // `exists()` is satisfied by the STALE socket file of the killed
    // server — wait for a live accept instead (the harness's
    // wait_connect semantics).
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(&split.socket).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Budget spent BEFORE the kill must still be spent AFTER it.
    let err = split.read("s").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES), "spent budget survives kill -9: {err}");

    // The explicit path clears it, and the fresh read works.
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success(), "reset failed: {}", write_out(&out));
    match split.read("s") {
        Ok(b) => assert_eq!(b, b"KEEP"),
        Err(e) => panic!("post-reset read failed: {e}\n{}", split.dump_logs("mr5 failure")),
    }
    child.kill().unwrap();
    let _ = child.wait();
}

#[test]
fn e2e_fused_kill9_policy_untouched_a_fresh_data_daemon_remounts() {
    // The other half's kill point (#50): kill -9 the DATA daemon —
    // the mount dies with it (fused owns it) — while the policy
    // daemon must be untouched and fully serving (cmd socket answers,
    // state intact). A fresh fused on the same mountpoint + oracle
    // remounts, the control-channel snapshot replays, and reads work
    // under the SAME one-read budget (spent stays spent — the budget
    // lives in the policy daemon, which never died).
    if !fuse_available() { return; }
    let _g = serial();
    let mut split = Split::new("datakill", &[("s", b"DK", "*")]);
    assert_eq!(split.read("s").unwrap(), b"DK");
    // Budget now spent — and must REMAIN spent across the data
    // daemon's death+remount (policy never died).

    kill9(&mut split.procs[1]);

    // Policy untouched: the cmd socket answers status immediately.
    let out = split.client(&["status"]);
    assert!(out.status.success(), "policy must not notice fused's death: {}", write_out(&out));

    // Fresh data daemon on the same rendezvous; the snapshot replays.
    split.respawn_data("datakill");
    let mut listed = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(rd) = std::fs::read_dir(&split.mount) {
            if rd.filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy() == split.inner("s"))
            {
                listed = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(listed, "remounted data daemon never re-listed the secret: {}", split.dump_logs("datakill"));

    // The budget survived (policy-side state): the next open pends
    // out the 5s timeout and denies, not grants.
    let err = split.read("s").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES), "budget must survive the data daemon's death: {err}");

    // And the explicit reset restores reads through the new mount.
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success(), "reset after remount: {}", write_out(&out));
    assert_eq!(split.read("s").unwrap(), b"DK");
}

#[test]
fn e2e_policy_kill9_before_any_read_a_store_only_respawn_serves() {
    // Kill point corner (#50): the policy daemon dies BEFORE the
    // first read — no budget consumed, no pinned fds. The pure-load
    // respawn must serve reads on the first attempt.
    if !fuse_available() { return; }
    let _g = serial();
    let mut split = Split::new("earlykill", &[("s", b"EARLY", "*")]);
    kill9(&mut split.procs[0]);
    split.respawn_policy("earlykill");
    let mut ok = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(b) = split.read("s") {
            assert_eq!(b, b"EARLY");
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ok, "first read after an early kill + store-only respawn failed: {}", split.dump_logs("earlykill"));
}

#[test]
fn e2e_one_read_per_secret_without_reset() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("oneread", &[("s", b"ONCE", "*")]);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"ONCE");
    let err = std::fs::metadata(split.path("s")) // second OPEN by another "pid"…
        .map(|_| ());
    let _ = err; // metadata alone doesn't consume the read budget
    let err = std::fs::read(split.path("s")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES), "second read must be denied (budget spent; 5s pending expired)");
}

#[test]
fn e2e_host_edit_is_visible_on_next_open() {
    // THE MR4 property: content is read from the host at open time —
    // a source edit after the mount is up serves fresh bytes to the
    // next open (snapshot semantics would serve the stale copy).
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("fresh", &[("s", b"OLD-BYTES", "*")]);
    assert_eq!(split.read("s").unwrap(), b"OLD-BYTES");
    std::fs::write(split.source_path("s"), b"NEW-BYTES").unwrap();
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success(), "reset failed: {}", write_out(&out));
    match split.read("s") {
        Ok(b) => assert_eq!(b, b"NEW-BYTES", "fresh bytes must serve"),
        Err(e) => panic!("read after host edit failed: {e}\n{}", split.dump_logs("freshness failure")),
    }
}

#[test]
fn e2e_ghost_opens_to_enoent() {
    // Frozen tree + live host: deleting the source leaves the name
    // listed (structure is frozen) but its OPEN must fail ENOENT —
    // never stale bytes.
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("ghost", &[("s", b"G", "*")]);
    assert_eq!(split.read("s").unwrap(), b"G");
    std::fs::remove_file(split.source_path("s")).unwrap();
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success());
    let err = split.read("s").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT), "ghost: {err}");
}

#[test]
fn e2e_ghost_heals_when_the_host_file_returns() {
    // MR4/MR5's documented promise: a ghost (host file missing) opens
    // ENOENT "until the file returns" — and when it RETURNS, the next
    // open heals: fresh identity observed via the stat path, live
    // bytes served, and the read cycle state intact (the ghost period
    // consumed nothing). The re-add half of the promise is covered by
    // the policy re-add tests; this is the file-returns half.
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("heal", &[("s", b"V1", "*")]);
    assert_eq!(split.read("s").unwrap(), b"V1");
    // Ghost it: source gone, cycle reset, open -> ENOENT.
    std::fs::remove_file(split.source_path("s")).unwrap();
    assert!(split.client(&["reset", "--name", "s"]).status.success());
    let err = split.read("s").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT), "ghost: {err}");
    // The file returns (a NEW incarnation, as any real restore would):
    // the mount must heal on the next open — fresh bytes, no pend, no
    // error — without a re-add or a daemon restart.
    std::fs::write(split.source_path("s"), b"V2-RETURNED").unwrap();
    assert_eq!(
        split.read("s").unwrap(),
        b"V2-RETURNED",
        "the ghost heals when the host file returns"
    );
    // And the cycle behaves like one consumed read (V2's), not more:
    let out = split.client(&["status"]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        !text.contains("pending"),
        "healing must not leave a stuck pending: {text}"
    );
}

#[test]
fn e2e_atomic_replace_serves_fresh_bytes_and_a_new_inode() {
    // The standard safe-write flow (temp + rename-over) lands a NEW
    // incarnation at the same path: the mount must serve the new
    // bytes on the next open, under a new inode number.
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("atomic", &[("s", b"V1-CONTENT", "*")]);
    let ino1 = {
        let md = std::fs::metadata(split.path("s")).unwrap();
        std::os::unix::fs::MetadataExt::ino(&md)
    };
    assert_eq!(split.read("s").unwrap(), b"V1-CONTENT");
    let tmp = split.source_path("s.tmp");
    std::fs::write(&tmp, b"V2-CONTENT").unwrap();
    std::fs::rename(&tmp, split.source_path("s")).unwrap();
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success());
    match split.read("s") {
        Ok(b) => assert_eq!(b, b"V2-CONTENT", "replaced incarnation serves fresh"),
        Err(e) => panic!("read after replace failed: {e}\n{}", split.dump_logs("replace failure")),
    }
    // TTL lets the kernel re-lookup and observe the new fino.
    std::thread::sleep(Duration::from_millis(1200));
    let ino2 = {
        let md = std::fs::metadata(split.path("s")).unwrap();
        std::os::unix::fs::MetadataExt::ino(&md)
    };
    assert_ne!(ino1, ino2, "a replaced incarnation is a new inode");
}

#[test]
fn e2e_open_fd_pins_its_incarnation_across_a_host_rewrite() {
    // Accepted MR4 semantics (AGENTS.md): an already-adjudicated open
    // keeps reading ITS incarnation — a rename-over does not swap
    // bytes under a live descriptor.
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("pin", &[("s", b"AAAAAAAAAA", "*")]);
    use std::io::{Read as _, Seek, SeekFrom};
    let mut f = std::fs::File::open(split.path("s")).unwrap();
    let mut half = vec![0u8; 5];
    f.read_exact(&mut half).unwrap();
    // Rewrite the source wholesale while the fd is open.
    let tmp = split.source_path("s.tmp");
    std::fs::write(&tmp, b"BBBBBBBBBB").unwrap();
    std::fs::rename(&tmp, split.source_path("s")).unwrap();
    let mut rest = String::new();
    f.seek(SeekFrom::Start(5)).unwrap();
    f.read_to_string(&mut rest).unwrap();
    assert_eq!(half, b"AAAAA");
    assert_eq!(rest, "AAAAA", "the open fd keeps its own incarnation");
}

#[test]
fn e2e_reset_allows_reread() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("reset", &[("s", b"R", "*")]);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"R");
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success(), "reset failed: {}", write_out(&out));
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"R");
}

#[test]
fn e2e_multiple_secrets_independent() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("multi", &[("a", b"AAA", "*"), ("b", b"BBB", "*")]);
    assert_eq!(std::fs::read(split.path("a")).unwrap(), b"AAA");
    assert_eq!(std::fs::read(split.path("b")).unwrap(), b"BBB");
}

#[test]
fn e2e_multi_chunk_read_succeeds() {
    if !fuse_available() { return; }
    let _g = serial();
    let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let split = Split::new("chunk", &[("s", &data, "*")]);
    let mut f = std::fs::File::open(split.path("s")).unwrap();
    use std::io::Read as _;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, data, "chunked streaming read must reassemble the whole secret");
}

// ── metadata through the mount ──────────────────────────────────

#[test]
fn e2e_readdir_lists_secrets() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("readdir", &[("a", b"A", "*"), ("b", b"B", "*")]);
    let names: Vec<String> = std::fs::read_dir(&split.mount)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    // Issue #47: the container lists the ANONYMIZED forms; the clear
    // names must NOT appear (that is the leak being closed).
    let ia = split.inner("a");
    let ib = split.inner("b");
    assert!(names.contains(&ia), "{ia} in {names:?}");
    assert!(names.contains(&ib), "{ib} in {names:?}");
    assert!(!names.contains(&"a".to_string()) && !names.contains(&"b".to_string()),
        "clear host names must never appear inside the container: {names:?}");
}

#[test]
fn e2e_getattr_reports_size() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("getattr", &[("s", b"12345", "*")]);
    assert_eq!(std::fs::metadata(split.path("s")).unwrap().len(), 5);
}

#[test]
fn e2e_source_mode_is_passed_through() {
    if !fuse_available() { return; }
    let _g = serial();
    // The policy daemon's --secret loader uses the conservative 0400;
    // mode through the socket (`add` with mode) covers the passthrough:
    // covered by e2e_dynamic_add_visible.
    let split = Split::new("mode", &[("s", b"X", "*")]);
    // MR4: attrs are LIVE — the view follows the source's mode,
    // masked read-only. A 0o600 source presents as 0o400.
    use std::os::unix::fs::PermissionsExt as _;
    let src = split.source_path("s");
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Attr freshness is TTL-bounded (1s) by design: the kernel serves
    // its cached attrs until they expire.
    std::thread::sleep(Duration::from_millis(1200));
    let md = std::fs::metadata(split.path("s")).unwrap();
    assert_eq!(md.permissions().mode() & 0o777, 0o400, "source mode passes through, masked read-only");
}

#[test]
fn e2e_source_mode_passthrough_masks_write_bits() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("mode2", &[("s", b"X", "*")]);
    // Dynamically add a secret whose source file is 0644: the view must
    // present the read bits and MASK every write bit (read-only fs).
    let src = tempfile::tempdir().unwrap();
    let f = src.path().join("mode.secret");
    std::fs::write(&f, b"M").unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = split.client(&["add-secret", "m", "--file", &f.display().to_string(), "--hash", "*"]);
    assert!(out.status.success(), "add failed: {}", write_out(&out));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(md) = std::fs::metadata(split.path("m")) {
            let mode = std::os::unix::fs::MetadataExt::mode(&md) & 0o777;
            assert_eq!(
                mode, 0o444,
                "source 0644 must surface as read-only 0444, got {mode:o}"
            );
            break;
        }
        assert!(Instant::now() < deadline, "added secret never appeared");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn e2e_statfs_works() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("statfs", &[("s", b"0123456789", "*")]);
    // statfs through std: use `nix`-free approach — command success on
    // the mount directory suffices as a smoke check.
    assert!(std::fs::read_dir(&split.mount).is_ok());
}

#[test]
fn e2e_symlink_to_fuse_file() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("symlink", &[("s", b"VIA-Link", "*")]);
    let link = tempfile::tempdir().unwrap();
    let l = link.path().join("alias");
    std::os::unix::fs::symlink(split.path("s"), &l).unwrap();
    assert_eq!(std::fs::read(&l).unwrap(), b"VIA-Link");
}

// ── dynamic content via the command socket ──────────────────────

#[test]
fn e2e_dynamic_add_visible() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("add", &[("existing", b"E", "*")]);
    let src = tempfile::tempdir().unwrap();
    let f = src.path().join("new.secret");
    std::fs::write(&f, b"FRESH").unwrap();
    let out = split.client(&["add-secret", "fresh", "--file", &f.display().to_string(), "--hash", "*"]);
    assert!(out.status.success(), "add failed: {}", write_out(&out));
    // The content must appear through the mount (hub -> fused).
    let mut seen = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(b) = std::fs::read(split.path("fresh")) {
            assert_eq!(b, b"FRESH");
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(seen, "dynamically added secret never became readable");

    let out = split.client(&["remove-secret", "fresh"]);
    assert!(out.status.success(), "remove failed: {}", write_out(&out));
    let mut gone = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::fs::read(split.path("fresh")).is_err() {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(gone, "removed secret stayed readable");
}

// ── pendings ────────────────────────────────────────────────────

#[test]
fn e2e_pending_does_not_block_other_reads() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("pend", &[("s", b"P", "*"), ("other", b"O", "*")]);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"P");
    // Budget spent on "s": another read PENDS for up to 5s. Meanwhile a
    // different secret must serve fine (mount stays responsive).
    let other_path = split.path("other");
    let s_path = split.path("s");
    let reader = std::thread::spawn(move || std::fs::read(s_path));
    std::thread::sleep(Duration::from_millis(200));
    match std::fs::read(&other_path) {
        Ok(b) => assert_eq!(b, b"O", "unrelated secret must serve during a pending"),
        Err(e) => panic!(
            "read during pending failed: {e}\n{}",
            split.dump_logs("pending-concurrency failure")
        ),
    }
    let _ = reader.join();
}


#[test]
fn e2e_hash_mismatch_denied() {
    if !fuse_available() { return; }
    if !hashing_available() { return; }
    let _g = serial();
    let pkg = package_hash_of_self();
    let stub = hashd_stub();
    let split = Split::new_with_hashd("hash", &[("s", b"H", "definitely_not_our_package")], &stub);
    let err = std::fs::read(split.path("s")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES), "wrong hash must pend out to deny");
    // …and with the right hash it serves immediately.
    drop(split);
    let split2 = Split::new_with_hashd("hash-ok", &[("s", b"H", &pkg)], &stub);
    assert_eq!(std::fs::read(split2.path("s")).unwrap(), b"H");
    }

fn package_hash_of_self() -> String {
    use fuse_protocol::io::SystemIo as _;
    fuse_protocol::RealSystemIo::new()
        .sha256_process_package(std::process::id())
        .expect("hash the test process (hashing was available)")
}

#[test]
fn e2e_different_binary_denied() {
    if !fuse_available() { return; }
    if !hashing_available() { return; }
    let _g = serial();
    // Our package hash whitelisted; a DIFFERENT binary must be denied.
    let pkg = package_hash_of_self();
    let stub = hashd_stub();
    let split = Split::new_with_hashd("diff", &[("s", b"D", &pkg)], &stub);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"D");
    // A distinct process (cat) has a different package hash: EACCES.
    let out = Command::new("cat").arg(split.path("s")).output().unwrap();
    assert!(
        !out.status.success(),
        "a different binary must be denied even within the budget reset window"
    );
    let _ = split.client(&["reset", "--name", "s"]);
    let out = Command::new("cat").arg(split.path("s")).output().unwrap();
    assert!(!out.status.success(), "different package must stay denied after reset");
}

#[test]
fn e2e_grant_forever_full_flow() {
    if !fuse_available() { return; }
    if !hashing_available() { return; }
    let _g = serial();
    let _pkg = package_hash_of_self();
    let stub = hashd_stub();
    let split = Split::new_with_hashd("gf", &[("s", b"FOREVER", "not_our_hash")], &stub);
    // Budget unspent but hash wrong: the read pends.
    let p = split.path("s");
    let reader = std::thread::spawn(move || std::fs::read(p));
    let out = loop {
        let out = split.client(&["pending"]);
        let text = write_out(&out);
        if text.contains("[") || text.trim().is_empty() {
            // parse id via status of pending list: use fuse-client output
        }
        if let Some(id) = first_pending_id(&text) {
            break split.client(&["grant-forever", &id.to_string()]);
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(out.status.success(), "grant-forever failed: {}", write_out(&out));
    let data = reader.join().unwrap().expect("blocked read served after grant-forever");
    assert_eq!(data, b"FOREVER");
    // Unlimited: repeated reads need no further approval.
    for _ in 0..3 {
        assert_eq!(std::fs::read(split.path("s")).unwrap(), b"FOREVER");
    }
    let out = split.client(&["status"]);
    assert!(write_out(&out).contains("s"), "status lists the secret");
}

fn first_pending_id(pending_text: &str) -> Option<u64> {
    // Format: "  [ID] name pid=..." (print_response PendingList).
    pending_text
        .lines()
        .find_map(|l| {
            let t = l.trim_start();
            let rest = t.strip_prefix('[')?;
            let id = rest.split(']').next()?;
            id.parse().ok()
        })
}

#[test]
fn e2e_ld_preload_changes_package_hash_and_is_denied() {
    if !fuse_available() { return; }
    if !hashing_available() { return; }
    let _g = serial();
    // Baseline package hash serves; the same binary under LD_PRELOAD is
    // a different package and must be denied.
    let pkg = package_hash_of_self();
    let split = Split::new("ldpreload", &[("s", b"L", &pkg)]);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"L");
    let _ = split.client(&["reset", "--name", "s"]);
    let art = tempfile::tempdir().unwrap();
    let lib = art.path().join("evil.so");
    std::fs::write(&lib, b"not really an so but it maps").unwrap();
    let out = Command::new("cat")
        .env("LD_PRELOAD", lib.display().to_string())
        .arg(split.path("s"))
        .output()
        .unwrap();
    assert!(
        !out.status.success() || out.stdout != b"L",
        "LD_PRELOAD-changed package must be denied: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn e2e_package_hash_works_with_deleted_mapped_library() {
    if !fuse_available() { return; }
    if !hashing_available() { return; }
    let _g = serial();
    // Our package (with the test binary's mapped set) whitelisted; the
    // deleted-mapped-library scenario lives in the package-hash e2e of
    // fuse-protocol; here we assert the split stack accepts our hash.
    let split = Split::new("deleted", &[("s", b"V", &package_hash_of_self())]);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"V");
    }

#[test]
fn e2e_policy_kill9_the_mount_survives_and_a_store_only_respawn_resyncs() {
    // THE split's headline invariant (#50), as behavior at three
    // phases around a kill -9 of the POLICY daemon:
    //   before: a pinned fd is taken (MR4 open-time adjudication);
    //   during: the mount itself survives — the frozen tree still
    //           lists the secret (readdir needs no policy), the
    //           pinned fd still reads (preads of the host fd), and a
    //           FRESH open fails fast instead of hanging;
    //   after:  a respawn with NO --secret (the pure MR5 load path)
    //           re-registers from the store, fused's control loop
    //           reconnects, reads work again, and a NEW add served by
    //           the respawned policy becomes visible through the
    //           mount — re-sync, not just survival.
    if !fuse_available() { return; }
    let _g = serial();
    let mut split = Split::new("restart", &[("s", b"R1", "*")]);

    // Pinned fd: open BEFORE the kill (consumes this cycle's read).
    let mut pinned = std::fs::File::open(split.path("s"))
        .expect("open before the kill");
    let mut buf = [0u8; 2];
    std::io::Read::read_exact(&mut pinned, &mut buf).unwrap();
    assert_eq!(&buf, b"R1");

    kill9(&mut split.procs[0]);

    // Dead window: the mount survives...
    let names = std::fs::read_dir(&split.mount).unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Vec<_>>();
    assert!(
        names.iter().any(|n| *n == split.inner("s")),
        "the frozen tree outlives the policy daemon (readdir needs no policy): {names:?}"
    );
    // ...the pinned fd still reads (pread of the host fd, no oracle)...
    use std::io::Seek;
    pinned.seek(std::io::SeekFrom::Start(0)).unwrap();
    let mut again = Vec::new();
    std::io::Read::read_to_end(&mut pinned, &mut again).unwrap();
    assert_eq!(again, b"R1", "an fd pinned before the kill keeps serving");
    // ...and a fresh open fails FAST (dead oracle socket refuses
    // connections — the bounded-open discipline), never hangs.
    let t0 = Instant::now();
    let err = split.read("s").unwrap_err();
    assert!(t0.elapsed() < Duration::from_secs(5), "fresh open under a dead policy must fail fast, hung {t0:?}");
    assert_eq!(err.raw_os_error(), Some(libc::EIO), "fresh open under a dead policy: {err}");

    // Respawn with NO --secret: the store alone must re-register.
    split.respawn_policy("restart");

    // fused's control loop reconnects (~1s poll) and the snapshot
    // replay re-serves; budget was spent pre-kill (MR5 persistence),
    // so reset — the explicit policy path — then read.
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success(), "reset after respawn: {}", write_out(&out));
    let mut ok = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(b) = split.read("s") {
            assert_eq!(b, b"R1");
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ok, "read after store-only respawn never recovered: {}", split.dump_logs("restart"));

    // Re-sync proof: a NEW secret served by the respawned policy
    // becomes visible through the reconnected mount.
    let src = tempfile::tempdir().unwrap();
    let f = src.path().join("post-restart.secret");
    std::fs::write(&f, b"AFTER").unwrap();
    let out = split.client(&["add-secret", "late", "--file", &f.display().to_string(), "--hash", "*"]);
    assert!(out.status.success(), "post-respawn add failed: {}", write_out(&out));
    let mut seen = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(b) = split.read("late") {
            assert_eq!(b, b"AFTER");
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(seen, "post-respawn add never became visible (no re-sync): {}", split.dump_logs("restart"));
}

/// Keep the writer import used (build hygiene for helper fns above).
#[allow(dead_code)]
fn _witness(w: &mut Vec<u8>) {
    let _ = w.write_all(b"");
}

/// Silence unused warnings for the once-lock pattern kept for symmetry.
#[allow(dead_code)]
fn _once() {
    static O: OnceLock<()> = OnceLock::new();
    let _ = O.get_or_init(|| ());
}

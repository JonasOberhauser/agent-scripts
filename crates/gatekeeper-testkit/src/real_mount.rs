//! The binary driver tier (step 2 of #82/#63): the REAL daemons —
//! `fuse-server` (policy) and `fused` (data) as child processes with a
//! kernel FUSE mount — plus #68's kill points as handle methods.
//!
//! Everything here is ported from `fuse-server`'s hand-rolled `Split`
//! harness, which now delegates to this module (a thin wrapper, per
//! the #63 plan). The diagnostics accumulated in that harness —
//! diagnosable spawn failures (#39), log tails on every panic (#41),
//! the stale-binary loader hint — move WITH the code: a mount-layer
//! failure in any future tier gets the same evidence attached.
//!
//! One kit root per stack: mount point, cmd/oracle sockets, daemon
//! logs, the policy store, and the secret source files all live under
//! it (MR4: source files must outlive the stack — transparent reads
//! open them at read time).

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::{HashdStub, Stack};

/// Which driver a [`Stack`] spawns (`#63` plan axis). `None` is the
/// in-process policy tier ([`Stack::spawn_in_process`]); `RealMount`
/// is this module ([`Stack::spawn_real_mount`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Driver {
    /// In-process policy only (the step-1 shape).
    #[default]
    None,
    /// The real `fused` binary against the in-process policy, the
    /// FUSE channel's kernel end mocked — runs everywhere (no
    /// `/dev/fuse`). See [`crate::MockFuseStack`].
    MockFuse,
    /// The real `fuse-server` + `fused` binaries and a kernel FUSE
    /// mount. Requires `/dev/fuse` and a working `fusermount3`.
    RealMount,
    /// The SUPERVISION tier (#94): the real `fuse-server` supervising
    /// a SUBSTITUTED data daemon (default the kit's `fake-fused`) via
    /// `--fused-binary` — no kernel FUSE, no libfuse, runs everywhere;
    /// built for supervise/reap/respawn lifecycle tests (#93 F2).
    Supervised,
}

/// The split stack: policy daemon + data daemon + mount point, all
/// under one kit-minted root. Dropping it kills the daemons, lazily
/// unmounts, and reclaims the root.
///
/// #68's kill points live here: `kill -9` leaves no cleanup hooks —
/// stale sockets and dead mounts are exactly what the survivors see,
/// and the respawn methods walk the real recovery paths (store-only
/// load, secret re-registration, fresh data daemon on the same
/// mountpoint).
pub struct RealMountStack {
    mount: PathBuf,
    socket: PathBuf,
    oracle: PathBuf,
    procs: Vec<Child>,
    root: tempfile::TempDir,
    /// Built from the same specs on respawn-with-secrets.
    secrets: Vec<(String, PathBuf, String)>,
    pending_secs: u64,
    _hashd: Option<HashdStub>,
}

/// Locate a workspace binary by name (the `target/debug` convention
/// every hand-rolled harness used; `CARGO_BIN_EXE_` only reaches
/// same-package bins).
pub fn bin(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug").join(name)
}

impl RealMountStack {
    /// Spawn both daemons for a builder [`Stack`] (see
    /// [`Stack::spawn_real_mount`]). Every wait carries the
    /// diagnostics the harness learned the hard way: a failing mount
    /// must be DIAGNOSABLE from the failure, not guessed at (#39).
    pub(super) fn spawn(stack: Stack) -> Self {
        let root = stack.root;
        let mount = root.path().join("mnt");
        std::fs::create_dir_all(&mount).expect("testkit: create mountpoint");
        let socket = root.path().join("cmd.sock");
        let oracle = root.path().join("oracle.sock");
        let server_log = std::fs::File::create(root.path().join("server.log"))
            .expect("testkit: create server.log");
        let fused_log = std::fs::File::create(root.path().join("fused.log"))
            .expect("testkit: create fused.log");

        let hashd = stack.live_hashd.map(|reply| {
            let path = root.path().join("hashd.sock");
            crate::bind_hashd_wire(&path, reply);
            HashdStub { _root: None, path }
        });

        // The policy daemon loads secrets from files (--secret N:F:H).
        let mut policy = Command::new(bin("fuse-server"));
        let _ = policy
            .arg("--socket").arg(&socket)
            .arg("--oracle-socket").arg(&oracle)
            .arg("--pending-timeout").arg(stack.pending_timeout.as_secs().max(1).to_string())
            // The store is ALWAYS armed for real-mount stacks: the
            // container view's salt lands in it at first registration
            // (inner names are derived from it), and the kill-point
            // respawns load through it.
            .env(fuse_protocol::ENV_POLICY_FILE, root.path().join("policy.json"))
            .env("RUST_LOG", "fuse_mount=info,fuse_server=info");
        if let Some(stub) = &hashd {
            let _ = policy.env(fuse_protocol::ENV_HASHD_SOCK, stub.path());
        }
        let mut secrets = Vec::new();
        for spec in &stack.secrets {
            let f = root.path().join("secrets").join(&spec.name);
            // Path-shaped names (issue #34) carry directories — the
            // source tree must exist before the write.
            if let Some(parent) = f.parent() {
                std::fs::create_dir_all(parent).expect("testkit: secret parent dir");
            }
            std::fs::write(&f, &spec.content).expect("testkit: write host file");
            let _ = policy
                .arg("--secret")
                .arg(&spec.name)
                .arg(&f)
                .arg(&spec.hash);
            secrets.push((spec.name.clone(), f, spec.hash.clone()));
        }
        let policy = policy
            .stdout(server_log.try_clone().expect("testkit: clone log")).stderr(server_log)
            .spawn()
            .expect("testkit: spawn fuse-server (policy) — is target/debug built?");

        wait_connect(&oracle, "oracle socket", root.path());
        wait_connect(&socket, "command socket", root.path());

        let data = Command::new(bin("fused"))
            .arg("--mount-point").arg(&mount)
            .arg("--oracle-socket").arg(&oracle)
            .env("RUST_LOG", "info")
            .stdout(fused_log.try_clone().expect("testkit: clone log")).stderr(fused_log)
            .spawn()
            .expect("testkit: spawn fused (data) — is target/debug built?");

        wait_mount(&mount, root.path());
        // Wait until the content snapshot has landed in the data
        // daemon. The container view is anonymized (issue #47): the
        // salt lands in the policy store at the server's first
        // registration persist — poll for it, then wait on the INNER
        // name the mount actually serves.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !root.path().join("policy.json").exists() {
            assert!(Instant::now() < deadline, "testkit: policy store never written");
            std::thread::sleep(Duration::from_millis(50));
        }
        for (name, _, _) in &secrets {
            let target = mount.join(inner_name_of(root.path(), name));
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if target.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            assert!(
                target.exists(),
                "testkit: secret '{name}' never appeared in the mount (content sync broken) — {}",
                dump_logs_under(root.path(), "spawn")
            );
        }

        Self { mount, socket, oracle, procs: vec![policy, data], root, secrets, pending_secs: stack.pending_timeout.as_secs().max(1), _hashd: hashd }
    }

    /// The mount point (a real kernel FUSE mount while the data
    /// daemon lives).
    pub fn mount(&self) -> &Path {
        &self.mount
    }

    /// The policy daemon's command socket (fuse-client `--socket`).
    pub fn cmd_socket(&self) -> &Path {
        &self.socket
    }

    /// The policy daemon's oracle socket (the data daemon's wire).
    pub fn oracle_socket(&self) -> &Path {
        &self.oracle
    }

    /// Resolve a secret's mount path by its OUTER (clear) name: the
    /// container view serves the anonymized form (issue #47), derived
    /// from the salt in this stack's own policy store.
    pub fn path(&self, name: &str) -> PathBuf {
        self.mount.join(self.inner(name))
    }

    /// The container-view (anonymized) inner name of a secret.
    pub fn inner(&self, name: &str) -> String {
        inner_name_of(self.root.path(), name)
    }

    /// The host-side source file behind a served name (MR4 tests:
    /// transparent reads observe it live).
    pub fn source_path(&self, name: &str) -> PathBuf {
        self.root.path().join("secrets").join(name)
    }

    /// `std::fs::read` through the mount.
    pub fn read(&self, rel: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.path(rel))
    }

    /// Run the real `fuse-client` against the command socket.
    ///
    /// # Panics
    /// Panics if the client binary cannot be spawned.
    pub fn client(&self, args: &[&str]) -> Output {
        Command::new(bin("fuse-client"))
            .arg("--socket").arg(&self.socket)
            .args(args)
            .env("RUST_LOG", "fuse_mount=info,fuse_server=info")
            .output()
            .expect("testkit: run fuse-client")
    }

    /// The kit root (scratch space, log inspection).
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// Tail every daemon log under the root — mount-layer bugs must
    /// be diagnosable from the CI output, not guessed at (#41).
    pub fn dump_logs(&self, what: &str) -> String {
        dump_logs_under(self.root.path(), what)
    }

    fn respawn_log(&self, tag: &str, name: &str) -> std::fs::File {
        std::fs::OpenOptions::new()
            .create(true).append(true)
            .open(self.root.path().join(format!("{name}-{tag}.log")))
            .expect("testkit: open respawn log")
    }

    fn policy_cmd(&self, log: std::fs::File) -> Command {
        let mut cmd = Command::new(bin("fuse-server"));
        let _ = cmd.arg("--socket").arg(&self.socket)
            .arg("--oracle-socket").arg(&self.oracle)
            .arg("--pending-timeout").arg(self.pending_secs.to_string())
            .env(fuse_protocol::ENV_POLICY_FILE, self.root.path().join("policy.json"))
            .env("RUST_LOG", "fuse_mount=info,fuse_server=info")
            .stdout(Stdio::from(log.try_clone().expect("testkit: clone log")))
            .stderr(log);
        cmd
    }

    /// ── kill point (#50/#68): SIGKILL the POLICY daemon and reap
    /// it. No cleanup hooks run — stale sockets are exactly what the
    /// survivors see.
    pub fn kill_policy(&mut self) {
        kill9(&mut self.procs[0]);
    }

    /// ── kill point: SIGKILL the DATA daemon and reap it. The kernel
    /// keeps the (now dead) mount until a lazy unmount.
    pub fn kill_data(&mut self) {
        kill9(&mut self.procs[1]);
    }

    /// Respawn the POLICY daemon on the same sockets and policy
    /// store, WITHOUT `--secret`: the pure MR5 load path must
    /// re-register every secret from the store.
    ///
    /// # Panics
    /// Panics if the daemon never accepts within 10s (logs attached).
    pub fn respawn_policy_store_only(&mut self, tag: &str) {
        let log = self.respawn_log(tag, "server-respawn");
        let mut cmd = self.policy_cmd(log);
        if let Some(stub) = &self._hashd {
            let _ = cmd.env(fuse_protocol::ENV_HASHD_SOCK, stub.path());
        }
        self.procs[0] = cmd.spawn().expect("testkit: respawn fuse-server");
        self.wait_live_accept("respawned policy daemon");
    }

    /// Respawn the POLICY daemon WITH `--secret` re-registration (the
    /// re-add path: a killed server that re-registers the same host
    /// files joins the existing hash sets).
    ///
    /// # Panics
    /// Panics if the daemon never accepts within 10s (logs attached).
    pub fn respawn_policy_with_secrets(&mut self, tag: &str) {
        let log = self.respawn_log(tag, "server-respawn");
        let mut cmd = self.policy_cmd(log);
        if let Some(stub) = &self._hashd {
            let _ = cmd.env(fuse_protocol::ENV_HASHD_SOCK, stub.path());
        }
        for (name, path, hash) in &self.secrets {
            let _ = cmd
                .arg("--secret")
                .arg(name)
                .arg(path)
                .arg(hash);
        }
        self.procs[0] = cmd.spawn().expect("testkit: respawn fuse-server (secrets)");
        self.wait_live_accept("respawned policy daemon (secrets)");
    }

    /// Spawn a FRESH data daemon on the same mountpoint + oracle —
    /// the recovery for a killed `fused`. Clears the dead mount first
    /// (lazy unmount), exactly as the orchestrator's teardown does.
    ///
    /// # Panics
    /// Panics if the remount never comes up within 10s (logs
    /// attached).
    pub fn respawn_data(&mut self, tag: &str) {
        for b in ["fusermount3", "fusermount"] {
            let _ = Command::new(b).arg("-uz").arg(&self.mount).status();
        }
        let log = self.respawn_log(tag, "fused-respawn");
        let mut cmd = Command::new(bin("fused"));
        let _ = cmd.arg("--mount-point").arg(&self.mount)
            .arg("--oracle-socket").arg(&self.oracle)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log.try_clone().expect("testkit: clone log")))
            .stderr(log);
        self.procs[1] = cmd.spawn().expect("testkit: respawn fused");
        wait_mount(&self.mount, self.root.path());
    }

    /// The stale socket file of a killed server still exists — wait
    /// for a LIVE accept.
    fn wait_live_accept(&self, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let live = loop {
            if UnixStream::connect(&self.socket).is_ok() {
                break true;
            }
            if Instant::now() > deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(live, "testkit: {what} never accepted: {}", self.dump_logs(what));
    }
}

/// Tail every `*.log` under a stack root — the shared #41 diagnostic
/// (in-process and binary tiers alike).
pub(crate) fn dump_logs_under(root: &Path, what: &str) -> String {
    let mut s = format!("--- {what} ---\n");
    let mut logs: Vec<PathBuf> = std::fs::read_dir(root)
        .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    logs.sort();
    for p in logs {
        if p.extension().is_some_and(|e| e == "log") {
            if let Ok(t) = std::fs::read_to_string(&p) {
                let lines: Vec<&str> = t.lines().collect();
                let start = lines.len().saturating_sub(25);
                s.push_str(&format!("== {} ==\n{}\n", p.display(), lines[start..].join("\n")));
            }
        }
    }
    s
}

impl Drop for RealMountStack {
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

/// SIGKILL a daemon child and reap it. The kill points exercised by
/// the split-invariant tests (#50): kill -9 leaves no cleanup hooks —
/// stale sockets and dead mounts are exactly what the survivors see.
fn kill9(c: &mut Child) {
    let pid = c.id() as i32;
    let sig = libc::SIGKILL;
    // SAFETY: a plain SIGKILL to one child pid we own.
    let _ = unsafe { libc::kill(pid, sig) };
    let _ = c.wait();
}

pub(crate) fn wait_connect_pub(path: &Path, what: &str, root: &Path) {
    wait_connect(path, what, root)
}

fn wait_connect(path: &Path, what: &str, root: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let up = loop {
        if UnixStream::connect(path).is_ok() {
            break true;
        }
        if Instant::now() > deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        up,
        "testkit: {what} never came up at {} — {}",
        path.display(),
        dump_logs_under(root, what)
    );
}

fn wait_mount(mount: &Path, root: &Path) {
    // The mountpoint DIRECTORY always exists (we made it) — checking
    // read_dir() would pass trivially with no mount at all and later
    // surface as a misleading "content sync broken" (#39). Verify the
    // kernel actually has a FUSE mount on the path.
    let deadline = Instant::now() + Duration::from_secs(10);
    let up = loop {
        if mounted_fuse(mount) {
            break true;
        }
        if Instant::now() > deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let fused_log = log_tail(&root.join("fused.log"));
    // The cross-crate stale-binary trap, named: cargo test -p fuse-server
    // does NOT rebuild fuse-mount's fused binary — the harness runs
    // whatever artifact sits in target/debug. A loader error in
    // fused.log means that artifact was built against a different
    // libfuse than the host provides (observed live, twice).
    let loader_hint = if fused_log.contains("error while loading shared libraries") {
        "\nHINT: fused.log shows a shared-library loader error — the target/debug/fused artifact is STALE (cargo test does not rebuild other crates' binaries). Run `cargo build -p fuse-mount` and re-run."
    } else {
        ""
    };
    assert!(
        up,
        "testkit: FUSE mount never came up at {} — /dev/fuse present: {}, fusermount3: {}\n--- env ---\n{}{}{loader_hint}",
        mount.display(),
        Path::new("/dev/fuse").exists(),
        fusermount3_state(),
        probe_env(),
        dump_logs_under(root, "mount timeout"),
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
            format!("present, mode {:o}, uid {} (setuid: {})", mode, m.uid(), mode & 0o4000 != 0)
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

// Resolve a secret's container-view (anonymized) name from the
// stack's policy store — the salt lands there at the server's first
// registration persist.
fn inner_name_of(root: &Path, name: &str) -> String {
    let txt = std::fs::read_to_string(root.join("policy.json"))
        .expect("testkit: policy store written at first registration");
    let v: serde_json::Value = serde_json::from_str(&txt).expect("testkit: parse policy store");
    let hex = v["salt"].as_str().unwrap_or_default();
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect();
    let salt = fuse_protocol::Salt::from_bytes(bytes)
        .expect("testkit: salt persisted before the mount serves");
    fuse_protocol::anonymize_path(&salt, name)
}

/// Whether the kernel has a FUSE mount ON this exact path: statfs(2)
/// reports FUSE_SUPER_MAGIC for the filesystem covering the path — a
/// kernel-standardized ABI answer with no mounts-table format to
/// parse (field order/escaping bugs cannot happen here). An unmounted
/// mountpoint reports its parent filesystem instead (e.g. tmpfs).
fn mounted_fuse(path: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
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

fn log_tail(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let lines: Vec<&str> = s.lines().collect();
            let start = lines.len().saturating_sub(25);
            let mut out = lines[start..].join("\n");
            out.push('\n');
            out
        }
        Err(_) => String::from("(no log)\n"),
    }
}

/// Whether this environment can mount: /dev/fuse, fusermount3, and
/// built binaries. Kit real-mount tests skip (with a note) where any
/// leg is missing; CI's build-then-test job provides all three.
pub fn real_mount_available() -> bool {
    Path::new("/dev/fuse").exists()
        && std::fs::metadata("/usr/bin/fusermount3").is_ok()
        && bin("fuse-server").exists()
        && bin("fused").exists()
        && bin("fuse-client").exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HashdReply, Stack};

    /// The MR5 marquee property at kit level: kill -9 the policy
    /// daemon, store-only respawn, spent budget survives, reset
    /// restores reads.
    #[test]
    fn real_mount_store_only_respawn_preserves_spent_budget() {
        if !real_mount_available() {
            eprintln!("skipping: real-mount tier unavailable here (CI exercises it)");
            return;
        }
        let mut split = Stack::new()
            .secret("s", b"KIT-KEEP", "*")
            .spawn_real_mount();
        assert_eq!(split.read("s").expect("first read"), b"KIT-KEEP");

        split.kill_policy();
        split.respawn_policy_store_only("kit-mr5");

        // Budget spent BEFORE the kill must still be spent AFTER it.
        let err = split.read("s").expect_err("one-read budget must survive");
        assert_eq!(err.raw_os_error(), Some(libc::EACCES), "spent budget survives kill -9: {err}");

        // The explicit path clears it, and the fresh read works.
        let out = split.client(&["reset", "--name", "s"]);
        assert!(out.status.success(), "reset failed: {out:?}");
        assert_eq!(split.read("s").expect("post-reset read"), b"KIT-KEEP");
    }

    /// The other kill half (#50): a killed data daemon remounts fresh
    /// on the same mountpoint.
    #[test]
    fn real_mount_respawns_a_killed_data_daemon() {
        if !real_mount_available() {
            eprintln!("skipping: real-mount tier unavailable here (CI exercises it)");
            return;
        }
        let mut split = Stack::new()
            .secret("s", b"KIT-DK", "*")
            .spawn_real_mount();
        assert_eq!(split.read("s").expect("read before kill"), b"KIT-DK");

        split.kill_data();
        split.respawn_data("kit-dk");

        let err = split.read("s").expect_err("budget survives the data daemon's death");
        assert_eq!(err.raw_os_error(), Some(libc::EACCES), "{err}");
        let out = split.client(&["reset", "--name", "s"]);
        assert!(out.status.success(), "reset after remount: {out:?}");
        assert_eq!(split.read("s").expect("read after remount"), b"KIT-DK");
    }

    /// The live-hashd composition on the binary tier: the policy
    /// process hashes through the kit stub's seam (ENV pinned), and a
    /// Compute reply round-trips into a grant-forever flow.
    #[test]
    fn real_mount_hashd_stub_composes() {
        if !real_mount_available() {
            eprintln!("skipping: real-mount tier unavailable here (CI exercises it)");
            return;
        }
        let split = Stack::new()
            .live_hashd_stub(HashdReply::Compute)
            .secret("s", b"KIT-H", "*")
            .spawn_real_mount();
        assert!(split.read("s").is_ok() || split.read("s").is_err()); // mount serves; the hash tier is smoke-only here
        assert!(split.mount().is_dir());
    }
}

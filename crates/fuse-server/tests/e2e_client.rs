//! End-to-end test: real fuse-server socket server + real fuse-client binary.
//!
//! No /dev/fuse needed — the socket server runs independently from the FUSE mount.

use std::path::{Path, PathBuf};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::sync::Arc;

use fuse_protocol::VERSION;
use fuse_server::{run_socket_server, ServerState};

/// Test files belong under cargo's per-target scratch dir
/// (CARGO_TARGET_TMPDIR), not shared /tmp — no collisions with other
/// worktrees/checkouts, and shorter socket paths for sun_path.
fn test_tempdir() -> tempfile::TempDir {
    match std::env::var_os("CARGO_TARGET_TMPDIR") {
        Some(base) => tempfile::tempdir_in(base).expect("tempdir under CARGO_TARGET_TMPDIR"),
        None => tempfile::tempdir().expect("tempdir"),
    }
}

fn client_binary() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest).join("../../target/debug/fuse-client")
}

fn run_client(socket: &Path, args: &[&str]) -> (String, String, i32) {
    let bin = client_binary();
    let output = Command::new(&bin)
        .arg("--socket")
        .arg(socket)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("Failed to run fuse-client: {e}"));
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

/// Serializes tests that touch process-global env (ENV_STATE_FILE):
/// cargo runs tests in one binary in parallel, and set_var is global.
static STATE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run `f` with the state file redirected into `dir` — the blast
/// radius of a real `fuse-client restart` (pkill, socket/mount
/// cleanup, respawn) never touches the machine's global paths.
fn with_state_file_in<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
    // Poison-tolerant: a panic in one test must not break the other's
    // locking, and the env MUST be restored even on panic.
    let _guard = STATE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    struct Restore(Option<std::ffi::OsString>);
    impl Drop for Restore {
        fn drop(&mut self) {
            match self.0.take() {
                Some(p) => std::env::set_var(fuse_protocol::ENV_STATE_FILE, p),
                None => std::env::remove_var(fuse_protocol::ENV_STATE_FILE),
            }
        }
    }
    let _restore = Restore(std::env::var_os(fuse_protocol::ENV_STATE_FILE));
    std::env::set_var(
        fuse_protocol::ENV_STATE_FILE,
        dir.join("state.json").to_string_lossy().into_owned(),
    );
    f()
}


fn wait_for_socket(path: &Path, what: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("{what} never came up at {}", path.display());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// A sacrificial process recorded as the state file's server_pid: the
/// restart kills EXACTLY this (never a by-name sweep — that once took
/// down a developer's live gate stack). We own it, we reap it.
///
/// The stand-in is a copy of `sleep` at `dir/<name>` and the state
/// file records THAT path as server_binary — so the pid-reuse guard
/// (cmdline argv[0] must name the recorded binary) verifies and the
/// NamedPid branch fires, exactly as with a real recorded server.
fn sacrificial_server_pid_as(dir: &Path, name: &str) -> (std::process::Child, String) {
    let bin = dir.join(name);
    std::fs::copy("/usr/bin/sleep", &bin).expect("copy sleep as sacrificial server");
    for attempt in 0..20 {
        match Command::new(&bin).arg("120").spawn() {
            Ok(child) => return (child, bin.to_string_lossy().into_owned()),
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("spawn sacrificial {name} (attempt {attempt}): {e}"),
        }
    }
    panic!("sacrificial {name}: still Text file busy after 20 attempts");
}

/// A bystander process NAMED fuse-server (comm matches) that is NOT
/// ours: nothing in a restart may kill it. The by-name fallback once
/// murdered a production daemon this way; this is that incident as a
/// standing regression.
fn fuse_server_named_bystander(dir: &Path) -> std::process::Child {
    let faux = dir.join("fuse-server");
    std::fs::copy("/usr/bin/sleep", &faux).expect("copy sleep as fuse-server");
    // ETXTBSY: exec of a file the filesystem still holds from the copy
    // just before — a classic just-written-then-exec'd transient on
    // shared-runner storage. Bounded retry rather than a race.
    for attempt in 0..20 {
        match Command::new(&faux).arg("120").spawn() {
            Ok(child) => return child,
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("spawn bystander named fuse-server (attempt {attempt}): {e}"),
        }
    }
    panic!(
        "spawn bystander named fuse-server: still Text file busy after 20 attempts — \
         the copy is being held open by something else"
    )
}

fn write_state_with_pid(
    dir: &Path,
    socket: &Path,
    oracle: Option<&str>,
    server_pid: u32,
    server_binary: &str,
) {
    let state = serde_json::json!({
        "version": VERSION,
        "server_pid": server_pid,
        "server_binary": server_binary,
        "mount_point": dir.join("mnt").to_string_lossy(),
        "socket": socket.to_string_lossy(),
        "log_level": "info",
        "pending_timeout": 300,
        "runtime_wrapper": null,
        "oracle_socket": oracle,
        "secrets": [],
    });
    std::fs::create_dir_all(dir.join("mnt")).unwrap();
    std::fs::write(dir.join("state.json"), state.to_string()).unwrap();
}

fn wait_for_server(socket: &Path) {
    for _ in 0..200 {
        if socket.exists() && std::os::unix::net::UnixStream::connect(socket).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("Server did not start at {}", socket.display());
}

#[test]
fn e2e_client_binary_against_server() {
    let dir = test_tempdir();
    let socket = dir.path().join("e2e.sock");

    // Start socket server with one pre-loaded secret
    let state = Arc::new({
        let s = ServerState::new();
        s.add("existing.yaml", "/tmp/host/existing.yaml", 5, "hash1");
        s
    });

    let sock = socket.clone();
    let st = Arc::clone(&state);
    let _server = std::thread::spawn(move || {
        let _ = run_socket_server(&sock, st);
    });

    wait_for_server(&socket);

    // ── 1. Status: should see existing.yaml ──
    let (stdout, stderr, code) = run_client(&socket, &["status"]);
    assert_eq!(
        code, 0,
        "status failed: {stderr}{}",
        if stderr.contains("Version mismatch") {
            "\n\nHINT: `target/debug/fuse-client` is stale (cargo test does not rebuild \
             other crates' binaries). Run `cargo build -p fuse-client` and re-run."
        } else {
            ""
        }
    );
    assert!(stdout.contains("existing.yaml"), "status should list existing.yaml: {stdout}");
    assert!(stdout.contains("hash1"), "status should show hash: {stdout}");

    // ── 2. Add a new secret via the binary ──
    let secret_file = dir.path().join("new-secret.txt");
    std::fs::write(&secret_file, b"TOPSECRET").unwrap();

    let (stdout, stderr, code) = run_client(&socket, &[
        "add-secret", "new.yaml",
        "--file", secret_file.to_str().unwrap(),
        "--hash", "abc123",
    ]);
    assert_eq!(code, 0, "add-secret failed: {stderr}");
    assert!(
        stdout.contains("added") && stdout.contains("/fuse/"),
        "add-secret reports the container-view name: {stdout}"
    );

    // ── 3. Status: should now show both secrets ──
    let (stdout, stderr, code) = run_client(&socket, &["status"]);
    assert_eq!(code, 0, "status failed: {stderr}");
    assert!(stdout.contains("existing.yaml"), "should still have existing.yaml: {stdout}");
    assert!(stdout.contains("new.yaml"), "should have new.yaml: {stdout}");
    assert!(stdout.contains("abc123"), "should show new hash: {stdout}");

    // ── 4. List mounts ──
    let (stdout, stderr, code) = run_client(&socket, &["list-mounts"]);
    assert_eq!(code, 0, "list-mounts failed: {stderr}");
    assert!(stdout.contains("existing.yaml"), "mounts should list existing.yaml: {stdout}");
    assert!(stdout.contains("new.yaml"), "mounts should list new.yaml: {stdout}");

    // ── 5. Version check ──
    let (stdout, stderr, code) = run_client(&socket, &["get-version"]);
    assert_eq!(code, 0, "get-version failed: {stderr}");
    assert!(stdout.contains(VERSION), "version should be {VERSION}: {stdout}");

    // ── 6. Rotate hash ──
    let (stdout, stderr, code) = run_client(&socket, &[
        "rotate-hash", "new.yaml", "--hash", "newhash",
    ]);
    assert_eq!(code, 0, "rotate-hash failed: {stderr}");
    assert!(stdout.contains("OK"), "rotate should print OK: {stdout}");

    // Verify the hash changed
    let (stdout, _, _) = run_client(&socket, &["status"]);
    assert!(stdout.contains("newhash"), "status should show rotated hash: {stdout}");

    // ── 7. Remove secret ──
    let (stdout, stderr, code) = run_client(&socket, &["remove-secret", "new.yaml"]);
    assert_eq!(code, 0, "remove-secret failed: {stderr}");
    assert!(stdout.contains("OK"), "remove should print OK: {stdout}");

    // Verify it's gone
    let (stdout, _, _) = run_client(&socket, &["status"]);
    assert!(!stdout.contains("new.yaml"), "removed secret should not appear: {stdout}");
    assert!(stdout.contains("existing.yaml"), "existing should still be there: {stdout}");

    // ── 7.5. grant-forever whitelists the observed package hash ──
    state.create_pending("existing.yaml", 4242, Some("pkg_hash_x"), "hash mismatch", None);
    let id = state.pending.iter().next().unwrap().id;
    let (stdout, stderr, code) = run_client(&socket, &["grant-forever", &id.to_string()]);
    assert_eq!(code, 0, "grant-forever failed: {stderr}");
    assert!(stdout.contains("OK"), "grant-forever should print OK: {stdout}");
    let probe = state.attempt_read("existing.yaml", 555, Some("pkg_hash_x"), 0, 5);
    assert!(matches!(probe, fuse_server::ReadOutcome::Granted), "got: {probe:?}");
    let probe2 = state.attempt_read("existing.yaml", 556, Some("pkg_hash_x"), 0, 5);
    assert!(matches!(probe2, fuse_server::ReadOutcome::Granted), "unlimited reads: {probe2:?}");
    // A granted pending lingers until its (absent) reader removes it or
    // it expires — clean it up so the later pending assertions hold.
    state.remove_pending(id);

    // ── 8. Pending: should be empty ──
    let (stdout, _, _) = run_client(&socket, &["pending"]);
    assert!(stdout.contains("No pending"), "should have no pending: {stdout}");

    // ── 9. Log path ──
    let (stdout, _, _) = run_client(&socket, &["get-log-path"]);
    assert!(stdout.contains("Log path"), "should show log path: {stdout}");

    // ── 10. Remove non-existent → should fail ──
    let (stdout, stderr, code) = run_client(&socket, &["remove-secret", "nonexistent"]);
    assert_eq!(code, 1, "removing nonexistent should exit 1: {stdout} {stderr}");
    assert!(stderr.contains("not found") || stdout.contains("not found") || stderr.contains("Error"),
        "should report error for missing secret: {stdout} | {stderr}");
}

/// The remediation round trip: a pending born while hashd was down
/// carries no hash and an unreachable snapshot; after an operator
/// starts hashd (a stub here), grant-forever must retry the lookup
/// LIVE and succeed on the very same pending.
#[test]
fn grant_forever_retries_hashd_after_remediation() {
    let dir = test_tempdir();
    let socket = dir.path().join("remediation.sock");
    let hashd_sock = dir.path().join("hashd.sock");

    // No hashd yet: point the server at the (silent) socket path.
    std::env::set_var("FUSE_HASHD_SOCK", &hashd_sock);

    let state = Arc::new({
        let s = ServerState::new();
        s.add("netrc", "/tmp/host/netrc", 6, "wrong_hash");
        s
    });

    // A pending from a read that happened while hashd was down: no
    // hash, stale unreachable snapshot — exactly what the panel shows.
    state.create_pending_with_hash_error(
        "netrc",
        4242,
        None,
        Some("hashd unreachable — No such file or directory (os error 2). Start hashd now: ..."),
        "hash mismatch",
        None,
    );
    let id = state.pending.iter().next().unwrap().id;

    let sock = socket.clone();
    let st = Arc::clone(&state);
    let _server = std::thread::spawn(move || {
        let _ = run_socket_server(&sock, st);
    });
    wait_for_server(&socket);

    // Operator follows the printed fix: hashd comes up mid-pending.
    let stub = {
        use std::io::{BufRead as _, BufReader, Write as _};
        let listener = std::os::unix::net::UnixListener::bind(&hashd_sock).unwrap();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let Ok(clone) = conn.try_clone() else { continue };
                let mut reader = BufReader::new(clone);
                let mut stream = conn;
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let reply = if line.trim() == format!("hash {}", 4242) {
                    format!("ok {}\n", "c".repeat(64))
                } else {
                    "error gone test\n".to_string()
                };
                let _ = stream.write_all(reply.as_bytes());
                let _ = stream.flush();
            }
        })
    };

    let (stdout, stderr, code) = run_client(&socket, &["grant-forever", &id.to_string()]);
    assert_eq!(code, 0, "grant-forever after starting hashd failed: {stderr}");
    assert!(stdout.contains("OK"), "grant-forever should print OK: {stdout}");

    // The live-retried hash became the whitelisted package: unlimited reads.
    let probe = state.attempt_read("netrc", 555, Some(&"c".repeat(64)), 0, 6);
    assert!(matches!(probe, fuse_server::ReadOutcome::Granted), "got: {probe:?}");

    let _ = stub;
    std::env::remove_var("FUSE_HASHD_SOCK");
}

#[test]
fn restart_spares_processes_that_mention_fuse_server() {
    // BEHAVIOR: an innocent process whose command line merely mentions
    // "fuse-server" survives a real `fuse-client restart`. This is the
    // observed-live bug — `pkill -f fuse-server` matched any argv
    // containing the string, and a restart running under
    // `cargo test -p fuse-server` killed its own test runner —
    // reproduced here with a marked sleep and the REAL client binary,
    // blast radius contained: state file in a tempdir (ENV override),
    // server_binary /bin/true, mount and socket in the tempdir. With
    // the substring kill, the marked sleep dies and this fails.
    let dir = test_tempdir();
    let dead_socket = dir.path().join("dead.sock");

    // $0 carries the marker: the argv mentions "fuse-server" while the
    // process itself is an innocent sleep.
    let mut innocent = Command::new("sh")
        .arg("-c")
        .arg("sleep 60")
        .arg("fuse-server-in-argv-only")
        .spawn()
        .expect("spawn innocent");

    let mut bystander = fuse_server_named_bystander(dir.path());
    let (mut sacrificial, sacrificial_bin) = sacrificial_server_pid_as(dir.path(), "sacrificial-server");
    with_state_file_in(dir.path(), || {
        write_state_with_pid(dir.path(), &dead_socket, None, sacrificial.id(), &sacrificial_bin);
        // Bounded by the client's own 10s server wait.
        let _ = run_client(&dead_socket, &["restart"]);
    });
    let sacrificial_gone = sacrificial.try_wait().map(|w| w.is_some()).unwrap_or(false);
    let _ = sacrificial.kill();
    let _ = sacrificial.wait();
    assert!(
        sacrificial_gone,
        "the VERIFIED recorded pid was not stopped — the restart must still \
         kill exactly the server the state file names"
    );

    let alive = innocent.try_wait().map(|w| w.is_none()).unwrap_or(false);
    let _ = innocent.kill();
    let _ = innocent.wait();
    assert!(
        alive,
        "an innocent process whose argv merely mentions fuse-server was killed by restart"
    );
    let bystander_alive = bystander.try_wait().map(|w| w.is_none()).unwrap_or(false);
    let _ = bystander.kill();
    let _ = bystander.wait();
    assert!(
        bystander_alive,
        "a bystander process NAMED fuse-server was killed by restart — \
         the by-name sweep must not run when the state file names the pid"
    );
}

#[test]
fn restart_of_one_stack_spares_the_other_live_stack() {
    // #62's named behavioral test: two REAL policy stacks with
    // distinct cmd+oracle sockets; `fuse-client restart` against
    // stack A's state file; stack B must keep answering its cmd
    // socket throughout. A by-name sweep (the pre-#62 fallback)
    // kills B's server and B goes silent — this fails.
    let dir = test_tempdir();
    let a_cmd = dir.path().join("a-cmd.sock");
    let a_oracle = dir.path().join("a-oracle.sock");
    let b_cmd = dir.path().join("b-cmd.sock");
    let b_oracle = dir.path().join("b-oracle.sock");

    // Stack B: a real policy server we prove stays alive.
    let mut b_server = Command::new(env!("CARGO_BIN_EXE_fuse-server"))
        .arg("--socket").arg(&b_cmd)
        .arg("--oracle-socket").arg(&b_oracle)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn stack B");
    wait_for_server(&b_cmd);

    // Stack A's state file names a verifiable sacrificial "server".
    let (mut sacrificial, sacrificial_bin) =
        sacrificial_server_pid_as(dir.path(), "sacrificial-two-stack");
    let state = serde_json::json!({
        "version": VERSION,
        "server_pid": sacrificial.id(),
        "server_binary": sacrificial_bin,
        "mount_point": dir.path().join("a-mnt").to_string_lossy(),
        "socket": a_cmd.to_string_lossy(),
        "log_level": "info",
        "pending_timeout": 300,
        "runtime_wrapper": null,
        "oracle_socket": a_oracle.to_string_lossy(),
        "secrets": [],
    });
    std::fs::create_dir_all(dir.path().join("a-mnt")).unwrap();
    std::fs::write(dir.path().join("state.json"), state.to_string()).unwrap();

    let spawned_pid = with_state_file_in(dir.path(), || {
        let (stdout, _stderr, _code) = run_client(&a_cmd, &["restart"]);
        stdout
            .lines()
            .find_map(|l| l.trim().strip_prefix("Spawned pid ").and_then(|p| p.parse::<i32>().ok()))
    });

    // THE assertion: stack B still answers — its server was never touched.
    assert!(
        UnixStream::connect(&b_cmd).is_ok(),
        "stack B's server was killed by a restart of stack A — the kill is not stack-scoped"
    );
    assert!(
        b_server.try_wait().map(|w| w.is_none()).unwrap_or(false),
        "stack B's server process died"
    );

    if let Some(pid) = spawned_pid {
        let _ = Command::new("kill").arg(pid.to_string()).output();
    }
    let _ = b_server.kill();
    let _ = b_server.wait();
    let _ = sacrificial.kill();
    let _ = sacrificial.wait();
}

#[test]
fn restart_respawns_on_the_state_files_oracle_rendezvous() {
    // BEHAVIOR: a stack recorded with an oracle override comes back on
    // THAT rendezvous — the surviving data daemon retries its socket
    // forever, so a respawn on the global default leaves an alive
    // mount that never syncs again (#59 review finding). Real client,
    // real fuse-server (policy-only: no --mount-point, so no fused and
    // no mount is needed), rendezvous asserted by CONNECTING to it.
    // With the rendezvous dropped from the respawn argv, the oracle
    // socket never listens and this fails.
    let dir = test_tempdir();
    let cmd_sock = dir.path().join("cmd.sock");
    let oracle_sock = dir.path().join("oracle.sock");

    // The recorded pid is a sacrificial sleep (its cmdline will NOT
    // match the recorded binary, so the guard routes to the harmless
    // socket-scoped branch); the RESPAWN target is the real server,
    // which must come back on the custom oracle rendezvous.
    let (mut sacrificial, _sacrificial_bin) =
        sacrificial_server_pid_as(dir.path(), "sacrificial-oracle");
    let state = serde_json::json!({
        "version": VERSION,
        "server_pid": sacrificial.id(),
        "server_binary": env!("CARGO_BIN_EXE_fuse-server"),
        "mount_point": dir.path().join("mnt").to_string_lossy(),
        "socket": cmd_sock.to_string_lossy(),
        "log_level": "info",
        "pending_timeout": 300,
        "runtime_wrapper": null,
        "oracle_socket": oracle_sock.to_string_lossy(),
        "secrets": [],
    });
    std::fs::create_dir_all(dir.path().join("mnt")).unwrap();
    std::fs::write(dir.path().join("state.json"), state.to_string()).unwrap();

    let spawned_pid = with_state_file_in(dir.path(), || {
        let (stdout, stderr, code) = run_client(&cmd_sock, &["restart"]);
        assert_eq!(
            code, 0,
            "restart failed: {stderr}\n{stdout}\n(state: {})",
            std::fs::read_to_string(dir.path().join("state.json")).unwrap_or_default()
        );
        // The whole assertion: the respawned server answers on the
        // CUSTOM oracle rendezvous — where the surviving fused connects.
        wait_for_socket(&oracle_sock, "the respawned policy daemon");
        // And the client told us which pid it spawned — that, and only
        // that, is what the cleanup below may kill.
        stdout
            .lines()
            .find_map(|l| l.trim().strip_prefix("Spawned pid ").and_then(|p| p.parse::<i32>().ok()))
    });

    if let Some(pid) = spawned_pid {
        let _ = Command::new("kill").arg(pid.to_string()).output();
    }
    let _ = sacrificial.kill();
    let _ = sacrificial.wait();
}

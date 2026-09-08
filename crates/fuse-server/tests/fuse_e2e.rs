//! End-to-end integration tests that actually mount a `GatekeeperFs` FUSE
//! filesystem and perform real file I/O through the kernel.
//!
//! These tests require `/dev/fuse`.  They are automatically skipped when
//! `/dev/fuse` is not available (e.g., inside a container without FUSE
//! support).  Run with:
//!
//! ```sh
//! cargo test -p fuse-server --test fuse_e2e -- --include-ignored
//! ```
//!
//! Two constraints discovered while validating on a real /dev/fuse
//! system (2026-09):
//! * Tests run **serially** (see `SERIAL`): parallel mounts in one
//!   process corrupt each other's fusermount3 fd passing.
//! * Unauthorized reads (wrong hash, second read) **pend** awaiting an
//!   interactive grant; denial arrives as EACCES only when the pending
//!   timeout expires.  Tests set a 1s timeout instead of the 300s
//!   default.

use std::sync::{Arc, Mutex, MutexGuard};

use fuse_protocol::{RealSystemIo, SystemIo};
use fuse_server::{run_socket_server, GatekeeperFs, ServerState};
use fuser::{BackgroundSession, MountOption};

// ── helpers ────────────────────────────────────────────────────

/// FUSE sessions must not mount/unmount in parallel within one process:
/// concurrent fusermount3 fd-passing corrupts sessions (observed as
/// "file descriptor N is not a socket" plus cross-test failures).
/// Every test holds this guard from before mount until after unmount.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn fuse_available() -> bool {
    std::path::Path::new("/dev/fuse").exists()
}

/// Can this context compute package hashes at all? Following
/// /proc/<pid>/map_files (even of ITSELF) requires CAP_SYS_ADMIN or
/// CAP_CHECKPOINT_RESTORE in the initial user namespace; without it,
/// every hash-configured test degrades to a loud skip instead of a
/// vacuous red.
fn hashing_available() -> bool {
    let range = std::fs::read_to_string("/proc/self/maps")
        .ok()
        .and_then(|maps| {
            maps.lines()
                .find(|l| l.contains('/'))
                .and_then(|l| l.split_whitespace().next().map(str::to_string))
        });
    let Some(range) = range else {
        return false;
    };
    let ok = std::fs::read(format!("/proc/self/map_files/{range}")).is_ok();
    if !ok {
        eprintln!(
            "skip: this context cannot follow /proc/self/map_files \
             (needs CAP_SYS_ADMIN/CAP_CHECKPOINT_RESTORE in the initial \
             user namespace) — hash-configured FUSE e2e tests skip loudly"
        );
    }
    ok
}

/// SHA-256 of the test binary's whole loaded package (exe + libraries) —
/// this is what the FUSE daemon computes for `req.pid()` when the test
/// process reads a file (issue #11: trust the whole package).
/// `None` = hashing unavailable here (loud skip by the caller).
fn current_package_hash() -> Option<String> {
    if !hashing_available() {
        return None;
    }
    let io = RealSystemIo::new();
    io.sha256_process_package(std::process::id())
        .map(Some)
        .expect("failed to hash test package")
}

fn make_state(secrets: &[(&str, &[u8], &str)]) -> Arc<ServerState> {
    let state = ServerState::new();
    for (name, content, hash) in secrets {
        state.add(*name, content.to_vec(), *hash);
    }
    Arc::new(state)
}

fn mount_fs(
    state: Arc<ServerState>,
    mount_point: &std::path::Path,
) -> BackgroundSession {
    let fs = GatekeeperFs::new(state, RealSystemIo::new());
    let options = vec![MountOption::FSName("gatekeeper-test".into())];
    fuser::spawn_mount2(fs, mount_point, &options)
        .expect("failed to mount FUSE filesystem")
}

// ── basic read ─────────────────────────────────────────────────

#[test]
fn e2e_read_secret() {
    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let Some(hash) = current_package_hash() else { return };
    let state = make_state(&[("secret", b"TOPSECRET", &hash)]);
    let _session = mount_fs(state, dir.path());

    let data = std::fs::read(dir.path().join("secret")).unwrap();
    assert_eq!(data, b"TOPSECRET");
}

// ── statfs (fails on unfixed code: ENOSYS) ─────────────────────

#[test]
fn e2e_statfs_works() {
    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let Some(hash) = current_package_hash() else { return };
    let state = make_state(&[("s", b"data", &hash)]);
    let _session = mount_fs(state, dir.path());

    // stat -f calls statfs; without the fix the default returns ENOSYS.
    let output = std::process::Command::new("stat")
        .args(["-f", "-c", "%T", &dir.path().to_string_lossy()])
        .output()
        .expect("failed to run stat");

    assert!(
        output.status.success(),
        "stat -f failed (missing statfs impl?): {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let fs_type = String::from_utf8_lossy(&output.stdout);
    assert!(
        fs_type.trim() != "UNKNOWN (0xffffffff)",
        "statfs returned garbage type: {fs_type}"
    );
}

// ── multi-chunk read (the bug fix) ─────────────────────────────

#[test]
fn e2e_multi_chunk_read_succeeds() {
    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let Some(hash) = current_package_hash() else { return };
    let secret = b"THIS_IS_A_LONGER_SECRET_VALUE_FOR_MULTI_CHUNK_READ_TEST!!!";
    let state = make_state(&[("s", secret, &hash)]);
    let _session = mount_fs(state, dir.path());

    // Read using a 4-byte buffer — forces the kernel to issue multiple
    // FUSE read requests.  Without the multi-chunk fix, the second read
    // would fail with EACCES.
    use std::io::Read;
    let mut file = std::fs::File::open(dir.path().join("s")).unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => panic!("multi-chunk read failed: {e}"),
        }
    }
    assert_eq!(buf, secret);
}

// ── different binary denied ────────────────────────────────────

#[test]
fn e2e_different_binary_denied() {
    // `cat`'s read pends (wrong binary); with a 1s pending timeout it is
    // denied and cat exits nonzero shortly after.

    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let Some(hash) = current_package_hash() else { return };
    let state = make_state(&[("s", b"DATA", &hash)]);
    *state.pending_timeout.lock().unwrap() = std::time::Duration::from_secs(1);
    let _session = mount_fs(state, dir.path());

    // `cat` has a different SHA-256 than the test binary, so the
    // gatekeeper denies the read.
    let output = std::process::Command::new("cat")
        .arg(dir.path().join("s"))
        .output()
        .expect("failed to run cat");

    assert!(
        !output.status.success(),
        "cat should be denied (wrong binary hash), but succeeded"
    );
}

// ── hash mismatch ──────────────────────────────────────────────

#[test]
fn e2e_hash_mismatch_denied() {
    // Wrong hash no longer fails instantly: the read pends awaiting an
    // interactive grant and turns into EACCES when the (short, for
    // tests) timeout expires.

    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let state = make_state(&[("s", b"DATA", "wrong_hash_value")]);
    *state.pending_timeout.lock().unwrap() = std::time::Duration::from_secs(1);
    let _session = mount_fs(state, dir.path());

    let result = std::fs::read(dir.path().join("s"));
    assert!(result.is_err(), "read should fail with wrong hash");
    let err = result.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EACCES),
        "expected EACCES for hash mismatch, got: {err}"
    );
}

// ── readdir ────────────────────────────────────────────────────

#[test]
fn e2e_readdir_lists_secrets() {
    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let Some(hash) = current_package_hash() else { return };
    let state = make_state(&[
        ("alpha", b"A", &hash),
        ("beta", b"BB", &hash),
    ]);
    let _session = mount_fs(state, dir.path());

    let entries: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();

    assert!(entries.contains(&"alpha".to_string()), "missing alpha: {entries:?}");
    assert!(entries.contains(&"beta".to_string()), "missing beta: {entries:?}");
}

// ── getattr (stat) ─────────────────────────────────────────────

#[test]
fn e2e_getattr_reports_size() {
    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let Some(hash) = current_package_hash() else { return };
    let state = make_state(&[("s", b"1234567890", &hash)]);
    let _session = mount_fs(state, dir.path());

    let meta = std::fs::metadata(dir.path().join("s")).unwrap();
    assert_eq!(meta.len(), 10);
    assert!(meta.permissions().readonly());
}

// ── nonexistent file ───────────────────────────────────────────

#[test]
fn e2e_nonexistent_file_enoent() {
    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let state = make_state(&[]);
    let _session = mount_fs(state, dir.path());

    let result = std::fs::read(dir.path().join("ghost"));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOENT),
        "expected ENOENT, got: {err}"
    );
}

// ── dynamic add after mount ────────────────────────────────────

#[test]
fn e2e_dynamic_add_visible() {
    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let Some(hash) = current_package_hash() else { return };
    let state = make_state(&[]);
    let state_handle = std::sync::Arc::clone(&state);
    let _session = mount_fs(state, dir.path());

    // Add a secret AFTER the filesystem is mounted.
    state_handle.add("dynamic", b"ADDED_LATER".to_vec(), &hash);

    // With TTL=0 the kernel always re-validates, so the new file is
    // immediately visible.
    let data = std::fs::read(dir.path().join("dynamic")).unwrap();
    assert_eq!(data, b"ADDED_LATER");
}

// ── reset allows re-read ───────────────────────────────────────

#[test]
fn e2e_reset_allows_reread() {
    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let Some(hash) = current_package_hash() else { return };
    let state = make_state(&[("s", b"DATA", &hash)]);
    *state.pending_timeout.lock().unwrap() = std::time::Duration::from_secs(1);
    let state_handle = std::sync::Arc::clone(&state);
    let _session = mount_fs(state, dir.path());

    // First read succeeds.
    let _ = std::fs::read(dir.path().join("s")).unwrap();

    // Second read pends, then is denied when the timeout expires.
    let err = std::fs::read(dir.path().join("s")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));

    // Reset via shared state.
    state_handle.reset(Some("s"));

    // Third read succeeds again.
    let data = std::fs::read(dir.path().join("s")).unwrap();
    assert_eq!(data, b"DATA");
}

// ── multiple secrets independent reads ─────────────────────────

#[test]
fn e2e_multiple_secrets_independent() {
    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let Some(hash) = current_package_hash() else { return };
    let state = make_state(&[
        ("a", b"AAA", &hash),
        ("b", b"BBB", &hash),
    ]);
    let _session = mount_fs(state, dir.path());

    let a = std::fs::read(dir.path().join("a")).unwrap();
    assert_eq!(a, b"AAA");

    // Reading 'a' doesn't affect 'b'.
    let b = std::fs::read(dir.path().join("b")).unwrap();
    assert_eq!(b, b"BBB");
}

// ── symlink to fuse file ───────────────────────────────────────

#[test]
fn e2e_symlink_to_fuse_file() {
    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let mount = tempfile::tempdir().unwrap();
    let staging = tempfile::tempdir().unwrap();
    let Some(hash) = current_package_hash() else { return };
    let state = make_state(&[("key", b"SECRET_KEY_DATA", &hash)]);
    let _session = mount_fs(state, mount.path());

    // Create a symlink in a separate directory pointing into the FUSE mount.
    let link = staging.path().join("key_link");
    std::os::unix::fs::symlink(mount.path().join("key"), &link).unwrap();

    let data = std::fs::read(&link).unwrap();
    assert_eq!(data, b"SECRET_KEY_DATA");
}

// ── root directory is a directory ──────────────────────────────

#[test]
fn e2e_root_is_directory() {
    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let Some(hash) = current_package_hash() else { return };
    let state = make_state(&[("s", b"x", &hash)]);
    let _session = mount_fs(state, dir.path());

    let meta = std::fs::metadata(dir.path()).unwrap();
    assert!(meta.is_dir());
}

// ── concurrent reads: pending doesn't block other operations ───

#[test]
fn e2e_pending_does_not_block_other_reads() {
    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let Some(_hash) = current_package_hash() else { return };
    let state = make_state(&[
        // "blocked" has a wrong hash → read triggers pending
        ("blocked", b"BLOCKED_DATA", "wrong_hash"),
        // "open" has wildcard hash → read succeeds immediately
        ("open", b"OPEN_DATA", "*"),
    ]);
    *state.pending_timeout.lock().unwrap() = std::time::Duration::from_secs(10);
    let _session = mount_fs(state.clone(), dir.path());

    // Spawn a thread that reads "blocked" — this will be pending (hash mismatch).
    // The thread blocks because the FUSE read waits for a grant.
    let blocked_path = dir.path().join("blocked");
    let blocked_thread = std::thread::spawn(move || {
        // This read blocks (pending) until grant or timeout
        std::fs::read(&blocked_path)
    });

    // Wait (bounded) until the blocked read actually registers a pending
    // request.  Registration is load-dependent: the server's read worker
    // hashes the reader's /proc/<pid>/exe first, so a fixed sleep races.
    let reg_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while state.pending.is_empty() && std::time::Instant::now() < reg_deadline {
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(
        !state.pending.is_empty(),
        "the blocked read must have registered a pending request"
    );

    // While "blocked" is pending, read "open" — this should succeed
    // immediately, proving the FUSE session is still responsive.
    let start = std::time::Instant::now();
    let open_data = std::fs::read(dir.path().join("open")).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(open_data, b"OPEN_DATA");
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "reading 'open' while 'blocked' is pending took {elapsed:?} — \
         FUSE session may be blocked"
    );

    // Grant the pending read so the blocked thread can finish
    let id = state.pending.iter().next().map(|p| p.id);
    if let Some(id) = id {
        state.grant_pending(id);
    }

    // Wait for the blocked thread to complete
    let blocked_result = blocked_thread.join().unwrap();
    // It may succeed (if grant arrived in time) or fail (EACCES on timeout)
    // — either way, the important thing is that "open" succeeded while it was pending.
    let _ = blocked_result;
}

// ── mode passthrough: source file bits appear (write-masked) ────

#[test]
fn e2e_source_mode_is_passed_through() {
    if !fuse_available() {
        return;
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let Some(hash) = current_package_hash() else { return };
    let state = ServerState::new();
    // 0600 on the source → presented as 0400 (write bits masked).
    state.add_with_mode("key", b"MODEDATA".to_vec(), &hash, 0o600);
    // 0644 on the source → presented as 0444.
    state.add_with_mode("pub", b"MODEDATA2".to_vec(), &hash, 0o644);
    let _session = mount_fs(Arc::new(state), dir.path());

    use std::os::unix::fs::PermissionsExt;
    let key = std::fs::metadata(dir.path().join("key")).unwrap();
    assert_eq!(key.permissions().mode() & 0o777, 0o400);
    let pubm = std::fs::metadata(dir.path().join("pub")).unwrap();
    assert_eq!(pubm.permissions().mode() & 0o777, 0o444);
}

// ── whole-package trust: LD_PRELOAD changes the hash (issue #11) ──

#[test]
fn e2e_ld_preload_changes_package_hash_and_is_denied() {
    if !fuse_available() {
        return;
    }
    if !hashing_available() {
        return; // the whole point is computing package hashes
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    // Artifacts must live OUTSIDE the mount dir: mount_fs overlays it
    // and would shadow anything compiled inside.
    let art = tempfile::tempdir().unwrap();

    // Compile a tiny dummy library to inject via LD_PRELOAD.
    let so = art.path().join("dummy.so");
    let src = art.path().join("dummy.c");
    std::fs::write(&src, "int agent_dummy = 1;\n").unwrap();
    let out = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(&src)
        .output()
        .expect("compile dummy .so");
    assert!(out.status.success(), "dummy .so build failed");

    // Measure the package hash of an unpolluted `cat` while it lives.
    // Poll until stable: hashing while the dynamic loader is still
    // mapping libraries would capture an incomplete package.
    let mut plain = std::process::Command::new("cat")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("spawn cat");
    let io = RealSystemIo::new();
    let mut cat_hash = io
        .sha256_process_package(plain.id())
        .expect("hash cat package");
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let again = io
            .sha256_process_package(plain.id())
            .expect("re-hash cat package");
        if again == cat_hash {
            break;
        }
        cat_hash = again;
    }
    plain.kill().unwrap();
    let _ = plain.wait();

    let state = make_state(&[("s", b"CATSECRET", &cat_hash)]);
    *state.pending_timeout.lock().unwrap() = std::time::Duration::from_secs(1);
    let _session = mount_fs(state.clone(), dir.path());

    // Positive control: a plain cat read is granted.
    let ok = std::process::Command::new("cat")
        .arg(dir.path().join("s"))
        .output()
        .expect("run plain cat");
    assert!(ok.status.success(), "plain cat should read: {ok:?}");
    assert_eq!(ok.stdout, b"CATSECRET");

    // Reset the one-read budget, then read with the injected library:
    // the package hash differs, so the read pends and is denied.
    state.reset(Some("s"));
    let bad = std::process::Command::new("cat")
        .arg(dir.path().join("s"))
        .env("LD_PRELOAD", &so)
        .output()
        .expect("run preloaded cat");
    assert!(
        !bad.status.success(),
        "LD_PRELOAD-injected read must be denied: {bad:?}"
    );
}

// ── grant-forever, full stack: FUSE + socket + real client (#11) ──

#[test]
fn e2e_grant_forever_full_flow() {
    if !fuse_available() {
        return;
    }
    if !hashing_available() {
        return; // grant-forever needs an observable package hash
    }
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    // The socket must live OUTSIDE the mount dir: the FUSE mount
    // shadows everything beneath it, and connect-by-path would ENOENT
    // even with a perfectly healthy listener.
    let aux = tempfile::tempdir().unwrap();
    let socket = aux.path().join("gf.sock");

    // The secret's allowed hash deliberately does not match the test
    // binary: every read pends until grant-forever whitelists it.
    let state = Arc::new(ServerState::new());
    state.add("s", b"FOREVER_SECRET".to_vec(), "not_our_hash");
    *state.pending_timeout.lock().unwrap() = std::time::Duration::from_secs(30);

    // Real socket server sharing the same state.
    let st = Arc::clone(&state);
    let sock = socket.clone();
    let _server = std::thread::spawn(move || {
        let _ = run_socket_server(&sock, st);
    });
    // Readiness probe speaks the real protocol: a bare connect+EOF
    // leaves the acceptor wedged on the half-open conversation.
    let mut ready = false;
    for _ in 0..300 {
        if fuse_protocol::run_command_once(&socket, "version", &fuse_protocol::Command::GetVersion).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(ready, "socket server never became ready");

    let _session = mount_fs(Arc::clone(&state), dir.path());

    // A reader blocks in pending (wrong hash).
    let path = dir.path().join("s");
    let reader = std::thread::spawn(move || std::fs::read(&path));

    // Wait (bounded) for the pending registration.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while state.pending.is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(!state.pending.is_empty(), "read must pend");

    // Grant forever through the REAL fuse-client binary.
    let id = state.pending.iter().next().unwrap().id;
    let out = std::process::Command::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/fuse-client"))
        .arg("--socket").arg(&socket)
        .args(["grant-forever", &id.to_string()])
        .output()
        .expect("run fuse-client");
    assert!(
        out.status.success(),
        "grant-forever failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // The blocked reader is served by the grant.
    let data = reader.join().unwrap().expect("blocked read served after grant-forever");
    assert_eq!(data, b"FOREVER_SECRET");

    // Unlimited: repeated reads by the SAME package need no further
    // approval and no resets.
    for _ in 0..3 {
        let again = std::fs::read(dir.path().join("s"))
            .expect("re-read must be granted without approval");
        assert_eq!(again, b"FOREVER_SECRET");
    }

    // And the secret reports the whitelisted hash + unlimited.
    let status = state.status();
    assert!(status.iter().any(|s| s.unlimited), "status must show unlimited: {status:?}");
}

// ── package hashing survives deleted-but-mapped libraries ───────

#[test]
fn e2e_package_hash_works_with_deleted_mapped_library() {
    if !fuse_available() {
        return;
    }
    if !hashing_available() {
        return; // hashes a live child's deleted mapping
    }
    let _serial = serial();
    let art = tempfile::tempdir().unwrap();

    // A dummy library, LD_PRELOADed into a live cat, then deleted from
    // disk: the mapping survives, the on-disk path is gone.  This is
    // the exact shape that made the whole package hash fail (None) on
    // a real host, leaving grant-forever with nothing to whitelist.
    let so = art.path().join("gone.so");
    let src = art.path().join("gone.c");
    std::fs::write(&src, "int agent_gone = 1;\n").unwrap();
    let out = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(&src)
        .output()
        .expect("compile gone.so");
    assert!(out.status.success());

    let mut child = std::process::Command::new("cat")
        .stdin(std::process::Stdio::piped())
        .env("LD_PRELOAD", &so)
        .spawn()
        .expect("spawn preloaded cat");
    std::fs::remove_file(&so).expect("delete the mapped library");
    std::thread::sleep(std::time::Duration::from_millis(200));

    let io = RealSystemIo::new();
    let h = io
        .sha256_process_package(child.id())
        .expect("package hash must succeed despite the deleted mapping");
    assert_eq!(h.len(), 64, "a real SHA-256 hex digest");

    child.kill().unwrap();
    let _ = child.wait();
}

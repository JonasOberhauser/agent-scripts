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
//! On a system with `/dev/fuse`, all tests should run and pass.

use std::sync::{Arc, Mutex};

use fuse_protocol::{RealSystemIo, SystemIo};
use fuse_server::{GatekeeperFs, ServerState};
use fuser::{BackgroundSession, MountOption};

// ── helpers ────────────────────────────────────────────────────

fn fuse_available() -> bool {
    std::path::Path::new("/dev/fuse").exists()
}

/// SHA-256 of the test binary itself — this is what the FUSE daemon will
/// compute for `req.pid()` when the test process reads a file.
fn current_exe_hash() -> String {
    let io = RealSystemIo::new();
    io.sha256_process_exe(std::process::id())
        .expect("failed to hash test binary")
}

fn make_state(secrets: &[(&str, &[u8], &str)]) -> Arc<Mutex<ServerState>> {
    let mut state = ServerState::new();
    for (name, content, hash) in secrets {
        state.add(*name, content.to_vec(), *hash);
    }
    Arc::new(Mutex::new(state))
}

fn mount_fs(
    state: Arc<Mutex<ServerState>>,
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
    let dir = tempfile::tempdir().unwrap();
    let hash = current_exe_hash();
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
    let dir = tempfile::tempdir().unwrap();
    let hash = current_exe_hash();
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
    let dir = tempfile::tempdir().unwrap();
    let hash = current_exe_hash();
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
    if !fuse_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let hash = current_exe_hash();
    let state = make_state(&[("s", b"DATA", &hash)]);
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
    if !fuse_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let state = make_state(&[("s", b"DATA", "wrong_hash_value")]);
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
    let dir = tempfile::tempdir().unwrap();
    let hash = current_exe_hash();
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
    let dir = tempfile::tempdir().unwrap();
    let hash = current_exe_hash();
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
    let dir = tempfile::tempdir().unwrap();
    let hash = current_exe_hash();
    let state = make_state(&[]);
    let state_handle = Arc::clone(&state);
    let _session = mount_fs(state, dir.path());

    // Add a secret AFTER the filesystem is mounted.
    state_handle
        .lock()
        .unwrap()
        .add("dynamic", b"ADDED_LATER".to_vec(), &hash);

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
    let dir = tempfile::tempdir().unwrap();
    let hash = current_exe_hash();
    let state = make_state(&[("s", b"DATA", &hash)]);
    let state_handle = Arc::clone(&state);
    let _session = mount_fs(state, dir.path());

    // First read succeeds.
    let _ = std::fs::read(dir.path().join("s")).unwrap();

    // Second read denied.
    let err = std::fs::read(dir.path().join("s")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));

    // Reset via shared state.
    state_handle.lock().unwrap().reset(Some("s"));

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
    let dir = tempfile::tempdir().unwrap();
    let hash = current_exe_hash();
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
    let mount = tempfile::tempdir().unwrap();
    let staging = tempfile::tempdir().unwrap();
    let hash = current_exe_hash();
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
    let dir = tempfile::tempdir().unwrap();
    let hash = current_exe_hash();
    let state = make_state(&[("s", b"x", &hash)]);
    let _session = mount_fs(state, dir.path());

    let meta = std::fs::metadata(dir.path()).unwrap();
    assert!(meta.is_dir());
}

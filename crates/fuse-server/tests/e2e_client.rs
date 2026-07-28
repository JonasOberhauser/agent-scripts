//! End-to-end test: real fuse-server socket server + real fuse-client binary.
//!
//! No /dev/fuse needed — the socket server runs independently from the FUSE mount.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use fuse_protocol::VERSION;
use fuse_server::{run_socket_server, ServerState};

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

fn wait_for_server(socket: &Path) {
    for _ in 0..200 {
        if socket.exists() {
            if std::os::unix::net::UnixStream::connect(socket).is_ok() {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("Server did not start at {}", socket.display());
}

#[test]
fn e2e_client_binary_against_server() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("e2e.sock");

    // Start socket server with one pre-loaded secret
    let state = Arc::new({
        let s = ServerState::new();
        s.add("existing.yaml", b"DATA1".to_vec(), "hash1");
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
    assert_eq!(code, 0, "status failed: {stderr}");
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
    assert!(stdout.contains("OK"), "add-secret should print OK: {stdout}");

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

//! Oracle service tests: the policy daemon's adjudication endpoint,
//! exercised over real unix sockets — allow/deny/pending-grant/expiry,
//! content forwarding to (fake) data daemons, and snapshot replay for
//! late joiners.

use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::time::Duration;

use fuse_protocol::oracle::{OracleCommand, OracleReply, OracleRequest};

use fuse_server::oracle_service::{run_oracle_server, OracleHub};
use fuse_server::{ReadOutcome, ServerState};

fn oracle_env() -> (std::path::PathBuf, Arc<ServerState>, std::thread::JoinHandle<()>) {
    // keep()d for the test's lifetime (unique per test; tmp litter only)
    let dir = tempfile::tempdir().unwrap().keep();
    let path = dir.join("oracle.sock");
    let state = Arc::new(ServerState::new());
    *state.pending_timeout.lock().unwrap() = Duration::from_secs(2);
    let s2 = Arc::clone(&state);
    let hub = OracleHub::new();
    let (moved, wait_path) = (path.clone(), path.clone());
    let t = std::thread::spawn(move || run_oracle_server(&moved, s2, hub).unwrap());
    // wait for listener
    for _ in 0..200 {
        if wait_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    (path, state, t)
}

fn ask(path: &std::path::Path, name: &str, pid: u32, offset: u64, size: u32) -> OracleReply {
    let mut conn = std::os::unix::net::UnixStream::connect(path).unwrap();
    let req = serde_json::to_string(&OracleRequest::Ask { name: name.into(), pid, offset, size }).unwrap();
    conn.write_all(format!("{req}\n").as_bytes()).unwrap();
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(line.trim()).unwrap()
}

#[test]
fn star_hash_ask_is_allowed_and_serves_offsets() {
    let (path, state, _t) = oracle_env();
    state.add("s", b"0123456789".to_vec(), "*");
    assert_eq!(ask(&path, "s", 10, 2, 3), OracleReply::Allow);
    assert_eq!(state.status()[0].access_count, 1, "allow records the read");
}

#[test]
fn unknown_secret_denies_enoent() {
    let (path, _state, _t) = oracle_env();
    match ask(&path, "nope", 1, 0, 4) {
        OracleReply::Deny { errno, .. } => assert_eq!(errno, libc::ENOENT),
        other => panic!("expected ENOENT deny, got {other:?}"),
    }
}

#[test]
fn second_pid_pends_then_grant_allows() {
    let (path, state, _t) = oracle_env();
    state.add("s", b"SECRETSECRET".to_vec(), "*");
    assert_eq!(ask(&path, "s", 10, 0, 6), OracleReply::Allow);
    // The same pid streaming FORWARD: allowed (multi-chunk read).
    assert_eq!(ask(&path, "s", 10, 6, 6), OracleReply::Allow);
    // A different pid after the budget is spent: pends (blocks!) — run
    // it on a thread, grant via state, and expect Allow.
    let p = path.clone();
    let asker = std::thread::spawn(move || ask(&p, "s", 20, 0, 6));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let id = loop {
        let Some(entry) = state.pending.iter().next() else {
            assert!(std::time::Instant::now() < deadline, "pending never appeared");
            std::thread::sleep(Duration::from_millis(10));
            continue;
        };
        break entry.id;
    };
    assert!(state.grant_pending(id));
    assert_eq!(asker.join().unwrap(), OracleReply::Allow);
}

#[test]
fn pending_expiry_denies_with_eacces() {
    let (path, state, _t) = oracle_env();
    *state.pending_timeout.lock().unwrap() = Duration::from_millis(300);
    state.add("s", b"X".to_vec(), "*");
    assert_eq!(ask(&path, "s", 10, 0, 1), OracleReply::Allow);
    match ask(&path, "s", 20, 0, 1) {
        OracleReply::Deny { errno, reason } => {
            assert_eq!(errno, libc::EACCES);
            assert!(reason.contains("expired") || reason.contains("denied"), "{reason}");
        }
        other => panic!("expected EACCES deny after expiry, got {other:?}"),
    }
}

/// A deny must unblock the waiting reader IMMEDIATELY with EPERM —
/// regression test: the wait loop used to ignore the pending's removal
/// and kept the reader stuck until the full pending timeout.
#[test]
fn deny_unblocks_the_reader_immediately_with_eperm() {
    let (path, state, _t) = oracle_env();
    state.add("s", b"X".to_vec(), "some_hash");
    // Long enough that a non-short-circuiting loop fails the time bound.
    *state.pending_timeout.lock().unwrap() = Duration::from_secs(15);
    let p = path.clone();
    let started = std::time::Instant::now();
    let asker = std::thread::spawn(move || ask(&p, "s", 30, 0, 1));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let id = loop {
        let Some(entry) = state.pending.iter().next() else {
            assert!(std::time::Instant::now() < deadline, "pending never appeared");
            std::thread::sleep(Duration::from_millis(10));
            continue;
        };
        break entry.id;
    };
    state.deny_pending(id);
    match asker.join().unwrap() {
        OracleReply::Deny { errno, reason } => {
            assert_eq!(errno, libc::EPERM, "deny must EPERM, reason was: {reason}");
            assert!(reason.contains("denied"), "{reason}");
        }
        other => panic!("expected EPERM deny after explicit deny, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "deny must unblock immediately, waited {:.1}s",
        started.elapsed().as_secs_f32()
    );
}

#[test]
fn wrong_hash_pends_and_carries_the_hash_error() {
    let (path, state, _t) = oracle_env();
    state.add("s", b"X".to_vec(), "some_hash");
    // The ask blocks while the pending waits: run it on a thread so the
    // pending entry can be inspected before it expires.
    let p = path.clone();
    let asker = std::thread::spawn(move || ask(&p, "s", 30, 0, 1));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let (pid_hash, hash_error) = loop {
        let Some(entry) = state.pending.iter().next() else {
            assert!(std::time::Instant::now() < deadline, "pending never appeared");
            std::thread::sleep(Duration::from_millis(10));
            continue;
        };
        break (entry.pid_hash.clone(), entry.hash_error.clone());
    };
    // Hashing goes through hashd only. Either a hashd answered (it is
    // installed and this context is hashable) — or the pending carries
    // a runnable command that starts one.
    if pid_hash.is_none() {
        let why = hash_error.as_deref().unwrap_or("");
        assert!(
            why.contains("(Re)start hashd now"),
            "hash failure must name the fix, got: {why:?}"
        );
        assert!(
            why.contains("systemd-run"),
            "hash failure must embed a runnable start command, got: {why:?}"
        );
    } else {
        assert!(hash_error.is_none(), "hash present: no error expected");
    }
    let _ = ReadOutcome::Granted; // import witness
    let _ = asker.join().unwrap();
}

/// A fake data daemon: hello + receive commands; verifies snapshot
/// replay for late joiners and live pushes on add/remove.
#[test]
fn control_channel_replays_snapshot_and_pushes_updates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oracle.sock");
    let state = Arc::new(ServerState::new());
    *state.pending_timeout.lock().unwrap() = Duration::from_secs(2);
    let hub = OracleHub::new();
    hub.upsert("seed", b"OLD", 0o400);
    let s2 = Arc::clone(&state);
    let hub2 = hub.clone();
    let moved = path.clone();
    std::thread::spawn(move || run_oracle_server(&moved, s2, hub2).unwrap());
    for _ in 0..200 {
        if path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Late-joining data daemon must receive the seed via the snapshot.
    let mut conn = std::os::unix::net::UnixStream::connect(&path).unwrap();
    conn.write_all(format!("{}\n", serde_json::to_string(&OracleRequest::Hello).unwrap()).as_bytes()).unwrap();
    let mut reader = BufReader::new(conn.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap(); // Ok ack
    line.clear();
    reader.read_line(&mut line).unwrap();
    let cmd: OracleCommand = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(
        cmd,
        OracleCommand::Upsert { name: "seed".into(), content: b"OLD".to_vec(), mode: 0o400 }
    );

    // Live push through the hub.
    hub.upsert("seed", b"NEW", 0o600);
    line.clear();
    reader.read_line(&mut line).unwrap();
    let cmd: OracleCommand = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(cmd, OracleCommand::Upsert { name: "seed".into(), content: b"NEW".to_vec(), mode: 0o600 });
}

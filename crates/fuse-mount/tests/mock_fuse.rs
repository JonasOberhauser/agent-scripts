//! E2E WITHOUT /dev/fuse: the REAL fused binary process against a
//! REAL oracle (in-process policy daemon over the true wire protocol)
//! — only the kernel end of the FUSE channel is the mock fuser
//! (`--mock-fuse`). This is the tier that runs everywhere: CI
//! containers, the authoring sandbox, fuzz hosts.
//!
//! The stack under test, in full: fused's control loop receiving
//! Serve from the oracle hub, LOOKUP's live-stat identity minting,
//! OPEN's MR4 adjudication (the policy daemon answers with a host fd
//! over SCM_RIGHTS), READ's preads of that fd, one-read semantics in
//! the policy daemon, RELEASE closing the fd.

#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fuse_server::oracle_service::{run_oracle_server, OracleHub};
use fuse_server::ServerState;

struct Fused {
    child: Child,
    control: std::path::PathBuf,
}

impl Drop for Fused {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.control);
    }
}

fn spawn_fused(dir: &Path, oracle: &Path) -> Fused {
    let control = dir.join("mock-fuse.sock");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("fused.log"))
        .unwrap();
    #[allow(clippy::zombie_processes)]
    let child = Command::new(env!("CARGO_BIN_EXE_fused"))
        .arg("--mount-point")
        .arg(dir.join("mnt"))
        .arg("--oracle-socket")
        .arg(oracle)
        .arg("--mock-fuse")
        .arg(&control)
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(log)
        .spawn()
        .expect("spawn fused");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if control.exists() {
            return Fused { child, control };
        }
        let _ = child;
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("fused never bound the mock control socket");
}

/// One driver connection to the mock kernel: JSON ops in, JSON
/// outcomes out.
struct Driver {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Driver {
    fn connect(control: &Path) -> Self {
        let sock = UnixStream::connect(control).expect("connect mock control socket");
        Self {
            reader: BufReader::new(sock.try_clone().unwrap()),
            writer: sock,
        }
    }

    fn op(&mut self, req: serde_json::Value) -> serde_json::Value {
        writeln!(self.writer, "{req}").unwrap();
        self.writer.flush().unwrap();
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("read driver reply");
        serde_json::from_str(line.trim()).expect("parse driver reply")
    }
}

fn errno_of(reply: &serde_json::Value) -> Option<i64> {
    reply["errno"].as_i64()
}

fn read_hex(reply: &serde_json::Value) -> Vec<u8> {
    let hex = reply["data_hex"].as_str().unwrap_or("");
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// The in-process policy daemon: real wire protocol, dead hashd seam
/// (#69), fast pendings, one secret with the wildcard hash.
fn oracle_env(dir: &Path) -> (std::path::PathBuf, Arc<ServerState>, OracleHub) {
    let mut st = ServerState::new();
    st.hashd_sock = dir.join("hashd-dead.sock").display().to_string();
    let state = Arc::new(st);
    *state.pending_timeout.lock().unwrap() = Duration::from_millis(150);
    let host = dir.join("host-secret");
    std::fs::write(&host, b"MOCK-FUSE-CONTENT").unwrap();
    state.add("s", &host, 1, "*");
    let hub = OracleHub::new();
    let path = dir.join("oracle.sock");
    let (s2, hub2, p2) = (Arc::clone(&state), hub.clone(), path.clone());
    std::thread::spawn(move || {
        run_oracle_server(&p2, s2, hub2).unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    (path, state, hub)
}

#[test]
fn fused_serves_a_full_read_path_over_the_mock_kernel() {
    let dir = tempfile::tempdir().unwrap();
    let (oracle, _state, hub) = oracle_env(dir.path());
    let fused = spawn_fused(dir.path(), &oracle);

    // The control loop needs a moment to connect and receive Serve;
    // poll the listing until the inner name appears.
    hub.serve("s", "ab12cd34ef56", 0o400);
    let mut driver = Driver::connect(&fused.control);
    let init = driver.op(serde_json::json!({"op": "init"}));
    assert!(init.get("minor").is_some(), "init must negotiate: {init}");

    let deadline = Instant::now() + Duration::from_secs(10);
    let listed = loop {
        let rd = driver.op(serde_json::json!({"op": "opendir", "ino": 1}));
        let fh = rd["fh"].as_u64().unwrap_or(0);
        let out = driver.op(
            serde_json::json!({"op": "readdir", "ino": 1, "fh": fh, "size": 4096}),
        );
        driver.op(serde_json::json!({"op": "releasedir", "ino": 1, "fh": fh}));
        let names: Vec<&str> = out["entries"]
            .as_array()
            .map(|a| a.iter().filter_map(|e| e["name"].as_str()).collect())
            .unwrap_or_default();
        if names.iter().copied().any(|n| n == "ab12cd34ef56") {
            break true;
        }
        assert!(Instant::now() < deadline, "Serve never reached the store: {out}");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(listed);

    // LOOKUP mints the identity via live stat through the oracle.
    let entry = driver.op(serde_json::json!({"op": "lookup", "ino": 1, "name": "ab12cd34ef56"}));
    let nodeid = entry["nodeid"].as_u64();
    let ino = nodeid.expect("lookup must answer a nodeid");
    assert!(entry["attr"]["size"].is_u64(), "lookup: {entry}");
    assert_eq!(entry["attr"]["size"], 17, "size comes from live stat: {entry}");

    // GETATTR (path stat: identity check against the oracle).
    let attr = driver.op(serde_json::json!({"op": "getattr", "ino": ino}));
    assert_eq!(attr["size"], 17, "getattr: {attr}");

    // OPEN: the policy daemon adjudicates and passes a host fd —
    // one-read budget spent by this successful open.
    let opened = driver.op(serde_json::json!({"op": "open", "ino": ino, "flags": 0}));
    let fh_val = opened["fh"].as_u64();
    let fh = fh_val.expect("open must answer an fh");

    // READ: preads of the passed fd, through the mock kernel.
    let data = driver.op(
        serde_json::json!({"op": "read", "fh": fh, "offset": 0, "size": 4096}),
    );
    assert_eq!(read_hex(&data), b"MOCK-FUSE-CONTENT");

    // EOF read returns empty, not an error.
    let eof = driver.op(
        serde_json::json!({"op": "read", "fh": fh, "offset": 17, "size": 16}),
    );
    assert_eq!(eof["len"], 0, "eof read: {eof}");

    // RELEASE closes the fd.
    let rel = driver.op(serde_json::json!({"op": "release", "ino": ino, "fh": fh}));
    assert!(rel.get("ok").is_some(), "release: {rel}");

    // ONE-READ semantics, end to end: the budget lives in the policy
    // daemon; a second OPEN pends out its 150ms and is denied — never
    // hangs, never grants.
    let t0 = Instant::now();
    let second = driver.op(serde_json::json!({"op": "open", "ino": ino, "flags": 0}));
    let elapsed = t0.elapsed();
    assert_eq!(errno_of(&second), Some(libc::EACCES as i64), "second open: {second}");
    assert!(
        elapsed >= Duration::from_millis(120),
        "the deny must come from a real pend-out, not a fast path: {elapsed:?}"
    );

    // STATFS: the served-file count.
    let st = driver.op(serde_json::json!({"op": "statfs"}));
    assert_eq!(st["files"], 2, "root + one secret: {st}");

    // A lookup for a name that was never served: ENOENT.
    let miss = driver.op(serde_json::json!({"op": "lookup", "ino": 1, "name": "nope"}));
    assert_eq!(errno_of(&miss), Some(libc::ENOENT as i64), "lookup miss: {miss}");

    // FORGET is oneway; follow it with a cheap sync (STATFS) so the
    // session never sees two requests queued at once.
    let forg = driver.op(serde_json::json!({"op": "forget", "ino": ino, "count": 1}));
    assert!(forg.get("ok").is_some(), "forget: {forg}");
    let sync = driver.op(serde_json::json!({"op": "statfs"}));
    assert!(sync.get("files").is_some(), "session alive after forget: {sync}");

    drop(driver);
    drop(fused);
}

/// A second driver connection after the first hangs up: the session
/// (and the store) survive; the new driver re-inits and reads again.
#[test]
fn the_session_survives_driver_reconnects() {
    let dir = tempfile::tempdir().unwrap();
    let (oracle, state, hub) = oracle_env(dir.path());
    let fused = spawn_fused(dir.path(), &oracle);
    hub.serve("s", "ab12cd34ef56", 0o400);

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut d = Driver::connect(&fused.control);
        d.op(serde_json::json!({"op": "init"}));
        let entry = d.op(serde_json::json!({"op": "lookup", "ino": 1, "name": "ab12cd34ef56"}));
        if entry["nodeid"].is_u64() {
            break;
        }
        assert!(Instant::now() < deadline, "Serve never arrived");
        std::thread::sleep(Duration::from_millis(50));
    }

    // Budget reset through the POLICY daemon (the CLI's `reset`
    // path), then a fresh driver on the SAME session.
    state.reset(Some("s"));

    let mut d2 = Driver::connect(&fused.control);
    let init = d2.op(serde_json::json!({"op": "init"}));
    assert!(init.get("minor").is_some());
    let entry = d2.op(serde_json::json!({"op": "lookup", "ino": 1, "name": "ab12cd34ef56"}));
    let nodeid = entry["nodeid"].as_u64();
    let ino = nodeid.expect("relookup must answer a nodeid");
    let opened = d2.op(serde_json::json!({"op": "open", "ino": ino, "flags": 0}));
    assert!(opened["fh"].is_u64(), "reopen after reconnect: {opened}");
}

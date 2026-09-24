//! Oracle service tests: the policy daemon's adjudication endpoint,
//! exercised over real unix sockets — allow/deny/pending-grant/expiry,
//! content forwarding to (fake) data daemons, and snapshot replay for
//! late joiners.

#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::io::{BufRead, BufReader, Read as _, Write};
use std::sync::Arc;
use std::time::Duration;

use fuse_protocol::oracle::{OracleCommand, OracleReply, OracleRequest};

use fuse_server::oracle_service::{run_oracle_server, OracleHub};
use fuse_server::{ReadOutcome, ServerState};

fn oracle_env() -> (std::path::PathBuf, Arc<ServerState>, std::thread::JoinHandle<()>) {
    // keep()d for the test's lifetime (unique per test; tmp litter only)
    let dir = tempfile::tempdir().unwrap().keep();
    // #59 discipline, applied to the hashd seam (#69): pin it to a
    // dead per-test path so a hashd running on the HOST (production
    // /run/fuse-hashd.sock) can neither answer nor error. Tests that
    // want a hashd bind their own stub and pin its path instead.
    oracle_env_with_hashd(&dir.join("hashd.dead.sock").display().to_string())
}

fn oracle_env_with_hashd(
    hashd_sock: &str,
) -> (std::path::PathBuf, Arc<ServerState>, std::thread::JoinHandle<()>) {
    let dir = tempfile::tempdir().unwrap().keep();
    let path = dir.join("oracle.sock");
    // Same arming discipline as main()'s policy_path: assign the
    // immutable socket on the mut local BEFORE the Arc is shared.
    let mut st = ServerState::new();
    st.hashd_sock = hashd_sock.to_string();
    let state = Arc::new(st);
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
fn failed_fd_pass_does_not_wedge_the_oracle() {
    // PR #48 review: the reader disconnects between sending Open and
    // the SCM_RIGHTS pass. The sendmsg failure used to be SILENT
    // (unwrap_or(0)) — now it is logged and a plain Error reply is
    // attempted, and above all the oracle keeps serving: a later open
    // still adjudicates and hands over the fd.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("s.bin");
    std::fs::write(&file, b"HOSTBYTES").unwrap();
    let oracle = dir.path().join("wedge.sock");
    let hub = OracleHub::clone(&fuse_server::ORACLE_HUB);
    let state = Arc::new(ServerState::new());
    {
        let len = std::fs::metadata(&file).unwrap().len() as usize;
        state.add("s", &file, len, "*");
        let _ = hub; // (serving not needed for direct opens)
    }
    let st = Arc::clone(&state);
    let p = oracle.clone();
    std::thread::spawn(move || {
        let _ = run_oracle_server(&p, st, hub);
    });
    for _ in 0..200 {
        if oracle.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Identity from a Stat round trip.
    let (kdev, kino) = {
        let mut c = std::os::unix::net::UnixStream::connect(&oracle).unwrap();
        writeln!(
            c,
            "{}",
            serde_json::to_string(&OracleRequest::Stat { name: "s".into() }).unwrap()
        )
        .unwrap();
        c.flush().unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(c), &mut line).unwrap();
        match serde_json::from_str::<OracleReply>(line.trim()).unwrap() {
            OracleReply::StatOk { kdev, kino, .. } => (kdev, kino),
            other => panic!("stat: {other:?}"),
        }
    };

    // The vanishing reader: send Open, then drop the connection
    // before the reply/fd can be written.
    {
        let mut c = std::os::unix::net::UnixStream::connect(&oracle).unwrap();
        writeln!(
            c,
            "{}",
            serde_json::to_string(&OracleRequest::Open {
                name: "s".into(),
                pid: 1111,
                kdev,
                kino,
            })
            .unwrap()
        )
        .unwrap();
        c.flush().unwrap();
        drop(c);
    }
    // Wait for the vanishing open to be ADJUDICATED — observed by its
    // EFFECT on the record (access_count == 1), never by sleeping for
    // a fixed interval: a sleep assumes the server thread's scheduling
    // and raced exactly that way in the field (the follow-up open hit
    // "exceeded access limit", pended, and expired after a hang).
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let served = state
            .status()
            .into_iter()
            .find(|s| s.name == "s")
            .expect("secret registered");
        if served.access_count >= 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the vanishing reader's open was never adjudicated — \
             the oracle stopped serving?"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // Re-arm the one-read cycle for the follow-up, as an operator would.
    state.reset(Some("s"));

    // The oracle still serves a fresh open: Allow + fd. The wait is
    // BOUNDED: if the reply never comes, fail with context instead of
    // hanging past the harness's 60s notice (the same discipline as
    // fused's OPEN_REPLY_TIMEOUT — an unbounded recv here once turned
    // a lost reply into an undiagnosable hang).
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let mut c = std::os::unix::net::UnixStream::connect(&oracle).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    writeln!(
        c,
        "{}",
        serde_json::to_string(&OracleRequest::Open {
            name: "s".into(),
            pid: 2222,
            kdev,
            kino,
        })
        .unwrap()
    )
    .unwrap();
    c.flush().unwrap();
    let mut buf = vec![0u8; 4096];
    let mut cmsg = nix::cmsg_space!(libc::cmsghdr, std::os::unix::io::RawFd);
    let mut fd = None;
    let n;
    {
        let mut iov = [std::io::IoSliceMut::new(&mut buf)];
        let raw = c.as_raw_fd();
        let msg = nix::sys::socket::recvmsg::<()>(
            raw,
            &mut iov,
            Some(&mut cmsg),
            nix::sys::socket::MsgFlags::empty(),
        )
        .unwrap();
        for cm in msg.cmsgs().unwrap() {
            if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = cm {
                fd = fds.first().copied();
            }
        }
        n = msg.bytes;
    }
    let reply: OracleReply =
        serde_json::from_str(String::from_utf8_lossy(&buf[..n]).trim()).unwrap();
    assert!(matches!(reply, OracleReply::Allow), "later opens still serve: {reply:?}");
    let fd = fd.expect("the fd must still arrive");
    // and it is the live host content
    let mut got = String::new();
    // SAFETY: recvmsg created this descriptor for us; taking ownership
    // as a File closes it (and the passed copy) on drop.
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    std::io::Read::read_to_string(&mut f, &mut got).unwrap();
    assert_eq!(got, "HOSTBYTES");
}

#[test]
fn open_passes_an_fd_and_stats_flow() {
    // MR4 seam: Open must (a) verify the caller's ino identity,
    // (b) answer Gone for a replaced incarnation, (c) on Allow
    // hand a readable fd for the CURRENT bytes via SCM_RIGHTS.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("s.bin");
    std::fs::write(&file, b"HOSTBYTES").unwrap();
    let oracle = dir.path().join("open.sock");
    let hub = OracleHub::clone(&fuse_server::ORACLE_HUB);
    let state = Arc::new(ServerState::new());
    {
        let md = std::fs::metadata(&file).unwrap();
        state.add("s", &file, md.len() as usize, "*");
        hub.serve("s", "x1", 0o400);
    }
    let st = Arc::clone(&state);
    let p = oracle.clone();
    std::thread::spawn(move || {
        let _ = run_oracle_server(&p, st, hub);
    });
    for _ in 0..200 {
        if oracle.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Stat: live identity.
    let mut c = std::os::unix::net::UnixStream::connect(&oracle).unwrap();
    writeln!(c, "{}", serde_json::to_string(&OracleRequest::Stat { name: "s".into() }).unwrap()).unwrap();
    c.flush().unwrap();
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(c.try_clone().unwrap()), &mut line).unwrap();
    let r: OracleReply = serde_json::from_str(line.trim()).unwrap();
    let (kdev, kino, size) = match r {
        OracleReply::StatOk { kdev, kino, size, regular: true, .. } => (kdev, kino, size),
        other => panic!("stat: {other:?}"),
    };
    assert_eq!(size, 9);

    // Open with the right identity: fd arrives with the reply.
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let mut c = std::os::unix::net::UnixStream::connect(&oracle).unwrap();
    writeln!(c, "{}", serde_json::to_string(&OracleRequest::Open {
        name: "s".into(), pid: 4242, kdev, kino,
    }).unwrap()).unwrap();
    c.flush().unwrap();
    let mut buf = vec![0u8; 4096];
    let mut cmsg = nix::cmsg_space!(libc::cmsghdr, std::os::unix::io::RawFd);
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let msg = {
        let raw = c.as_raw_fd();
        nix::sys::socket::recvmsg::<()>(
            raw, &mut iov, Some(&mut cmsg), nix::sys::socket::MsgFlags::empty(),
        ).unwrap()
    };
    let mut fd = None;
    for cm in msg.cmsgs().unwrap() {
        if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = cm {
            fd = fds.first().copied();
        }
    }
    let n = msg.bytes;
    let reply: OracleReply =
        serde_json::from_str(String::from_utf8_lossy(&buf[..n]).trim()).unwrap();
    assert!(matches!(reply, OracleReply::Allow), "open: {reply:?}");
    let fd = fd.expect("fd ancillary");
    // SAFETY: descriptor received via SCM_RIGHTS; owned here on.
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut got = String::new();
    f.read_to_string(&mut got).unwrap();
    assert_eq!(got, "HOSTBYTES");

    // Open with a WRONG identity: the incarnation check answers Stale.
    let mut c = std::os::unix::net::UnixStream::connect(&oracle).unwrap();
    writeln!(c, "{}", serde_json::to_string(&OracleRequest::Open {
        name: "s".into(), pid: 4243, kdev, kino: fuse_protocol::Kino(kino.0.wrapping_add(1)),
    }).unwrap()).unwrap();
    c.flush().unwrap();
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(c), &mut line).unwrap();
    let r: OracleReply = serde_json::from_str(line.trim()).unwrap();
    assert!(matches!(r, OracleReply::Stale), "replaced incarnation: {r:?}");
}


#[test]
fn star_hash_ask_is_allowed_and_serves_offsets() {
    let (path, state, _t) = oracle_env();
    state.add("s", "/tmp/host/s", 10, "*");
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
    state.add("s", "/tmp/host/s", 12, "*");
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
    state.add("s", "/tmp/host/s", 1, "*");
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
    state.add("s", "/tmp/host/s", 1, "some_hash");
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

/// The OTHER branch of the hashd seam, deterministically: a stub
/// hashd answers `ok <hash>` on the state's pinned socket, so the
/// pending must carry the pid hash and NO error — regardless of
/// whether the machine running the test has a live production hashd
/// (the leak that made `wrong_hash_pends_and_carries_the_hash_error`
/// fail on a real host: the production hashd answered with `gone` for
/// the synthetic pid).
#[test]
fn stub_hashd_answer_carries_the_pid_hash_not_an_error() {
    let canned = "a".repeat(64);
    // Bind the stub on a per-test path and pin the state to it.
    let dir = tempfile::tempdir().unwrap().keep();
    let sock = dir.join("hashd.stub.sock");
    let stub_sock = sock.clone();
    let canned2 = canned.clone();
    std::thread::spawn(move || {
        let listener = std::os::unix::net::UnixListener::bind(&stub_sock).unwrap();
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { break };
            use std::io::{BufRead, BufReader, Write};
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            // One question, one answer — the hashd wire contract.
            let _ = writeln!(conn, "ok {canned2}");
            let _ = conn.flush();
        }
    });
    let (path, state, _t) = oracle_env_with_hashd(&sock.display().to_string());
    state.add("s", "/tmp/host/s", 1, "some_hash");
    // Wait for the stub listener before asking.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !sock.exists() {
        assert!(std::time::Instant::now() < deadline, "stub hashd never bound");
        std::thread::sleep(Duration::from_millis(10));
    }

    // The ask presents no hash; adjudication hashes via the seam. The
    // canned hash is NOT the secret's permitted hash, so it pends —
    // carrying the observed hash for grant-forever.
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
    assert_eq!(pid_hash.as_deref(), Some(canned.as_str()),
        "a hashd that answered must land in the pending");
    assert!(hash_error.is_none(), "no error expected, got: {hash_error:?}");
    let _ = asker.join().unwrap();
}

#[test]
fn wrong_hash_pends_and_carries_the_hash_error() {
    let (path, state, _t) = oracle_env();
    state.add("s", "/tmp/host/s", 1, "some_hash");
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
    hub.serve("seed", "d1", 0o400);
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
    // Old daemons send a bare hello (no version) — must still parse
    // and still receive the snapshot.
    let mut conn = std::os::unix::net::UnixStream::connect(&path).unwrap();
    conn.write_all(b"{\"type\":\"hello\"}\n").unwrap();
    let mut reader = BufReader::new(conn.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap(); // Ok ack
    line.clear();
    reader.read_line(&mut line).unwrap();
    let cmd: OracleCommand = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(
        cmd,
        OracleCommand::Serve { name: "seed".into(), inner: "d1".into(), mode: 0o400 }
    );

    // Live push through the hub.
    hub.serve("seed", "d2", 0o600);
    line.clear();
    reader.read_line(&mut line).unwrap();
    let cmd: OracleCommand = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(cmd, OracleCommand::Serve { name: "seed".into(), inner: "d2".into(), mode: 0o600 });
}

#[test]
fn a_stuck_data_daemon_does_not_wedge_the_policy_daemon() {
    // Issue #77: a control connection whose peer STOPPED READING
    // (stuck-but-alive data daemon) must not block broadcast forever
    // — it wedges the hub lock and with it every AddSecret/Remove on
    // the command socket. The dead-peer case (EPIPE) is handled; the
    // full-buffer case is the bug. A stuck peer must be dropped like
    // a dead one.
    let dir = tempfile::tempdir().unwrap();
    let oracle = dir.path().join("stuck.sock");
    let state = Arc::new(ServerState::new());
    *state.pending_timeout.lock().unwrap() = Duration::from_secs(1);
    let host = dir.path().join("host");
    std::fs::write(&host, b"X").unwrap();
    state.add("s", &host, 1, "*");
    let hub = OracleHub::new();
    {
        let (st, hb, p) = (Arc::clone(&state), hub.clone(), oracle.clone());
        std::thread::spawn(move || { let _ = run_oracle_server(&p, st, hb); });
    }
    for _ in 0..200 {
        if oracle.exists() { break; }
        std::thread::sleep(Duration::from_millis(10));
    }

    // The stuck daemon: connects, says Hello (becomes a control
    // connection), then NEVER reads. Clamp its receive buffer small
    // so filling it is deterministic.
    use std::os::unix::io::AsRawFd;
    let mut stuck = std::os::unix::net::UnixStream::connect(&oracle).unwrap();
    // SAFETY: setsockopt(2) on our own fd with a c_int operand.
    unsafe {
        let sz: libc::c_int = 4096;
        libc::setsockopt(
            stuck.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    stuck.write_all(b"{\"type\":\"hello\"}\n").unwrap();
    std::thread::sleep(Duration::from_millis(200)); // registered

    // Fill the stuck peer's buffer (big names, ~1MB total), then one
    // more broadcast and a state mutation — all must COMPLETE. Run
    // under a watchdog: the bug manifests as an unbounded block.
    let hb2 = hub.clone();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let big = "n".repeat(64 * 1024);
        for _ in 0..16 {
            hb2.serve(&big, "x", 0o400);
        }
        hb2.serve("final", "x", 0o400);
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(8))
        .expect("broadcast wedged on a stuck control peer — the hub lock \
                 is held and the command socket is frozen (issue #77)");

    // And the policy daemon still answers work afterwards.
    assert_eq!(
        state.attempt_read("s", 7, Some("*"), 0, 1),
        ReadOutcome::Granted
    );
    drop(stuck);
}

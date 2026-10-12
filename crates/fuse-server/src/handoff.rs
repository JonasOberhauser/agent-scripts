//! Handoff mode (#93 F2, the seamless restart): the OLD server side
//! and the NEW server client side of the frozen dialect in
//! `fuse_protocol::handoff`.
//!
//! Old side (`enter_handoff_mode`): invoked by the client-protocol
//! `Handoff` command — stop the listeners, take the custody batch back
//! from OUR fused over the same-version oracle wire
//! (`Surrender` → `SurrenderPayload` with SCM_RIGHTS), record the
//! rendezvous in the state file, and LINGER serving the stepwise
//! handoff socket until `Commit` (retire the fused, exit 0), `Abort`,
//! or the timeout — all degrading to today's restart behavior.
//!
//! New side (`resume_from_handoff`): at startup, before spawning a
//! fused — `Status`, then re-runnable `GetFd`/`GetState`, so a server
//! that died mid-operation costs the next attempt nothing but a
//! re-request (the old side keeps every copy until `Commit`).
//!
//! The fd never leaves the daemons; the client only triggers.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{error, info, warn};

use fuse_protocol::handoff::{HandoffReply, HandoffRequest, HANDOFF_PROTOCOL_VERSION};
use fuse_protocol::oracle::OracleCommand;
use fuse_protocol::ServerStateFile;

use crate::OracleHub;

/// The custody batch the old side holds between take-back and commit.
#[derive(Default)]
pub struct Custody {
    /// fd[0] = the mount connection; the rest are open host fds in
    /// table order (matching the state payload's table).
    pub fds: Vec<OwnedFd>,
    pub session: Option<serde_json::Value>,
    pub session_schema: u32,
}

pub type SharedCustody = Arc<Mutex<Custody>>;

/// Receive one JSON line plus its SCM_RIGHTS batch (the frozen
/// dialect's one-line-per-connection contract makes the oracle
/// service's single-recvmsg first-line reader exactly right here).
pub(crate) use crate::oracle_service::read_first_line_with_fds as recv_line_with_fds;

/// The take-back: ask OUR fused (same-version wire) to surrender, and
/// collect the batch it sends back. Keeps working if the daemon is
/// already gone (`Ok(None)` — nothing to hand off).
pub(crate) fn take_back(
    _oracle_socket: &Path,
    hub: &OracleHub,
    child: &mut std::process::Child,
) -> Result<Option<Custody>, String> {
    // The hub's control connection is one-way push; the payload comes
    // back on a FRESH oracle connection carrying SCM_RIGHTS.
    hub.push_control_only(&OracleCommand::Surrender);
    // The daemon needs a moment; its payload connection lands on the
    // oracle listener this server still owns during handoff entry.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut custody_from_mailbox: Option<crate::oracle_service::Surrendered> = None;
    while custody_from_mailbox.is_none() && Instant::now() < deadline {
        // Probe via the pending-payload mailbox the oracle server
        // stashes SurrenderPayload connections into (see
        // oracle_service::handle_conn).
        if let Some(s) = crate::oracle_service::take_surrender_payload() {
            custody_from_mailbox = Some(s);
            break;
        } else if let Ok(Some(_)) = child.try_wait() {
            return Ok(None); // daemon died before surrendering
        } else {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let Some(s) = custody_from_mailbox else {
        // A fused that does not know Surrender (older build, or the
        // real daemon predating the feature) simply stays silent: no
        // custody, caller falls back.
        warn!("handoff: the supervised fused did not surrender in time — no custody");
        return Ok(None);
    };
    if s.fds.is_empty() {
        return Err("surrender payload carried no fds".into());
    }
    Ok(Some(Custody {
        fds: s.fds,
        session: Some(s.state),
        session_schema: s.schema,
    }))
}

/// Record the pending handoff in the stack's state file (additive
/// fields only — pre-field files parse unchanged).
pub(crate) fn record_in_state_file(
    state_file: &Path,
    handoff_socket: &Path,
    fused_pid: u32,
) -> Result<(), String> {
    let text = std::fs::read_to_string(state_file).unwrap_or_default();
    let mut f: ServerStateFile =
        serde_json::from_str(&text).map_err(|e| format!("state file unreadable: {e}"))?;
    f.handoff_socket = Some(handoff_socket.display().to_string());
    f.supervised_pid = Some(fused_pid);
    let tmp = state_file.with_extension("handoff.tmp");
    std::fs::write(&tmp, serde_json::to_vec(&f).map_err(|e| e.to_string())?)
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, state_file).map_err(|e| format!("rename: {e}"))
}

/// OLD side, the linger: serve the handoff socket one command per
/// connection until Commit/Abort/timeout. Never destroys the custody
/// before Commit. Returns when the old server should exit.
pub(crate) fn serve_handoff(
    listener: UnixListener,
    custody: SharedCustody,
    mut child: std::process::Child,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    let _ = listener
        .set_nonblocking(true)
        .inspect_err(|e| warn!("handoff: nonblocking listener: {e}"));
    let mut committed_to: Option<u32> = None;
    let mut fd_taken_by: Option<u32> = None;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((conn, _)) => {
                let _ = conn.set_nonblocking(false);
                let last =
                    serve_one_handoff_conn(conn, &custody, &mut committed_to, &mut fd_taken_by);
                if last {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                warn!("handoff: accept: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    if committed_to.is_none() {
        info!("handoff: timeout/abort — degrading to today's restart behavior");
    }
    retire_fused(&mut child);
}

/// Retire the supervised fused (Retire, then the hard way), close the
/// custody copies LAST, and exit. Called from the linger loop's end
/// and from the timeout path alike.
fn retire_fused(child: &mut std::process::Child) {
    // Already gone?
    if let Ok(Some(_)) = child.try_wait() {
        return;
    }
    // Best effort: the graceful word first (it closes its own copies).
    let hub = OracleHub::clone(&crate::ORACLE_HUB);
    hub.push_control_only(&OracleCommand::Retire);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// #97's zombie lesson baked in: kill(0) succeeds and /proc lists
/// unreaped corpses — liveness is the scheduler state, not the pid's
/// existence.
fn pid_alive(pid: u32) -> bool {
    let pid_t = pid as libc::pid_t;
    // SAFETY: kill(0) — a pure liveness probe, no signal delivered.
    let rc = unsafe { libc::kill(pid_t, 0) };
    if rc != 0 {
        return false;
    }
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let state = stat
        .rsplit(')')
        .next()
        .map(|rest| rest.split_whitespace().next().unwrap_or("Z").to_string())
        .unwrap_or_else(|| "Z".into());
    state != "Z" && state != "X"
}

/// One connection = one command. Returns true when the loop should
/// end (Commit or Abort arrived).
fn serve_one_handoff_conn(
    conn: UnixStream,
    custody: &SharedCustody,
    committed_to: &mut Option<u32>,
    fd_taken_by: &mut Option<u32>,
) -> bool {
    let mut writer = match conn.try_clone() {
        Ok(w) => w,
        Err(_) => return false,
    };
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
        return false;
    }
    let req: HandoffRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(
                writer,
                "{}",
                serde_json::to_string(&HandoffReply::Error {
                    message: format!("malformed handoff request: {e}"),
                })
                .expect("internal enum: infallible")
            );
            return false;
        }
    };
    let reply = match req {
        HandoffRequest::Status => {
            let c = custody.lock().expect("custody lock");
            HandoffReply::Status {
                handoff_protocol_version: HANDOFF_PROTOCOL_VERSION,
                has_fd: !c.fds.is_empty(),
                session_schema: c.session_schema,
                committed_to: *committed_to,
                fused_pid: None,
            }
        }
        HandoffRequest::GetFd { requester_pid, .. } => {
            // First live taker wins; a dead taker's slot is inherited.
            if let Some(&first) = fd_taken_by.as_ref() {
                if first != requester_pid && pid_alive(first) {
                    HandoffReply::Error {
                        message: format!(
                            "custody in flight: server pid {first} already took it over — \
                             stand down and retry if it fails"
                        ),
                    }
                } else {
                    *fd_taken_by = Some(requester_pid);
                    let c = custody.lock().expect("custody lock");
                    let raws: Vec<RawFd> = c.fds.iter().map(|f| f.as_raw_fd()).collect();
                    match send_reply_with_fds(
                        &writer,
                        &HandoffReply::Fd {
                            fd_count: raws.len() as u32,
                        },
                        &raws,
                    ) {
                        Ok(()) => return false,
                        Err(e) => HandoffReply::Error { message: e },
                    }
                }
            } else {
                *fd_taken_by = Some(requester_pid);
                let c = custody.lock().expect("custody lock");
                let raws: Vec<RawFd> = c.fds.iter().map(|f| f.as_raw_fd()).collect();
                match send_reply_with_fds(
                    &writer,
                    &HandoffReply::Fd {
                        fd_count: raws.len() as u32,
                    },
                    &raws,
                ) {
                    Ok(()) => return false,
                    Err(e) => HandoffReply::Error { message: e },
                }
            }
        }
        HandoffRequest::GetState => {
            let c = custody.lock().expect("custody lock");
            match &c.session {
                Some(state) => HandoffReply::State {
                    state: state.clone(),
                },
                None => HandoffReply::Error {
                    message: "no session state".into(),
                },
            }
        }
        HandoffRequest::Commit { new_server_pid } => {
            if committed_to.is_some() {
                HandoffReply::Error {
                    message: "already committed".into(),
                }
            } else {
                *committed_to = Some(new_server_pid);
                info!("handoff: committed to new server pid {new_server_pid}");
                HandoffReply::Ok
            }
        }
        HandoffRequest::Abort { ref reason } => {
            info!("handoff: aborted by the new server: {reason}");
            HandoffReply::Ok
        }
    };
    let _ = writeln!(
        writer,
        "{}",
        serde_json::to_string(&reply).expect("internal enum: infallible")
    );
    let is_final = matches!(
        req,
        HandoffRequest::Commit { .. } | HandoffRequest::Abort { .. }
    );
    is_final
}

/// Write the reply line with `fds` attached as one SCM_RIGHTS batch.
fn send_reply_with_fds(
    stream: &UnixStream,
    reply: &HandoffReply,
    fds: &[RawFd],
) -> Result<(), String> {
    let line = serde_json::to_string(reply).map_err(|e| e.to_string())?;
    let iov = [std::io::IoSlice::new(line.as_bytes())];
    let cmsg = [nix::sys::socket::ControlMessage::ScmRights(fds)];
    let _sent = nix::sys::socket::sendmsg::<()>(
        stream.as_raw_fd(),
        &iov,
        &cmsg,
        nix::sys::socket::MsgFlags::empty(),
        None,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

// ── NEW side ─────────────────────────────────────────────────────

/// The takeover result for the spawning path in main.
pub struct Takeover {
    pub custody: Custody,
    pub handoff_socket: std::path::PathBuf,
}

impl Takeover {
    /// The mount-connection fd (custody fd[0]) as a raw number for the
    /// child's pre_exec dup2 — the OwnedFd stays owned HERE, keeping
    /// the kernel connection open for the whole daemon lifetime.
    pub fn mount_fd_raw(&self) -> std::os::unix::io::RawFd {
        self.custody.fds[0].as_raw_fd()
    }

    /// Write the serialized session state where the resuming fused
    /// reads it (beside the oracle socket — the stack's own space).
    pub fn write_session_state(&self) -> Result<std::path::PathBuf, String> {
        let mut path = self.handoff_socket.clone();
        let _was = path.set_extension("resume.json");
        let session = fuse_protocol::handoff::HandoffSession {
            session_schema: self.custody.session_schema,
            payload: self
                .custody
                .session
                .clone()
                .unwrap_or_else(|| serde_json::json!({})),
        };
        std::fs::write(
            &path,
            serde_json::to_vec(&session).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("write {}: {e}", path.display()))?;
        Ok(path)
    }
}

/// Clear the pending-handoff fields after a committed takeover (the
/// next restart must not chase a dead rendezvous).
pub fn clear_pending_in_state_file(state_file: Option<&Path>) {
    let Some(sf) = state_file else { return };
    let Ok(text) = std::fs::read_to_string(sf) else {
        return;
    };
    let Ok(mut f) = serde_json::from_str::<ServerStateFile>(&text) else {
        return;
    };
    f.handoff_socket = None;
    f.supervised_pid = None;
    let tmp = sf.with_extension("clear.tmp");
    if std::fs::write(&tmp, serde_json::to_vec(&f).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&tmp, sf);
    }
}

/// At startup: if the state file records a pending handoff, run the
/// stepwise client — Status first (dialect + progress), then the fd
/// batch and the state. `None` when there is nothing to resume.
///
/// On `Commit`-able success the caller spawns the new fused with the
/// inherited fd and THEN calls [`commit_handoff`]. A failure here is
/// NOT an abort of the old server — the next attempt re-runs this and
/// the old side still holds everything (review on #97: resumable).
/// # Panics
/// Panics only on lock poisoning of the surrender mailbox contract.
pub fn resume_from_handoff(state_file: &Path) -> Option<Takeover> {
    let text = std::fs::read_to_string(state_file).ok()?;
    let f: ServerStateFile = serde_json::from_str(&text).ok()?;
    let sock = f.handoff_socket?;
    let path = Path::new(&sock).to_path_buf();
    // A handoff socket with nobody listening = a dead old server:
    // fresh-mount fallback, no one to talk to.
    let probe = UnixStream::connect(&path).ok()?;
    drop(probe);

    let mut conn = match UnixStream::connect(&path) {
        Ok(c) => c,
        Err(e) => {
            warn!(
                "handoff: cannot reach the old server at {}: {e}",
                path.display()
            );
            return None;
        }
    };
    // Status first: dialect gate + the race arbiter.
    match handoff_roundtrip(&mut conn, &HandoffRequest::Status) {
        Ok(HandoffReply::Status {
            handoff_protocol_version,
            has_fd,
            session_schema,
            committed_to,
            ..
        }) => {
            if handoff_protocol_version != HANDOFF_PROTOCOL_VERSION {
                warn!("handoff: dialect v{handoff_protocol_version} != v{HANDOFF_PROTOCOL_VERSION} — declining");
                return None;
            }
            if let Some(pid) = committed_to {
                warn!("handoff: already committed to server pid {pid} — standing down");
                return None;
            }
            if !has_fd {
                warn!("handoff: the old server holds no custody — fresh mount");
                return None;
            }
            info!("handoff: old server live, custody available (schema {session_schema})");
        }
        other => {
            warn!("handoff: status failed ({other:?}) — fresh mount");
            return None;
        }
    }

    // The fd batch (repeatable by design).
    let mut fconn = match UnixStream::connect(&path) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let _ = writeln!(
        fconn,
        "{}",
        serde_json::to_string(&HandoffRequest::GetFd {
            attempt: 1,
            requester_pid: std::process::id()
        })
        .expect("internal enum: infallible")
    );
    let (line, _leftover, fds) = match recv_line_with_fds(&fconn) {
        Ok(x) => x,
        Err(e) => {
            warn!("handoff: fd batch failed: {e}");
            return None;
        }
    };
    let line = String::from_utf8_lossy(&line).to_string();
    let reply: HandoffReply = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(_) => return None,
    };
    let HandoffReply::Fd { fd_count } = reply else {
        warn!("handoff: fd batch reply was {reply:?}");
        return None;
    };
    if fds.len() as u32 != fd_count || fds.is_empty() {
        warn!(
            "handoff: fd count mismatch ({}/{} — fresh mount",
            fds.len(),
            fd_count
        );
        return None;
    }

    // The session state (repeatable).
    let mut sconn = match UnixStream::connect(&path) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let state = match handoff_roundtrip(&mut sconn, &HandoffRequest::GetState) {
        Ok(HandoffReply::State { state }) => Some(state),
        _ => None,
    };

    Some(Takeover {
        custody: Custody {
            fds,
            session: state,
            session_schema: 0,
        },
        handoff_socket: path,
    })
}

/// One command, one reply, one connection (the listener's contract).
fn handoff_roundtrip(conn: &mut UnixStream, req: &HandoffRequest) -> Result<HandoffReply, String> {
    let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    conn.write_all(format!("{line}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(conn.try_clone().map_err(|e| e.to_string())?);
    let mut resp = String::new();
    let _n = reader.read_line(&mut resp).map_err(|e| e.to_string())?;
    serde_json::from_str(resp.trim()).map_err(|e| e.to_string())
}

/// The new pair is serving — release the old server.
pub fn commit_handoff(socket: &Path) {
    if let Ok(mut conn) = UnixStream::connect(socket) {
        match handoff_roundtrip(
            &mut conn,
            &HandoffRequest::Commit {
                new_server_pid: std::process::id(),
            },
        ) {
            Ok(_) => info!("handoff: committed — the old pair is retiring"),
            Err(e) => error!("handoff: commit failed ({e}) — the old server will time out"),
        }
    }
}

// ── OLD side, the mode entry ─────────────────────────────────────

/// Boot-time records the conductor needs but the command handler does
/// not carry: the stack's rendezvous paths and the supervised child.
pub static STACK_PATHS: std::sync::OnceLock<(std::path::PathBuf, std::path::PathBuf)> =
    std::sync::OnceLock::new();

/// The supervised fused child (moved here from main for the mode's
/// duration; None when the server runs without supervision).
pub static SUPERVISED: Mutex<Option<std::process::Child>> = Mutex::new(None);

/// Enter handoff mode (old side). Runs on the conductor thread the
/// command handler spawned. Sequence:
///
/// 1. grace — the Ok reply must reach the client;
/// 2. take-back — the custody batch from OUR fused (same-version wire);
/// 3. record the rendezvous + supervised pid in the state file;
/// 4. stop presenting the stack sockets (unlink; the lingering
///    listeners hold only unbound inodes);
/// 5. linger on the handoff socket until Commit/Abort/timeout;
/// 6. exit — after retiring the fused and (implicitly) dropping the
///    custody copies, which always happens AFTER a successful
///    transfer kept its duplicates alive in the new pair.
/// # Panics
/// Panics only on lock poisoning (the supervised/custody locks are
/// poison-free by contract).
pub fn enter_handoff_mode(state_file: &Path, timeout: Duration) -> Result<(), String> {
    if let Err(e) = enter_handoff_mode_inner(state_file, timeout) {
        // The Ok already reached the client — it will NOT send TERM.
        // Degrade honestly to the legacy shutdown contract: sockets
        // unlinked, process gone; its restart spawns fresh (a fresh
        // mount, exactly the pre-handoff behavior).
        tracing::error!("handoff mode failed ({e}) — degrading to the legacy shutdown");
        if let Some((cmd_sock, oracle_sock)) = STACK_PATHS.get() {
            let _ = std::fs::remove_file(cmd_sock);
            let _ = std::fs::remove_file(oracle_sock);
        }
        std::process::exit(0);
    }
    Ok(())
}

fn enter_handoff_mode_inner(state_file: &Path, timeout: Duration) -> Result<(), String> {
    std::thread::sleep(Duration::from_millis(250));
    let Some((cmd_sock, oracle_sock)) = STACK_PATHS.get() else {
        return Err("stack paths not recorded (no handoff for this boot)".into());
    };
    let handoff_sock = fuse_protocol::handoff::handoff_socket_path(oracle_sock);

    // 2. take-back (before anything stops: the payload connection
    //    lands on the oracle listener this server still owns).
    let custody: SharedCustody = Arc::new(Mutex::new(Custody::default()));
    let fused_pid;
    {
        let mut guard = SUPERVISED.lock().expect("supervised lock");
        match guard.as_mut() {
            Some(child) => {
                fused_pid = child.id();
                let hub = OracleHub::clone(&crate::ORACLE_HUB);
                match take_back(oracle_sock, &hub, child)? {
                    Some(c) => {
                        let mut slot = custody.lock().expect("custody lock");
                        slot.fds = c.fds;
                        slot.session = c.session;
                        slot.session_schema = c.session_schema;
                    }
                    None => warn!(
                        "handoff: no custody (fused did not surrender) — linger will report empty"
                    ),
                }
            }
            None => return Err("no supervised fused — handoff mode is meaningless".into()),
        }
    }

    // 3. record the rendezvous (additive fields; pre-field files parse).
    record_in_state_file(state_file, &handoff_sock, fused_pid)?;

    // 4. stop presenting the stack sockets.
    let _ = std::fs::remove_file(cmd_sock);
    let _ = std::fs::remove_file(oracle_sock);

    // 5. linger.
    let _ = std::fs::remove_file(&handoff_sock);
    let listener = UnixListener::bind(&handoff_sock)
        .map_err(|e| format!("bind {}: {e}", handoff_sock.display()))?;
    info!(
        "handoff: lingering at {} (timeout {timeout:?})",
        handoff_sock.display()
    );
    let child = SUPERVISED.lock().expect("supervised lock").take();
    match child {
        Some(c) => serve_handoff(listener, custody, c, timeout),
        None => unreachable!("the supervised child was present above"),
    }
    // 6. exit — the stack belongs to the new pair (or nobody came and
    // today's behavior already ran its course in serve_handoff).
    std::process::exit(0);
}

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

/// The take-back window: how long the old fused may take to
/// surrender after the word goes out.
const TAKE_BACK_TIMEOUT: Duration = Duration::from_secs(10);
/// The linger/accept poll cadence.
const HANDOFF_POLL: Duration = Duration::from_millis(50);
/// B1-b: nobody engaged at all (no taker, no commit) for this long
/// after the last connection ⇒ treat as a declined takeover and
/// retire — a bare probe-and-disappear must not strand the stack for
/// the full linger timeout.
const HANDOFF_IDLE_ABORT: Duration = Duration::from_secs(3);

/// How long the old fused gets to exit on the Retire word before the
/// supervisor falls back to the hard kill.
const RETIRE_GRACE: Duration = Duration::from_secs(5);

/// The custody batch the old side holds between take-back and commit.
#[derive(Default)]
pub struct Custody {
    /// fd\[0\] = the mount connection; the rest are open host fds in
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
    //
    // The word is RE-BROADCAST until answered: the daemon's control
    // connection may still be establishing when the restart fires
    // (its Hello races the Surrender), and one lost push would turn
    // every restart into the full timeout.
    const SURRENDER_REPUSH: Duration = Duration::from_millis(200);
    let deadline = Instant::now() + TAKE_BACK_TIMEOUT;
    let mut last_push: Option<Instant> = None;
    let mut custody_from_mailbox: Option<crate::oracle_service::Surrendered> = None;
    while custody_from_mailbox.is_none() && Instant::now() < deadline {
        // Probe via the pending-payload mailbox the oracle server
        // stashes SurrenderPayload connections into (see
        // oracle_service::handle_conn).
        if let Some(s) = crate::oracle_service::take_surrender_payload() {
            custody_from_mailbox = Some(s);
            break;
        } else if crate::oracle_service::take_surrender_refusal() {
            // The daemon ANSWERED "cannot surrender" (the real fused
            // until fd extraction lands): fail fast — no 10s penalty
            // on every restart, handoff refused cleanly.
            warn!("handoff: the supervised fused refused to surrender — no custody");
            return Ok(None);
        } else if let Ok(Some(_)) = child.try_wait() {
            return Ok(None); // daemon died before surrendering
        } else {
            let controls_up = hub.control_len() > 0;
            let due = last_push.is_none_or(|t| t.elapsed() >= SURRENDER_REPUSH);
            if controls_up && due {
                hub.push_control_only(&OracleCommand::Surrender);
                last_push = Some(Instant::now());
            }
            std::thread::sleep(HANDOFF_POLL);
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
    let mut deadline = Instant::now() + timeout;
    let mut last_activity = Instant::now();
    let _ = listener
        .set_nonblocking(true)
        .inspect_err(|e| warn!("handoff: nonblocking listener: {e}"));
    let mut committed_to: Option<u32> = None;
    let mut fd_taken_by: Option<u32> = None;
    loop {
        // M1: a LIVE taker suspends the wall clock — evaluated EVERY
        // iteration, not only on connections (a silent mid-takeover
        // successor must not have the mount yanked by the timeout).
        if committed_to.is_none() {
            if let Some(&taker) = fd_taken_by.as_ref() {
                if pid_alive(taker) {
                    deadline = Instant::now() + timeout;
                }
            }
        }
        // B1-b: a probe-and-disappear with NOBODY engaged retires the
        // old pair early instead of stranding the stack.
        if committed_to.is_none()
            && fd_taken_by.is_none()
            && last_activity.elapsed() >= HANDOFF_IDLE_ABORT
        {
            info!("handoff: idle with no taker — treating as a declined takeover");
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        match listener.accept() {
            Ok((conn, _)) => {
                // The rendezvous grants fds: never answer a stranger.
                let Some(cred) = peer_credentials(&conn) else {
                    warn!("handoff: refused a non-same-uid peer on the rendezvous");
                    continue;
                };
                last_activity = Instant::now();
                let _ = conn.set_nonblocking(false);
                let last = serve_one_handoff_conn(
                    conn,
                    cred,
                    &custody,
                    &mut committed_to,
                    &mut fd_taken_by,
                );
                if last {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(HANDOFF_POLL);
            }
            Err(e) => {
                warn!("handoff: accept: {e}");
                std::thread::sleep(HANDOFF_POLL);
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
    let deadline = Instant::now() + RETIRE_GRACE;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// The handoff rendezvous GRANTS FILE DESCRIPTORS to whoever it
/// answers — it must never answer a stranger. Same effective uid only
/// (SO_PEERCRED on both directions: the old server checks every
/// caller, the new server verifies the old one before adopting its
/// custody). The socket file itself is created 0600; the uid check is
/// the load-bearing half (the default rendezvous lives in /tmp).
pub(crate) fn peer_credentials(stream: &UnixStream) -> Option<libc::ucred> {
    use std::os::unix::io::AsRawFd as _;
    let fd = stream.as_raw_fd();
    let sol = libc::SOL_SOCKET;
    let opt = libc::SO_PEERCRED;
    let len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let mut len_out = len;
    let mut ucred: std::mem::MaybeUninit<libc::ucred> = std::mem::MaybeUninit::uninit();
    let cred_ptr = ucred.as_mut_ptr().cast();
    let len_ptr = &mut len_out as *mut libc::socklen_t;
    // SAFETY: getsockopt(2) with a valid fd, SOL_SOCKET/SO_PEERCRED,
    // and properly sized out-pointers — pure kernel query, no
    // allocation, operands are hoisted bindings.
    let rc = unsafe { libc::getsockopt(fd, sol, opt, cred_ptr, len_ptr) };
    if rc != 0 {
        return None;
    }
    // SAFETY: the getsockopt above returned 0, so the ucred out-
    // pointer was fully initialized by the kernel.
    let ucred = unsafe { ucred.assume_init() };
    // SAFETY: getuid(2) is async-signal-safe and cannot fail.
    let our_uid = unsafe { libc::getuid() };
    (ucred.uid == our_uid).then_some(ucred)
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
    cred: libc::ucred,
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
            // B3: the CLAIMED pid must equal the caller's KERNEL pid
            // (SO_PEERCRED) — claims are worthless here, and a live
            // taker's slot must not be spoofable.
            let kernel_pid = u32::try_from(cred.pid).unwrap_or(u32::MAX);
            if requester_pid != kernel_pid {
                HandoffReply::Error {
                    message: format!(
                        "claimed pid {requester_pid} is not the kernel pid {} — \
                         the kernel verifies identity here",
                        cred.pid
                    ),
                }
            } else if let Some(&first) = fd_taken_by.as_ref() {
                if first != kernel_pid && pid_alive(first) {
                    // First live taker wins; stand down and retry.
                    HandoffReply::Error {
                        message: format!(
                            "custody in flight: server pid {first} already took it over — \
                             stand down and retry if it fails"
                        ),
                    }
                } else {
                    // Same taker re-requesting, or the first died and
                    // the slot is inherited (the resumability contract).
                    *fd_taken_by = Some(kernel_pid);
                    match send_fd_batch(&writer, custody) {
                        Ok(()) => return false,
                        Err(e) => HandoffReply::Error { message: e },
                    }
                }
            } else {
                *fd_taken_by = Some(kernel_pid);
                match send_fd_batch(&writer, custody) {
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
            // B3: only the taker of record may commit — a naked Commit
            // from any other same-uid process must never retire the
            // old pair out from under a live mid-resume successor.
            let committer_pid = u32::try_from(cred.pid).unwrap_or(u32::MAX);
            if committed_to.is_some() {
                HandoffReply::Error {
                    message: "already committed".into(),
                }
            } else if *fd_taken_by != Some(committer_pid) {
                HandoffReply::Error {
                    message: format!(
                        "commit refused: kernel pid {committer_pid} never took custody (holder: {:?})",
                        fd_taken_by
                    ),
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

/// One custody batch out (the single GetFd send path). The batch line
/// IS the reply — `true` means "written, no tail line needed".
fn send_fd_batch(writer: &UnixStream, custody: &SharedCustody) -> Result<(), String> {
    let c = custody.lock().expect("custody lock");
    let raws: Vec<RawFd> = c.fds.iter().map(|f| f.as_raw_fd()).collect();
    send_reply_with_fds(
        writer,
        &HandoffReply::Fd {
            fd_count: raws.len() as u32,
        },
        &raws,
    )
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
    /// The mount-connection fd (custody fd\[0\]) as a raw number for the
    /// child's pre_exec dup2 — the OwnedFd stays owned HERE, keeping
    /// the kernel connection open for the whole daemon lifetime.
    pub fn mount_fd_raw(&self) -> std::os::unix::io::RawFd {
        self.custody.fds[0].as_raw_fd()
    }

    /// Write the serialized session state where the resuming fused
    /// reads it (beside the oracle socket — the stack's own space).
    pub fn write_session_state(&self) -> Result<std::path::PathBuf, String> {
        let path = self.resume_state_path();
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

    /// Where the resuming fused reads its session from.
    fn resume_state_path(&self) -> std::path::PathBuf {
        let mut path = self.handoff_socket.clone();
        let _was = path.set_extension("resume.json");
        path
    }

    /// Remove the resume artifact once adopted (or on degrade — the
    /// next attempt re-serializes it fresh).
    pub fn discard_resume_state(&self) {
        let _ = std::fs::remove_file(self.resume_state_path());
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
/// inherited fd and THEN calls \[`commit_handoff`\]. A failure here is
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
    let status_schema;
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
                abort_handoff(&path, "dialect mismatch");
                return None;
            }
            if let Some(pid) = committed_to {
                warn!("handoff: already committed to server pid {pid} — standing down");
                return None;
            }
            if !has_fd {
                warn!("handoff: the old server holds no custody — fresh mount");
                abort_handoff(&path, "no custody");
                return None;
            }
            status_schema = session_schema;
            info!("handoff: old server live, custody available (schema {session_schema})");
        }
        other => {
            // Unreachable/failed status: nobody proved reachable to
            // abort — nothing to send.
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
            session_schema: status_schema,
        },
        handoff_socket: path,
    })
}

/// B1-b: a DECLINED takeover must not strand the stack — tell the old
/// pair to retire now instead of blocking the mount for the timeout.
fn abort_handoff(socket: &Path, reason: &str) {
    if let Ok(mut conn) = UnixStream::connect(socket) {
        if let Err(e) = handoff_roundtrip(
            &mut conn,
            &HandoffRequest::Abort {
                reason: reason.to_string(),
            },
        ) {
            warn!("handoff: abort after decline failed ({e}) — the old server times out");
        }
    }
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
pub fn engage_handoff(state_file: &Path, timeout: Duration) -> Result<(), String> {
    // B1: custody FIRST, synchronously, BEFORE the Ok — a fused that
    // cannot surrender (the real fused until fd extraction lands)
    // means handoff mode is REFUSED and the client takes the legacy
    // TERM flow, byte for byte today's behavior. Entering handoff
    // mode with empty custody unlinked the stack sockets under a
    // live mount — the production regression the review caught.
    let Some((cmd_sock, oracle_sock)) = STACK_PATHS.get() else {
        return Err("stack paths not recorded (no handoff for this boot)".into());
    };
    let handoff_sock = fuse_protocol::handoff::handoff_socket_path(oracle_sock);

    let mut custody = Custody::default();
    let fused_pid;
    {
        let mut guard = SUPERVISED.lock().expect("supervised lock");
        match guard.as_mut() {
            Some(child) => {
                fused_pid = child.id();
                let hub = OracleHub::clone(&crate::ORACLE_HUB);
                match take_back(oracle_sock, &hub, child)? {
                    Some(c) => {
                        custody.fds = c.fds;
                        custody.session = c.session;
                        custody.session_schema = c.session_schema;
                    }
                    None => {
                        return Err(
                            "handoff unavailable: the supervised fused did not surrender \
                             (no custody — refusing rather than degrading the restart)"
                                .into(),
                        );
                    }
                }
            }
            None => return Err("no supervised fused — handoff mode is meaningless".into()),
        }
    }

    // Record the rendezvous BEFORE the Ok reaches the client.
    record_in_state_file(state_file, &handoff_sock, fused_pid)?;

    // Bind the rendezvous BEFORE the Ok too — the successor may race
    // the reply.
    let _ = std::fs::remove_file(&handoff_sock);
    let listener = UnixListener::bind(&handoff_sock)
        .map_err(|e| format!("bind {}: {e}", handoff_sock.display()))?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = 0o600;
        let _ = std::fs::set_permissions(&handoff_sock, std::fs::Permissions::from_mode(mode));
    }

    // The conductor: grace for the reply, then stop presenting the
    // stack sockets and linger. It owns the rest of the process.
    let custody: SharedCustody = std::sync::Arc::new(std::sync::Mutex::new(custody));
    let cmd_sock = cmd_sock.clone();
    let oracle_sock = oracle_sock.clone();
    // The conductor owns the rest of the process life; the handle
    // is deliberately discarded.
    let _conductor = std::thread::spawn(move || {
        std::thread::sleep(HANDOFF_POLL);
        let _ = std::fs::remove_file(&cmd_sock);
        let _ = std::fs::remove_file(&oracle_sock);
        info!("handoff: lingering (timeout {timeout:?})");
        let child = SUPERVISED.lock().expect("supervised lock").take();
        match child {
            Some(c) => serve_handoff(listener, custody, c, timeout),
            None => unreachable!("the supervised child was present above"),
        }
        std::process::exit(0);
    });
    Ok(())
}

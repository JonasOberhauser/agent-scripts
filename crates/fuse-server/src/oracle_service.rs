//! The policy daemon's oracle service: the adjudication endpoint the
//! data daemon (`fused`) talks to, plus the control channel that pushes
//! content updates to it.
//!
//! Two connection kinds on one listener, distinguished by the first
//! line:
//!
//! * `{"type":"hello"}` — a persistent CONTROL connection; the policy
//!   daemon pushes `Upsert`/`Remove` commands to it as secrets change.
//! * `Ask {...}` — a short-lived (possibly long-blocked, while a
//!   pending waits for a grant) adjudication request.
//!
//! Every Ask runs the full policy pipeline synchronously: hashd
//! package-hash lookup → one-read semantics → pending + wait until
//! grant/expiry → Allow/Deny. The data daemon serves bytes only on
//! Allow.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{error, info, warn};

use fuse_protocol::oracle::{OracleCommand, OracleReply, OracleRequest};
use fuse_protocol::PendingAccessInfo;

use crate::state::{ReadOutcome, ServerState};

/// Live control connections to data daemons: content updates are pushed
/// to every one of them (best effort — a data daemon that vanished is
/// logged, not fatal; its next reconnect re-syncs).
#[derive(Clone, Default)]
pub struct OracleHub {
    controls: Arc<Mutex<Vec<UnixStream>>>,
    /// Latest content state (upserts/removes in order) so a data daemon
    /// connecting LATE still receives every secret.
    snapshot: Arc<Mutex<Vec<OracleCommand>>>,
}

impl OracleHub {
    pub fn new() -> Self {
        Self::default()
    }

    fn broadcast(&self, cmd: &OracleCommand) {
        self.snapshot.lock()
            .expect("oracle hub lock: never held across a panic — poisoning means a server bug").push(cmd.clone());
        let mut controls = self.controls.lock()
            .expect("oracle hub lock: never held across a panic — poisoning means a server bug");
        controls.retain(|stream| {
            let mut w = stream;
            match serde_json::to_string(cmd) {
                Ok(line) => {
                    if writeln!(w, "{line}").and_then(|_| w.flush()).is_ok() {
                        true
                    } else {
                        info!("oracle: data daemon control connection went away");
                        false
                    }
                }
                Err(e) => {
                    warn!("oracle: cannot serialize command: {e}");
                    true
                }
            }
        });
    }

    /// Announce a secret in the frozen mount tree with its CURRENT
    /// host identity (MR4): no content — bytes only ever travel as
    /// fds at open time.
    pub fn serve(&self, name: &str, inner: &str, mode: u32) {
        self.broadcast(&OracleCommand::Serve {
            name: name.to_string(),
            inner: inner.to_string(),
            mode,
        });
    }

    pub fn remove(&self, name: &str) {
        self.broadcast(&OracleCommand::Remove { name: name.to_string() });
    }
}

/// Package hash for the reader, ALWAYS via the hashd helper: this
/// daemon is deliberately unprivileged and must never touch
/// `/proc/<pid>/map_files` itself (that is hashd's one job). Failures
/// carry the commands that fix them, so a pending shown to a human
/// says what to run.
pub(crate) fn compute_pid_hash(
    state: &ServerState,
    pid: u32,
) -> (Option<String>, Option<String>) {
    // Resolved once at construction (immutable field, borrowed for
    // the whole call — no guard to own it out of): production keeps
    // the ambient env->default resolution; in-process harnesses pin
    // it pre-share (#69).
    let socket = state.hashd_sock.as_str();
    // ask() honors the #38 busy-retry promise internally.
    match fuse_protocol::hashd::ask(socket, pid) {
        Ok(h) => (Some(h), None),
        Err(hashd_err) => {
            let hash_error = fuse_protocol::hashd::actionable_error(
                &hashd_err,
                socket,
                sibling_hashd_binary().as_deref(),
            );
            warn!("hashd ({socket}) could not hash pid {pid}: {hash_error}");
            (None, Some(hash_error))
        }
    }
}

/// Where a hashd binary lives next to this server, so remediation can
/// name a runnable command instead of a placeholder: cargo builds every
/// workspace binary into the same target dir.
fn sibling_hashd_binary() -> Option<String> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("hashd")))
        .filter(|p| p.exists())
        .map(|p| p.display().to_string())
}

fn process_name(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Adjudicate one Ask end-to-end, including blocking on a pending until
/// it is granted or expires.
/// Stat a secret's host file by name (MR4): live identity + attrs,
/// no adjudication — metadata visibility is unchanged from the
/// snapshot era.
fn stat_secret(state: &ServerState, name: &str) -> OracleReply {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Some(host) = state.host_path(name) else {
        return OracleReply::Gone;
    };
    match std::fs::metadata(&host) {
        Ok(md) => OracleReply::StatOk {
            kdev: fuse_protocol::KDev(md.dev()),
            kino: fuse_protocol::Kino(md.ino()),
            size: md.len(),
            mode: md.permissions().mode() & 0o7777,
            regular: md.is_file(),
        },
        Err(_) => OracleReply::Gone,
    }
}

/// Write `line` to the stream with `fds` attached as SCM_RIGHTS.
/// Extracted so the failure path is observable (PR #48 review: the
/// lost-fd case used to be silent, hanging the reader).
fn send_reply_with_fd(
    stream: &std::os::unix::net::UnixStream,
    line: &str,
    fds: &[std::os::unix::io::RawFd],
) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;
    let iov = [std::io::IoSlice::new(line.as_bytes())];
    let cmsg = nix::sys::socket::ControlMessage::ScmRights(fds);
    let _sent = nix::sys::socket::sendmsg::<()>(
        stream.as_raw_fd(),
        &iov,
        &[cmsg],
        nix::sys::socket::MsgFlags::empty(),
        None,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Adjudicated open (MR4): verify the incarnation, run the one-read +
/// hash policy (the same adjudication Ask uses, at open time), and on
/// Allow hand the host fd to fused as SCM_RIGHTS ancillary data on
/// the reply line — the policy daemon NEVER reads content, it only
/// opens and passes descriptors.
fn open_secret(
    state: &ServerState,
    name: &str,
    pid: u32,
    kdev: fuse_protocol::KDev,
    kino: fuse_protocol::Kino,
    stream: &mut std::os::unix::net::UnixStream,
) {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;

    let reply_line = |r: &OracleReply| -> String {
        serde_json::to_string(r)
            .expect("serializing oracle reply: internal enum, infallible")
    };

    let Some(host) = state.host_path(name) else {
        let _ = writeln!(stream, "{}", reply_line(&OracleReply::Gone));
        let _ = stream.flush();
        return;
    };
    let Ok(file) = std::fs::File::open(&host) else {
        let _ = writeln!(stream, "{}", reply_line(&OracleReply::Gone));
        let _ = stream.flush();
        return;
    };
    // The descriptor's OWN identity — atomic open+verify (no TOCTOU
    // between a path stat and the open).
    let Ok(md) = file.metadata() else {
        let _ = writeln!(stream, "{}", reply_line(&OracleReply::Gone));
        let _ = stream.flush();
        return;
    };
    if !md.is_file() {
        let _ = writeln!(stream, "{}", reply_line(&OracleReply::Gone));
        let _ = stream.flush();
        return;
    }
    if fuse_protocol::KDev(md.dev()) != kdev || fuse_protocol::Kino(md.ino()) != kino {
        // Host incarnation changed since the caller's inode was
        // recorded: the file it asked about no longer exists. ESTALE
        // makes the kernel re-resolve and pick up the new incarnation.
        let _ = writeln!(stream, "{}", reply_line(&OracleReply::Stale));
        let _ = stream.flush();
        return;
    }
    // Live size refreshes the adjudication record.
    state.observe_size(name, md.len() as usize);
    match adjudicate(state, name, pid, 0, md.len() as usize) {
        OracleReply::Allow => {
            // SAFETY: nix sendmsg writes the reply line with the fd as
            // SCM_RIGHTS ancillary data; the kernel duplicates the
            // descriptor into the receiving process.
            let fds = [file.as_raw_fd()];
            let line = reply_line(&OracleReply::Allow);
            if let Err(e) = send_reply_with_fd(stream, &line, &fds) {
                // The reader would otherwise wait on silence until its
                // open deadline. Say why it failed, then answer with a
                // plain Error line so it fails fast instead.
                error!("open {name}: fd pass to data daemon failed: {e}");
                let _ = writeln!(
                    stream,
                    "{}",
                    reply_line(&OracleReply::Error {
                        message: "fd pass failed".into()
                    })
                );
                let _ = stream.flush();
                return;
            }
            let _ = stream.flush();
            // Our copy closes on drop; fused holds its own now.
        }
        other => {
            let _ = writeln!(stream, "{}", reply_line(&other));
            let _ = stream.flush();
        }
    }
}

fn adjudicate(state: &ServerState, name: &str, pid: u32, offset: usize, size: usize) -> OracleReply {
    let (pid_hash, hash_error) = compute_pid_hash(state, pid);
    match state.attempt_read(name, pid, pid_hash.as_deref(), offset, size) {
        ReadOutcome::Granted => OracleReply::Allow,
        ReadOutcome::DeniedLocked => OracleReply::Deny {
            errno: libc::EACCES,
            reason: "lockdown armed: new unauthorized access is refused".into(),
        },
        ReadOutcome::NotFound => OracleReply::Deny {
            errno: libc::ENOENT,
            reason: "secret not found".into(),
        },
        ReadOutcome::AlreadyAccessed | ReadOutcome::HashMismatch { .. } => {
            // Narrowed above; re-run only to fetch the denial text.
            let reason = state
                .attempt_read(name, pid, None, offset, size)
                .denial_reason()
                .unwrap_or_else(|| "access denied".into());
            let timeout = *state
            .pending_timeout
            .lock()
            .expect("pending-timeout lock: never held across a panic");
            if timeout.is_zero() {
                return OracleReply::Deny { errno: libc::EACCES, reason };
            }
            let id = state.create_pending_with_hash_error(
                name,
                pid,
                pid_hash.as_deref(),
                hash_error.as_deref(),
                &reason,
                process_name(pid).as_deref(),
            );
            info!(
                "Access pending for '{name}' by pid {pid}: {reason} (id={id}). \
                 Waiting up to {}s for grant...",
                timeout.as_secs()
            );
            let deadline = Instant::now() + timeout;
            loop {
                if state.is_pending_granted(id) {
                    state.remove_pending(id);
                    if state.granted_read(name, pid, offset, size) {
                        return OracleReply::Allow;
                    }
                    return OracleReply::Deny {
                        errno: libc::ENOENT,
                        reason: "secret vanished while granted".into(),
                    };
                }
                // Expiry FIRST (issue #66): the honest reason at the
                // boundary is "expired", and the entry is RETAINED —
                // a hash-bearing one becomes a remembered denial for
                // the panel; cleanup drops the anonymous ones.
                if Instant::now() > deadline {
                    warn!("Pending access {id} timed out");
                    return OracleReply::Deny { errno: libc::EACCES, reason: format!("pending {id} expired: {reason}") };
                }
                if state.is_pending_denied(id) {
                    // An operator deny releases the blocked reader AT
                    // ONCE — waiting out the timeout would pin the
                    // reading process for minutes after the decision
                    // was already made.
                    return OracleReply::Deny {
                        errno: libc::EPERM,
                        reason: format!("pending {id} denied: {reason}"),
                    };
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

/// One accepted connection: control (`hello` first) or asks.
fn handle_conn(state: &Arc<ServerState>, hub: &OracleHub, conn: UnixStream) {
    // #103: a SurrenderPayload connection carries its fd batch as
    // SCM_RIGHTS on the FIRST line — ancillary data cannot pass
    // through a buffered reader (it would be swallowed), so peek the
    // first line with recvmsg BEFORE any BufReader exists.
    {
        let (line, fds) = match recv_first_line_with_fds(&conn) {
            Ok(x) => x,
            Err(e) => {
                warn!("oracle: first-line recv failed ({e}) — closing");
                return;
            }
        };
        if let Ok(OracleRequest::SurrenderPayload {
            session_schema,
            state: payload,
        }) = serde_json::from_str::<OracleRequest>(line.trim())
        {
            info!(
                "oracle: takeover payload received (schema {session_schema}, {} fds)",
                fds.len()
            );
            let mut mbox = TAKEOVER_MAILBOX
                .lock()
                .expect("takeover lock: no panics under it by contract");
            *mbox = Some(TakeoverPayload {
                fds,
                session_schema,
                state: payload,
            });
            return;
        }
        // Not a payload: continue with the buffered handling of the
        // same first line (recvmsg consumed it raw).
        handle_conn_first(state, hub, conn, line);
    }
}

/// The buffered path, with the first line already consumed raw.
fn handle_conn_first(
    state: &Arc<ServerState>,
    hub: &OracleHub,
    conn: UnixStream,
    first: String,
) {
    let mut reader = BufReader::new(match conn.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    });
    let mut stream = conn;
    let mut first = first;
    let _ = &mut first;
    // Control connection: hello — register and hold the stream open;
    // the hub writes commands into it.
    if let Ok(OracleRequest::Hello { version }) = serde_json::from_str(first.trim()) {
        // Mixed vintages are the #37 field-report failure mode: an old
        // `fused` still holding the mount speaks a protocol the new
        // server's upserts no longer match, and every read goes ENOENT
        // with nothing in any log. Surface the skew the moment we can
        // see it. Old daemons send no version — we cannot check those.
        match version.as_deref() {
            Some(v) if !fuse_protocol::versions_compatible(v, fuse_protocol::VERSION) => {
                warn!(
                    "data daemon reports protocol v{} vs server v{} — mixed vintages; \
                     requesting the mount session (Surrender, #103)",
                    v, fuse_protocol::VERSION
                );
                // #103 fd handover: ask the incompatible daemon for its
                // mount session instead of parking it. A daemon that
                // knows the word answers with a SurrenderPayload
                // connection; one that doesn't ignores it (logged as an
                // unrecognized line on its side) and the gate times out
                // into the fresh-mount fallback. Either way it is NOT
                // registered into the hub — an incompatible daemon must
                // not receive this-vintage Serve pushes.
                let line = serde_json::to_string(&OracleCommand::Surrender)
                    .expect("internal enum: infallible");
                let _w = writeln!(stream, "{line}");
                let _f = stream.flush();
                let pid = peer_pid(&stream);
                let mut pending = TAKEOVER_PENDING
                    .lock()
                    .expect("takeover lock: no panics under it by contract");
                *pending = Some(TakeoverPending {
                    daemon_pid: pid,
                    control: stream.try_clone().ok(),
                });
                // The gate must still LEARN about the incompatible
                // daemon (its offer carries the version) so the
                // takeover branch can run — mismatch ≠ invisible.
                if let Some(pid) = pid {
                    let mut slot = ADOPTION_OFFER
                        .lock()
                        .expect("adoption slot: no panics under the lock by contract");
                    *slot = Some(AdoptionOffer {
                        pid,
                        version: version.clone(),
                    });
                }
                return; // hold nothing further on THIS thread's borrow
            }
            _ => {}
        }
        // #103: a compatible Hello from a takeover-successor wakes
        // the transplant loop (its Retire step waits for this).
        RESUMED_HELLO.store(true, std::sync::atomic::Ordering::SeqCst);
        // Offer ourselves to the adoption gate (#93): the startup
        // window polls this slot; a surviving daemon's reconnect IS
        // the adoption handshake — no new protocol.
        if let Some(pid) = peer_pid(&stream) {
            let mut slot = ADOPTION_OFFER
                .lock()
                .expect("adoption slot: no panics under the lock by contract");
            *slot = Some(AdoptionOffer {
                pid,
                version: version.clone(),
            });
        }
        let _ = writeln!(stream, "{}", serde_json::to_string(&OracleReply::Ok)
                .expect("serializing Ok ack: internal enum, infallible"));
        // Replay the content snapshot: late joiners get every secret.
        for cmd in hub.snapshot.lock()
            .expect("oracle hub lock: never held across a panic — poisoning means a server bug").iter() {
            let _ = writeln!(stream, "{}", serde_json::to_string(cmd)
                .expect("serializing replayed command: internal enum, infallible"));
        }
        let _ = stream.flush();
        // Bound the hub's writes to this connection (issue #77): a
        // stuck-but-alive data daemon — socket buffer full, peer not
        // reading — would otherwise block broadcast FOREVER while it
        // holds the hub lock, freezing every AddSecret/Remove on the
        // command socket. A healthy local daemon drains its socket in
        // microseconds; 2s is generous. On timeout the write errors
        // and broadcast drops the connection exactly like a dead peer
        // (logged below); the daemon's reconnect re-syncs from the
        // snapshot.
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
        hub.controls.lock()
            .expect("oracle hub lock: never held across a panic — poisoning means a server bug").push(stream);
        return;
    }
    // Otherwise: one or more requests on this connection.
    let mut line = first;
    loop {
        match serde_json::from_str::<OracleRequest>(line.trim()) {
            Ok(OracleRequest::Ask { name, pid, offset, size }) => {
                let reply = adjudicate(state, &name, pid, offset as usize, size as usize);
                let _ = writeln!(stream, "{}", serde_json::to_string(&reply)
                .expect("serializing reply line: internal enum, infallible"));
                let _ = stream.flush();
            }
            Ok(OracleRequest::Stat { name }) => {
                let reply = stat_secret(state, &name);
                let _ = writeln!(stream, "{}", serde_json::to_string(&reply)
                .expect("serializing reply line: internal enum, infallible"));
                let _ = stream.flush();
            }
            Ok(OracleRequest::Open { name, pid, kdev, kino }) => {
                open_secret(state, &name, pid, kdev, kino, &mut stream);
            }
            _ => {
                let _ = writeln!(
                    stream,
                    "{}",
                    serde_json::to_string(&OracleReply::Error { message: "malformed request".into() })
                        .expect("serializing Error reply: internal enum, infallible")
                );
                return;
            }
        }
        line.clear();
        if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
            return;
        }
    }
}

/// Process-wide hub the protocol closures use to forward content
/// changes (the servatui protocols close over `&ServerState` only).
pub static ORACLE_HUB: std::sync::LazyLock<OracleHub> = std::sync::LazyLock::new(OracleHub::new);

/// A daemon's Hello, offered to the adoption gate (#93 adopt-the-
/// survivor): filled by every control connection, consumed by the
/// startup gate that decides adopt-vs-spawn.
#[derive(Debug, Clone)]
pub struct AdoptionOffer {
    pub pid: u32,
    pub version: Option<String>,
}

pub static ADOPTION_OFFER: std::sync::Mutex<Option<AdoptionOffer>> =
    std::sync::Mutex::new(None);

/// #103 fd handover: the incompatible daemon's CONTROL connection
/// (kept for the Retire word once the successor serves), plus its pid.
pub struct TakeoverPending {
    pub daemon_pid: Option<u32>,
    pub control: Option<UnixStream>,
}

pub static TAKEOVER_PENDING: std::sync::Mutex<Option<TakeoverPending>> =
    std::sync::Mutex::new(None);

/// A received takeover payload: the fd batch (fd\[0\] = the live
/// /dev/fuse connection, fd\[1..\] = open host fds) and the
/// session-state envelope (schema + opaque JSON).
pub struct TakeoverPayload {
    pub fds: Vec<std::os::fd::OwnedFd>,
    pub session_schema: u32,
    pub state: serde_json::Value,
}

pub static TAKEOVER_MAILBOX: std::sync::Mutex<Option<TakeoverPayload>> =
    std::sync::Mutex::new(None);

/// #103: set on every COMPATIBLE Hello — the takeover transplant
/// loop watches it to learn its successor is serving (then Retires
/// the old daemon). The adoption gate consumed its own offer first,
/// so a regular adopted daemon's Hello cannot false-wake a transplant
/// (transplant only runs on the incompatible path).
pub static RESUMED_HELLO: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The kernel-verified pid of the connected peer (SO_PEERCRED).
/// Read the first line WITH any SCM_RIGHTS batch attached to it
/// (#103 takeover payloads). Stream sockets deliver ancillary data
/// with some byte range — recvmsg until the newline, collecting fds
/// from every cmsg that arrives.
fn recv_first_line_with_fds(
    conn: &UnixStream,
) -> Result<(String, Vec<std::os::fd::OwnedFd>), String> {
    use std::os::fd::AsRawFd as _;
    use std::os::fd::FromRawFd as _;
    let mut line = Vec::new();
    let mut owned_fds: Vec<std::os::fd::OwnedFd> = Vec::new();
    let fd = conn.as_raw_fd();
    let mut buf = [0u8; 4096];
    let mut cmsg_space = nix::cmsg_space!(libc::cmsghdr, std::os::unix::io::RawFd);
    loop {
        let n = {
            let mut iov = [std::io::IoSliceMut::new(&mut buf)];
            let msg = nix::sys::socket::recvmsg::<()>(
                fd,
                &mut iov,
                Some(&mut cmsg_space),
                nix::sys::socket::MsgFlags::empty(),
            )
            .map_err(|e| format!("recvmsg: {e}"))?;
            let mut collected: Vec<std::os::fd::OwnedFd> = Vec::new();
            let cmsgs: Vec<_> = msg.cmsgs().map(|it| it.collect()).unwrap_or_default();
            for c in cmsgs {
                if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = c {
                    for raw in fds {
                        // SAFETY: the kernel placed this fd in our table.
                        collected.push(unsafe {
                            std::os::fd::OwnedFd::from_raw_fd(raw)
                        });
                    }
                }
            }
            owned_fds.extend(collected);
            msg.bytes
        };
        if n == 0 {
            return Err("connection closed before a full line".into());
        }
        line.extend_from_slice(&buf[..n]);
        if let Some(nl) = line.iter().position(|&b| b == b'\n') {
            line.truncate(nl);
            return Ok((String::from_utf8_lossy(&line).into_owned(), owned_fds));
        }
    }
}

pub(crate) fn peer_pid(stream: &UnixStream) -> Option<u32> {
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
    // properly sized out-pointers — pure kernel query, no allocation.
    let rc = unsafe { libc::getsockopt(fd, sol, opt, cred_ptr, len_ptr) };
    if rc != 0 {
        return None;
    }
    // SAFETY: rc == 0, so the kernel fully initialized the ucred.
    Some(unsafe { ucred.assume_init() }.pid as u32)
}

/// Run the oracle listener. Blocks.
pub fn run_oracle_server(socket_path: &std::path::Path, state: Arc<ServerState>, hub: OracleHub) -> Result<(), String> {
    let stop = std::sync::atomic::AtomicBool::new(false);
    run_oracle_server_with_stop(socket_path, state, hub, &stop)
}

/// Like [`run_oracle_server`], with a stop seam for long-running test
/// harnesses (the e2e fuzz marathon): set the flag and connect once
/// (the poison pill wakes the blocking accept) — the loop exits and
/// the thread reclaims. Without it, every stack-up leaked one immortal
/// accept thread, and ~2k fuzz worlds hit the process/thread limit
/// (the fused under test then died spawning its own threads).
pub fn run_oracle_server_with_stop(
    socket_path: &std::path::Path,
    state: Arc<ServerState>,
    hub: OracleHub,
    stop: &std::sync::atomic::AtomicBool,
) -> Result<(), String> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).map_err(|e| e.to_string())?;
    info!("Oracle server listening at {}", socket_path.display());
    for conn in listener.incoming().flatten() {
        if stop.load(std::sync::atomic::Ordering::Acquire) {
            info!("oracle: stop requested — shutting down the listener");
            break;
        }
        let state = Arc::clone(&state);
        let hub = hub.clone();
        let _conn_thread = std::thread::spawn(move || handle_conn(&state, &hub, conn));
    }
    Ok(())
}

/// Convenience for callers/tests: one blocking ask against a listener.
pub fn ask(socket_path: &std::path::Path, name: &str, pid: u32, offset: u64, size: u32) -> Result<OracleReply, String> {
    let mut conn = UnixStream::connect(socket_path).map_err(|e| e.to_string())?;
    let req = serde_json::to_string(&OracleRequest::Ask { name: name.into(), pid, offset, size })
        .map_err(|e| e.to_string())?;
    conn.write_all(format!("{req}\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(conn.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    let _n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(line.trim()).map_err(|e| e.to_string())
}

/// Unused import guard for PendingAccessInfo (kept for API parity in tests).
#[allow(dead_code)]
fn _pending_type_witness(_: Option<PendingAccessInfo>) {}


#[cfg(test)]
mod takeover_wire_tests {
    use super::*;
    use std::os::fd::AsRawFd as _;

    /// The payload path end to end in-process: a fake daemon sends
    /// the SurrenderPayload line with an SCM_RIGHTS batch; the
    /// receiver must yield the line AND the fds.
    #[test]
    fn recv_first_line_with_fds_gets_line_and_batch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let f = tempfile::tempfile().unwrap();
        let fd = f.as_raw_fd();
        let payload = serde_json::json!({
            "type": "surrender_payload",
            "session_schema": 1,
            "state": {"next_fino": 1, "tree": [], "labels": [], "identities": [], "open_fds": [], "proto_major": 7, "proto_minor": 9}
        });
        std::thread::spawn(move || {
            let c = UnixStream::connect(&path).unwrap();
            let bytes = format!("{payload}\n");
            let iov = [std::io::IoSlice::new(bytes.as_bytes())];
            let cmsg = nix::sys::socket::ControlMessage::ScmRights(&[fd]);
            let _sent = nix::sys::socket::sendmsg::<()>(
                c.as_raw_fd(), &iov, &[cmsg],
                nix::sys::socket::MsgFlags::empty(), None,
            ).unwrap();
        });
        let (conn, _) = listener.accept().unwrap();
        let (line, fds) = recv_first_line_with_fds(&conn)
            .unwrap_or_else(|e| panic!("recv failed: {e}"));
        assert!(line.contains("surrender_payload"), "{line}");
        assert_eq!(fds.len(), 1);
        use std::io::Read as _;
        let mut probe = std::fs::File::from(fds.into_iter().next().unwrap());
        let mut buf = [0u8; 1];
        let _ = probe.read(&mut buf);
    }
}

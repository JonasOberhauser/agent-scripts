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

use tracing::{info, warn};

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
        self.snapshot.lock().unwrap().push(cmd.clone());
        let mut controls = self.controls.lock().unwrap();
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

    pub fn upsert(&self, name: &str, content: &[u8], mode: u32) {
        self.broadcast(&OracleCommand::Upsert {
            name: name.to_string(),
            content: content.to_vec(),
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
pub(crate) fn compute_pid_hash(pid: u32) -> (Option<String>, Option<String>) {
    let socket = std::env::var("FUSE_HASHD_SOCK")
        .unwrap_or_else(|_| fuse_protocol::hashd::DEFAULT_SOCK.to_string());
    match fuse_protocol::hashd::ask(&socket, pid) {
        Ok(h) => (Some(h), None),
        Err(hashd_err) => {
            let hash_error = fuse_protocol::hashd::actionable_error(
                &hashd_err,
                &socket,
                sibling_hashd_binary().as_deref(),
            );
            warn!("hashd ({socket}) could not hash pid {pid}: {hashd_err}");
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
fn adjudicate(state: &ServerState, name: &str, pid: u32, offset: usize, size: usize) -> OracleReply {
    let (pid_hash, hash_error) = compute_pid_hash(pid);
    match state.attempt_read(name, pid, pid_hash.as_deref(), offset, size) {
        ReadOutcome::Granted => OracleReply::Allow,
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
            let timeout = *state.pending_timeout.lock().unwrap();
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
                if state.is_pending_denied(id) {
                    // A deny releases the blocked reader AT ONCE — waiting
                    // out the timeout would pin the reading process for
                    // minutes after the decision was already made.
                    return OracleReply::Deny {
                        errno: libc::EPERM,
                        reason: format!("pending {id} denied: {reason}"),
                    };
                }
                if Instant::now() > deadline {
                    state.remove_pending(id);
                    warn!("Pending access {id} timed out");
                    return OracleReply::Deny { errno: libc::EACCES, reason: format!("pending {id} expired: {reason}") };
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

/// One accepted connection: control (`hello` first) or asks.
fn handle_conn(state: &Arc<ServerState>, hub: &OracleHub, conn: UnixStream) {
    let mut reader = BufReader::new(match conn.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    });
    let mut stream = conn;
    let mut first = String::new();
    if reader.read_line(&mut first).is_err() {
        return;
    }
    // Control connection: hello — register and hold the stream open;
    // the hub writes commands into it.
    if let Ok(OracleRequest::Hello) = serde_json::from_str(first.trim()) {
        let _ = writeln!(stream, "{}", serde_json::to_string(&OracleReply::Ok).unwrap());
        // Replay the content snapshot: late joiners get every secret.
        for cmd in hub.snapshot.lock().unwrap().iter() {
            let _ = writeln!(stream, "{}", serde_json::to_string(cmd).unwrap());
        }
        let _ = stream.flush();
        hub.controls.lock().unwrap().push(stream);
        return;
    }
    // Otherwise: one or more asks on this connection.
    let mut line = first;
    loop {
        match serde_json::from_str::<OracleRequest>(line.trim()) {
            Ok(OracleRequest::Ask { name, pid, offset, size }) => {
                let reply = adjudicate(state, &name, pid, offset as usize, size as usize);
                let _ = writeln!(stream, "{}", serde_json::to_string(&reply).unwrap());
                let _ = stream.flush();
            }
            _ => {
                let _ = writeln!(
                    stream,
                    "{}",
                    serde_json::to_string(&OracleReply::Error { message: "malformed request".into() }).unwrap()
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

/// Run the oracle listener. Blocks.
pub fn run_oracle_server(socket_path: &std::path::Path, state: Arc<ServerState>, hub: OracleHub) -> Result<(), String> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).map_err(|e| e.to_string())?;
    info!("Oracle server listening at {}", socket_path.display());
    for conn in listener.incoming().flatten() {
        let state = Arc::clone(&state);
        let hub = hub.clone();
        std::thread::spawn(move || handle_conn(&state, &hub, conn));
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
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(line.trim()).map_err(|e| e.to_string())
}

/// Unused import guard for PendingAccessInfo (kept for API parity in tests).
#[allow(dead_code)]
fn _pending_type_witness(_: Option<PendingAccessInfo>) {}

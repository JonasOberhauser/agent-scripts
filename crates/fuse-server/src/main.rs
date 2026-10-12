//! fuse-server: the POLICY daemon of the gatekeeper split.
//!
//! It owns the trust decisions (one-read semantics, package hashes via
//! hashd, pendings, grants), the servatui command socket for
//! fuse-client, and the oracle endpoint the data daemon (`fused`)
//! connects to. It holds NO secret bytes in split mode: content goes to
//! the data daemon through the oracle hub, metadata stays here.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic, unused_results))]

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use clap::Parser;
use tracing::{error, info, warn};

use fuse_server::{handoff, OracleHub, ServerState};

#[derive(Parser)]
#[command(name = fuse_protocol::SERVER_BIN, about = "FUSE gatekeeper POLICY daemon (decisions + command socket; data lives in fused)")]
struct Cli {
    /// Accepted for backward compatibility with older orchestrators;
    /// mounting is the data daemon's job now.
    #[arg(short, long)]
    mount_point: Option<PathBuf>,
    #[arg(short, long, default_value = fuse_protocol::DEFAULT_CMD_SOCKET)]
    socket: PathBuf,
    /// Boot-time secret: NAME, FILE, HASH as three words — no
    /// delimiter grammar, nothing to escape (colons are ordinary
    /// path characters). Repeatable.
    #[arg(long, num_args = 3, value_names = ["NAME", "FILE", "HASH"])]
    secret: Vec<String>,
    #[arg(long)]
    allow_other: bool,
    /// Substitute the supervised data-daemon binary (issue #94): the
    /// supervision seam — tests drive the lifecycle with a fake fused
    /// that needs no kernel FUSE mount. Same argv otherwise.
    #[arg(long)]
    fused_binary: Option<std::path::PathBuf>,
    #[arg(long, default_value = "info")]
    log_level: String,
    #[arg(long, default_value_t = 300)]
    pending_timeout: u64,
    #[arg(long, default_value = fuse_protocol::DEFAULT_LOG_PATH)]
    log_path: PathBuf,
    /// Socket where the data daemon (fused) connects for adjudication
    /// and content updates.
    #[arg(long, default_value = fuse_protocol::DEFAULT_ORACLE_SOCKET)]
    oracle_socket: PathBuf,
}

/// Pre-computed CStrings for async-signal-safe unlink in the handler.
static CLEANUP_SOCKETS: OnceLock<(std::ffi::CString, std::ffi::CString)> = OnceLock::new();

extern "C" fn shutdown_handler(_sig: libc::c_int) {
    if let Some((cmd, oracle)) = CLEANUP_SOCKETS.get() {
        // Signal-handler context — only unlink(2) (async-signal-safe)
        // on CStrings precomputed before the handler was armed; no
        // allocation, locks, or Rust runtime calls. One op per block.
        let cmd_ptr = cmd.as_ptr();
        // SAFETY: see above.
        let _unlinked = unsafe { libc::unlink(cmd_ptr) };
        let oracle_ptr = oracle.as_ptr();
        // SAFETY: see above.
        let _unlinked = unsafe { libc::unlink(oracle_ptr) };
    }
    let code = 130;
    // SAFETY: _exit(2) is the async-signal-safe way out of a handler; it
    // intentionally skips atexit/destructors to avoid non-signal-safe
    // cleanup in this context.
    unsafe { libc::_exit(code) }
}

// Supervised data daemon: lives in the handoff module (the conductor
// needs it for take-back and retirement; the signal path predates
// this and never touches the child — kill -9 leaves the orphan to
// the restart path, by design).

/// Spawn the supervised data daemon (#93 F2): resuming an inherited
/// mount-connection fd when a handoff takeover provided one — the fd
/// reaches the child at fd 3 by exec inheritance (pre_exec dup2, the
/// async-signal-safe pair of fork and exec), with the serialized
/// session state beside it; the child ADOPTS the session instead of
/// mounting fresh.
fn spawn_fused(
    cli: &Cli,
    mount_point: &Path,
    takeover: Option<&handoff::Takeover>,
) -> Result<std::process::Child, String> {
    let exe = std::env::current_exe().expect("current exe");
    let sibling = exe
        .parent()
        .map(|d| d.join(fuse_protocol::FUSED_BIN))
        .filter(|p| p.exists());
    let fused = cli.fused_binary.clone().or(sibling);
    let Some(fused) = fused else {
        return Err(format!(
            "no data daemon found next to {} — build it (cargo build --workspace)",
            exe.display()
        ));
    };
    let mut cmd = std::process::Command::new(&fused);
    let _args = cmd
        .arg("--mount-point")
        .arg(mount_point)
        .arg(fuse_protocol::ORACLE_SOCKET_FLAG)
        .arg(&cli.oracle_socket);
    if let Some(tk) = takeover {
        let raw = tk.mount_fd_raw();
        let state_path = tk
            .write_session_state()
            .map_err(|e| format!("resume state: {e}"))?;
        let _resume_args = cmd
            .arg("--resume-fd")
            .arg("3")
            .arg("--resume-state")
            .arg(&state_path);
        // SAFETY: pre_exec runs between fork and exec; dup2(2) and
        // close-on-nothing are async-signal-safe, the operand is a
        // plain descriptor number of an open file this process owns.
        let set_fd = move || {
            // SAFETY: dup2(2) on one owned descriptor number —
            // async-signal-safe between fork and exec by contract.
            let rc = unsafe { libc::dup2(raw, 3) };
            if rc == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        };
        use std::os::unix::process::CommandExt as _;
        // SAFETY: the closure performs only dup2(2) — async-signal-
        // safe between fork and exec, on a descriptor this process
        // owns; the builder return is chained, not a result.
        let _builder = unsafe { cmd.pre_exec(set_fd) };
    }
    cmd.spawn()
        .map_err(|e| format!("spawn {}: {e}", fused.display()))
}

fn stale_socket(path: &Path) {
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            error!(
                "Another server is running at {}. Kill it first.",
                path.display()
            );
            std::process::exit(1);
        }
        warn!("Removing stale socket at {}", path.display());
        let _ = std::fs::remove_file(path);
    }
}

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::builder().parse_lossy(&cli.log_level))
        .init();

    info!(
        "fuse-server (policy daemon) v{} starting",
        fuse_protocol::VERSION
    );
    info!("  socket:          {}", cli.socket.display());
    info!("  oracle-socket:   {}", cli.oracle_socket.display());
    info!("  pending-timeout: {}s", cli.pending_timeout);

    // Boot-time records for the handoff conductor (#93 F2).
    let _recorded = handoff::STACK_PATHS.set((cli.socket.clone(), cli.oracle_socket.clone()));

    // NEW side (#93 F2): a pending handoff in the state file means an
    // old server lingers with the custody — take it over BEFORE
    // spawning anything, so the new fused can RESUME the mount
    // session instead of mounting fresh. None = no handoff (or it
    // declined); the spawn below is then the ordinary one.
    let state_file = std::env::var_os(fuse_protocol::ENV_STATE_FILE).map(std::path::PathBuf::from);
    let mut takeover = state_file.as_deref().and_then(handoff::resume_from_handoff);
    if takeover.is_some() {
        info!("  handoff: custody taken over — the new fused will resume the mount session");
    }

    // --mount-point means SUPERVISE a data daemon at that mount point
    // (the one-command contract of the old monolith): spawn fused next
    // to this binary and keep it as a child; on our exit it dies too.
    if let Some(mp) = &cli.mount_point {
        info!(
            "  mount-point:     {} (spawning supervised data daemon)",
            mp.display()
        );
        match spawn_fused(&cli, mp, takeover.as_ref()) {
            Ok(c) => {
                let _replaced = handoff::SUPERVISED
                    .lock()
                    .expect("supervised-fused lock: set once at spawn")
                    .replace(c);
            }
            Err(e) => {
                if takeover.is_some() {
                    // The resume spawn failed: degrade to the fresh
                    // mount. Dropping OUR custody copy is safe — the
                    // old server holds its own until commit, and
                    // without a resuming daemon the mount cannot be
                    // served by this pair anyway.
                    error!("resume spawn failed ({e}) — degrading to a fresh mount");
                    takeover = None;
                    match spawn_fused(&cli, mp, None) {
                        Ok(c) => {
                            let _replaced = handoff::SUPERVISED
                                .lock()
                                .expect("supervised-fused lock")
                                .replace(c);
                        }
                        Err(e2) => error!("cannot spawn data daemon: {e2}"),
                    }
                } else {
                    // The #37 field-report trap: serving adds with no
                    // data daemon looks "healthy" while nothing reaches
                    // a mount — fail loudly instead.
                    error!("{e} — refusing to run mount-less");
                    std::process::exit(1);
                }
            }
        }
    }

    stale_socket(&cli.socket);
    stale_socket(&cli.oracle_socket);

    if let (Ok(a), Ok(b)) = (
        std::ffi::CString::new(cli.socket.to_string_lossy().as_bytes()),
        std::ffi::CString::new(cli.oracle_socket.to_string_lossy().as_bytes()),
    ) {
        let _set = CLEANUP_SOCKETS.set((a, b)).ok();
    }
    // SAFETY: the registered handler performs only async-signal-safe
    // operations (see its own SAFETY note); signal(2) stores the raw
    // handler address, which outlives the process lifetime (a static
    // extern "C" fn).
    let handler = shutdown_handler as *const () as usize;
    let sigint = libc::SIGINT;
    // SAFETY: the registered handler performs only async-signal-safe
    // operations (see its own SAFETY note); signal(2) stores the raw
    // handler address, which outlives the process lifetime (a static
    // extern "C" fn).
    let _prev = unsafe { libc::signal(sigint, handler) };
    let sigterm = libc::SIGTERM;
    // SAFETY: as above.
    let _prev = unsafe { libc::signal(sigterm, handler) };

    // ── State: metadata here, content pushed to the data daemon ──
    let mut state = ServerState::new();
    state.pending_timeout = std::sync::Mutex::new(Duration::from_secs(cli.pending_timeout));
    state.log_path = cli.log_path.to_string_lossy().to_string();
    // MR5: arm persistence and LOAD BEFORE ANY SOCKET ACCEPTS — a
    // grant decided against unloaded state is the bug class this
    // exists to kill. (CLI secrets load after; adds JOIN their hash
    // sets per the overwrite semantics, so nothing loaded is lost.)
    state.policy_path = Some(fuse_server::policy_store::policy_path());
    {
        use fuse_server::policy_store;
        let hub = OracleHub::clone(&fuse_server::ORACLE_HUB);
        let report = policy_store::load(&mut state, &hub);
        info!(
            "  policy store:    {} restored, {} ghosts{}",
            report.restored,
            report.ghosts,
            if report.corrupted {
                " — CORRUPT FILE RENAMED ASIDE, STARTED FRESH"
            } else if report.unreadable {
                " — UNREADABLE, PERSISTENCE DISARMED (nothing will overwrite it)"
            } else {
                ""
            }
        );
    }

    let hub = OracleHub::clone(&fuse_server::ORACLE_HUB);
    // num_args = 3: flat \[name, file, hash, ...\] triples; chunk them.
    for spec in cli.secret.chunks(3) {
        match parse_secret(&spec[0], &spec[1], &spec[2]) {
            Ok((name, host, hash)) => {
                // MR4: register by stat — identity + size, never bytes.
                let md = match std::fs::metadata(&host) {
                    Ok(md) => md,
                    Err(e) => {
                        error!("cannot stat {}: {e}", host.display());
                        std::process::exit(1);
                    }
                };
                use std::os::unix::fs::MetadataExt;
                info!(
                    "Registering secret '{name}' ({} bytes, host inode {})",
                    md.len(),
                    md.ino()
                );
                state.add_with_mode(&name, host.clone(), md.len() as usize, &hash, 0o400);
                let inner = fuse_protocol::anonymize_path(&state.anon_salt, &name);
                hub.serve(&name, &inner, 0o400);
            }
            Err(e) => {
                error!("Bad --secret {:?}: {e}", spec);
                std::process::exit(1);
            }
        }
    }
    let state = Arc::new(state);

    // ── Command socket (fuse-client / servatui) ──────────────────
    let socket_path = cli.socket.clone();
    let socket_state = Arc::clone(&state);
    let _socket_server = std::thread::spawn(move || {
        if let Err(e) = fuse_server::run_socket_server(&socket_path, socket_state) {
            error!("Socket server error: {e}");
            std::process::exit(1);
        }
    });

    // Handoff commit watcher (#93 F2): the new pair counts as serving
    // once the new fused's control connection (Hello) lands — then the
    // old server may retire. On timeout we KEEP the custody (closing
    // it would tear the mount) and leave the old server to its own
    // timeout — the next restart retries the takeover.
    if let Some(tk) = takeover {
        let sock = tk.handoff_socket.clone();
        let hub2 = OracleHub::clone(&hub);
        let sf = state_file.clone();
        // The watcher is fire-and-forget: its outcome is logged, the
        // handle deliberately discarded.
        let _watcher = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            while Instant::now() < deadline {
                if hub2.control_len() > 0 {
                    handoff::commit_handoff(&sock);
                    handoff::clear_pending_in_state_file(sf.as_deref());
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            error!(
                "handoff: the new fused never connected — NOT committing; \
                 custody stays here (the old server will time out and the \
                 next restart retries the takeover)"
            );
        });
    }

    // ── Oracle endpoint (fused: adjudication + content) ───────────
    // Blocks the main thread for the daemon's lifetime.
    if let Err(e) = fuse_server::run_oracle_server(&cli.oracle_socket, state, hub) {
        error!("Oracle server error: {e}");
        let _ = std::fs::remove_file(&cli.socket);
        std::process::exit(1);
    }
}

/// Three WORDS (clap's num_args = 3 delivers them as a triple) — no
/// delimiter grammar, nothing to escape, no string parsing: colons
/// and tildes are ordinary path characters.
fn parse_secret(
    name: &str,
    file: &str,
    hash: &str,
) -> Result<(String, std::path::PathBuf, String), String> {
    if name.is_empty() || hash.is_empty() {
        return Err("NAME and HASH must be non-empty".into());
    }
    let file_path = std::path::PathBuf::from(file);
    let host =
        std::fs::canonicalize(&file_path).map_err(|e| format!("cannot resolve {file}: {e}"))?;
    Ok((name.to_string(), host, hash.to_string()))
}

#[cfg(test)]
mod secret_spec_tests {
    use super::parse_secret;

    #[test]
    fn colons_in_the_file_path_are_ordinary_characters() {
        // three words, no delimiter: nothing to escape anywhere
        let dir = tempfile::tempdir().unwrap();
        let weird = dir.path().join("a:b:c.yaml");
        std::fs::write(&weird, b"DATA").unwrap();
        let (name, file, hash) = parse_secret("api", &weird.display().to_string(), "*").unwrap();
        assert_eq!(name, "api");
        assert_eq!(file, std::fs::canonicalize(&weird).unwrap());
        assert_eq!(hash, "*");
    }

    #[test]
    fn rejects_empty_name_or_hash() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("s.yaml");
        std::fs::write(&f, b"DATA").unwrap();
        let fs = f.display().to_string();
        assert!(parse_secret("", &fs, "*").is_err());
        assert!(parse_secret("n", &fs, "").is_err());
    }
}

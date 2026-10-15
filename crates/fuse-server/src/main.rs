//! fuse-server: the POLICY daemon of the gatekeeper split.
//!
//! It owns the trust decisions (one-read semantics, package hashes via
//! hashd, pendings, grants), the servatui command socket for
//! fuse-client, and the oracle endpoint the data daemon (`fused`)
//! connects to. It holds NO secret bytes in split mode: content goes to
//! the data daemon through the oracle hub, metadata stays here.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic, unused_results))]
#![cfg_attr(test, allow(unknown_lints, inline_literal))]

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use clap::Parser;
use tracing::{error, info, warn};

use fuse_server::{OracleHub, ServerState};

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
    /// Adoption window (#93 adopt-the-survivor): how long to wait for
    /// a surviving data daemon to reconnect before spawning a fresh
    /// one. 0 (default) = spawn immediately — adoption is a RESTART-
    /// path feature; the client's respawn passes a nonzero window so
    /// cold starts pay nothing.
    #[arg(long, default_value_t = 0)]
    adopt_window: u64,
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

/// Exit status for signal-caused shutdowns (128+SIGINT/TERM).
const EXIT_SIGNALLED: i32 = 130;
/// Generic startup/config failure exit.
const EXIT_FAILURE: i32 = 1;
/// The conservative secret mode for boot-time secrets (read-only).
const BOOT_SECRET_MODE: u32 = 0o400;
/// Poll cadence while waiting on spawned children/sockets.
const SPAWN_POLL: Duration = Duration::from_millis(50);
/// The mount-point flag (argv contract with fused).
const MOUNT_POINT_FLAG: &str = "--mount-point";
/// The unmount tool pair, most-specific first.
const UNMOUNT_TOOLS: [&str; 2] = ["fusermount3", "fusermount"];
/// The lazy-unmount flag.
const LAZY_UNMOUNT_FLAG: &str = "-uz";
/// Secrets arrive as flat triples.
const SECRET_WORDS: usize = 3;

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
    let code = EXIT_SIGNALLED;
    // SAFETY: _exit(2) is the async-signal-safe way out of a handler; it
    // intentionally skips atexit/destructors to avoid non-signal-safe
    // cleanup in this context.
    unsafe { libc::_exit(code) }
}

/// Supervised data daemon (kept alive by being our child; killed when
/// we exit, per Rust child-process semantics on drop is NOT guaranteed —
/// so we also store it to reap on shutdown).
static SUPERVISED_FUSED: std::sync::Mutex<Option<std::process::Child>> =
    std::sync::Mutex::new(None);

fn stale_socket(path: &Path) {
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            error!("Another server is running at {}. Kill it first.", path.display());
            std::process::exit(EXIT_FAILURE);
        }
        warn!("Removing stale socket at {}", path.display());
        let _ = std::fs::remove_file(path);
    }
}

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .parse_lossy(&cli.log_level),
        )
        .init();

    info!("fuse-server (policy daemon) v{} starting", fuse_protocol::VERSION);
    info!("  socket:          {}", cli.socket.display());
    info!("  oracle-socket:   {}", cli.oracle_socket.display());
    info!("  pending-timeout: {}s", cli.pending_timeout);
    // --mount-point handling lives AFTER the oracle endpoint comes
    // up: the ADOPTION GATE (#93) may take the surviving daemon
    // instead of spawning. See the tail of main().

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
            if report.corrupted { " — CORRUPT FILE RENAMED ASIDE, STARTED FRESH" }
            else if report.unreadable { " — UNREADABLE, PERSISTENCE DISARMED (nothing will overwrite it)" }
            else { "" }
        );
    }

    let hub = OracleHub::clone(&fuse_server::ORACLE_HUB);
    // num_args = 3: flat [name, file, hash, ...] triples; chunk them.
    for spec in cli.secret.chunks(SECRET_WORDS) {
        match parse_secret(&spec[0], &spec[1], &spec[2]) {
            Ok((name, host, hash)) => {
                // MR4: register by stat — identity + size, never bytes.
                let md = match std::fs::metadata(&host) {
                    Ok(md) => md,
                    Err(e) => {
                        error!("cannot stat {}: {e}", host.display());
                        std::process::exit(EXIT_FAILURE);
                    }
                };
                use std::os::unix::fs::MetadataExt;
                info!(
                    "Registering secret '{name}' ({} bytes, host inode {})",
                    md.len(),
                    md.ino()
                );
                state.add_with_mode(&name, host.clone(), md.len() as usize, &hash, BOOT_SECRET_MODE);
                let inner = fuse_protocol::anonymize_path(&state.anon_salt, &name);
                hub.serve(&name, &inner, BOOT_SECRET_MODE);
            }
            Err(e) => {
                error!("Bad --secret {:?}: {e}", spec);
                std::process::exit(EXIT_FAILURE);
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
            std::process::exit(EXIT_FAILURE);
        }
    });

    // ── Oracle endpoint (fused: adjudication + content) ───────────
    // On its own thread: the ADOPTION GATE must run after the oracle
    // is listening, and the gate belongs on the main thread.
    let oracle_path = cli.oracle_socket.clone();
    let oracle = std::thread::spawn(move || {
        if let Err(e) = fuse_server::run_oracle_server(&oracle_path, state, hub) {
            error!("Oracle server error: {e}");
            std::process::exit(EXIT_FAILURE);
        }
    });

    // ── Adoption gate (#93: adopt the surviving daemon) ───────────
    // --mount-point now means ENSURE a daemon serves that mountpoint:
    // a surviving fused from the previous server reconnects to this
    // oracle within ~1s (its control loop), the Hello carries its
    // version, and SO_PEERCRED names its pid. Compatible + serving OUR
    // mountpoint => ADOPT: no spawn, no mount touch — the snapshot
    // replay in the Hello handler resyncs the served set (the
    // kill-9-respawn flow, generalized). Otherwise fall through to a
    // fresh spawn, clearing any stale mount first.
    if let Some(mp) = &cli.mount_point {
        let window = std::time::Duration::from_secs(cli.adopt_window);
        if cli.adopt_window == 0 {
            info!(
                "  mount-point:     {} (no adoption window; spawning supervised data daemon)",
                mp.display()
            );
            spawn_fresh(&cli, mp);
        } else if let Some(offer) = wait_for_adoption_offer(window) {
            let version_ok = offer
                .version
                .as_deref()
                .is_some_and(|v| fuse_protocol::versions_compatible(v, fuse_protocol::VERSION));
            let mp_ok = daemon_serves_mountpoint(offer.pid, mp);
            if version_ok && mp_ok {
                info!(
                    "  mount-point:     {} — ADOPTED the surviving data daemon \
                     (pid {}, {})",
                    mp.display(),
                    offer.pid,
                    offer.version.as_deref().unwrap_or("?")
                );
                ADOPTED_DAEMON_PID.store(offer.pid, std::sync::atomic::Ordering::SeqCst);
            } else {
                warn!(
                    "  mount-point:     {} — surviving daemon pid {} not adoptable \
                     (version {:?} compatible={}, serves mountpoint={}); spawning fresh",
                    mp.display(),
                    offer.pid,
                    offer.version,
                    version_ok,
                    mp_ok
                );
                spawn_fresh(&cli, mp);
            }
        } else {
            info!(
                "  mount-point:     {} — no surviving daemon within {:?}; spawning fresh",
                mp.display(),
                window
            );
            spawn_fresh(&cli, mp);
        }
    }

    // Park for the daemon's lifetime (the oracle thread owns exit).
    let _ = oracle.join();
}

/// The adopted daemon's pid (0 = none). An adopted daemon is NOT a
/// child: it survives this server's death by design and reconnects to
/// the NEXT one — that is the adopt flow's whole point.
static ADOPTED_DAEMON_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn wait_for_adoption_offer(window: std::time::Duration) -> Option<fuse_server::AdoptionOffer> {
    let deadline = std::time::Instant::now() + window;
    loop {
        {
            let mut slot = fuse_server::ADOPTION_OFFER
                .lock()
                .expect("adoption slot: no panics under the lock by contract");
            if let Some(offer) = slot.take() {
                return Some(offer);
            }
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(SPAWN_POLL);
    }
}

/// Verify the daemon is OURS for this stack: its argv carries this
/// mount point. Kernel-stable, works across every daemon vintage —
/// no protocol involved (#65's exact-pid discipline, mountpoint form).
fn daemon_serves_mountpoint(pid: u32, mp: &Path) -> bool {
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let args: Vec<&str> = raw
        .split(|&b| b == 0)
        .map(|b| std::str::from_utf8(b).unwrap_or(""))
        .collect();
    let mp_str = mp.to_string_lossy();
    args.windows(2).any(|w| w[0] == MOUNT_POINT_FLAG && w[1] == mp_str)
}

/// The fresh-spawn branch: clear a stale mount (the #54-validated
/// world: ENOTCONN corpse) and spawn a supervised child, exactly the
/// pre-adoption behavior. The mountpoint cleanup lives HERE — with
/// the decision — not in the client, which can no longer know
/// whether adoption will succeed.
fn spawn_fresh(cli: &Cli, mp: &Path) {
    clear_stale_mount(mp);
    let exe = std::env::current_exe().expect("current exe");
    let sibling = exe
        .parent()
        .map(|d| d.join(fuse_protocol::FUSED_BIN))
        .filter(|p| p.exists());
    // The seam (#94): an explicit --fused-binary wins over the
    // exe-sibling default; without either, the loud #37 failure.
    let fused = cli.fused_binary.clone().or(sibling);
    match fused {
        Some(fused) => {
            info!("  mount-point:     {} (spawning supervised data daemon)", mp.display());
            let child = std::process::Command::new(&fused)
                .arg(MOUNT_POINT_FLAG)
                .arg(mp)
                .arg(fuse_protocol::ORACLE_SOCKET_FLAG)
                .arg(&cli.oracle_socket)
                .spawn();
            match child {
                Ok(c) => {
                    let _replaced = SUPERVISED_FUSED
                        .lock()
                        .expect("supervised-fused lock: set once at spawn")
                        .replace(c);
                }
                Err(e) => error!("cannot spawn data daemon {}: {e}", fused.display()),
            }
        }
        None => {
            // Serving adds with no data daemon looks "healthy" to
            // every client while nothing ever reaches a mount —
            // the PR #37 field-report trap.  Fail loudly instead.
            error!(
                "--mount-point given but no data daemon found next to {} — build it \
                 (cargo build --workspace) or start `fused` manually; refusing to run \
                 mount-less",
                exe.display()
            );
            std::process::exit(EXIT_FAILURE);
        }
    }
}

/// A dead FUSE mount occupies the path (ENOTCONN corpse — the #54
/// world): lazy-unmount it and recreate the directory so the fresh
/// daemon can mount. Best-effort with the manual remediation spelled
/// out, the #37 discipline.
fn clear_stale_mount(mp: &Path) {
    let enotconn = |r: std::io::Result<std::fs::Metadata>| match r {
        Err(e) => e.raw_os_error() == Some(libc::ENOTCONN),
        Ok(_) => false,
    };
    if !enotconn(std::fs::metadata(mp)) {
        return;
    }
    info!("  stale mount at {} — lazy unmounting", mp.display());
    for tool in UNMOUNT_TOOLS {
        let _clear = std::process::Command::new(tool).arg(LAZY_UNMOUNT_FLAG).arg(mp).output();
        if !enotconn(std::fs::metadata(mp)) {
            break;
        }
    }
    if enotconn(std::fs::metadata(mp)) {
        error!(
            "cannot clear the stale mount at {} — run: fusermount3 -uz {}",
            mp.display(),
            mp.display()
        );
        std::process::exit(EXIT_FAILURE);
    }
    let _rm = std::fs::remove_dir_all(mp);
    let _mk = std::fs::create_dir_all(mp);
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
    let host = std::fs::canonicalize(&file_path)
        .map_err(|e| format!("cannot resolve {file}: {e}"))?;
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
        let (name, file, hash) =
            parse_secret("api", &weird.display().to_string(), "*").unwrap();
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

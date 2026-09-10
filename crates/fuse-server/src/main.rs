//! fuse-server: the POLICY daemon of the gatekeeper split.
//!
//! It owns the trust decisions (one-read semantics, package hashes via
//! hashd, pendings, grants), the servatui command socket for
//! fuse-client, and the oracle endpoint the data daemon (`fused`)
//! connects to. It holds NO secret bytes in split mode: content goes to
//! the data daemon through the oracle hub, metadata stays here.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use clap::Parser;
use fuse_protocol::io::SystemIo as _;
use fuse_protocol::RealSystemIo;
use tracing::{error, info, warn};

use fuse_server::{OracleHub, ServerState};

#[derive(Parser)]
#[command(name = "fuse-server", about = "FUSE gatekeeper POLICY daemon (decisions + command socket; data lives in fused)")]
struct Cli {
    /// Accepted for backward compatibility with older orchestrators;
    /// mounting is the data daemon's job now.
    #[arg(short, long)]
    mount_point: Option<PathBuf>,
    #[arg(short, long, default_value = "/tmp/fuse-gatekeeper.sock")]
    socket: PathBuf,
    #[arg(long, value_name = "NAME:FILE:HASH")]
    secret: Vec<String>,
    #[arg(long)]
    allow_other: bool,
    #[arg(long, default_value = "info")]
    log_level: String,
    #[arg(long, default_value_t = 300)]
    pending_timeout: u64,
    #[arg(long, default_value = "/tmp/fuse-gatekeeper.log")]
    log_path: PathBuf,
    /// Socket where the data daemon (fused) connects for adjudication
    /// and content updates.
    #[arg(long, default_value = "/tmp/fuse-gatekeeper-oracle.sock")]
    oracle_socket: PathBuf,
}

/// Pre-computed CStrings for async-signal-safe unlink in the handler.
static CLEANUP_SOCKETS: OnceLock<(std::ffi::CString, std::ffi::CString)> = OnceLock::new();

extern "C" fn shutdown_handler(_sig: libc::c_int) {
    if let Some((cmd, oracle)) = CLEANUP_SOCKETS.get() {
        unsafe {
            libc::unlink(cmd.as_ptr());
            libc::unlink(oracle.as_ptr());
        }
    }
    unsafe { libc::_exit(130); }
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
            std::process::exit(1);
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
    // --mount-point means SUPERVISE a data daemon at that mount point
    // (the one-command contract of the old monolith): spawn fused next
    // to this binary and keep it as a child; on our exit it dies too.
    if let Some(mp) = &cli.mount_point {
        let exe = std::env::current_exe().expect("current exe");
        let fused = exe.parent().map(|d| d.join("fused")).filter(|p| p.exists());
        match fused {
            Some(fused) => {
                info!("  mount-point:     {} (spawning supervised data daemon)", mp.display());
                let child = std::process::Command::new(&fused)
                    .arg("--mount-point").arg(mp)
                    .arg("--oracle-socket").arg(&cli.oracle_socket)
                    .spawn();
                match child {
                    Ok(c) => {
                        SUPERVISED_FUSED.lock().unwrap().replace(c);
                    }
                    Err(e) => error!("cannot spawn data daemon {}: {e}", fused.display()),
                }
            }
            None => error!(
                "--mount-point given but no data daemon found next to {} —                  build `fused` or start it manually",
                exe.display()
            ),
        }
    }
    let _ = cli.allow_other;

    stale_socket(&cli.socket);
    stale_socket(&cli.oracle_socket);

    if let (Ok(a), Ok(b)) = (
        std::ffi::CString::new(cli.socket.to_string_lossy().as_bytes()),
        std::ffi::CString::new(cli.oracle_socket.to_string_lossy().as_bytes()),
    ) {
        CLEANUP_SOCKETS.set((a, b)).ok();
    }
    unsafe {
        libc::signal(libc::SIGINT, shutdown_handler as *const () as usize);
        libc::signal(libc::SIGTERM, shutdown_handler as *const () as usize);
    }

    // ── State: metadata here, content pushed to the data daemon ──
    let mut state = ServerState::new();
    state.pending_timeout = std::sync::Mutex::new(Duration::from_secs(cli.pending_timeout));
    state.log_path = cli.log_path.to_string_lossy().to_string();
    let hub = OracleHub::clone(&fuse_server::ORACLE_HUB);
    let io = RealSystemIo::new();
    for spec in &cli.secret {
        match parse_secret(spec, &io) {
            Ok((name, content, hash)) => {
                info!("Registering secret '{name}' ({} bytes -> data daemon)", content.len());
                state.add_with_mode(&name, content.clone(), &hash, 0o400);
                hub.upsert(&name, &content, 0o400);
            }
            Err(e) => {
                error!("Bad --secret '{spec}': {e}");
                std::process::exit(1);
            }
        }
    }
    let state = Arc::new(state);

    // ── Command socket (fuse-client / servatui) ──────────────────
    let socket_path = cli.socket.clone();
    let socket_state = Arc::clone(&state);
    std::thread::spawn(move || {
        if let Err(e) = fuse_server::run_socket_server(&socket_path, socket_state) {
            error!("Socket server error: {e}");
            std::process::exit(1);
        }
    });

    // ── Oracle endpoint (fused: adjudication + content) ───────────
    // Blocks the main thread for the daemon's lifetime.
    if let Err(e) = fuse_server::run_oracle_server(&cli.oracle_socket, state, hub) {
        error!("Oracle server error: {e}");
        let _ = std::fs::remove_file(&cli.socket);
        std::process::exit(1);
    }
}

fn parse_secret(spec: &str, io: &RealSystemIo) -> Result<(String, Vec<u8>, String), String> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err("expected NAME:FILE:HASH".into());
    }
    let name = parts[0].to_string();
    let content = io
        .read_file(std::path::Path::new(parts[1]))
        .map_err(|e| e.0)?;
    let hash = parts[2].to_string();
    Ok((name, content, hash))
}

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use clap::Parser;
use fuser::MountOption;
use fuse_protocol::{RealSystemIo, SystemIo};
use fuse_server::{GatekeeperFs, ServerState};
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "fuse-server", about = "FUSE gatekeeper filesystem + CRUD socket server")]
struct Cli {
    #[arg(short, long)]
    mount_point: PathBuf,
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
}

/// Pre-computed CString for async-signal-safe unlink in the signal handler.
static CLEANUP_SOCKET: OnceLock<std::ffi::CString> = OnceLock::new();

/// Signal handler: removes the socket file and exits.
/// Only uses async-signal-safe functions (unlink, _exit).
extern "C" fn shutdown_handler(_sig: libc::c_int) {
    if let Some(path) = CLEANUP_SOCKET.get() {
        unsafe { libc::unlink(path.as_ptr()); }
    }
    // _exit is async-signal-safe; std::process::exit is NOT (runs atexit handlers).
    unsafe { libc::_exit(130); } // 128 + SIGINT(2)
}

/// Try to unmount a stale FUSE mount at `mount_point`.
/// Tries fusermount, fusermount3, then umount -l.
fn unmount_if_mounted(mount_point: &Path) {
    for (cmd, flag) in [("fusermount", "-uz"), ("fusermount3", "-uz"), ("umount", "-l")] {
        match std::process::Command::new(cmd).arg(flag).arg(mount_point).output() {
            Ok(output) if output.status.success() => {
                info!("Unmounted stale mount at {} via {} {}", mount_point.display(), cmd, flag);
                return;
            }
            _ => {}
        }
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
    let io = RealSystemIo::new();

    info!("fuse-server v{} starting", fuse_protocol::VERSION);
    info!("  mount-point:     {}", cli.mount_point.display());
    info!("  socket:          {}", cli.socket.display());
    info!("  allow-other:     {}", cli.allow_other);
    info!("  pending-timeout: {}s", cli.pending_timeout);
    info!("  log-path:        {}", cli.log_path.display());

    // ── Startup cleanup: take over from stale instance ───────────

    // 1. If socket exists and is connectable, another server is running.
    if cli.socket.exists() {
        if std::os::unix::net::UnixStream::connect(&cli.socket).is_ok() {
            error!("Server already running at {}. Use 'fuse-client' or kill the existing process.", cli.socket.display());
            std::process::exit(1);
        }
        // Socket exists but not connectable — stale, remove it.
        warn!("Removing stale socket at {}", cli.socket.display());
        let _ = std::fs::remove_file(&cli.socket);
    }

    // 2. Unmount any stale FUSE mount before we try to mount.
    unmount_if_mounted(&cli.mount_point);

    // 3. Ensure mount point directory exists.
    if !cli.mount_point.exists() {
        if let Err(e) = std::fs::create_dir_all(&cli.mount_point) {
            error!("Failed to create mount point {}: {e}", cli.mount_point.display());
            std::process::exit(1);
        }
    }

    // ── Install shutdown handler ─────────────────────────────────
    // On SIGINT/SIGTERM: unlink socket, then _exit.
    // The kernel automatically releases the FUSE mount when the process dies.
    if let Ok(socket_cstr) = std::ffi::CString::new(cli.socket.to_string_lossy().as_bytes()) {
        CLEANUP_SOCKET.set(socket_cstr).ok();
    }
    unsafe {
        libc::signal(libc::SIGINT, shutdown_handler as *const () as usize);
        libc::signal(libc::SIGTERM, shutdown_handler as *const () as usize);
    }

    // ── Build state ──────────────────────────────────────────────
    let mut state = ServerState::new();
    state.pending_timeout = std::sync::Mutex::new(Duration::from_secs(cli.pending_timeout));
    state.log_path = cli.log_path.to_string_lossy().to_string();
    for spec in &cli.secret {
        match parse_secret(spec, &io) {
            Ok((name, content, hash)) => {
                info!("Loaded secret '{name}' ({} bytes)", content.len());
                state.add(&name, content, &hash);
            }
            Err(e) => {
                error!("Bad --secret '{spec}': {e}");
                std::process::exit(1);
            }
        }
    }
    let state = Arc::new(state);

    // ── Start socket server ──────────────────────────────────────
    let socket_path = cli.socket.clone();
    let socket_state = Arc::clone(&state);
    std::thread::spawn(move || {
        if let Err(e) = fuse_server::run_socket_server(&socket_path, socket_state) {
            error!("Socket server error: {e}");
        }
    });

    // Wait for socket to be connectable.
    let mut socket_ready = false;
    for _ in 0..200 {
        if cli.socket.exists() {
            info!("Socket file exists, probing connectability...");
            match std::os::unix::net::UnixStream::connect(&cli.socket) {
                Ok(_) => {
                    info!("Socket probe succeeded — this connect+drop will trigger server-side 'connection closed'");
                    socket_ready = true;
                    break;
                }
                Err(_) => {
                    // Not ready yet
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !socket_ready {
        error!("Socket server did not start in time");
        cleanup_and_exit(&cli.socket, &cli.mount_point, 1);
    }
    info!("Socket ready at {}", cli.socket.display());

    // ── Mount FUSE (blocks until unmounted or signal) ────────────
    let mut options = vec![MountOption::FSName("gatekeeper".into())];
    if cli.allow_other {
        options.push(MountOption::AllowOther);
    }

    info!("Mounting FUSE at {}", cli.mount_point.display());
    let fs = GatekeeperFs::new(Arc::clone(&state), RealSystemIo::new());

    match fuser::mount2(fs, &cli.mount_point, &options) {
        Ok(()) => info!("FUSE unmounted cleanly."),
        Err(e) => {
            error!("FUSE mount error: {e}");
            cleanup_and_exit(&cli.socket, &cli.mount_point, 1);
        }
    }

    // ── Normal shutdown cleanup ──────────────────────────────────
    cleanup_and_exit(&cli.socket, &cli.mount_point, 0);
}

/// Remove socket and unmount. Called on normal exit or error.
fn cleanup_and_exit(socket: &Path, mount_point: &Path, code: i32) {
    let _ = std::fs::remove_file(socket);
    unmount_if_mounted(mount_point);
    std::process::exit(code);
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

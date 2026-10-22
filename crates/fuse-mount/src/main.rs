//! fused — the gatekeeper DATA daemon.
//!
//! Holds the secret bytes and the FUSE mount. Holds NO policy: every
//! read asks the policy daemon (`fuse-server`) over the oracle socket;
//! content updates arrive on the same socket's control channel. Either
//! half alone is useless — compromise of fused yields no authorization,
//! compromise of the policy daemon yields no bytes.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic, unused_results))]
#![cfg_attr(test, allow(unknown_lints, inline_literal))]

use std::path::PathBuf;

use clap::Parser;
use tracing::{error, info};


#[derive(Parser)]
#[command(name = fuse_protocol::FUSED_BIN, about = FUSED_ABOUT)]
struct Cli {
    #[arg(short, long)]
    mount_point: PathBuf,
    /// Policy daemon's oracle socket (adjudication + content updates).
    #[arg(short, long, default_value = fuse_protocol::DEFAULT_ORACLE_SOCKET)]
    oracle_socket: String,
    /// Serve a MOCK kernel instead of mounting: JSON-line ops on this
    /// unix socket become real FUSE wire requests into the same
    /// session code the kernel drives. Runs (and fuzzes) fused
    /// without /dev/fuse — every layer above the kernel stays real.
    #[arg(long)]
    mock_fuse: Option<PathBuf>,
    /// #103 takeover: resume a mount session inherited from a
    /// predecessor instead of mounting fresh. The /dev/fuse
    /// connection arrives pre-dup2'd at `resume_fd`; the host fds at
    /// `resume_fds_base + i` in the state's open_fds order; the
    /// session state JSON at `resume_state`.
    #[arg(long)]
    resume_fd: Option<i32>,
    #[arg(long)]
    resume_fds_base: Option<i32>,
    #[arg(long)]
    resume_state: Option<PathBuf>,
    #[arg(long, default_value = DEFAULT_LOG_LEVEL)]
    log_level: String,
}

/// The FUSE filesystem name.
const FS_NAME: &str = "gatekeeper";
/// CLI defaults.
const DEFAULT_LOG_LEVEL: &str = "info";
const FUSED_ABOUT: &str = "FUSE gatekeeper DATA daemon: secret bytes + mount; access decided by the policy daemon";
const EXIT_FAILURE: i32 = 1;
/// Resume declined (schema mismatch / unreadable state): the caller
/// (spawn path) falls back to a fresh mount.
const EXIT_TAKEOVER_DECLINED: i32 = 3;

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder().parse_lossy(&cli.log_level),
        )
        .init();

    if !cli.mount_point.exists() {
        if let Err(e) = std::fs::create_dir_all(&cli.mount_point) {
            error!("Failed to create mount point {}: {e}", cli.mount_point.display());
            std::process::exit(EXIT_FAILURE);
        }
    }

    let store = fuse_mount::fs::Store::default();

    // Content sync runs beside the mount; it reconnects on policy
    // daemon restarts (data daemon survives them — the mount stays).
    let store_for_resume = store.clone();
    {
        let store = store.clone();
        let oracle = cli.oracle_socket.clone();
        let _control_loop =
            std::thread::spawn(move || fuse_mount::fs::run_control_loop(store, oracle));
    }

    info!(
        "fused v{} mounting at {} (policy daemon: {})",
        fuse_protocol::VERSION,
        cli.mount_point.display(),
        cli.oracle_socket
    );
    let fuser_fs = fuse_mount::fs::FusedFs::new(store, &cli.oracle_socket);
    if let Some(control) = cli.mock_fuse {
        // The DI branch: same FusedFs, same session dispatch — the
        // kernel end of the channel is our mock instead of /dev/fuse.
        fuse_mount::mock_fuser::serve(fuser_fs, &control);
        return;
    }
    let mut fuser_fs = fuser_fs;

    // ── #103 takeover resume: same connection, same kernel state ──
    if let (Some(fd), Some(state_path)) = (cli.resume_fd, &cli.resume_state) {
        let base = cli.resume_fds_base.unwrap_or(fd + 1);
        let raw = std::fs::read_to_string(state_path)
            .unwrap_or_else(|e| {
                eprintln!("resume state unreadable: {e}");
                std::process::exit(EXIT_TAKEOVER_DECLINED);
            });
        let state: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| {
                eprintln!("resume state unparseable: {e}");
                std::process::exit(EXIT_TAKEOVER_DECLINED);
            });
        let schema = state[fuse_protocol::oracle::TAKEOVER_KEY_SCHEMA]
            .as_u64()
            .unwrap_or(u64::MAX) as u32;
        if schema != fuse_mount::fs::TAKEOVER_SESSION_SCHEMA {
            eprintln!(
                "resume declined: session schema {schema} != {} (this build cannot \
                 serve that session shape — falling back to fresh mount is the \
                 caller's business)",
                fuse_mount::fs::TAKEOVER_SESSION_SCHEMA
            );
            std::process::exit(EXIT_TAKEOVER_DECLINED);
        }
        let ts: fuse_mount::fs::TakeoverState = serde_json::from_value(state[fuse_protocol::oracle::TAKEOVER_KEY_STATE].clone())
            .unwrap_or_else(|e| {
                eprintln!("takeover state does not match schema 1: {e}");
                std::process::exit(EXIT_TAKEOVER_DECLINED);
            });
        let inner = fuse_mount::fs::takeover_restore(&ts)
            .unwrap_or_else(|e| {
                eprintln!("takeover restore failed: {e}");
                std::process::exit(EXIT_TAKEOVER_DECLINED);
            });

        // rebuild the store from the restored inner state
        store_for_resume.install_restored(inner);

        // the predecessor's open host fds: base + fd_index, mapped by
        // their ORIGINAL fh numbers (the kernel still uses those).
        use std::os::fd::FromRawFd as _;
        let table = ts
            .open_fds
            .iter()
            .map(|ofd| {
                let raw = base + ofd.fd_index as i32;
                // SAFETY: the spawner dup2'd this exact fd for us.
                let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
                (ofd.fh, owned)
            });
        fuser_fs.resume_fds(table);

        info!(
            "fused v{} RESUMING session (fd {fd}, {} inherited open fds) at {}",
            fuse_protocol::VERSION,
            ts.open_fds.len(),
            cli.mount_point.display()
        );
        // SAFETY: the spawner dup2'd the connection fd to resume_fd.
        let conn_fd = unsafe {
            std::os::fd::OwnedFd::from_raw_fd(fd)
        };
        let mut session = fuser::Session::from_fd_resumed(
            fuser_fs,
            conn_fd,
            fuser::SessionACL::Owner,
            ts.proto_major,
            ts.proto_minor,
        );
        match session.run() {
            Ok(()) => info!("FUSE unmounted cleanly (resumed session)."),
            Err(e) => {
                error!("FUSE resumed session error: {e}");
                std::process::exit(EXIT_FAILURE);
            }
        }
        return;
    }

    let options = vec![fuser::MountOption::FSName(FS_NAME.into())];
    match fuser::mount2(fuser_fs, &cli.mount_point, &options) {
        Ok(()) => info!("FUSE unmounted cleanly."),
        Err(e) => {
            error!("FUSE mount error: {e}");
            std::process::exit(EXIT_FAILURE);
        }
    }
}

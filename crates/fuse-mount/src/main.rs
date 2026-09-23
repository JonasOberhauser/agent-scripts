//! fused — the gatekeeper DATA daemon.
//!
//! Holds the secret bytes and the FUSE mount. Holds NO policy: every
//! read asks the policy daemon (`fuse-server`) over the oracle socket;
//! content updates arrive on the same socket's control channel. Either
//! half alone is useless — compromise of fused yields no authorization,
//! compromise of the policy daemon yields no bytes.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic, unused_results))]

use std::path::PathBuf;

use clap::Parser;
use tracing::{error, info};


#[derive(Parser)]
#[command(name = "fused", about = "FUSE gatekeeper DATA daemon: secret bytes + mount; access decided by the policy daemon")]
struct Cli {
    #[arg(short, long)]
    mount_point: PathBuf,
    /// Policy daemon's oracle socket (adjudication + content updates).
    #[arg(short, long, default_value = "/tmp/fuse-gatekeeper-oracle.sock")]
    oracle_socket: String,
    /// Serve a MOCK kernel instead of mounting: JSON-line ops on this
    /// unix socket become real FUSE wire requests into the same
    /// session code the kernel drives. Runs (and fuzzes) fused
    /// without /dev/fuse — every layer above the kernel stays real.
    #[arg(long)]
    mock_fuse: Option<PathBuf>,
    #[arg(long, default_value = "info")]
    log_level: String,
}

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
            std::process::exit(1);
        }
    }

    let store = fuse_mount::fs::Store::default();

    // Content sync runs beside the mount; it reconnects on policy
    // daemon restarts (data daemon survives them — the mount stays).
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
    let options = vec![fuser::MountOption::FSName("gatekeeper".into())];
    match fuser::mount2(fuser_fs, &cli.mount_point, &options) {
        Ok(()) => info!("FUSE unmounted cleanly."),
        Err(e) => {
            error!("FUSE mount error: {e}");
            std::process::exit(1);
        }
    }
}

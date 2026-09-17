//! fused — the gatekeeper DATA daemon.
//!
//! Holds the secret bytes and the FUSE mount. Holds NO policy: every
//! read asks the policy daemon (`fuse-server`) over the oracle socket;
//! content updates arrive on the same socket's control channel. Either
//! half alone is useless — compromise of fused yields no authorization,
//! compromise of the policy daemon yields no bytes.

use std::path::PathBuf;

use clap::Parser;
use tracing::{error, info};

mod fs;

#[derive(Parser)]
#[command(name = "fused", about = "FUSE gatekeeper DATA daemon: secret bytes + mount; access decided by the policy daemon")]
struct Cli {
    #[arg(short, long)]
    mount_point: PathBuf,
    /// Policy daemon's oracle socket (adjudication + content updates).
    #[arg(short, long, default_value = "/tmp/fuse-gatekeeper-oracle.sock")]
    oracle_socket: String,
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

    let store = fs::Store::default();

    // Content sync runs beside the mount; it reconnects on policy
    // daemon restarts (data daemon survives them — the mount stays).
    {
        let store = store.clone();
        let oracle = cli.oracle_socket.clone();
        std::thread::spawn(move || fs::run_control_loop(store, oracle));
    }

    info!(
        "fused v{} mounting at {} (policy daemon: {})",
        fuse_protocol::VERSION,
        cli.mount_point.display(),
        cli.oracle_socket
    );
    let fuser_fs = fs::FusedFs::new(store, &cli.oracle_socket);
    let options = vec![fuser::MountOption::FSName("gatekeeper".into())];
    match fuser::mount2(fuser_fs, &cli.mount_point, &options) {
        Ok(()) => info!("FUSE unmounted cleanly."),
        Err(e) => {
            error!("FUSE mount error: {e}");
            std::process::exit(1);
        }
    }
}

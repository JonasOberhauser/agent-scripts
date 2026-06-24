use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::Parser;
use fuser::MountOption;
use fuse_protocol::{RealSystemIo, SystemIo};
use fuse_server::{GatekeeperFs, ServerState};
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "fuse-server", about = "FUSE gatekeeper filesystem + CRUD socket server")]
struct Cli {
    /// Directory to mount the FUSE filesystem.
    #[arg(short, long)]
    mount_point: PathBuf,

    /// Path for the Unix domain socket.
    #[arg(short, long, default_value = "/tmp/fuse-gatekeeper.sock")]
    socket: PathBuf,

    /// Initial secret: <name>:<file_path>:<sha256_of_allowed_binary>
    /// Can be repeated for multiple secrets.
    #[arg(long, value_name = "NAME:FILE:HASH")]
    secret: Vec<String>,

    /// Allow other users to access the mount.
    #[arg(long)]
    allow_other: bool,

    /// Log level (e.g. "info", "debug", "warn").
    /// Only used when RUST_LOG is not set, since spawn_independent + sudo
    /// strips environment variables.
    #[arg(long, default_value = "info")]
    log_level: String,
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

    // Build initial state.
    let mut state = ServerState::new();
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
    let state = Arc::new(Mutex::new(state));

    // Ensure mount point exists.
    if !cli.mount_point.exists() {
        if let Err(e) = std::fs::create_dir_all(&cli.mount_point) {
            error!("Failed to create mount point {}: {e}", cli.mount_point.display());
            std::process::exit(1);
        }
    }

    // Start socket server in background.
    let socket_path = cli.socket.clone();
    let socket_state = Arc::clone(&state);

    std::thread::spawn(move || {
        if let Err(e) = fuse_server::run_socket_server(&socket_path, socket_state) {
            error!("Socket server error: {e}");
        }
    });

    // Wait for socket to appear.
    for _ in 0..200 {
        if cli.socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !cli.socket.exists() {
        error!("Socket server did not start in time");
        std::process::exit(1);
    }
    info!("Socket ready at {}", cli.socket.display());

    // Mount FUSE.
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
            std::process::exit(1);
        }
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

//! `netrcd` — the host-side credential broker daemon.
//!
//! One unix socket (0666), one JSON line per request, credentials and
//! policy entirely host-side. See the crate docs for the model.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use netrcd::daemon::{Daemon, DaemonConfig};
use netrcd::exec::RealExecutor;

#[derive(Parser)]
#[command(about = "Host-side netrc credential broker")]
struct Cli {
    /// Socket path (bind-mount the PARENT DIRECTORY into containers —
    /// a bind-mounted socket file pins the inode and breaks across
    /// restarts).
    #[arg(long, default_value = "/run/netrcd/netrcd.sock")]
    socket: PathBuf,

    /// Directory of shared site profiles (`auth`, `pins`, headers).
    #[arg(long, default_value = "/etc/netrcd/profiles.d")]
    profiles_dir: PathBuf,

    /// Directory of user grants (`allow` rules, limits).
    #[arg(long, default_value = "/etc/netrcd/config.d")]
    grants_dir: PathBuf,

    /// netrc credential file (repeatable).
    #[arg(long = "netrc", default_value = "~/.netrc")]
    netrc: Vec<PathBuf>,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let cli = Cli::parse();

    // Credential files are read ONCE at startup (and on SIGHUP): the
    // daemon re-reads from disk on reload, so one-read fuse mounts can
    // be re-served by the operator if needed.
    let mut netrc_texts = Vec::new();
    for path in &cli.netrc {
        let expanded = shellexpand(&path.to_string_lossy());
        match std::fs::read_to_string(&expanded) {
            Ok(text) => netrc_texts.push((expanded, text)),
            Err(e) => tracing::error!("netrc {expanded}: {e}"),
        }
    }

    let config = DaemonConfig {
        socket: cli.socket.clone(),
        profiles_dir: cli.profiles_dir.clone(),
        grants_dir: cli.grants_dir.clone(),
        netrc_texts,
        executor: Arc::new(RealExecutor { ca_path: None }),
    };

    let daemon = match Daemon::start(config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("netrcd: cannot start on {}: {e}", cli.socket.display());
            std::process::exit(1);
        }
    };
    tracing::info!("netrcd listening on {}", daemon.socket_path().display());

    // SIGHUP is picked up by the accept loop; park the main thread.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

fn shellexpand(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}/{}", home.to_string_lossy(), rest);
        }
    }
    path.to_string()
}

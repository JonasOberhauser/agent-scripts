use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use run_agent::{
    run_agent, AgentConfig, Runtime, SecretMapping, DEFAULT_MOUNT_POINT, DEFAULT_SOCKET,
};
use tracing::error;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "run-agent",
    about = "Launch a secure agent session: FUSE gatekeeper + container"
)]
struct Cli {
    /// SHA-256 of the allowed agent binary.
    binary_checksum: String,

    /// Guest subfolder under ~/.config/ (e.g. `goose`).
    agent_subfolder: String,

    /// Secret to serve through FUSE: HOST:CONTAINER.
    /// HOST is the real file/dir on the host; CONTAINER is an absolute path
    /// inside the container where the secret should appear (e.g.
    /// `/root/.config/opencode/auth.json`).
    /// Directories are mapped recursively (like `cp -r`).
    /// Can be specified multiple times.
    #[arg(long, value_name = "HOST:CONTAINER")]
    secret: Vec<String>,

    /// Path to the fuse-server binary.
    #[arg(long, default_value = "fuse-server")]
    fuse_server: PathBuf,

    /// Unix socket path for the shared fuse-server.
    #[arg(long, default_value = DEFAULT_SOCKET, env = "FUSE_GATEKEEPER_SOCKET")]
    socket: PathBuf,

    /// FUSE mount point (shared across projects).
    #[arg(long, default_value = DEFAULT_MOUNT_POINT)]
    mount_point: PathBuf,

    /// Run fuse-server under sudo (implies --allow-other).
    #[arg(long)]
    sudo: bool,

    /// Pass --allow-other to the fuse-server so other users can access the
    /// FUSE mount.  NOT needed with rootless podman (the default), where
    /// container root maps to your host UID.  Only needed for rootful
    /// Docker/Podman where container UID 0 != your host UID.
    #[arg(long)]
    allow_other: bool,

    /// Container runtime to use.
    #[arg(long, default_value = "auto")]
    runtime: Runtime,

    /// Wrapper command for the container runtime (e.g. "flatpak-spawn --host"
    /// to use the host's podman from inside a toolbox).
    #[arg(long)]
    runtime_wrapper: Option<String>,

    /// Container image name.
    #[arg(long, default_value = "agentbox")]
    image: String,

    /// Memory limit for the container.
    #[arg(long, default_value = "224G")]
    memory: String,

    /// CPU limit for the container.
    #[arg(long, default_value = "90")]
    cpus: String,

    /// Log level for the fuse-server (e.g. "info", "debug", "warn").
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Extra arguments passed to the container command.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    container_args: Vec<String>,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let secrets: Vec<SecretMapping> = cli
        .secret
        .iter()
        .map(|s| SecretMapping::parse(s))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|e| {
            error!("{e}");
            std::process::exit(2);
        });

    let mut config = AgentConfig::from_args(
        &cli.binary_checksum,
        secrets,
        &cli.agent_subfolder,
        &cli.container_args,
    );
    config.fuse_server_path = resolve_fuse_server(&cli.fuse_server);
    config.socket_path = cli.socket;
    config.mount_point = cli.mount_point;
    config.use_sudo = cli.sudo;
    config.allow_other = cli.allow_other || cli.sudo;
    config.runtime = cli.runtime;
    config.runtime_wrapper = cli.runtime_wrapper;
    config.image_name = cli.image;
    config.memory = cli.memory;
    config.cpus = cli.cpus;
    config.log_level = cli.log_level;

    let plans_candidate = std::path::Path::new("./plans/shared");
    if plans_candidate.exists() {
        config.plans_path = Some(plans_candidate.to_path_buf());
    }

    let mut io = fuse_protocol::RealSystemIo::new();
    match run_agent(&mut io, &config) {
        Ok(result) => {
            if result.container_exit_code != 0 {
                return ExitCode::from(result.container_exit_code as u8);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// Resolve the fuse-server binary path.
///
/// 1. If the user gave an absolute path, use it as-is.
/// 2. Otherwise, look for `fuse-server` next to the current executable
///    (handles the common case where all binaries live in `target/release/`).
/// 3. Fall back to PATH lookup.
fn resolve_fuse_server(configured: &Path) -> PathBuf {
    if configured.is_absolute() {
        return configured.to_path_buf();
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(configured);
            if candidate.exists() {
                return candidate;
            }
        }
    }

    configured.to_path_buf()
}

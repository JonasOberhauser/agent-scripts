use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use run_agent::{run_agent, AgentConfig};
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

    /// Host path to the secret config file.
    host_config_file: String,

    /// Guest subfolder under ~/.config/ (e.g. `goose`).
    agent_subfolder: String,

    /// Path to the fuse-server binary.
    #[arg(long, default_value = "fuse-server")]
    fuse_server: PathBuf,

    /// Container image name.
    #[arg(long, default_value = "agentbox")]
    image: String,

    /// Memory limit for the container.
    #[arg(long, default_value = "224G")]
    memory: String,

    /// CPU limit for the container.
    #[arg(long, default_value = "90")]
    cpus: String,

    /// Extra arguments passed to the container command.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    container_args: Vec<String>,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let mut config = AgentConfig::from_args(
        &cli.binary_checksum,
        &cli.host_config_file,
        &cli.agent_subfolder,
        &cli.container_args,
    );
    config.fuse_server_path = cli.fuse_server;
    config.image_name = cli.image;
    config.memory = cli.memory;
    config.cpus = cli.cpus;

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

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use fuse_client::send_command;
use fuse_protocol::{Command, Response, SystemIo};

#[derive(Parser)]
#[command(name = "fuse-client", about = "Send CRUD commands to the fuse-server")]
struct Cli {
    /// Path to the Unix domain socket.
    #[arg(short, long, env = "FUSE_GATEKEEPER_SOCKET", default_value = "/tmp/fuse-gatekeeper.sock")]
    socket: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Reset the access counter for one secret (or all).
    Reset {
        /// Secret name. Omit to reset all.
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Reset all secrets.
    ResetAll,
    /// Show status of every secret.
    Status,
    /// Add a new secret to the mount.
    AddSecret {
        name: String,
        /// Path to the file whose contents will be the secret.
        #[arg(short, long)]
        file: PathBuf,
        /// SHA-256 of the allowed binary.
        #[arg(long)]
        hash: String,
    },
    /// Remove a secret from the mount.
    RemoveSecret { name: String },
    /// Replace the allowed binary hash for a secret.
    RotateHash {
        name: String,
        #[arg(long)]
        hash: String,
    },
    /// List all mounted secrets.
    ListMounts,
}

fn main() {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::from_default_env()
    ).init();

    let cli = Cli::parse();
    let io = fuse_protocol::RealSystemIo::new();
    let cmd = build_command(&cli.command, &io);

    let cmd = match cmd {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    match send_command(&io, &cli.socket, cmd) {
        Ok(resp) => {
            print_response(&resp);
            if matches!(resp, Response::Error { .. }) {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Connection error: {e}");
            std::process::exit(1);
        }
    }
}

fn build_command<S: SystemIo>(cmd: &Commands, io: &S) -> Result<Command, String> {
    Ok(match cmd {
        Commands::Reset { name } => Command::Reset {
            name: name.clone(),
        },
        Commands::ResetAll => Command::Reset { name: None },
        Commands::Status => Command::Status,
        Commands::AddSecret { name, file, hash } => {
            let content = io.read_file(file).map_err(|e| e.0)?;
            Command::AddSecret {
                name: name.clone(),
                content,
                hash: hash.clone(),
            }
        }
        Commands::RemoveSecret { name } => Command::RemoveSecret {
            name: name.clone(),
        },
        Commands::RotateHash { name, hash } => Command::RotateHash {
            name: name.clone(),
            new_hash: hash.clone(),
        },
        Commands::ListMounts => Command::ListMounts,
    })
}

fn print_response(resp: &Response) {
    match resp {
        Response::Ok => println!("OK"),
        Response::Error { message } => eprintln!("Error: {message}"),
        Response::Status { secrets } => {
            if secrets.is_empty() {
                println!("No secrets configured.");
            } else {
                println!("{:<24} {:>8} {:>8}  HASH", "NAME", "READS", "SIZE");
                for s in secrets {
                    println!(
                        "{:<24} {:>8} {:>8}  {}",
                        s.name, s.access_count, s.size, s.allowed_hash
                    );
                }
            }
        }
        Response::MountList { mounts } => {
            if mounts.is_empty() {
                println!("No secrets mounted.");
            } else {
                for m in mounts {
                    println!("  {} ({} bytes)", m.name, m.size);
                }
            }
        }
    }
}

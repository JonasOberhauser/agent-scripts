use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use fuse_client::send_command;
use fuse_protocol::{Command, Response, SystemIo};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

#[derive(Parser)]
#[command(name = "fuse-client", about = "Send CRUD commands to the fuse-server")]
struct Cli {
    /// Path to the Unix domain socket.
    #[arg(short, long, env = "FUSE_GATEKEEPER_SOCKET", default_value = "/tmp/fuse-gatekeeper.sock")]
    socket: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Reset the access counter for one secret (or all).
    Reset {
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
        #[arg(short, long)]
        file: PathBuf,
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
    /// List pending access requests waiting for approval.
    Pending,
    /// Grant a pending access request.
    Grant { id: u64 },
    /// Deny a pending access request.
    Deny { id: u64 },
}

fn main() {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::from_default_env()
    ).init();

    let cli = Cli::parse();
    let io = fuse_protocol::RealSystemIo::new();

    match &cli.command {
        Some(cmd) => {
            let cmd = match build_command(cmd, &io) {
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
        None => {
            // Interactive mode
            if let Err(e) = interactive(&io, &cli.socket) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn build_command<S: SystemIo>(cmd: &Commands, io: &S) -> Result<Command, String> {
    Ok(match cmd {
        Commands::Reset { name } => Command::Reset { name: name.clone() },
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
        Commands::RemoveSecret { name } => Command::RemoveSecret { name: name.clone() },
        Commands::RotateHash { name, hash } => Command::RotateHash {
            name: name.clone(),
            new_hash: hash.clone(),
        },
        Commands::ListMounts => Command::ListMounts,
        Commands::Pending => Command::ListPending,
        Commands::Grant { id } => Command::Grant { id: *id },
        Commands::Deny { id } => Command::Deny { id: *id },
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
        Response::PendingList { pending } => {
            if pending.is_empty() {
                println!("No pending access requests.");
            } else {
                println!("PENDING ACCESS REQUESTS:");
                for p in pending {
                    println!(
                        "  [{}] {} pid={} hash={} reason=\"{}\" expires_at={}",
                        p.id, p.secret_name, p.pid,
                        p.pid_hash.as_deref().unwrap_or("<unknown>"),
                        p.reason, p.expires_at
                    );
                }
            }
        }
    }
}

const HELP_TEXT: &str = "\
COMMANDS:
  status              Show all secrets and access counts
  mounts              List mounted secret files
  reset [NAME]        Reset access counter (all if no name)
  add NAME FILE HASH  Add a new secret
  remove NAME         Remove a secret
  rotate NAME HASH    Change the allowed binary hash
  pending             Show pending access requests
  grant ID            Grant a pending access request
  deny ID             Deny a pending access request
  help                Show this help
  exit / quit         Exit";

fn interactive<S: SystemIo>(io: &S, socket: &std::path::Path) -> Result<(), String> {
    println!("fuse-client interactive mode. Type 'help' for commands, 'exit' to quit.");

    let mut rl: DefaultEditor = DefaultEditor::new().map_err(|e| e.to_string())?;

    // Background thread: poll for pending accesses every 3 seconds.
    // Sets a flag so the main loop can check between readline calls.
    let pending_flag = Arc::new(AtomicBool::new(false));
    let poll_flag = pending_flag.clone();
    let socket_owned = socket.to_path_buf();

    std::thread::spawn(move || {
        let io = fuse_protocol::RealSystemIo::new();
        loop {
            std::thread::sleep(Duration::from_secs(3));
            if let Ok(Response::PendingList { pending }) =
                send_command(&io, &socket_owned, Command::ListPending)
            {
                if !pending.is_empty() {
                    poll_flag.store(true, Ordering::SeqCst);
                }
            }
        }
    });

    loop {
        // Check for pending accesses before each prompt
        if pending_flag.swap(false, Ordering::SeqCst) {
            check_and_handle_pending(io, socket, &mut rl)?;
        }

        let line = match rl.readline("fuse-client> ") {
            Ok(line) => line,
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(e) => return Err(e.to_string()),
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let _ = rl.add_history_entry(trimmed);

        if matches!(trimmed, "exit" | "quit") {
            break;
        }

        if trimmed == "help" {
            println!("{HELP_TEXT}");
            continue;
        }

        // Parse the interactive command
        let parts: Vec<&str> = trimmed.splitn(4, ' ').collect();
        let cmd_str = parts[0];

        let result = match cmd_str {
            "status" => send_command(io, socket, Command::Status),
            "mounts" | "list" => send_command(io, socket, Command::ListMounts),
            "reset" => {
                let name = parts.get(1).map(|s| s.to_string());
                send_command(io, socket, Command::Reset { name })
            }
            "add" => {
                if parts.len() < 4 {
                    eprintln!("Usage: add NAME FILE HASH");
                    continue;
                }
                let name = parts[1].to_string();
                let file = std::path::PathBuf::from(parts[2]);
                let hash = parts[3].to_string();
                match io.read_file(&file) {
                    Ok(content) => send_command(io, socket, Command::AddSecret {
                        name,
                        content,
                        hash,
                    }),
                    Err(e) => {
                        eprintln!("Error reading file: {e}");
                        continue;
                    }
                }
            }
            "remove" => {
                if parts.len() < 2 {
                    eprintln!("Usage: remove NAME");
                    continue;
                }
                send_command(io, socket, Command::RemoveSecret { name: parts[1].to_string() })
            }
            "rotate" => {
                if parts.len() < 3 {
                    eprintln!("Usage: rotate NAME HASH");
                    continue;
                }
                send_command(io, socket, Command::RotateHash {
                    name: parts[1].to_string(),
                    new_hash: parts[2].to_string(),
                })
            }
            "pending" => send_command(io, socket, Command::ListPending),
            "grant" => {
                if parts.len() < 2 {
                    eprintln!("Usage: grant ID");
                    continue;
                }
                match parts[1].parse::<u64>() {
                    Ok(id) => send_command(io, socket, Command::Grant { id }),
                    Err(_) => {
                        eprintln!("Invalid ID: {}", parts[1]);
                        continue;
                    }
                }
            }
            "deny" => {
                if parts.len() < 2 {
                    eprintln!("Usage: deny ID");
                    continue;
                }
                match parts[1].parse::<u64>() {
                    Ok(id) => send_command(io, socket, Command::Deny { id }),
                    Err(_) => {
                        eprintln!("Invalid ID: {}", parts[1]);
                        continue;
                    }
                }
            }
            _ => {
                eprintln!("Unknown command: '{cmd_str}'. Type 'help' for commands.");
                continue;
            }
        };

        match result {
            Ok(resp) => print_response(&resp),
            Err(e) => eprintln!("Connection error: {e}"),
        }
    }

    println!("Goodbye.");
    Ok(())
}

/// Check for pending accesses and prompt the user to grant/deny.
fn check_and_handle_pending<S: SystemIo>(
    io: &S,
    socket: &std::path::Path,
    rl: &mut DefaultEditor,
) -> Result<(), String> {
    let pending = match send_command(io, socket, Command::ListPending) {
        Ok(Response::PendingList { pending }) => pending,
        _ => return Ok(()),
    };

    if pending.is_empty() {
        return Ok(());
    }

    println!("\n⚡ {} pending access request(s):", pending.len());
    for p in &pending {
        println!(
            "  [{}] secret='{}' pid={} hash={} reason='{}'",
            p.id,
            p.secret_name,
            p.pid,
            p.pid_hash.as_deref().unwrap_or("<unknown>"),
            p.reason
        );
    }

    for p in &pending {
        let prompt = format!(
            "  Grant access [{}] to '{}' (pid {})? [y/N] ",
            p.id, p.secret_name, p.pid
        );
        let answer = match rl.readline(&prompt) {
            Ok(line) => line.trim().to_lowercase(),
            Err(_) => continue,
        };
        if answer == "y" || answer == "yes" {
            match send_command(io, socket, Command::Grant { id: p.id }) {
                Ok(Response::Ok) => println!("  Granted."),
                Ok(other) => println!("  Server response: {other:?}"),
                Err(e) => eprintln!("  Error: {e}"),
            }
        } else {
            match send_command(io, socket, Command::Deny { id: p.id }) {
                Ok(Response::Ok) => println!("  Denied."),
                Ok(other) => println!("  Server response: {other:?}"),
                Err(e) => eprintln!("  Error: {e}"),
            }
        }
    }
    println!();

    Ok(())
}

use std::io::{self as stdio, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use fuse_client::send_command;
use fuse_protocol::{Command, Response, ServerStateFile, SystemIo, VERSION as CLIENT_VERSION};

// ── CLI (non-interactive) ──────────────────────────────────────

#[derive(Parser)]
#[command(name = "fuse-client", about = "Send CRUD commands to the fuse-server")]
struct Cli {
    #[arg(short, long, env = "FUSE_GATEKEEPER_SOCKET", default_value = "/tmp/fuse-gatekeeper.sock")]
    socket: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    Reset { #[arg(short, long)] name: Option<String> },
    ResetAll,
    Status,
    AddSecret { name: String, #[arg(short, long)] file: PathBuf, #[arg(long)] hash: String },
    RemoveSecret { name: String },
    RotateHash { name: String, #[arg(long)] hash: String },
    ListMounts,
    Pending,
    Grant { id: u64 },
    Deny { id: u64 },
    GetVersion,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let io = fuse_protocol::RealSystemIo::new();

    // Check server: if running, verify version; if not, offer to start.
    if io.try_unix_connect(&cli.socket) {
        check_version_or_restart(&io, &cli.socket);
    } else {
        check_start_server(&io, &cli.socket);
    }

    match &cli.command {
        Some(cmd) => {
            let cmd = build_clap_command(cmd, &io);
            match cmd {
                Ok(command) => match send_command(&io, &cli.socket, command) {
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
                },
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        None => {
            if let Err(e) = interactive(&io, &cli.socket) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn build_clap_command<S: SystemIo>(cmd: &Commands, io: &S) -> Result<Command, String> {
    Ok(match cmd {
        Commands::Reset { name } => Command::Reset { name: name.clone() },
        Commands::ResetAll => Command::Reset { name: None },
        Commands::Status => Command::Status,
        Commands::AddSecret { name, file, hash } => {
            let content = io.read_file(file).map_err(|e| e.0)?;
            Command::AddSecret { name: name.clone(), content, hash: hash.clone() }
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
        Commands::GetVersion => Command::GetVersion,
    })
}

// ── Version check & server restart ─────────────────────────────

fn check_version_or_restart(io: &fuse_protocol::RealSystemIo, socket: &Path) {
    let server_version = match send_command(io, socket, Command::GetVersion) {
        Ok(Response::Version { version }) => version,
        Ok(_) => {
            // Server responded but doesn't understand GetVersion — it's
            // an older version.  This IS a mismatch.
            "<unknown (old server)>".to_string()
        }
        Err(e) => {
            // Can't communicate at all — proceed without version check.
            eprintln!("Warning: cannot query server version: {e}");
            return;
        }
    };

    if server_version == CLIENT_VERSION {
        return; // Match
    }

    eprintln!(
        "Version mismatch: client={}, server={}",
        CLIENT_VERSION, server_version
    );

    print!("Restart server to update? [y/N] ");
    stdio::stdout().flush().unwrap();
    let mut input = String::new();
    if stdio::stdin().read_line(&mut input).is_err() {
        return;
    }

    if input.trim().to_lowercase() != "y" {
        eprintln!("Exiting. Restart the server manually, then re-run fuse-client.");
        std::process::exit(1);
    }

    restart_server(io, socket);
}

/// Read the state file written by the orchestrator.
fn read_state_file() -> Option<ServerStateFile> {
    let state_path = Path::new("/tmp/fuse-gatekeeper-state.json");
    let io = fuse_protocol::RealSystemIo::new();
    let data = io.read_file(state_path).ok()?;
    serde_json::from_slice(&data).ok()
}

/// Spawn a new fuse-server from a state file, wait for the socket,
/// and restore all secrets.  Used by both restart and start-if-not-running.
fn start_server_from_state(
    io: &fuse_protocol::RealSystemIo,
    socket: &Path,
    state: &ServerStateFile,
) {
    // Build server command
    let mut cmd_args: Vec<String> = vec![
        "--mount-point".into(), state.mount_point.clone(),
        "--socket".into(), state.socket.clone(),
    ];
    if state.allow_other {
        cmd_args.push("--allow-other".into());
    }
    cmd_args.push("--log-level".into());
    cmd_args.push(state.log_level.clone());
    cmd_args.push("--pending-timeout".into());
    cmd_args.push(state.pending_timeout.to_string());

    let (spawn_prog, spawn_args): (String, Vec<String>) = if let Some(w) = &state.runtime_wrapper {
        let parts: Vec<String> = w.split_whitespace().map(|s| s.to_string()).collect();
        let mut args = parts[1..].to_vec();
        args.push(state.server_binary.clone());
        args.extend(cmd_args);
        (parts[0].clone(), args)
    } else {
        (state.server_binary.clone(), cmd_args)
    };

    eprintln!(
        "  Binary:   {}",
        state.server_binary
    );
    eprintln!("  Wrapper:  {}", state.runtime_wrapper.as_deref().unwrap_or("(none)"));
    eprintln!("  Program:  {spawn_prog}");
    eprintln!("  Args:     {}", spawn_args.join(" "));
    eprintln!("  Mount:    {}", state.mount_point);
    eprintln!("  Socket:   {}", state.socket);

    // Check binary exists
    if std::process::Command::new(&spawn_prog)
        .arg("--help")
        .output().is_err()
    {
        eprintln!("  WARNING: cannot execute '{spawn_prog}' — check PATH");
    }

    // Clean up stale mount point and socket before spawning
    eprintln!("  Cleaning up stale mount/socket...");
    if let Some(w) = &state.runtime_wrapper {
        let wparts: Vec<&str> = w.split_whitespace().collect();
        let mut umount_args: Vec<&str> = wparts[1..].to_vec();
        umount_args.extend(&["fusermount", "-uz", &state.mount_point]);
        let _ = std::process::Command::new(wparts[0]).args(&umount_args).output();
    } else {
        let _ = std::process::Command::new("fusermount").arg("-uz").arg(&state.mount_point).output();
    }
    let _ = std::fs::remove_file(&state.socket);
    let _ = std::fs::remove_dir_all(&state.mount_point);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let _ = std::fs::create_dir_all(&state.mount_point);

    // Spawn new server as independent daemon
    eprintln!("Starting server (v{})...", CLIENT_VERSION);
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&spawn_prog);
    cmd.args(&spawn_args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    match cmd.spawn() {
        Ok(child) => {
            eprintln!("  Spawned pid {}", child.id());
        }
        Err(e) => {
            eprintln!("Failed to start server: {e}");
            eprintln!("Start it manually with: run-agent ...");
            std::process::exit(1);
        }
    }

    // Wait for socket
    eprintln!("Waiting for server...");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if io.try_unix_connect(socket) {
            break;
        }
        if std::time::Instant::now() > deadline {
            eprintln!("Server did not start within 10s. Start it manually.");
            std::process::exit(1);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // Re-add secrets
    eprintln!("Restoring {} secret(s)...", state.secrets.len());
    for entry in &state.secrets {
        let content = match io.read_file(Path::new(&entry.host_path)) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("  Skip {}: cannot read {}: {e}", entry.fuse_name, entry.host_path);
                continue;
            }
        };
        match send_command(io, socket, Command::AddSecret {
            name: entry.fuse_name.clone(),
            content,
            hash: entry.hash.clone(),
        }) {
            Ok(Response::Ok) => eprintln!("  Restored {}", entry.fuse_name),
            Ok(other) => eprintln!("  Error restoring {}: {other:?}", entry.fuse_name),
            Err(e) => eprintln!("  Error restoring {}: {e}", entry.fuse_name),
        }
    }

    eprintln!("Server ready (v{}).", CLIENT_VERSION);
}

fn restart_server(io: &fuse_protocol::RealSystemIo, socket: &Path) {
    let state = match read_state_file() {
        Some(s) => s,
        None => {
            eprintln!("Failed to read state file.");
            return ask_reset_anyway();
        }
    };

    // Try to get current secret status (for display)
    let status_info = match send_command(io, socket, Command::Status) {
        Ok(Response::Status { secrets }) => {
            let names: Vec<&str> = secrets.iter().map(|s| s.name.as_str()).collect();
            format!("{} secret(s): {}", secrets.len(), names.join(", "))
        }
        _ => "could not query current secrets".to_string(),
    };
    eprintln!("Current server state: {status_info}");

    // Kill old server using pkill (state file PID may be the orchestrator)
    eprintln!("Stopping old server...");
    if let Some(w) = &state.runtime_wrapper {
        let wparts: Vec<&str> = w.split_whitespace().collect();
        let mut kill_args: Vec<&str> = wparts[1..].to_vec();
        kill_args.extend(&["pkill", "-f", "fuse-server"]);
        let _ = std::process::Command::new(wparts[0]).args(&kill_args).output();
    } else {
        let _ = std::process::Command::new("pkill").arg("-f").arg("fuse-server").output();
    }
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Wait for socket to disappear
    for _ in 0..30 {
        if !io.try_unix_connect(socket) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // Clean up stale FUSE mount so the new server can mount cleanly
    if let Some(w) = &state.runtime_wrapper {
        let wparts: Vec<&str> = w.split_whitespace().collect();
        let mut umount_args: Vec<&str> = wparts[1..].to_vec();
        umount_args.extend(&["fusermount", "-uz", &state.mount_point]);
        let _ = std::process::Command::new(wparts[0]).args(&umount_args).output();
    } else {
        let _ = std::process::Command::new("fusermount").arg("-uz").arg(&state.mount_point).output();
    }
    let _ = std::fs::remove_file(&state.socket);
    let _ = std::fs::remove_dir_all(&state.mount_point);
    std::thread::sleep(std::time::Duration::from_millis(500));

    start_server_from_state(io, socket, &state);
}

/// Called when the server is not running at all.  Offers to start it
/// from the state file.
fn check_start_server(io: &fuse_protocol::RealSystemIo, socket: &Path) {
    print!("Server is not running. Start it? [y/N] ");
    stdio::stdout().flush().unwrap();
    let mut input = String::new();
    if stdio::stdin().read_line(&mut input).is_err() {
        return;
    }
    if input.trim().to_lowercase() != "y" {
        return;
    }

    match read_state_file() {
        Some(state) => start_server_from_state(io, socket, &state),
        None => {
            eprintln!(
                "No state file found at /tmp/fuse-gatekeeper-state.json.\n\
                 Start the server manually with: run-agent ..."
            );
        }
    }
}

fn ask_reset_anyway() {
    eprintln!("Failed to get current secret list for restore.");
    print!("Reset server anyways (all secrets will be lost)? [y/N] ");
    stdio::stdout().flush().unwrap();
    let mut input = String::new();
    let _ = stdio::stdin().read_line(&mut input);
    if input.trim().to_lowercase() == "y" {
        let _ = std::process::Command::new("pkill").arg("-f").arg("fuse-server").output();
        eprintln!("Server killed. Re-run run-agent to start a fresh server.");
        std::process::exit(0);
    } else {
        eprintln!("Exiting without restarting.");
        std::process::exit(1);
    }
}

// ── Plugin system ──────────────────────────────────────────────

/// What a command plugin returns after execution.
enum ShellAction {
    Continue,
    Exit,
}

/// A single command plugin.  Each plugin owns its argument parsing
/// (the raw remaining text after the command name) and execution logic.
/// This eliminates duplication between CLI and interactive modes.
struct Plugin {
    name: &'static str,
    help: &'static str,
    execute: fn(args: &str, io: &fuse_protocol::RealSystemIo, socket: &Path) -> ShellAction,
}

fn all_plugins() -> Vec<Plugin> {
    vec![
        Plugin {
            name: "status",
            help: "Show all secrets and access counts",
            
            execute: |_, io, sock| {
                run_simple(io, sock, Command::Status)
            },
        },
        Plugin {
            name: "mounts",
            help: "List mounted secret files",
            
            execute: |_, io, sock| run_simple(io, sock, Command::ListMounts),
        },
        Plugin {
            name: "reset",
            help: "Reset access counter for one or all secrets",
            
            execute: |args, io, sock| {
                let name = args.split_whitespace().next().map(|s| s.to_string());
                run_simple(io, sock, Command::Reset { name })
            },
        },
        Plugin {
            name: "reset-all",
            help: "Reset all access counters",
            
            execute: |_, io, sock| run_simple(io, sock, Command::Reset { name: None }),
        },
        Plugin {
            name: "add",
            help: "Add a new secret from a file",
            
            execute: |args, io, sock| {
                let parts: Vec<&str> = args.trim().splitn(3, char::is_whitespace).collect();
                if parts.len() < 3 {
                    eprintln!("Usage: add NAME FILE HASH");
                    return ShellAction::Continue;
                }
                let file = PathBuf::from(parts[1]);
                match io.read_file(&file) {
                    Ok(content) => run_simple(io, sock, Command::AddSecret {
                        name: parts[0].to_string(),
                        content,
                        hash: parts[2].to_string(),
                    }),
                    Err(e) => {
                        eprintln!("Error reading file: {e}");
                        ShellAction::Continue
                    }
                }
            },
        },
        Plugin {
            name: "remove",
            help: "Remove a secret",
            
            execute: |args, io, sock| {
                let name = args.trim();
                if name.is_empty() {
                    eprintln!("Usage: remove NAME");
                    return ShellAction::Continue;
                }
                run_simple(io, sock, Command::RemoveSecret { name: name.to_string() })
            },
        },
        Plugin {
            name: "rotate",
            help: "Change the allowed binary hash",
            
            execute: |args, io, sock| {
                let parts: Vec<&str> = args.trim().splitn(2, char::is_whitespace).collect();
                if parts.len() < 2 {
                    eprintln!("Usage: rotate NAME HASH");
                    return ShellAction::Continue;
                }
                run_simple(io, sock, Command::RotateHash {
                    name: parts[0].to_string(),
                    new_hash: parts[1].to_string(),
                })
            },
        },
        Plugin {
            name: "pending",
            help: "Show pending access requests waiting for approval",
            
            execute: |_, io, sock| run_simple(io, sock, Command::ListPending),
        },
        Plugin {
            name: "grant",
            help: "Grant a pending access request",
            
            execute: |args, io, sock| {
                match args.trim().parse::<u64>() {
                    Ok(id) => run_simple(io, sock, Command::Grant { id }),
                    Err(_) => {
                        eprintln!("Usage: grant ID (ID must be a number)");
                        ShellAction::Continue
                    }
                }
            },
        },
        Plugin {
            name: "deny",
            help: "Deny a pending access request",
            
            execute: |args, io, sock| {
                match args.trim().parse::<u64>() {
                    Ok(id) => run_simple(io, sock, Command::Deny { id }),
                    Err(_) => {
                        eprintln!("Usage: deny ID (ID must be a number)");
                        ShellAction::Continue
                    }
                }
            },
        },
        Plugin {
            name: "version",
            help: "Show client and server versions",
            execute: |_, io, sock| {
                println!("Client: {}", CLIENT_VERSION);
                match send_command(io, sock, Command::GetVersion) {
                    Ok(Response::Version { version }) => println!("Server: {version}"),
                    Ok(_) => println!("Server: <unknown response>"),
                    Err(e) => println!("Server: <unreachable: {e}>"),
                }
                ShellAction::Continue
            },
        },
        Plugin {
            name: "help",
            help: "Show available commands",
            
            execute: |_, _, _| {
                print_help();
                ShellAction::Continue
            },
        },
        Plugin {
            name: "exit",
            help: "Exit the shell",
            
            execute: |_, _, _| ShellAction::Exit,
        },
        Plugin {
            name: "quit",
            help: "Exit the shell",
            
            execute: |_, _, _| ShellAction::Exit,
        },
    ]
}

/// Send a command and print the response. Returns Continue.
fn run_simple(
    io: &fuse_protocol::RealSystemIo,
    socket: &Path,
    cmd: Command,
) -> ShellAction {
    match send_command(io, socket, cmd) {
        Ok(resp) => print_response(&resp),
        Err(e) => eprintln!("Connection error: {e}"),
    }
    ShellAction::Continue
}

fn print_help() {
    println!("COMMANDS:");
    let max_name = all_plugins().iter().map(|p| p.name.len()).max().unwrap_or(0);
    for p in all_plugins() {
        if p.name == "exit" || p.name == "quit" {
            continue;
        }
        println!("  {:<width$}  {}", p.name, p.help, width = max_name);
    }
    println!("  {:<width$}  Exit the shell", "exit", width = max_name);
}

// ── Response printing ──────────────────────────────────────────

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
                        p.id,
                        p.secret_name,
                        p.pid,
                        p.pid_hash.as_deref().unwrap_or("<unknown>"),
                        p.reason,
                        p.expires_at
                    );
                }
            }
        }
        Response::Version { version } => {
            println!("Server version: {version}");
        }
    }
}

// ── Interactive shell (crossterm-based, real-time pending) ─────

fn interactive(
    io: &fuse_protocol::RealSystemIo,
    socket: &Path,
) -> Result<(), String> {
    use crossterm::terminal;

    println!("fuse-client interactive mode. Type 'help' for commands, 'exit' to quit.");
    println!("Pending access requests appear automatically — no need to type 'pending'.");

    terminal::enable_raw_mode().map_err(|e| e.to_string())?;
    let result = interactive_loop(io, socket);
    let _ = terminal::disable_raw_mode();
    println!();
    println!("Goodbye.");
    result
}

fn interactive_loop(
    io: &fuse_protocol::RealSystemIo,
    socket: &Path,
) -> Result<(), String> {
    use crossterm::{
        event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
        terminal::{self},
    };

    let plugins = all_plugins();
    let mut input = String::new();
    let mut cursor_pos: usize = 0;
    let mut history: Vec<String> = Vec::new();
    let mut history_idx: Option<usize> = None;
    let mut pending: Vec<fuse_protocol::PendingAccessInfo> = Vec::new();
    let mut pending_grant_mode: Option<usize> = None; // index into pending for yes/no prompt

    fn redraw(
        input: &str,
        cursor_pos: usize,
        pending: &[fuse_protocol::PendingAccessInfo],
        pending_grant_mode: Option<usize>,
    ) {
        use crossterm::{cursor, execute, style::{Color, SetForegroundColor}, terminal::{self, ClearType}};

        // Move cursor to the start and clear everything below
        let _ = execute!(
            std::io::stdout(),
            cursor::MoveToColumn(0),
            terminal::Clear(ClearType::FromCursorDown),
        );

        // Draw pending access pop-up
        if !pending.is_empty() {
            let _ = execute!(std::io::stdout(), SetForegroundColor(Color::Yellow));
            println!();
            for (i, p) in pending.iter().enumerate() {
                let active = pending_grant_mode == Some(i);
                let prefix = if active { "  ▸ " } else { "  ⚡ " };
                println!(
                    "{prefix}[{}] secret='{}' pid={} hash={} reason='{}'",
                    p.id,
                    p.secret_name,
                    p.pid,
                    p.pid_hash.as_deref().unwrap_or("<unknown>"),
                    p.reason
                );
                if active {
                    let _ = execute!(std::io::stdout(), SetForegroundColor(Color::Cyan));
                    println!("    Grant access [{}]? [y/N] ", p.id);
                    let _ = execute!(std::io::stdout(), SetForegroundColor(Color::Yellow));
                }
            }
            let _ = execute!(std::io::stdout(), SetForegroundColor(Color::Reset));
        }

        // Draw prompt + input
        let pending_count = if pending.is_empty() { String::new() } else { format!("({} pending) ", pending.len()) };
        print!("{pending_count}fuse-client> {input}");
        // Position cursor
        let _ = execute!(
            std::io::stdout(),
            cursor::MoveToColumn((format!("{pending_count}fuse-client> ").len() + cursor_pos) as u16),
        );
        let _ = std::io::stdout().flush();
    }

    redraw(&input, cursor_pos, &pending, pending_grant_mode);

    loop {
        // Poll for input with 3-second timeout
        if event::poll(std::time::Duration::from_secs(3)).map_err(|e| e.to_string())? {
            // Terminal event
            match event::read().map_err(|e| e.to_string())? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    // If in grant mode, handle y/n
                    if let Some(idx) = pending_grant_mode {
                        match key.code {
                            KeyCode::Char('y') | KeyCode::Char('Y') => {
                                let p = &pending[idx];
                                let _ = send_command(io, socket, Command::Grant { id: p.id });
                                pending.remove(idx);
                                pending_grant_mode = None;
                            }
                            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Enter => {
                                let p = &pending[idx];
                                let _ = send_command(io, socket, Command::Deny { id: p.id });
                                pending.remove(idx);
                                pending_grant_mode = None;
                            }
                            _ => {}
                        }
                        redraw(&input, cursor_pos, &pending, pending_grant_mode);
                        continue;
                    }

                    match key.code {
                        KeyCode::Enter => {
                            let line = std::mem::take(&mut input);
                            cursor_pos = 0;
                            // Move to next line for output
                            println!();
                            let _ = std::io::stdout().flush();

                            // Temporarily exit raw mode for command output
                            let _ = terminal::disable_raw_mode();

                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                let _ = terminal::enable_raw_mode();
                                redraw(&input, cursor_pos, &pending, pending_grant_mode);
                                continue;
                            }
                            history.push(line.clone());
                            history_idx = None;

                            if trimmed == "exit" || trimmed == "quit" {
                                return Ok(());
                            }

                            let (cmd_name, args) = match trimmed.split_once(' ') {
                                Some((n, r)) => (n, r),
                                None => (trimmed, ""),
                            };

                            match plugins.iter().find(|p| p.name == cmd_name) {
                                Some(plugin) => {
                                    if let ShellAction::Exit = (plugin.execute)(args, io, socket) {
                                        return Ok(());
                                    }
                                }
                                None => {
                                    eprintln!("Unknown command: '{cmd_name}'. Type 'help' for commands.");
                                }
                            }

                            let _ = terminal::enable_raw_mode();
                            redraw(&input, cursor_pos, &pending, pending_grant_mode);
                        }
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            input.clear();
                            cursor_pos = 0;
                            history_idx = None;
                            redraw(&input, cursor_pos, &pending, pending_grant_mode);
                        }
                        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL)
                            && input.is_empty() => {
                                return Ok(());
                            }
                        KeyCode::Char(c) => {
                            input.insert(cursor_pos, c);
                            cursor_pos += 1;
                            redraw(&input, cursor_pos, &pending, pending_grant_mode);
                        }
                        KeyCode::Backspace
                            if cursor_pos > 0 => {
                                cursor_pos -= 1;
                                input.remove(cursor_pos);
                                redraw(&input, cursor_pos, &pending, pending_grant_mode);
                            }
                        KeyCode::Delete
                            if cursor_pos < input.len() => {
                                input.remove(cursor_pos);
                                redraw(&input, cursor_pos, &pending, pending_grant_mode);
                            }
                        KeyCode::Left
                            if cursor_pos > 0 => {
                                cursor_pos -= 1;
                                redraw(&input, cursor_pos, &pending, pending_grant_mode);
                            }
                        KeyCode::Right
                            if cursor_pos < input.len() => {
                                cursor_pos += 1;
                                redraw(&input, cursor_pos, &pending, pending_grant_mode);
                            }
                        KeyCode::Home => {
                            cursor_pos = 0;
                            redraw(&input, cursor_pos, &pending, pending_grant_mode);
                        }
                        KeyCode::End => {
                            cursor_pos = input.len();
                            redraw(&input, cursor_pos, &pending, pending_grant_mode);
                        }
                        KeyCode::Up
                            if !history.is_empty() => {
                                history_idx = Some(match history_idx {
                                    Some(0) => 0,
                                    Some(i) => i - 1,
                                    None => history.len() - 1,
                                });
                                input = history[history_idx.unwrap()].clone();
                                cursor_pos = input.len();
                                redraw(&input, cursor_pos, &pending, pending_grant_mode);
                            }
                        KeyCode::Down => {
                            match history_idx {
                                Some(i) if i + 1 < history.len() => {
                                    history_idx = Some(i + 1);
                                    input = history[i + 1].clone();
                                }
                                _ => {
                                    history_idx = None;
                                    input.clear();
                                }
                            }
                            cursor_pos = input.len();
                            redraw(&input, cursor_pos, &pending, pending_grant_mode);
                        }
                        KeyCode::Tab => {
                            // Simple tab completion: complete command name
                            let word = input.split_whitespace().next().unwrap_or("");
                            if !word.is_empty() && !input.contains(' ') {
                                if let Some(p) = plugins.iter().find(|pl| pl.name.starts_with(word)) {
                                    input = p.name.to_string();
                                    cursor_pos = input.len();
                                    redraw(&input, cursor_pos, &pending, pending_grant_mode);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        } else {
            // Timeout — poll for pending accesses
            let new_pending = match send_command(io, socket, Command::ListPending) {
                Ok(Response::PendingList { pending: p }) => p,
                _ => Vec::new(),
            };

            // Clean up expired entries
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let live: Vec<_> = new_pending.into_iter().filter(|p| p.expires_at > now).collect();

            if live != pending {
                pending = live;
                // Auto-enter grant mode for the first pending if not already handling one
                if pending_grant_mode.is_none() && !pending.is_empty() {
                    pending_grant_mode = Some(0);
                }
                // Adjust grant mode if current index is out of bounds
                if let Some(idx) = pending_grant_mode {
                    if idx >= pending.len() {
                        pending_grant_mode = if pending.is_empty() { None } else { Some(0) };
                    }
                }
                redraw(&input, cursor_pos, &pending, pending_grant_mode);
            }
        }
    }
}

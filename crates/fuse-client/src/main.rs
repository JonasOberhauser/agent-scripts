use std::io::{self as stdio, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use fuse_client::send_command;
use fuse_protocol::{Command, Response, ServerStateFile, SystemIo, VERSION as CLIENT_VERSION};

// ── Console abstraction ────────────────────────────────────────

/// Output abstraction so plugins work in both CLI (stdout) and TUI
/// (log area) modes without knowing which they're in.
trait Console {
    fn print_line(&mut self, text: &str);
    fn print_error(&mut self, text: &str);
}

/// Prints to stdout / stderr — used in CLI mode.
struct StdoutConsole;

impl Console for StdoutConsole {
    fn print_line(&mut self, text: &str) {
        println!("{text}");
    }
    fn print_error(&mut self, text: &str) {
        eprintln!("{text}");
    }
}

/// Collects lines into a Vec — used in TUI mode where ratatui
/// renders them in the log area.
struct BufferConsole {
    lines: Vec<String>,
}

impl BufferConsole {
    fn new() -> Self {
        Self { lines: Vec::new() }
    }
}

impl Console for BufferConsole {
    fn print_line(&mut self, text: &str) {
        self.lines.push(text.to_string());
    }
    fn print_error(&mut self, text: &str) {
        self.lines.push(format!("Error: {text}"));
    }
}

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
                        print_response(&resp, &mut StdoutConsole);
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
    execute: fn(args: &str, io: &fuse_protocol::RealSystemIo, socket: &Path, out: &mut dyn Console) -> ShellAction,
}

fn all_plugins() -> Vec<Plugin> {
    vec![
        Plugin {
            name: "status",
            help: "Show all secrets and access counts",
            
            execute: |_, io, sock, out| {
                run_simple(io, sock, Command::Status, out)
            },
        },
        Plugin {
            name: "mounts",
            help: "List mounted secret files",
            
            execute: |_, io, sock, out| run_simple(io, sock, Command::ListMounts, out),
        },
        Plugin {
            name: "reset",
            help: "Reset access counter for one or all secrets",
            
            execute: |args, io, sock, out| {
                let name = args.split_whitespace().next().map(|s| s.to_string());
                run_simple(io, sock, Command::Reset { name }, out)
            },
        },
        Plugin {
            name: "reset-all",
            help: "Reset all access counters",
            
            execute: |_, io, sock, out| run_simple(io, sock, Command::Reset { name: None }, out),
        },
        Plugin {
            name: "add",
            help: "Add a new secret from a file",
            
            execute: |args, io, sock, out| {
                let parts: Vec<&str> = args.trim().splitn(3, char::is_whitespace).collect();
                if parts.len() < 3 {
                    out.print_error("Usage: add NAME FILE HASH");
                    return ShellAction::Continue;
                }
                let file = PathBuf::from(parts[1]);
                match io.read_file(&file) {
                    Ok(content) => run_simple(io, sock, Command::AddSecret {
                        name: parts[0].to_string(),
                        content,
                        hash: parts[2].to_string(),
                    }, out),
                    Err(e) => {
                        out.print_error(&format!("Error reading file: {e}"));
                        ShellAction::Continue
                    }
                }
            },
        },
        Plugin {
            name: "remove",
            help: "Remove a secret",
            
            execute: |args, io, sock, out| {
                let name = args.trim();
                if name.is_empty() {
                    out.print_error("Usage: remove NAME");
                    return ShellAction::Continue;
                }
                run_simple(io, sock, Command::RemoveSecret { name: name.to_string() }, out)
            },
        },
        Plugin {
            name: "rotate",
            help: "Change the allowed binary hash",
            
            execute: |args, io, sock, out| {
                let parts: Vec<&str> = args.trim().splitn(2, char::is_whitespace).collect();
                if parts.len() < 2 {
                    out.print_error("Usage: rotate NAME HASH");
                    return ShellAction::Continue;
                }
                run_simple(io, sock, Command::RotateHash {
                    name: parts[0].to_string(),
                    new_hash: parts[1].to_string(),
                }, out)
            },
        },
        Plugin {
            name: "pending",
            help: "Show pending access requests waiting for approval",
            
            execute: |_, io, sock, out| run_simple(io, sock, Command::ListPending, out),
        },
        Plugin {
            name: "grant",
            help: "Grant a pending access request",
            
            execute: |args, io, sock, out| {
                match args.trim().parse::<u64>() {
                    Ok(id) => run_simple(io, sock, Command::Grant { id }, out),
                    Err(_) => {
                        out.print_error("Usage: grant ID (ID must be a number)");
                        ShellAction::Continue
                    }
                }
            },
        },
        Plugin {
            name: "deny",
            help: "Deny a pending access request",
            
            execute: |args, io, sock, out| {
                match args.trim().parse::<u64>() {
                    Ok(id) => run_simple(io, sock, Command::Deny { id }, out),
                    Err(_) => {
                        out.print_error("Usage: deny ID (ID must be a number)");
                        ShellAction::Continue
                    }
                }
            },
        },
        Plugin {
            name: "version",
            help: "Show client and server versions",
            execute: |_, io, sock, out| {
                out.print_line(&format!("Client: {}", CLIENT_VERSION));
                match send_command(io, sock, Command::GetVersion) {
                    Ok(Response::Version { version }) => out.print_line(&format!("Server: {version}")),
                    Ok(_) => out.print_line("Server: <unknown response>"),
                    Err(e) => out.print_line(&format!("Server: <unreachable: {e}>")),
                }
                ShellAction::Continue
            },
        },
        Plugin {
            name: "help",
            help: "Show available commands",
            
            execute: |_, _, _, out| {
                print_help(out);
                ShellAction::Continue
            },
        },
        Plugin {
            name: "exit",
            help: "Exit the shell",
            
            execute: |_, _, _, _| ShellAction::Exit,
        },
        Plugin {
            name: "quit",
            help: "Exit the shell",
            
            execute: |_, _, _, _| ShellAction::Exit,
        },
    ]
}

fn run_simple(
    io: &fuse_protocol::RealSystemIo,
    socket: &Path,
    cmd: Command,
    out: &mut dyn Console,
) -> ShellAction {
    match send_command(io, socket, cmd) {
        Ok(resp) => print_response(&resp, out),
        Err(e) => out.print_error(&format!("Connection error: {e}")),
    }
    ShellAction::Continue
}

fn print_help(out: &mut dyn Console) {
    out.print_line("COMMANDS:");
    let max_name = all_plugins().iter().map(|p| p.name.len()).max().unwrap_or(0);
    for p in all_plugins() {
        if p.name == "exit" || p.name == "quit" {
            continue;
        }
        out.print_line(&format!("  {:<width$}  {}", p.name, p.help, width = max_name));
    }
    out.print_line(&format!("  {:<width$}  Exit the shell", "exit", width = max_name));
}

// ── Response printing ──────────────────────────────────────────

fn print_response(resp: &Response, out: &mut dyn Console) {
    match resp {
        Response::Ok => out.print_line("OK"),
        Response::Error { message } => out.print_error(message),
        Response::Status { secrets } => {
            if secrets.is_empty() {
                out.print_line("No secrets configured.");
            } else {
                out.print_line(&format!("{:<24} {:>8} {:>8}  HASH", "NAME", "READS", "SIZE"));
                for s in secrets {
                    out.print_line(&format!(
                        "{:<24} {:>8} {:>8}  {}",
                        s.name, s.access_count, s.size, s.allowed_hash
                    ));
                }
            }
        }
        Response::MountList { mounts } => {
            if mounts.is_empty() {
                out.print_line("No secrets mounted.");
            } else {
                for m in mounts {
                    out.print_line(&format!("  {} ({} bytes)", m.name, m.size));
                }
            }
        }
        Response::PendingList { pending } => {
            if pending.is_empty() {
                out.print_line("No pending access requests.");
            } else {
                out.print_line("PENDING ACCESS REQUESTS:");
                for p in pending {
                    out.print_line(&format!(
                        "  [{}] {} pid={} hash={} reason=\"{}\" expires_at={}",
                        p.id, p.secret_name, p.pid,
                        p.pid_hash.as_deref().unwrap_or("<unknown>"),
                        p.reason, p.expires_at
                    ));
                }
            }
        }
        Response::Version { version } => {
            out.print_line(&format!("Server version: {version}"));
        }
    }
}

// ── Interactive shell (ratatui + tui-input) ────────────────────

fn interactive(
    io: &fuse_protocol::RealSystemIo,
    socket: &Path,
) -> Result<(), String> {
    use crossterm::{
        event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{
        backend::CrosstermBackend,
        layout::{Constraint, Direction, Layout},
        style::{Color, Style},
        text::Line,
        widgets::{Block, Borders, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap},
        Terminal,
    };
    use std::io as std_io;
    use tui_input::Input;
    use tui_input::backend::crossterm::EventHandler;

    enable_raw_mode().map_err(|e| e.to_string())?;
    execute!(std_io::stdout(), EnterAlternateScreen).map_err(|e| e.to_string())?;
    let backend = CrosstermBackend::new(std_io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|e| e.to_string())?;

    let plugins = all_plugins();
    let mut input = Input::default();
    let mut history: Vec<String> = Vec::new();
    let mut history_idx: Option<usize> = None;
    let mut log_lines: Vec<String> = vec!["fuse-client TUI. Type 'help' for commands.".into()];
    let mut pending: Vec<fuse_protocol::PendingAccessInfo>;
    let mut grant_idx: Option<usize> = None;
    let mut log_scroll_up: u16 = 0; // lines scrolled up from bottom (0 = auto-scroll to latest)

    let poll = || match send_command(io, socket, Command::ListPending) {
        Ok(Response::PendingList { pending: p }) => p,
        _ => Vec::new(),
    };
    pending = poll();
    if !pending.is_empty() { grant_idx = Some(0); }

    let result = (|| {
        loop {
            terminal.draw(|f| {
                // Two-pane layout: 80% log (top), 3 lines input (bottom)
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(3), Constraint::Length(3)])
                    .split(f.area());

                // ── Log pane (scrollable) ──
                let log_height = chunks[0].height.saturating_sub(2) as usize; // -border
                let total = log_lines.len();
                let base_scroll = total.saturating_sub(log_height) as u16;
                let scroll = base_scroll.saturating_sub(log_scroll_up);

                let title = if log_scroll_up > 0 {
                    format!("Log (↑{} lines scrolled)", log_scroll_up)
                } else {
                    "Log".to_string()
                };

                let lines: Vec<Line> = log_lines.iter().map(|s| Line::from(s.as_str())).collect();
                f.render_widget(
                    Paragraph::new(lines)
                        .scroll((scroll, 0))
                        .block(Block::default().borders(Borders::ALL).title(title))
                        .wrap(Wrap { trim: false }),
                    chunks[0],
                );

                // Scrollbar on the right edge of the log pane
                let mut sb_state = ScrollbarState::new(total)
                    .position((total.saturating_sub(log_height) - log_scroll_up as usize).min(total))
                    .viewport_content_length(log_height);
                f.render_stateful_widget(
                    Scrollbar::new(ScrollbarOrientation::VerticalRight)
                        .begin_symbol(None)
                        .end_symbol(None),
                    chunks[0].inner(ratatui::layout::Margin { horizontal: 0, vertical: 1 }),
                    &mut sb_state,
                );

                // ── Pending pop-up (overlays the log pane) ──
                if !pending.is_empty() {
                    let h = (pending.len() + 4) as u16;
                    let pop = ratatui::layout::Rect {
                        x: chunks[0].x + 1,
                        y: chunks[0].y + 1,
                        width: chunks[0].width.saturating_sub(2),
                        height: h.min(chunks[0].height.saturating_sub(2)),
                    };
                    f.render_widget(Clear, pop);
                    let mut pl: Vec<Line> = vec![Line::from(format!(" {} pending request(s)", pending.len()))];
                    for (i, p) in pending.iter().enumerate() {
                        let m = if grant_idx == Some(i) { "▶" } else { "⚡" };
                        pl.push(Line::from(format!(" {m} [{}] {} pid={} {}", p.id, p.secret_name, p.pid, p.reason)));
                    }
                    if let Some(idx) = grant_idx {
                        pl.push(Line::from(""));
                        pl.push(Line::from(format!("  Grant [{}]? [y/N]", pending[idx].id)));
                    }
                    f.render_widget(
                        Paragraph::new(pl)
                            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow)).title("⚠ Pending"))
                            .style(Style::default().bg(Color::Black)),
                        pop,
                    );
                }

                // ── Input pane (fixed at bottom) ──
                let prompt = if pending.is_empty() { "fuse-client> ".into() } else { format!("({}p) fuse-client> ", pending.len()) };
                f.render_widget(
                    Paragraph::new(format!("{prompt}{}", input.value()))
                        .block(Block::default().borders(Borders::ALL).title("Input")),
                    chunks[1],
                );
                f.set_cursor_position((
                    chunks[1].x + 1 + prompt.len() as u16 + input.visual_cursor() as u16,
                    chunks[1].y + 1,
                ));
            }).map_err(|e| e.to_string())?;

            if event::poll(std::time::Duration::from_secs(3)).map_err(|e| e.to_string())? {
                let ev = event::read().map_err(|e| e.to_string())?;
                let Event::Key(key) = ev else { continue };
                if key.kind != KeyEventKind::Press { continue }

                // ── Log scrolling (always available) ──
                match key.code {
                    KeyCode::PageUp => {
                        log_scroll_up = log_scroll_up.saturating_add(5);
                        continue;
                    }
                    KeyCode::PageDown => {
                        log_scroll_up = log_scroll_up.saturating_sub(5);
                        continue;
                    }
                    _ => {}
                }

                // ── Grant mode (y/n for pending) ──
                if let Some(idx) = grant_idx {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            let p = pending[idx].clone();
                            let _ = send_command(io, socket, Command::Grant{ id: p.id });
                            log_lines.push(format!("Granted [{}]", p.id));
                            log_scroll_up = 0;
                            pending.remove(idx);
                            grant_idx = if pending.is_empty() { None } else { Some(idx.min(pending.len()-1)) };
                            continue;
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Enter => {
                            let p = pending[idx].clone();
                            let _ = send_command(io, socket, Command::Deny{ id: p.id });
                            log_lines.push(format!("Denied [{}]", p.id));
                            log_scroll_up = 0;
                            pending.remove(idx);
                            grant_idx = if pending.is_empty() { None } else { Some(idx.min(pending.len()-1)) };
                            continue;
                        }
                        KeyCode::Up if idx > 0 => { grant_idx = Some(idx-1); continue }
                        KeyCode::Down if idx+1 < pending.len() => { grant_idx = Some(idx+1); continue }
                        _ => {}
                    }
                }

                // ── Normal input handling ──
                match key.code {
                    KeyCode::Enter => {
                        let line = input.value().to_string();
                        input.reset(); history_idx = None;
                        if line.trim().is_empty() { continue }
                        history.push(line.clone());
                        if line.trim()=="exit" || line.trim()=="quit" { return Ok(()); }
                        log_lines.push(format!("> {line}"));
                        let (cn, args) = line.trim().split_once(' ').unwrap_or((line.trim(),""));
                        match plugins.iter().find(|p| p.name==cn) {
                            Some(pl) => {
                                let mut buf = BufferConsole::new();
                                if let ShellAction::Exit = (pl.execute)(args, io, socket, &mut buf) { return Ok(()); }
                                log_lines.extend(buf.lines);
                            }
                            None => log_lines.push(format!("Unknown: '{cn}'")),
                        }
                        log_scroll_up = 0; // auto-scroll to bottom on new output
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => { input.reset(); history_idx=None; }
                    KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) && input.value().is_empty() => return Ok(()),
                    KeyCode::Tab => {
                        let w = input.value().split_whitespace().next().unwrap_or("");
                        if !w.is_empty() && !input.value().contains(' ') {
                            if let Some(p) = plugins.iter().find(|pl| pl.name.starts_with(w)) { input = Input::new(p.name.into()); }
                        }
                    }
                    KeyCode::Up if grant_idx.is_none() => {
                        if !history.is_empty() {
                            history_idx = Some(match history_idx { Some(0)=>0, Some(i)=>i-1, None=>history.len()-1 });
                            input = Input::new(history[history_idx.unwrap()].clone());
                        }
                    }
                    KeyCode::Down if grant_idx.is_none() => {
                        match history_idx {
                            Some(i) if i+1<history.len() => { history_idx=Some(i+1); input=Input::new(history[i+1].clone()); }
                            _ => { history_idx=None; input.reset(); }
                        }
                    }
                    _ => { let _ = input.handle_event(&Event::Key(key)); }
                }
            } else {
                // Timeout: poll pending
                let np = poll();
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                let live: Vec<_> = np.into_iter().filter(|p| p.expires_at > now).collect();
                if live != pending {
                    pending = live;
                    if grant_idx.is_none() && !pending.is_empty() { grant_idx = Some(0); }
                    if let Some(i) = grant_idx { if i >= pending.len() { grant_idx = if pending.is_empty() {None} else {Some(0)}; } }
                }
            }
        }
    })();

    disable_raw_mode().ok();
    execute!(std_io::stdout(), LeaveAlternateScreen).ok();
    println!("Goodbye.");
    result
}

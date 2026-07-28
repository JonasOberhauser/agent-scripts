use std::io::{self as stdio, Write};
use std::path::PathBuf;

use clap::Parser;
use fuse_protocol::{Response, ServerStateFile, VERSION as CLIENT_VERSION, client_protocols};
use servyi_servatui::{App, Console};

// ── Console implementations ────────────────────────────────────

struct StdoutConsole;
impl Console for StdoutConsole {
    fn print_line(&mut self, text: &str) { println!("{text}"); }
    fn print_error(&mut self, text: &str) { eprintln!("{text}"); }
}

struct BufferConsole { lines: Vec<String> }
impl BufferConsole {
    fn new() -> Self { Self { lines: Vec::new() } }
}
impl Console for BufferConsole {
    fn print_line(&mut self, text: &str) { self.lines.push(text.to_string()); }
    fn print_error(&mut self, text: &str) { self.lines.push(format!("Error: {text}")); }
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
    GetLogPath,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let app = App::builder(&cli.socket)
        .protocol_all(client_protocols())
        .build();

    if app.server_running() {
        check_version_or_restart(&app);
    } else {
        check_start_server(&app);
    }

    match &cli.command {
        Some(cmd) => {
            let (proto_name, args) = build_clap_command(cmd);
            match app.run_cli_command(&proto_name, &args) {
                Ok(lines) => {
                    let mut out = StdoutConsole;
                    for line in lines { out.print_line(&line); }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        None => {
            if let Err(e) = interactive(&app) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn build_clap_command(cmd: &Commands) -> (String, String) {
    match cmd {
        Commands::Reset { name } => ("reset".into(), name.clone().unwrap_or_default()),
        Commands::ResetAll => ("reset-all".into(), "".into()),
        Commands::Status => ("status".into(), "".into()),
        Commands::AddSecret { name, file, hash } => {
            ("add".into(), format!("{name} {} {hash}", file.display()))
        }
        Commands::RemoveSecret { name } => ("remove".into(), name.clone()),
        Commands::RotateHash { name, hash } => ("rotate".into(), format!("{name} {hash}")),
        Commands::ListMounts => ("mounts".into(), "".into()),
        Commands::Pending => ("pending".into(), "".into()),
        Commands::Grant { id } => ("grant".into(), id.to_string()),
        Commands::Deny { id } => ("deny".into(), id.to_string()),
        Commands::GetVersion => ("version".into(), "".into()),
        Commands::GetLogPath => ("logpath".into(), "".into()),
    }
}

// ── Version check & server restart ─────────────────────────────

fn check_version_or_restart(app: &App) {
    let server_version = match app.run_cli_command_raw("version", "") {
        Ok((_, raw)) => {
            serde_json::from_slice::<Response>(&raw)
                .ok()
                .and_then(|r| match r {
                    Response::Version { version } => Some(version),
                    _ => None,
                })
                .unwrap_or_else(|| "<unknown (old server)>".to_string())
        }
        Err(e) => {
            eprintln!("Warning: cannot query server version: {e}");
            return;
        }
    };

    if server_version == CLIENT_VERSION {
        return;
    }

    eprintln!("Version mismatch: client={}, server={}", CLIENT_VERSION, server_version);

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

    let log_path = match app.run_cli_command_raw("logpath", "") {
        Ok((_, raw)) => {
            serde_json::from_slice::<Response>(&raw)
                .ok()
                .and_then(|r| match r {
                    Response::LogPath { path } if !path.is_empty() => {
                        eprintln!("  Old server log: {path}");
                        Some(path)
                    }
                    _ => None,
                })
        }
        Err(_) => None,
    };

    let log_path: Option<String> = Some(log_path.unwrap_or_else(|| {
        eprintln!("Old server doesn't support log path discovery.");
        print!("Log file path (relative to cwd or absolute, Enter=/tmp/fuse-gatekeeper.log): ");
        stdio::stdout().flush().unwrap();
        let mut log_input = String::new();
        let _ = stdio::stdin().read_line(&mut log_input);
        let trimmed = log_input.trim();
        if trimmed.is_empty() { "/tmp/fuse-gatekeeper.log".to_string() }
        else { trimmed.to_string() }
    }));

    restart_server(app, log_path.as_deref());
}

fn read_state_file() -> Option<ServerStateFile> {
    let data = std::fs::read("/tmp/fuse-gatekeeper-state.json").ok()?;
    serde_json::from_slice(&data).ok()
}

fn start_server_from_state(app: &App, state: &ServerStateFile, log_path: Option<&str>) {
    let mut cmd_args: Vec<String> = vec![
        "--mount-point".into(), state.mount_point.clone(),
        "--socket".into(), state.socket.clone(),
    ];
    if state.allow_other { cmd_args.push("--allow-other".into()); }
    cmd_args.push("--log-level".into());
    cmd_args.push(state.log_level.clone());
    cmd_args.push("--pending-timeout".into());
    cmd_args.push(state.pending_timeout.to_string());
    if let Some(lp) = log_path {
        cmd_args.push("--log-path".into());
        cmd_args.push(lp.into());
    }

    let (spawn_prog, spawn_args): (String, Vec<String>) = if let Some(w) = &state.runtime_wrapper {
        let parts: Vec<String> = w.split_whitespace().map(|s| s.to_string()).collect();
        let mut args = parts[1..].to_vec();
        args.push(state.server_binary.clone());
        args.extend(cmd_args);
        (parts[0].clone(), args)
    } else {
        (state.server_binary.clone(), cmd_args)
    };

    eprintln!("  Binary:   {}", state.server_binary);
    eprintln!("  Wrapper:  {}", state.runtime_wrapper.as_deref().unwrap_or("(none)"));
    eprintln!("  Program:  {spawn_prog}");
    eprintln!("  Args:     {}", spawn_args.join(" "));

    if std::process::Command::new(&spawn_prog).arg("--help").output().is_err() {
        eprintln!("  WARNING: cannot execute '{spawn_prog}' — check PATH");
    }

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

    eprintln!("Starting server (v{})...", CLIENT_VERSION);
    let effective_log = log_path.unwrap_or("/tmp/fuse-gatekeeper.log");
    let log_path_buf = std::path::PathBuf::from(effective_log);
    let log_file = std::fs::OpenOptions::new()
        .create(true).truncate(true).write(true)
        .open(&log_path_buf)
        .unwrap_or_else(|e| { eprintln!("open log file: {e}"); std::process::exit(1); });
    let log_file2 = log_file.try_clone().unwrap_or_else(|e| { eprintln!("dup log fd: {e}"); std::process::exit(1); });
    eprintln!("  Log:       {}", log_path_buf.display());

    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&spawn_prog);
    cmd.args(&spawn_args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log_file))
        .stderr(std::process::Stdio::from(log_file2));
    unsafe { cmd.pre_exec(|| { libc::setsid(); Ok(()) }); }
    match cmd.spawn() {
        Ok(child) => eprintln!("  Spawned pid {}", child.id()),
        Err(e) => {
            eprintln!("Failed to start server: {e}");
            eprintln!("Start it manually with: run-agent ...");
            std::process::exit(1);
        }
    }

    eprintln!("Waiting for server...");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if app.server_running() { break; }
        if std::time::Instant::now() > deadline {
            eprintln!("Server did not start within 10s. Start it manually.");
            std::process::exit(1);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    eprintln!("Restoring {} secret(s)...", state.secrets.len());
    for entry in &state.secrets {
        let args = format!("{} {} {}", entry.fuse_name, entry.host_path, entry.hash);
        match app.run_cli_command("add", &args) {
            Ok(_) => eprintln!("  Restored {}", entry.fuse_name),
            Err(e) => eprintln!("  Error restoring {}: {e}", entry.fuse_name),
        }
    }
    eprintln!("Server ready (v{}).", CLIENT_VERSION);
}

fn restart_server(app: &App, log_path: Option<&str>) {
    let state = match read_state_file() {
        Some(s) => s,
        None => {
            eprintln!("Failed to read state file.");
            return ask_reset_anyway();
        }
    };

    let status_info = match app.run_cli_command_raw("status", "") {
        Ok((_, raw)) => {
            serde_json::from_slice::<Response>(&raw)
                .ok()
                .and_then(|r| match r {
                    Response::Status { secrets } => {
                        let names: Vec<&str> = secrets.iter().map(|s| s.name.as_str()).collect();
                        Some(format!("{} secret(s): {}", secrets.len(), names.join(", ")))
                    }
                    _ => None,
                })
                .unwrap_or_else(|| "could not query current secrets".to_string())
        }
        Err(_) => "could not query current secrets".to_string(),
    };
    eprintln!("Current server state: {status_info}");

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

    for _ in 0..30 {
        if !app.server_running() { break; }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

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

    start_server_from_state(app, &state, log_path);
}

fn check_start_server(app: &App) {
    print!("Server is not running. Start it? [y/N] ");
    stdio::stdout().flush().unwrap();
    let mut input = String::new();
    if stdio::stdin().read_line(&mut input).is_err() { return; }
    if input.trim().to_lowercase() != "y" { return; }

    match read_state_file() {
        Some(state) => start_server_from_state(app, &state, None),
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

enum ShellAction { Continue, Exit }

struct Plugin {
    name: &'static str,
    help: &'static str,
    execute: fn(args: &str, app: &App, out: &mut dyn Console) -> ShellAction,
}

fn run_simple(app: &App, proto_name: &str, args: &str, out: &mut dyn Console) -> ShellAction {
    match app.run_cli_command(proto_name, args) {
        Ok(lines) => { for l in lines { out.print_line(&l); } }
        Err(e) => out.print_error(&format!("Connection error: {e}")),
    }
    ShellAction::Continue
}

fn all_plugins() -> Vec<Plugin> {
    vec![
        Plugin { name: "status", help: "Show all secrets and access counts",
            execute: |args, app, out| run_simple(app, "status", args, out) },
        Plugin { name: "mounts", help: "List mounted secret files",
            execute: |args, app, out| run_simple(app, "mounts", args, out) },
        Plugin { name: "reset", help: "Reset access counter for one or all secrets",
            execute: |args, app, out| run_simple(app, "reset", args, out) },
        Plugin { name: "reset-all", help: "Reset all access counters",
            execute: |args, app, out| run_simple(app, "reset-all", args, out) },
        Plugin { name: "add", help: "Add a new secret from a file",
            execute: |args, app, out| run_simple(app, "add", args, out) },
        Plugin { name: "remove", help: "Remove a secret",
            execute: |args, app, out| run_simple(app, "remove", args, out) },
        Plugin { name: "rotate", help: "Change the allowed binary hash",
            execute: |args, app, out| run_simple(app, "rotate", args, out) },
        Plugin { name: "pending", help: "Show pending access requests",
            execute: |args, app, out| run_simple(app, "pending", args, out) },
        Plugin { name: "grant", help: "Grant a pending access request",
            execute: |args, app, out| run_simple(app, "grant", args, out) },
        Plugin { name: "deny", help: "Deny a pending access request",
            execute: |args, app, out| run_simple(app, "deny", args, out) },
        Plugin { name: "version", help: "Show client and server versions",
            execute: |_, app, out| {
                out.print_line(&format!("Client: {}", CLIENT_VERSION));
                run_simple(app, "version", "", out)
            } },
        Plugin { name: "help", help: "Show available commands",
            execute: |_, _, out| { print_help(out); ShellAction::Continue } },
        Plugin { name: "exit", help: "Exit the shell",
            execute: |_, _, _| ShellAction::Exit },
        Plugin { name: "quit", help: "Exit the shell",
            execute: |_, _, _| ShellAction::Exit },
    ]
}

fn print_help(out: &mut dyn Console) {
    out.print_line("COMMANDS:");
    let max_name = all_plugins().iter().map(|p| p.name.len()).max().unwrap_or(0);
    for p in all_plugins() {
        if p.name == "exit" || p.name == "quit" { continue; }
        out.print_line(&format!("  {:<width$}  {}", p.name, p.help, width = max_name));
    }
    out.print_line(&format!("  {:<width$}  Exit the shell", "exit", width = max_name));
}

// ── Interactive shell (ratatui + tui-input) ────────────────────

fn interactive(app: &App) -> Result<(), String> {
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
    write!(std_io::stdout(), "\x1b[?1007h").map_err(|e| e.to_string())?;
    std_io::stdout().flush().ok();

    let backend = CrosstermBackend::new(std_io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|e| e.to_string())?;

    let plugins = all_plugins();
    let mut input = Input::default();
    let mut history: Vec<String> = Vec::new();
    let mut history_idx: Option<usize> = None;
    let mut log_lines: Vec<String> = vec!["fuse-client TUI. Type 'help' for commands.".into()];
    let mut pending: Vec<fuse_protocol::PendingAccessInfo>;
    let mut grant_idx: Option<usize> = None;
    let mut log_scroll_up: u16 = 0;

    let poll = || match app.run_cli_command_raw("pending", "") {
        Ok((_, raw)) => {
            serde_json::from_slice::<Response>(&raw)
                .ok()
                .and_then(|r| match r {
                    Response::PendingList { pending } => Some(pending),
                    _ => None,
                })
                .unwrap_or_default()
        }
        Err(_) => Vec::new(),
    };
    pending = poll();
    if !pending.is_empty() { grant_idx = Some(0); }

    let result = (|| {
        loop {
            let term_h = terminal.size().map(|s| s.height as usize).unwrap_or(24);
            let log_h = term_h.saturating_sub(3).saturating_sub(2);
            let max_scroll = log_lines.len().saturating_sub(log_h);
            log_scroll_up = ((log_scroll_up as usize).min(max_scroll)) as u16;

            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(3), Constraint::Length(3)])
                    .split(f.area());

                let log_height = chunks[0].height.saturating_sub(2) as usize;
                let total = log_lines.len();
                let base_scroll = total.saturating_sub(log_height) as u16;
                let scroll = base_scroll.saturating_sub(log_scroll_up);

                let title = if log_scroll_up > 0 {
                    format!("Log (↑{} lines scrolled)", log_scroll_up)
                } else { "Log".to_string() };

                let lines: Vec<Line> = log_lines.iter().map(|s| Line::from(s.as_str())).collect();
                f.render_widget(
                    Paragraph::new(lines)
                        .scroll((scroll, 0))
                        .block(Block::default().borders(Borders::ALL).title(title))
                        .wrap(Wrap { trim: false }),
                    chunks[0],
                );

                let max_scroll = total.saturating_sub(log_height);
                let clamped = (log_scroll_up as usize).min(max_scroll);
                let mut sb_state = ScrollbarState::new(max_scroll + 1)
                    .position(max_scroll - clamped)
                    .viewport_content_length(log_height);
                f.render_stateful_widget(
                    Scrollbar::new(ScrollbarOrientation::VerticalRight)
                        .begin_symbol(None).end_symbol(None),
                    chunks[0].inner(ratatui::layout::Margin { horizontal: 0, vertical: 1 }),
                    &mut sb_state,
                );

                if !pending.is_empty() && grant_idx.is_some() {
                    let pl: Vec<Line> = {
                        let mut lines = Vec::new();
                        lines.push(Line::from(""));
                        for (i, p) in pending.iter().enumerate() {
                            let active = grant_idx == Some(i);
                            let prefix = if active { "▶" } else { " " };
                            lines.push(Line::from(format!(
                                " {prefix} [{}] {}  (pid {})", p.id, p.secret_name, p.pid
                            )));
                            lines.push(Line::from(format!(
                                "     hash: {}  reason: {}",
                                p.pid_hash.as_deref().unwrap_or("<unknown>"), p.reason
                            )));
                            lines.push(Line::from(""));
                        }
                        lines.push(Line::from(" [y] Grant   [n] Deny   [↑↓] Navigate   [Esc] Close"));
                        lines
                    };
                    let h = pl.len() as u16 + 2;
                    let pop = ratatui::layout::Rect {
                        x: chunks[0].x + 1, y: chunks[0].y + 1,
                        width: chunks[0].width.saturating_sub(2),
                        height: h.min(chunks[0].height.saturating_sub(2)),
                    };
                    f.render_widget(Clear, pop);
                    f.render_widget(
                        Paragraph::new(pl)
                            .block(Block::default()
                                .borders(Borders::ALL)
                                .border_style(Style::default().fg(Color::Yellow))
                                .title(format!("⚠ {} Pending Access Request(s)", pending.len())))
                            .style(Style::default().bg(Color::Black)),
                        pop,
                    );
                }

                let prompt = if pending.is_empty() { "> ".into() } else { format!("({}p) > ", pending.len()) };
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

            let poll_timeout = if grant_idx.is_some() || !pending.is_empty() {
                std::time::Duration::from_millis(500)
            } else {
                std::time::Duration::from_secs(3)
            };

            if event::poll(poll_timeout).map_err(|e| e.to_string())? {
                let ev = event::read().map_err(|e| e.to_string())?;
                let key = match ev {
                    Event::Key(k) if k.kind == KeyEventKind::Press => k,
                    _ => continue,
                };

                match key.code {
                    KeyCode::PageUp => { log_scroll_up = log_scroll_up.saturating_add(5); continue; }
                    KeyCode::PageDown => { log_scroll_up = log_scroll_up.saturating_sub(5); continue; }
                    KeyCode::Up if !key.modifiers.contains(KeyModifiers::CONTROL) && grant_idx.is_none() => {
                        log_scroll_up = log_scroll_up.saturating_add(1); continue;
                    }
                    KeyCode::Down if !key.modifiers.contains(KeyModifiers::CONTROL) && grant_idx.is_none() => {
                        log_scroll_up = log_scroll_up.saturating_sub(1); continue;
                    }
                    _ => {}
                }

                if let Some(idx) = grant_idx {
                    match key.code {
                        KeyCode::Esc => { grant_idx = None; continue; }
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            let p = pending[idx].clone();
                            match app.run_cli_command("grant", &p.id.to_string()) {
                                Ok(_) => log_lines.push(format!("Granted [{}] {} (pid {})", p.id, p.secret_name, p.pid)),
                                Err(e) => log_lines.push(format!("Grant failed [{}]: {e}", p.id)),
                            }
                            log_scroll_up = 0;
                            pending.remove(idx);
                            grant_idx = if pending.is_empty() { None } else { Some(idx.min(pending.len()-1)) };
                            continue;
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Enter => {
                            let p = pending[idx].clone();
                            match app.run_cli_command("deny", &p.id.to_string()) {
                                Ok(_) => log_lines.push(format!("Denied [{}] {} (pid {})", p.id, p.secret_name, p.pid)),
                                Err(e) => log_lines.push(format!("Deny failed [{}]: {e}", p.id)),
                            }
                            log_scroll_up = 0;
                            pending.remove(idx);
                            grant_idx = if pending.is_empty() { None } else { Some(idx.min(pending.len()-1)) };
                            continue;
                        }
                        KeyCode::Up if idx > 0 => { grant_idx = Some(idx-1); continue }
                        KeyCode::Down if idx+1 < pending.len() => { grant_idx = Some(idx+1); continue }
                        _ => {}
                    }
                    continue;
                }

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
                                if let ShellAction::Exit = (pl.execute)(args, app, &mut buf) { return Ok(()); }
                                log_lines.extend(buf.lines);
                            }
                            None => log_lines.push(format!("Unknown: '{cn}'")),
                        }
                        log_scroll_up = 0;
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => { input.reset(); history_idx=None; }
                    KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) && input.value().is_empty() => return Ok(()),
                    KeyCode::Tab => {
                        let w = input.value().split_whitespace().next().unwrap_or("");
                        if !w.is_empty() && !input.value().contains(' ') {
                            if let Some(p) = plugins.iter().find(|pl| pl.name.starts_with(w)) {
                                input = Input::new(p.name.into());
                            }
                        }
                    }
                    KeyCode::Up if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if !history.is_empty() {
                            history_idx = Some(match history_idx { Some(0)=>0, Some(i)=>i-1, None=>history.len()-1 });
                            input = Input::new(history[history_idx.unwrap()].clone());
                        }
                    }
                    KeyCode::Down if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        match history_idx {
                            Some(i) if i+1<history.len() => { history_idx=Some(i+1); input=Input::new(history[i+1].clone()); }
                            _ => { history_idx=None; input.reset(); }
                        }
                    }
                    _ => { let _ = input.handle_event(&Event::Key(key)); }
                }
            } else {
                let np = poll();
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                let live: Vec<_> = np.into_iter().filter(|p| p.expires_at > now).collect();
                if live != pending {
                    let had_new = live.len() > pending.len();
                    let current_id = grant_idx.and_then(|i| pending.get(i)).map(|p| p.id);
                    pending = live;
                    if let Some(id) = current_id {
                        grant_idx = pending.iter().position(|p| p.id == id);
                    }
                    if had_new && grant_idx.is_none() && !pending.is_empty() { grant_idx = Some(0); }
                    if let Some(i) = grant_idx {
                        if i >= pending.len() { grant_idx = if pending.is_empty() { None } else { Some(0) }; }
                    }
                }
            }
        }
    })();

    write!(std_io::stdout(), "\x1b[?1007l").ok();
    std_io::stdout().flush().ok();
    disable_raw_mode().ok();
    execute!(std_io::stdout(), LeaveAlternateScreen).ok();
    println!("Goodbye.");
    result
}

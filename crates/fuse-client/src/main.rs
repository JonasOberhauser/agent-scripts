use std::path::PathBuf;

use clap::Parser;
use fuse_protocol::{client_protocols, ServerStateFile, VERSION as CLIENT_VERSION};
use servyi_servatui::App;

mod pending_layer;

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
                    for line in lines {
                        println!("{line}");
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        None => {
            // Interactive mode: poll the server for pending access requests
            // in the background so grant/deny can complete active IDs.
            // On poll failure the last known list is kept.
            let pending: fuse_protocol::PendingIds =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            {
                let pending = pending.clone();
                let socket = cli.socket.clone();
                std::thread::spawn(move || loop {
                    if let Ok(ids) = fuse_protocol::poll_pending_once(&socket) {
                        *pending.lock().unwrap() = ids;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                });
            }
            let protocols = fuse_protocol::client_protocols_with_pending(pending.clone());
            let mut display = servatui_display::Display::new();
            display.add_layer(Box::new(pending_layer::PendingBadgeLayer::new(pending)));
            // Display::run drives run_tui_with_events: the badge layer's
            // frame/route closures ride the overlay + event hooks.
            if let Err(e) = display.run(&cli.socket, &protocols) {
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
    use fuse_protocol::Response;

    let server_version = match app.run_cli_command_raw("version", "") {
        Ok((_, raw)) => serde_json::from_slice::<Response>(&raw)
            .ok()
            .and_then(|r| match r {
                Response::Version { version } => Some(version),
                _ => None,
            })
            .unwrap_or_else(|| "<unknown (old server)>".to_string()),
        Err(e) => {
            eprintln!("Warning: cannot query server version: {e}");
            return;
        }
    };

    if server_version == CLIENT_VERSION {
        return;
    }

    eprintln!("Version mismatch: client={}, server={}", CLIENT_VERSION, server_version);
    eprint!("Restart server to update? [y/N] ");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return;
    }
    if input.trim().to_lowercase() != "y" {
        eprintln!("Exiting. Restart the server manually, then re-run fuse-client.");
        std::process::exit(1);
    }

    let log_path = match app.run_cli_command_raw("logpath", "") {
        Ok((_, raw)) => serde_json::from_slice::<Response>(&raw)
            .ok()
            .and_then(|r| match r {
                Response::LogPath { path } if !path.is_empty() => Some(path),
                _ => None,
            }),
        Err(_) => None,
    };

    let log_path = log_path.unwrap_or_else(|| {
        eprintln!("Old server doesn't support log path discovery.");
        eprint!("Log file path (Enter=/tmp/fuse-gatekeeper.log): ");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
        let t = s.trim();
        if t.is_empty() { "/tmp/fuse-gatekeeper.log".to_string() } else { t.to_string() }
    });

    restart_server(app, Some(&log_path));
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
    use fuse_protocol::Response;

    let state = match read_state_file() {
        Some(s) => s,
        None => {
            eprintln!("Failed to read state file.");
            return ask_reset_anyway();
        }
    };

    let status_info = match app.run_cli_command_raw("status", "") {
        Ok((_, raw)) => serde_json::from_slice::<Response>(&raw)
            .ok()
            .and_then(|r| match r {
                Response::Status { secrets } => {
                    let names: Vec<&str> = secrets.iter().map(|s| s.name.as_str()).collect();
                    Some(format!("{} secret(s): {}", secrets.len(), names.join(", ")))
                }
                _ => None,
            })
            .unwrap_or_else(|| "could not query current secrets".to_string()),
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
    eprint!("Server is not running. Start it? [y/N] ");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() { return; }
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
    eprint!("Reset server anyways (all secrets will be lost)? [y/N] ");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    if input.trim().to_lowercase() == "y" {
        let _ = std::process::Command::new("pkill").arg("-f").arg("fuse-server").output();
        eprintln!("Server killed. Re-run run-agent to start a fresh server.");
        std::process::exit(0);
    } else {
        eprintln!("Exiting without restarting.");
        std::process::exit(1);
    }
}

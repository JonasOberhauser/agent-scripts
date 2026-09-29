#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic, unused_results))]
use std::path::PathBuf;

use clap::Parser;
use fuse_protocol::{client_protocols, ServerStateFile, VERSION as CLIENT_VERSION};
use servyi_servatui::App;

mod pending_layer;

#[derive(Parser)]
#[command(name = "fuse-client", about = "Send CRUD commands to the fuse-server")]
struct Cli {
    #[arg(short, long, env = fuse_protocol::ENV_CMD_SOCKET, default_value = fuse_protocol::DEFAULT_CMD_SOCKET)]
    socket: PathBuf,
    /// Shell completion mode (also auto-engaged when COMP_LINE is set,
    /// per bash's `complete -C`). The remaining argv (or COMP_LINE/
    /// COMP_POINT) carry the words being completed. Hidden: it is a
    /// protocol for the shell, not a user-facing command.
    #[arg(long, hide = true)]
    complete: bool,
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
    /// Grant a pending access permanently (whitelists the package hash).
    GrantForever { id: u64 },
    Deny { id: u64 },
    GetVersion,
    GetLogPath,
    /// Emit the delegating shell-completion scripts (issue servyi/
    /// servatui#5). The scripts are dumb and static — they simply
    /// invoke `fuse-client --complete`; the binary does the dynamic
    /// work against the live server.
    Completions { shell: String },
    /// Restart the fuse-server from the state file: stop the old
    /// daemon (and its supervised data daemon), clean up socket and
    /// mount point, respawn with the same configuration and re-add
    /// every secret from the state file's host paths.  This is the
    /// same flow the client runs on a version mismatch, exposed as a
    /// one-word command; it asks no questions.
    Restart,
}

fn main() {
    // Panel actions log to a file next to the state file: the TUI's
    // alternate screen hides stderr, and truncated title messages are
    // not a debugging interface.
    let log_path = std::env::var(fuse_protocol::ENV_STATE_FILE)
        .ok()
        .map(|p| {
            std::path::Path::new(&p)
                .with_file_name("fuse-gatekeeper-client.log")
                .to_string_lossy()
                .to_string()
        })
        .unwrap_or_else(|| "/tmp/fuse-gatekeeper-client.log".to_string());
    // Default to info: an unset RUST_LOG must not silence the panel
    // action log (that is the whole point of the file).
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env_lossy();
    if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::sync::Mutex::new(file))
            .init();
        tracing::info!("fuse-client starting (log: {log_path})");
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    let cli = Cli::parse();

    // Shell completion comes FIRST: it must never hit the version
    // handshake, the log, or anything slow — a Tab press waits on it.
    if cli.complete || std::env::var_os("COMP_LINE").is_some() {
        complete_mode(&cli.socket);
        return;
    }
    if let Some(Commands::Completions { shell }) = &cli.command {
        print_completion_script(shell);
        return;
    }

    let app = App::builder(&cli.socket)
        .protocol_all(client_protocols())
        .build();

    if let Some(Commands::Restart) = &cli.command {
        let log_path = discover_log_path(&app);
        restart_server(&app, log_path.as_deref());
        return;
    }

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
            let pending: fuse_protocol::PendingIds =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let secrets: fuse_protocol::SecretNames =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            // The worker's 1s poll refreshes BOTH live completion
            // sources: pending request ids (grant/deny) and the server's
            // secret names (reset/remove/rotate) — the old state-file
            // source went stale the moment a secret changed.
            let protocols =
                fuse_protocol::client_protocols_with_snapshots(pending.clone(), secrets.clone());
            // One pending layer, registered for the whole session: it
            // polls on its own (rate-limited, non-blocking — all server
            // I/O goes through a worker thread, so a wedged server can
            // never freeze the render loop) and hides itself while idle.
            // Display::run creates the shared BuiltinTui and attaches it
            // as an ordinary layer, so the builtin input line and the
            // panel are peers with activation-based keyboard focus.
            let panel_error = pending_layer::no_error();
            // Display snapshot for issue #34 collapsed name rendering.
            let collapsed_names: pending_layer::CollapsedNames = Default::default();
            // Supported log-window path (servatui >= 0.8.3): both the
            // panel and the worker push into the sink; Display::run
            // drains it into the builtin log at the start of every
            // frame — so action failures (with their remediation
            // commands) are visible in the TUI, not only in the /tmp
            // log file.
            let log_sink: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
                Default::default();
            let talk = pending_layer::spawn_worker(
                cli.socket.clone(),
                pending.clone(),
                secrets,
                collapsed_names.clone(),
                panel_error.clone(),
                log_sink.clone(),
            );
            let mut display = servatui_display::Display::new();
            let panel_sink = std::sync::Arc::clone(&log_sink);
            let panel = pending_layer::PendingPanelLayer::new(
                pending,
                Box::new(talk),
                panel_error,
            )
            .with_collapsed_names(collapsed_names.clone())
            .with_log_window(Box::new(move |line: &str| {
                panel_sink
                    .lock()
                    .expect("panel log sink lock: TUI callback, single consumer")
                    .push(line.to_string());
            }));
            let _layer_id = display.add_layer(Box::new(panel));
            display.set_log_sink(log_sink);
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
        Commands::GrantForever { id } => ("grant-forever".into(), id.to_string()),
        Commands::Deny { id } => ("deny".into(), id.to_string()),
        Commands::GetVersion => ("version".into(), "".into()),
        Commands::GetLogPath => ("logpath".into(), "".into()),
        // Handled before the App exists — never reaches the socket.
        Commands::Completions { .. } => unreachable!("completions handled pre-App"),
        Commands::Restart => unreachable!("restart runs its own local flow"),
    }
}

// ── Shell completion (servyi/servatui#5) ───────────────────────

/// Slice a completing line into (confirmed prior words, the word
/// being completed). Pure — the unit tests pin the edge cases.
fn split_completing(line_before_cursor: &str) -> (Vec<String>, String) {
    let mut words: Vec<String> = line_before_cursor
        .split_whitespace()
        .map(|w| w.to_string())
        .collect();
    // A trailing (or doubled) space means a NEW empty word is being
    // completed: "reset " → (["reset"], "").
    let starting_new = line_before_cursor.ends_with(char::is_whitespace)
        || line_before_cursor.is_empty();
    let completing = if starting_new {
        String::new()
    } else {
        words.pop().unwrap_or_default()
    };
    (words, completing)
}

/// One minimal servatui step round over the cmd socket, with a hard
/// timeout: completion must never hang the shell. Mirrors
/// `run_cli_command_raw`'s wire sequence exactly: the bare command
/// NAME frame (a JSON string), the parsed-args frame, then the
/// response line; the finalize sentinel closes the exchange.
/// Connect failure (dead server) returns None — callers degrade to
/// command names.
fn one_shot_query(
    socket: &std::path::Path,
    name: &str,
    command: &fuse_protocol::Command,
) -> Option<String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    let mut c = UnixStream::connect(socket).ok()?;
    let _ = c.set_read_timeout(Some(std::time::Duration::from_millis(200)));
    let _ = c.set_write_timeout(Some(std::time::Duration::from_millis(200)));
    let name_frame = serde_json::to_string(name).ok()?;
    let args_frame = serde_json::to_string(command).ok()?;
    c.write_all(format!("{name_frame}\n").as_bytes()).ok()?;
    c.write_all(format!("{args_frame}\n").as_bytes()).ok()?;
    let mut line = String::new();
    {
        let mut reader = BufReader::new(c.try_clone().ok()?);
        if reader.read_line(&mut line).is_err() {
            return None;
        }
    }
    // finalize sentinel — the daemon's step protocol expects it.
    let _ = c.write_all(b"null\n");
    let _ = c.flush();
    Some(line)
}

/// The candidate VALUES for a command's first argument, from the live
/// server — the single kind→query mapping (shared shape with the TUI
/// completers): PendingIds → `pending`, SecretNames → `status`.
fn live_candidates(socket: &std::path::Path, word: &str) -> Vec<String> {
    use fuse_protocol::{Command, Completer, COMMAND_TABLE, Response};
    let Some(spec) = COMMAND_TABLE.iter().find(|s| s.name == word) else {
        return Vec::new();
    };
    match spec.complete {
        Completer::None => Vec::new(),
        Completer::PendingIds => one_shot_query(socket, "pending", &Command::ListPending)
            .and_then(|reply| serde_json::from_str::<Response>(reply.trim()).ok())
            .map(|resp| match resp {
                Response::PendingList { pending } => {
                    pending.iter().map(|p| p.id.to_string()).collect()
                }
                _ => Vec::new(),
            })
            .unwrap_or_default(),
        // First-argument completion only — `rotate NAME HASH` must not
        // complete into the hash position; the caller checks arity.
        Completer::SecretNames { .. } => one_shot_query(socket, "status", &Command::Status)
            .and_then(|reply| serde_json::from_str::<Response>(reply.trim()).ok())
            .map(|resp| match resp {
                Response::Status { secrets, .. } => {
                    secrets.iter().map(|s| s.name.clone()).collect()
                }
                _ => Vec::new(),
            })
            .unwrap_or_default(),
    }
}

/// Completion entry: print one candidate per line (bare words — both
/// bash's `complete -C` and fish's `-a` expect position candidates).
fn complete_mode(socket: &std::path::Path) {
    use fuse_protocol::COMMAND_TABLE;
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    // bash: COMP_LINE/COMP_POINT. fish: argv after --complete.
    let (prior, completing) = if let Some(line) = std::env::var_os("COMP_LINE") {
        let line = line.to_string_lossy().into_owned();
        let point = std::env::var("COMP_POINT")
            .ok()
            .and_then(|p| p.parse::<usize>().ok())
            .unwrap_or(line.len())
            .min(line.len());
        split_completing(&line[..point])
    } else {
        // fish: everything AFTER --complete is the command line being
        // completed (a custom --socket sits before the flag).
        let argv: Vec<String> = std::env::args()
            .skip_while(|a| a != "--complete")
            .skip(1)
            .collect();
        split_completing(&argv.join(" "))
    };

    // bash's COMP_LINE (and fish's `commandline -cp`) include the
    // program's own word first — drop it so "fuse-client sta"
    // completes the COMMAND, not an argument of a command named
    // "fuse-client".
    let prog = std::env::args()
        .next()
        .and_then(|a| {
            std::path::Path::new(&a)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "fuse-client".to_string());
    let mut prior = prior;
    if prior.first().map(|w| w == &prog).unwrap_or(false) {
        let _removed = prior.remove(0);
    }

    let candidates: Vec<String> = if prior.is_empty() {
        // First word: command names (compile-time table — the command
        // surface is not served over the wire, per the issue thread).
        COMMAND_TABLE
            .iter()
            .map(|s| s.name.to_string())
            .filter(|n| n.starts_with(&completing))
            .collect()
    } else {
        // Argument position: only the FIRST argument completes (the
        // SecretNames `rotate` hash guard falls out — arity check).
        let is_first_arg = prior.len() == 1;
        if !is_first_arg {
            Vec::new()
        } else {
            live_candidates(socket, &prior[0])
                .into_iter()
                .filter(|c| c.starts_with(&completing))
                .collect()
        }
    };
    for c in candidates {
        let _ = writeln!(out, "{c}");
    }
    let _ = out.flush();
}

/// The delegating shell scripts — dumb and static; the binary is the
/// smart dynamic half. Hand-written (three ~4-line scripts) rather
/// than a clap_complete dependency for the same protocol.
/// None = unsupported shell (caller reports and exits nonzero).
fn completion_script(shell: &str) -> Option<String> {
    match shell {
        "bash" => Some("complete -C fuse-client fuse-client\n".to_string()),
        "zsh" => Some(
            "autoload -U +X bashcompinit && bashcompinit\ncomplete -C fuse-client fuse-client\n"
                .to_string(),
        ),
        "fish" => Some(
            "complete -c fuse-client -f -a '(fuse-client --complete (commandline -cop))'\n"
                .to_string(),
        ),
        _ => None,
    }
}

fn print_completion_script(shell: &str) {
    match completion_script(shell) {
        Some(script) => print!("{script}"),
        None => {
            eprintln!("unsupported shell {shell:?} (bash | zsh | fish)");
            std::process::exit(1);
        }
    }
}

// ── Version check & server restart ─────────────────────────────

/// Where the running server says it logs; None when unreachable or it
/// predates logpath discovery (callers decide their own fallback).
fn discover_log_path(app: &App) -> Option<String> {
    use fuse_protocol::Response;
    app.run_cli_command_raw("logpath", "")
        .ok()
        .and_then(|(_, raw)| serde_json::from_slice::<Response>(&raw).ok())
        .and_then(|r| match r {
            Response::LogPath { path } if !path.is_empty() => Some(path),
            _ => None,
        })
}

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

    if fuse_protocol::protocol_compatible(&server_version, CLIENT_VERSION) {
        return;
    }

    eprintln!("Version mismatch: client={}, server={}", CLIENT_VERSION, server_version);
    eprint!("Restart server to update? [y/N] ");
    let _flushed = std::io::Write::flush(&mut std::io::stdout()).ok();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return;
    }
    if input.trim().to_lowercase() != "y" {
        eprintln!("Exiting. Restart the server manually, then re-run fuse-client.");
        std::process::exit(1);
    }

    let log_path = discover_log_path(app);

    let log_path = log_path.unwrap_or_else(|| {
        eprintln!("Old server doesn't support log path discovery.");
        eprint!("Log file path (Enter=/tmp/fuse-gatekeeper.log): ");
        let _flushed = std::io::Write::flush(&mut std::io::stdout()).ok();
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
        let t = s.trim();
        if t.is_empty() { fuse_protocol::DEFAULT_LOG_PATH.to_string() } else { t.to_string() }
    });

    restart_server(app, Some(&log_path));
}

/// How the restart stops the old server, as DATA: the pid the state
/// file names (after a pid-reuse guard), or — when the state file
/// names no pid — a socket-scoped orphan match. Extracted so the
/// decision is testable without executing any kill (#62).
enum ServerKillSpec {
    /// The state file names the pid AND /proc/<pid>/cmdline still
    /// names the fuse-server binary: signal exactly this process.
    NamedPid { pid: i32 },
    /// No recorded pid, or the pid now belongs to something else
    /// (reused): match orphans PRECISELY by the stack's own socket
    /// path — a command line carrying `--socket <state.socket>`. A
    /// bare-name sweep (`pkill -x fuse-server`) is NEVER produced:
    /// on a multi-stack machine it kills every policy daemon, and
    /// the observed-live incident did exactly that.
    OrphanBySocket { socket: String },
}

/// Pid-reuse guard: the state file's pid only counts when the
/// process behind it still looks like OUR server. Pure over its
/// inputs (the cmdline bytes) so it stays testable.
fn pid_cmdline_names_server(cmdline: &[u8], server_binary: &str) -> bool {
    // cmdline args are NUL-separated; the executable is argv[0].
    let argv0 = cmdline.split(|&b| b == 0).next().unwrap_or(&[]);
    let argv0 = String::from_utf8_lossy(argv0);
    argv0 == server_binary
        || argv0.ends_with(&format!("/{server_binary}"))
        || server_binary.ends_with(&format!("/{argv0}"))
}

fn server_kill_spec(state: &ServerStateFile) -> ServerKillSpec {
    if state.server_pid != 0 {
        let cmdline = std::fs::read(format!("/proc/{}/cmdline", state.server_pid));
        let verified = cmdline
            .map(|c| pid_cmdline_names_server(&c, &state.server_binary))
            .unwrap_or(false);
        if verified {
            return ServerKillSpec::NamedPid { pid: state.server_pid as i32 };
        }
        // pid gone or reused: fall through to the socket-scoped match,
        // never a name sweep.
    }
    ServerKillSpec::OrphanBySocket { socket: state.socket.clone() }
}

/// The argv the restart respawns the server with, as DATA: extracting
/// it makes the state-file -> argv mapping testable without spawning
/// anything or touching the fixed state-file path.
fn respawn_argv(state: &ServerStateFile) -> Vec<String> {
    let mut argv = vec![
        "--mount-point".to_string(),
        state.mount_point.clone(),
        "--socket".to_string(),
        state.socket.clone(),
    ];
    if let Some(oracle) = &state.oracle_socket {
        // The surviving data daemon retries THIS rendezvous; respawning
        // on the global default would orphan it (an alive mount that
        // never syncs again).
        argv.push("--oracle-socket".to_string());
        argv.push(oracle.clone());
    }
    argv.push("--log-level".to_string());
    argv.push(state.log_level.clone());
    argv.push("--pending-timeout".to_string());
    argv.push(state.pending_timeout.to_string());
    argv
}


fn read_state_file() -> Option<ServerStateFile> {
    let data = std::fs::read(fuse_protocol::state_file()).ok()?;
    serde_json::from_slice(&data).ok()
}

fn start_server_from_state(app: &App, state: &ServerStateFile, log_path: Option<&str>) {
    let mut cmd_args = respawn_argv(state);
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
    let effective_log = log_path.unwrap_or(fuse_protocol::DEFAULT_LOG_PATH);
    let log_path_buf = std::path::PathBuf::from(effective_log);
    let log_file = std::fs::OpenOptions::new()
        .create(true).truncate(true).write(true)
        .open(&log_path_buf)
        .unwrap_or_else(|e| { eprintln!("open log file: {e}"); std::process::exit(1); });
    let log_file2 = log_file.try_clone().unwrap_or_else(|e| { eprintln!("dup log fd: {e}"); std::process::exit(1); });
    eprintln!("  Log:       {}", log_path_buf.display());

    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&spawn_prog);
    let _cmd = cmd
        .args(&spawn_args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log_file))
        .stderr(std::process::Stdio::from(log_file2));
    fn child_setsid() -> std::io::Result<()> {
        // SAFETY: setsid(2) takes no pointers and has no memory-safety
        // preconditions; failure (already a process-group leader) is
        // reported via the return value, which pre_exec propagates.
        let _sid = unsafe { libc::setsid() };
        Ok(())
    }
    let cmd_mut = &mut cmd;
    let setsid_cb = child_setsid;
    // SAFETY: `pre_exec` runs the callback between fork(2) and
    // execve(2), where only async-signal-safe operations are allowed.
    // The callback above calls only setsid(2) and returns — no
    // allocation, no locks, no libc state; re-check its body when
    // editing it (nothing enforces this).
    let _cmd = unsafe { cmd_mut.pre_exec(setsid_cb) };
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
                Response::Status { secrets, .. } => {
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
    match server_kill_spec(&state) {
        ServerKillSpec::NamedPid { pid, .. } => {
            // The state file NAMES the server and the pid-reuse guard
            // passed: signal exactly this process.
            // SAFETY: a plain signal to one verified pid; no
            // process-group or pattern semantics involved.
            let sig = libc::SIGTERM;
            // SAFETY: a plain signal to one verified pid; no
            // process-group or pattern semantics involved.
            let _killed = unsafe { libc::kill(pid, sig) };
        }
        ServerKillSpec::OrphanBySocket { socket } => {
            // Unnamed or pid-reused: match orphans by the stack's OWN
            // socket path — `--socket <path>` in the command line.
            // Precise on multi-stack machines; a bare-name sweep
            // here took down the developer's production gate stack
            // (observed live).
            let pat = format!("--socket {socket}");
            if let Some(w) = &state.runtime_wrapper {
                let wparts: Vec<&str> = w.split_whitespace().collect();
                let mut kill_args: Vec<&str> = wparts[1..].to_vec();
                kill_args.extend(&["pkill", "-f", &pat]);
                let _ = std::process::Command::new(wparts[0]).args(&kill_args).output();
            } else {
                let _ = std::process::Command::new("pkill")
                    .arg("-f")
                    .arg(&pat)
                    .output();
            }
        }
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
    let _flushed = std::io::Write::flush(&mut std::io::stdout()).ok();
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
    let _flushed = std::io::Write::flush(&mut std::io::stdout()).ok();
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    if input.trim().to_lowercase() == "y" {
        // #62 discipline here too: the reset kills through the same
        // precise spec as restart — a raw `pkill -f fuse-server` here
        // was the last bare sweep in the client, with the same blast
        // radius as the original incident (anything mentioning the
        // string, every stack on the machine).
        let state = read_state_file();
        let st = ServerStateFile {
            version: String::new(),
            server_pid: 0,
            server_binary: String::new(),
            mount_point: String::new(),
            socket: "/tmp/fuse-gatekeeper.sock".into(),
            log_level: "info".into(),
            pending_timeout: 10,
            runtime_wrapper: None,
            oracle_socket: None,
            secrets: vec![],
        };
        let st = state.as_ref().unwrap_or(&st);
        match server_kill_spec(st) {
            ServerKillSpec::NamedPid { pid, .. } => {
                let sig = libc::SIGTERM;
                // SAFETY: one verified pid, plain SIGTERM.
                let _killed = unsafe { libc::kill(pid, sig) };
            }
            ServerKillSpec::OrphanBySocket { socket } => {
                let pat = format!("--socket {socket}");
                let _ = std::process::Command::new("pkill")
                    .arg("-f")
                    .arg(&pat)
                    .output();
            }
        }
        eprintln!("Server killed. Re-run run-agent to start a fresh server.");
        std::process::exit(0);
    } else {
        eprintln!("Exiting without restarting.");
        std::process::exit(1);
    }
}

// ── completion unit tests ──────────────────────────────────────

/// Minimal servatui step-protocol listener. Binds SYNCHRONOUSLY (the
/// client's connect can never race an unbound socket), then serves
/// one exchange — read request line, reply `resp`, consume the null
/// sentinel — on a detached thread.
#[cfg(test)]
fn spawn_step_listener(socket: &std::path::Path, resp: &str) {
    use std::io::{BufRead, BufReader, Write};
    let _ = std::fs::remove_file(socket);
    let l = std::os::unix::net::UnixListener::bind(socket).expect("bind fake");
    let resp = resp.to_string();
    std::thread::spawn(move || {
        if let Ok((s, _)) = l.accept() {
            // The real wire: name frame, then args frame, then reply,
            // then the finalize sentinel.
            let mut name = String::new();
            let mut args = String::new();
            let mut reader = BufReader::new(&s);
            reader.read_line(&mut name).expect("read name");
            reader.read_line(&mut args).expect("read args");
            let _ = (&s).write_all(format!("{resp}\n").as_bytes());
            let mut sentinel = String::new();
            let _ = BufReader::new(&s).read_line(&mut sentinel);
            assert_eq!(name.trim(), "\"status\"", "first frame is the name");
        }
    });
}

#[test]
fn split_completing_slices_word_and_prefix() {
    // mid-word
    let (prior, w) = split_completing("fuse-client reset exi");
    assert_eq!(prior, vec!["fuse-client", "reset"]);
    assert_eq!(w, "exi");
    // trailing space opens a NEW empty word
    let (prior, w) = split_completing("fuse-client reset ");
    assert_eq!(prior, vec!["fuse-client", "reset"]);
    assert_eq!(w, "");
    // cursor before the line end (bash COMP_POINT): at offset 13 one
    // char into `reset` the completing word is "r"; at 17 (end of
    // `reset`) it is the whole word.
    let (prior, w) = split_completing("fuse-client reset existing.yaml");
    let (p2, w2) = split_completing(&"fuse-client reset existing.yaml"[..13]);
    let (p3, w3) = split_completing(&"fuse-client reset existing.yaml"[..17]);
    assert_eq!(w, "existing.yaml");
    assert_eq!(w2, "r");
    assert_eq!(w3, "reset");
    assert_eq!(prior.len(), 2);
    assert_eq!(p2.len(), 1);
    assert_eq!(p3.len(), 1);
    // empty line
    let (prior, w) = split_completing("");
    assert!(prior.is_empty());
    assert_eq!(w, "");
    // first word mid-typing
    let (prior, w) = split_completing("sta");
    assert!(prior.is_empty());
    assert_eq!(w, "sta");
}

#[test]
fn live_candidates_reads_secret_names_from_status_reply() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("u1.sock");
    let reply = r#"{"type":"status","secrets":[{"name":"a.yaml","access_count":0,"allowed_hashes":[],"inner":"h1","size":3,"unlimited":false}],"lockdown":false}"#;
    spawn_step_listener(&sock, reply);
    let got = live_candidates(&sock, "reset");
    assert_eq!(got, vec!["a.yaml".to_string()]);
}

#[test]
fn live_candidates_reads_pending_ids_from_pending_reply() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("u2.sock");
    let reply = r#"{"type":"pending_list","pending":[{"id":7,"secret_name":"a.yaml","pid":42,"pid_hash":null,"reason":"one-read","expires_at":999}]}"#;
    spawn_step_listener(&sock, reply);
    let got = live_candidates(&sock, "grant");
    assert_eq!(got, vec!["7".to_string()]);
}

#[test]
fn live_candidates_degrades_to_empty_on_dead_socket_and_bad_replies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dead = dir.path().join("nope.sock");
    assert!(live_candidates(&dead, "reset").is_empty());
    assert!(live_candidates(&dead, "grant").is_empty());
    // non-completing commands never query at all
    assert!(live_candidates(&dead, "status").is_empty());
    // unknown command word
    assert!(live_candidates(&dead, "nonsense").is_empty());
    let sock = dir.path().join("u3.sock");
    spawn_step_listener(&sock, "not json at all");
    // unparseable reply degrades to empty, never panics
    assert!(live_candidates(&sock, "reset").is_empty());
    // wrong response variant for the query degrades to empty
    let sock2 = dir.path().join("u4.sock");
    spawn_step_listener(&sock2, r#"{"type":"ok"}"#);
    assert!(live_candidates(&sock2, "reset").is_empty());
}

#[test]
fn completion_scripts_delegate_to_the_binary() {
    // Scripts must delegate via `complete -C` / fish `-a` — nothing
    // static about commands may live in the script.
    let bash = completion_script("bash").expect("bash");
    let zsh = completion_script("zsh").expect("zsh");
    let fish = completion_script("fish").expect("fish");
    assert!(bash.contains("complete -C fuse-client fuse-client"), "{bash}");
    assert!(zsh.contains("bashcompinit") && zsh.contains("complete -C"), "{zsh}");
    assert!(fish.contains("--complete"), "{fish}");
    assert!(completion_script("tcsh").is_none());
    assert!(completion_script("").is_none());
}

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn respawn_argv_carries_the_oracle_rendezvous() {
        // The #59 review finding: a stack running with --oracle-socket
        // must come back on the SAME rendezvous — the surviving data
        // daemon retries that socket forever, and a respawn on the
        // global default leaves an alive mount that never syncs again.
        let base = ServerStateFile {
            version: "0.30.0".into(),
            server_pid: 7,
            server_binary: "/x/fuse-server".into(),
            mount_point: "/m".into(),
            socket: "/s".into(),
            log_level: "info".into(),
            pending_timeout: 10,
            runtime_wrapper: None,
            oracle_socket: Some("/tmp/.tmpABC/oracle.sock".into()),
            secrets: vec![],
        };
        let argv = respawn_argv(&base);
        let i = argv
            .iter()
            .position(|a| a == "--oracle-socket")
            .expect("the rendezvous flag is present");
        assert_eq!(argv[i + 1], "/tmp/.tmpABC/oracle.sock");
        // and the global default stays implicit when unset
        let mut plain = base.clone();
        plain.oracle_socket = None;
        assert!(!respawn_argv(&plain).contains(&"--oracle-socket".to_string()));
    }
}

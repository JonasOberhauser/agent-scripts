#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic, unused_results, unknown_lints, inline_literal))]
use std::path::{Path, PathBuf};

use fuse_protocol::{client_protocols, ServerStateFile, VERSION as CLIENT_VERSION};
use servyi_servatui::App;

/// The message positions this crate uses (servyi/lints #7/#16
/// protocol): prose constructors whose string arguments are messages
/// by definition, not constants to name.
macro_rules! register_message {
    ($m:ident) => {
        #[allow(dead_code)]
        const _: &[(&str, &str)] = &[("servyi::message", stringify!($m))];
    };
}
register_message!(help);
register_message!(about);



mod pending_layer;

/// This binary's name — the clap tree, the completion scripts, and
/// the COMP_LINE fallback all reference it; retyping it invites
/// drift the day the binary is renamed.
const BIN_NAME: &str = env!("CARGO_PKG_NAME");

/// Base name of the client action log (beside the state file, or
/// /tmp when no state file is known).
const CLIENT_LOG_BASE: &str = "fuse-gatekeeper-client.log";
/// Exit codes.
const EXIT_FAILURE: i32 = 1;
/// The interactive yes-literal.
const CONFIRM_YES: &str = "y";
/// Poll/wait cadences.
const RESTART_GRACE: std::time::Duration = std::time::Duration::from_millis(500);
/// Socket I/O timeouts for the completion/listener probes.
const SOCKET_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(200);
/// The null poll reply.
const POLL_NULL: &[u8] = b"null\n";
/// The completion handoff word.
const COMPLETE_FLAG: &str = "--complete";
/// argv flags passed to respawned servers.
const FLAG_MOUNT_POINT: &str = "--mount-point";
const FLAG_SOCKET: &str = "--socket";
const FLAG_LOG_LEVEL: &str = "--log-level";
const FLAG_PENDING_TIMEOUT: &str = "--pending-timeout";
const FLAG_ADOPT_WINDOW: &str = "--adopt-window";
const FLAG_LOG_PATH: &str = "--log-path";
/// Default log level + pending timeout for fresh state files.
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_PENDING_TIMEOUT: u64 = 10;
/// The takeover adoption window the restart path asks for (secs).
const ADOPT_WINDOW_SECS: &str = "3";
/// The temp suffix for atomic state rewrites.
const STATE_TMP_EXT: &str = "pid.tmp";
/// The clap arg ids (referenced by both the builder and get_one).
const ARG_SOCKET: &str = "socket";
const SHORT_SOCKET: char = 's';
const ARG_SHELL: &str = "shell";
const ARG_COMPLETE: &str = "complete";
/// The orphan-sweep signal and pattern flags.
const SWEEP_SIGNAL: &str = "kill";
const PKILL_FULL: &str = "-f";
/// The orphan-sweep binary.
const PKILL_BIN: &str = "pkill";
/// The orphan probe's help check.
const PROBE_HELP: &str = "--help";
const SEP_PATH: char = '/';
/// Placeholder when a stale state names no binary.
const UNKNOWN_SERVER: &str = "<unknown (old server)>";
/// Status-query failure prose.
const COULD_NOT_QUERY: &str = "could not query current secrets";
/// The old-server stop bound.
const STOP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);


/// The client-LOCAL commands (never on the wire): declared once,
/// referenced everywhere.
// Necessity: subcommand words (names restate values — servyi/lints#16).
#[allow(unknown_lints)]
#[allow(inline_literal)]
mod local {
    pub const RESTART: &str = "restart";
    pub const COMPLETIONS: &str = "completions";
}

/// The full CLI, COMBINED from the registered protocols (each row
/// carries its own clap pattern — servatui's `cli` feature) plus the
/// client's local commands and top-level options. Nothing here
/// restates a command's grammar (servyi/servatui#5).
fn build_cli(protocols: &[servyi_servatui::Protocol]) -> clap::Command {
    // The client's own extras (top-level options + local subcommands);
    // every protocol becomes a subcommand with its carried pattern.
    let extras = clap::Command::new(BIN_NAME)
        .about("Send CRUD commands to the fuse-server")
        .arg(
            clap::Arg::new(ARG_SOCKET)
                .short(SHORT_SOCKET)
                .long(ARG_SOCKET)
                .env(fuse_protocol::ENV_CMD_SOCKET)
                .default_value(fuse_protocol::DEFAULT_CMD_SOCKET)
                .value_parser(clap::value_parser!(PathBuf))
                .global(true),
        )
        .arg(
            clap::Arg::new(ARG_COMPLETE)
                .long(ARG_COMPLETE)
                .hide(true)
                .action(clap::ArgAction::SetTrue)
                .help("Shell completion mode (also auto-engaged when COMP_LINE is set)"),
        )
        .subcommand(
            clap::Command::new(local::RESTART).about(
                "Restart the fuse-server from the state file: stop the old \
daemon (and its supervised data daemon), clean up socket and mount \
point, respawn with the same configuration and re-add every secret \
from the state file's host paths.",
            ),
        )
        .subcommand(
            clap::Command::new(local::COMPLETIONS)
                .about("Emit the delegating shell-completion scripts (bash | zsh | fish)")
                .arg(clap::Arg::new(ARG_SHELL).required(true)),
        );
    servyi_servatui::cli::clap_tree(extras, protocols)
}

fn main() {
    // Panel actions log to a file next to the state file: the TUI's
    // alternate screen hides stderr, and truncated title messages are
    // not a debugging interface.
    let log_path = std::env::var(fuse_protocol::ENV_STATE_FILE)
        .ok()
        .map(|p| {
            std::path::Path::new(&p)
                .with_file_name(CLIENT_LOG_BASE)
                .to_string_lossy()
                .to_string()
        })
        .unwrap_or_else(|| format!("/tmp/{CLIENT_LOG_BASE}"));
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

    // One protocol set feeds BOTH the combined CLI tree and the App —
    // the patterns and the runtime read the same rows.
    let protocols = client_protocols();
    let matches = build_cli(&protocols).get_matches();

    let socket = matches
        .get_one::<PathBuf>(ARG_SOCKET)
        .cloned()
        .expect("default_value guarantees a socket");

    // Shell completion comes FIRST: it must never hit the version
    // handshake, the log, or anything slow — a Tab press waits on it.
    if matches.get_flag(ARG_COMPLETE) || std::env::var_os(fuse_protocol::COMP_LINE).is_some() {
        complete_mode(&socket);
        return;
    }
    if let Some((name, sub)) = matches.subcommand() {
        if name == local::COMPLETIONS {
            print_completion_script(sub.get_one::<String>(ARG_SHELL).expect("required"));
            return;
        }
    }

    // Serialize the args-string BEFORE the App takes the protocols:
    // (name, args) for the table command, if any.
    // Local commands (restart/completions) are not table rows: they
    // have no protocol, so they dispatch to None.
    let dispatch = matches.subcommand().and_then(|(name, sub)| {
        protocols
            .iter()
            .find(|p| p.name == name)
            .map(|proto| {
                (
                    name.to_string(),
                    servyi_servatui::cli::args_string(&proto.clap_args, sub),
                )
            })
    });
    let app = App::builder(&socket).protocol_all(protocols).build();

    if let Some((name, _)) = matches.subcommand() {
        if name == local::RESTART {
            let log_path = discover_log_path(&app);
            restart_server(&app, log_path.as_deref());
            return;
        }
    }

    if app.server_running() {
        check_version_or_restart(&app);
    } else {
        check_start_server(&app);
    }

    match dispatch {
        Some((name, args)) => {
            match app.run_cli_command(&name, &args) {
                Ok(lines) => {
                    for line in lines {
                        println!("{line}");
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(EXIT_FAILURE);
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
            let log_sink: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
            let talk = pending_layer::spawn_worker(
                socket.clone(),
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
            if let Err(e) = display.run(&socket, &protocols) {
                eprintln!("Error: {e}");
                std::process::exit(EXIT_FAILURE);
            }
        }
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
    let starting_new = line_before_cursor
        .chars()
        .next_back()
        .is_some_and(char::is_whitespace)
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
    let _ = c.set_read_timeout(Some(SOCKET_IO_TIMEOUT));
    let _ = c.set_write_timeout(Some(SOCKET_IO_TIMEOUT));
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
    let _ = c.write_all(POLL_NULL);
    let _ = c.flush();
    Some(line)
}

/// The candidate VALUES for a command's first argument, from the live
/// server — the single kind→query mapping (shared shape with the TUI
/// completers): PendingIds → `pending`, SecretNames → `status`.
fn live_candidates(socket: &std::path::Path, word: &str) -> Vec<String> {
    use fuse_protocol::{COMMAND_TABLE, Response};
    let Some(spec) = COMMAND_TABLE.iter().find(|s| s.name == word) else {
        return Vec::new();
    };
    // The SINGLE kind→query mapping lives on Completer
    // (`query`/`values_from`), shared with the TUI's poller wiring.
    let Some((query_word, cmd)) = spec.complete.query() else {
        return Vec::new();
    };
    one_shot_query(socket, query_word, &cmd)
        .and_then(|reply| serde_json::from_str::<Response>(reply.trim()).ok())
        .map(|resp| spec.complete.values_from(&resp))
        .unwrap_or_default()
}

/// Completion entry: print one candidate per line (bare words — both
/// bash's `complete -C` and fish's `-a` expect position candidates).
// Necessity: shell-completion argv indexing (skip(1), prior[0],
// join(" ")) — the positional protocol of the completion environment.
#[allow(unknown_lints)]
#[allow(inline_literal)]
fn complete_mode(socket: &std::path::Path) {
    use fuse_protocol::COMMAND_TABLE;
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    // bash: COMP_LINE/COMP_POINT. fish: argv after --complete.
    let (prior, completing) = if let Some(line) = std::env::var_os(fuse_protocol::COMP_LINE) {
        let line = line.to_string_lossy().into_owned();
        let point = std::env::var(fuse_protocol::COMP_POINT)
            .ok()
            .and_then(|p| p.parse::<usize>().ok())
            .unwrap_or(line.len())
            .min(line.len());
        split_completing(&line[..point])
    } else {
        // fish: everything AFTER --complete is the command line being
        // completed (a custom --socket sits before the flag).
        let argv: Vec<String> = std::env::args()
            .skip_while(|a| a != COMPLETE_FLAG)
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
        .unwrap_or_else(|| BIN_NAME.to_string());
    let mut prior = prior;
    if prior.first().map(|w| w == &prog).unwrap_or(false) {
        let _removed = prior.remove(0);
    }

    let candidates: Vec<String> = if prior.is_empty() {
        // First word: command names (compile-time table — the command
        // surface is not served over the wire, per the issue thread).
        fuse_protocol::prefix_filter::prefixed(
            COMMAND_TABLE.iter().map(|s| s.name.to_string()),
            &completing,
        )
        .collect()
    } else {
        // Argument position: only the FIRST argument completes (the
        // SecretNames `rotate` hash guard falls out — arity check).
        let is_first_arg = prior.len() == 1;
        if !is_first_arg {
            Vec::new()
        } else {
            fuse_protocol::prefix_filter::prefixed(live_candidates(socket, &prior[0]), &completing)
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
        "bash" => Some(format!("complete -C {b} {b}\n", b = BIN_NAME)),
        "zsh" => Some(format!(
            "autoload -U +X bashcompinit && bashcompinit\ncomplete -C {b} {b}\n",
            b = BIN_NAME
        )),
        "fish" => Some(format!(
            "complete -c {b} -f -a '({b} --complete (commandline -cop))'\n",
            b = BIN_NAME
        )),
        _ => None,
    }
}

fn print_completion_script(shell: &str) {
    match completion_script(shell) {
        Some(script) => print!("{script}"),
        None => {
            eprintln!("unsupported shell {shell:?} (bash | zsh | fish)");
            std::process::exit(EXIT_FAILURE);
        }
    }
}

// ── Version check & server restart ─────────────────────────────

/// Where the running server says it logs; None when unreachable or it
/// predates logpath discovery (callers decide their own fallback).
fn discover_log_path(app: &App) -> Option<String> {
    use fuse_protocol::Response;
    app.run_cli_command_raw(fuse_protocol::cmd::LOGPATH, "")
        .ok()
        .and_then(|(_, raw)| serde_json::from_slice::<Response>(&raw).ok())
        .and_then(|r| match r {
            Response::LogPath { path } if !path.is_empty() => Some(path),
            _ => None,
        })
}

fn check_version_or_restart(app: &App) {
    use fuse_protocol::Response;

    let server_version = match app.run_cli_command_raw(fuse_protocol::cmd::VERSION, "") {
        Ok((_, raw)) => serde_json::from_slice::<Response>(&raw)
            .ok()
            .and_then(|r| match r {
                Response::Version { version } => Some(version),
                _ => None,
            })
            .unwrap_or_else(|| UNKNOWN_SERVER.to_string()),
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
    if input.trim().to_lowercase() != CONFIRM_YES {
        eprintln!("Exiting. Restart the server manually, then re-run fuse-client.");
        std::process::exit(EXIT_FAILURE);
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
    // Basename equality: handles every spelling (./x, /a/b/x, a/b/x)
    // that names the same binary — the old ends_with("/x") missed
    // spellings like "./fuse-server".
    argv0 == server_binary
        || Path::new(argv0.as_ref()).file_name().is_some_and(|a| {
            Path::new(server_binary).file_name().is_some_and(|b| a == b)
        })
}

/// The kernel-verified pid serving `path`'s listening socket, by
/// connecting and asking SO_PEERCRED (review on #105: no /proc
/// scanning, no argv patterns — the socket names its owner).
fn socket_listener_pid(path: &std::path::Path) -> Option<u32> {
    use std::os::unix::io::AsRawFd as _;
    let stream = std::os::unix::net::UnixStream::connect(path).ok()?;
    let fd = stream.as_raw_fd();
    let sol = libc::SOL_SOCKET;
    let opt = libc::SO_PEERCRED;
    let len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let mut len_out = len;
    let mut ucred: std::mem::MaybeUninit<libc::ucred> = std::mem::MaybeUninit::uninit();
    let cred_ptr = ucred.as_mut_ptr().cast();
    let len_ptr = &mut len_out as *mut libc::socklen_t;
    // SAFETY: getsockopt(2) with a valid connected fd and properly
    // sized out-pointers — a pure kernel query.
    let rc = unsafe { libc::getsockopt(fd, sol, opt, cred_ptr, len_ptr) };
    if rc != 0 {
        return None;
    }
    // SAFETY: rc == 0 — the kernel initialized the out-pointer.
    let ucred = unsafe { ucred.assume_init() };
    u32::try_from(ucred.pid).ok()
}

/// Rewrite the state file with the successor's pid (additive: every
/// other field is carried over verbatim from the state we respawned).
fn record_successor_pid(state: &ServerStateFile, pid: u32) {
    let mut next = state.clone();
    next.server_pid = pid;
    if let Ok(bytes) = serde_json::to_vec(&next) {
        let path = fuse_protocol::state_file();
        let tmp = path.with_extension(STATE_TMP_EXT);
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
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
        FLAG_MOUNT_POINT.to_string(),
        state.mount_point.clone(),
        FLAG_SOCKET.to_string(),
        state.socket.clone(),
    ];
    if let Some(oracle) = &state.oracle_socket {
        // The surviving data daemon retries THIS rendezvous; respawning
        // on the global default would orphan it (an alive mount that
        // never syncs again).
        argv.push(fuse_protocol::ORACLE_SOCKET_FLAG.to_string());
        argv.push(oracle.clone());
    }
    argv.push(FLAG_LOG_LEVEL.to_string());
    argv.push(state.log_level.clone());
    argv.push(FLAG_PENDING_TIMEOUT.to_string());
    argv.push(state.pending_timeout.to_string());
    // #93 adopt-the-survivor: give a surviving daemon 3s to reconnect
    // to the respawned server (its control loop retries every 1s)
    // before it spawns a fresh one.
    argv.push(FLAG_ADOPT_WINDOW.to_string());
    argv.push(ADOPT_WINDOW_SECS.to_string());
    argv
}


fn read_state_file() -> Option<ServerStateFile> {
    let data = std::fs::read(fuse_protocol::state_file()).ok()?;
    serde_json::from_slice(&data).ok()
}


// ── issue #98: the state file's recorded server_binary goes stale ──
//
/// How the respawn resolves the server binary (issue #98): the
/// recorded path may be gone (cargo clean, moved checkout, or a
/// release-only client build), and the client's own sibling binary
/// is often a valid stand-in.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BinaryResolution {
    /// The recorded path exists — use it.
    Recorded(std::path::PathBuf),
    /// Recorded is gone; the sibling beside THIS executable exists.
    SiblingSubstitute {
        recorded: std::path::PathBuf,
        sibling: std::path::PathBuf,
    },
    /// Neither exists: name it, do not spawn.
    Missing {
        recorded: std::path::PathBuf,
        sibling: std::path::PathBuf,
    },
}

/// Resolve the respawn's server binary. `sibling_dir` is the client's
/// own executable directory (injected for tests).
pub(crate) fn resolve_server_binary(
    recorded: &str,
    sibling_dir: Option<&std::path::Path>,
) -> BinaryResolution {
    let rec = std::path::PathBuf::from(recorded);
    if rec.exists() {
        return BinaryResolution::Recorded(rec);
    }
    // The client's own sibling (same convention the server uses to
    // find `fused`): a release-only client build has no sibling
    // either — then Missing must degrade to the build/run-agent hint.
    let sibling = sibling_dir
        .map(|d| d.join(fuse_protocol::SERVER_BIN))
        .unwrap_or_else(|| std::path::PathBuf::from(fuse_protocol::SERVER_BIN));
    if sibling.exists() {
        return BinaryResolution::SiblingSubstitute { recorded: rec, sibling };
    }
    BinaryResolution::Missing { recorded: rec, sibling }
}

/// The diagnosis/remediation text for a failed resolution (issue #98:
/// "check PATH" misdiagnosed a stale absolute path).
pub(crate) fn binary_diagnosis(res: &BinaryResolution) -> String {
    match res {
        BinaryResolution::Missing { recorded, sibling } => {
            let recorded_str = recorded.to_string_lossy();
            let stale = format!(
                "the recorded server binary no longer exists:\n  {recorded_str}\n\
                 (stale after cargo clean, a moved checkout, or a \\
                 release-only client build)"
            );
            if !recorded_str.contains(SEP_PATH) {
                format!(
                    "{stale}\n  and a bare name failed — also check PATH.\n\
                     Remediation: cargo build --bin fuse-server, or re-run \\
                     run-agent (writes a fresh state file)."
                )
            } else {
                format!(
                    "{stale}\n  and no sibling '{}' beside this client.\n\
                     Remediation: cargo build --bin fuse-server, or re-run \\
                     run-agent (writes a fresh state file).",
                    sibling.display()
                )
            }
        }
        other => format!("usable: {other:?}"),
    }
}

fn start_server_from_state(app: &App, state: &ServerStateFile, log_path: Option<&str>) {
    let mut cmd_args = respawn_argv(state);
    if let Some(lp) = log_path {
        cmd_args.push(FLAG_LOG_PATH.into());
        cmd_args.push(lp.into());
    }

    // Issue #98: the recorded binary may be stale (cargo clean, moved
    // checkout, release-only client build).  Resolve BEFORE touching
    // anything — Missing must not remove the socket it cannot re-serve.
    let sibling_dir = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.to_path_buf()));
    let resolution = resolve_server_binary(
        &state.server_binary,
        sibling_dir.as_deref(),
    );
    let effective_binary = match &resolution {
        BinaryResolution::Recorded(p) => p.clone(),
        BinaryResolution::SiblingSubstitute { sibling, .. } => {
            eprintln!(
                "  NOTE: recorded binary is gone; using the sibling {}",
                sibling.display()
            );
            sibling.clone()
        }
        BinaryResolution::Missing { .. } => {
            eprintln!("  ERROR: {}", binary_diagnosis(&resolution));
            std::process::exit(EXIT_FAILURE);
        }
    };
    let effective_binary_str = effective_binary.to_string_lossy().into_owned();

    // Necessity: wrapper argv splitting (parts[0], parts[1..]).
    #[allow(unknown_lints)]
    #[allow(inline_literal)]
    let (spawn_prog, spawn_args): (String, Vec<String>) = if let Some(w) = &state.runtime_wrapper {
        let parts: Vec<String> = w.split_whitespace().map(|s| s.to_string()).collect();
        let mut args = parts[1..].to_vec();
        args.push(effective_binary_str.clone());
        args.extend(cmd_args);
        (parts[0].clone(), args)
    } else {
        (effective_binary_str.clone(), cmd_args)
    };

    eprintln!("  Binary:   {} (recorded: {})", effective_binary.display(), state.server_binary);
    eprintln!("  Wrapper:  {}", state.runtime_wrapper.as_deref().unwrap_or("(none)"));
    eprintln!("  Program:  {spawn_prog}");
    eprintln!("  Args:     {}", spawn_args.join(" "));

    if std::process::Command::new(&spawn_prog).arg(PROBE_HELP).output().is_err() {
        // Issue #98: "check PATH" misdiagnosed stale absolute paths.
        // A bare NAME failing is PATH-flavored; an absolute path
        // failing is executability (permissions, format) — name that.
        if spawn_prog.contains(SEP_PATH) {
            eprintln!(
                "  WARNING: cannot execute '{spawn_prog}' — permissions or format, \
                 not PATH; the diagnosis below applies"
            );
        } else {
            eprintln!("  WARNING: cannot execute '{spawn_prog}' — check PATH");
        }
    }

    eprintln!("  Cleaning up stale socket...");
    // NO mount teardown here (#93 adopt-the-survivor): the respawned
    // server ADOPTS the surviving daemon when it can, and clears a
    // stale mount itself when it cannot — the cleanup moved to the
    // decision point (spawn_fresh in the server). Destroying the
    // mount here would detach the live one and strand the surviving
    // daemon as an unreachable orphan.
    let _ = std::fs::remove_file(&state.socket);
    std::thread::sleep(RESTART_GRACE);

    eprintln!("Starting server (v{})...", CLIENT_VERSION);
    let effective_log = log_path.unwrap_or(fuse_protocol::DEFAULT_LOG_PATH);
    let log_path_buf = std::path::PathBuf::from(effective_log);
    // APPEND (#93 F4): truncating destroyed the pre-restart log lines —
    // exactly the forensics a failed restart needs.
    let log_file = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open(&log_path_buf)
        .unwrap_or_else(|e| { eprintln!("open log file: {e}"); std::process::exit(EXIT_FAILURE); });
    let log_file2 = log_file.try_clone().unwrap_or_else(|e| { eprintln!("dup log fd: {e}"); std::process::exit(EXIT_FAILURE); });
    eprintln!("  Log:       {}", log_path_buf.display());

    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&spawn_prog);
    // The STACK'S environment, not the client's (#93 F1): whatever the
    // orchestrator pinned (policy store, hashd socket) the respawn
    // carries — absent entries inherit as before.
    for (k, v) in &state.env {
        let _env = cmd.env(k, v);
    }
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
        Ok(child) => {
            eprintln!("  Spawned pid {}", child.id());
            // Record the successor's pid: the NEXT restart walks the
            // precise NamedPid kill instead of the orphan path. The
            // live report's round-2 failure was exactly this file
            // still naming a dead pid.
            record_successor_pid(state, child.id());
        }
        Err(e) => {
            eprintln!("Failed to start server: {e}");
            eprintln!("{}", binary_diagnosis(&resolution));
            eprintln!("Start it manually with: run-agent ...");
            std::process::exit(EXIT_FAILURE);
        }
    }

    eprintln!("Waiting for server...");
    let deadline = std::time::Instant::now() + STOP_DEADLINE;
    loop {
        if app.server_running() { break; }
        if std::time::Instant::now() > deadline {
            eprintln!("Server did not start within 10s. Start it manually.");
            std::process::exit(EXIT_FAILURE);
        }
        std::thread::sleep(SOCKET_IO_TIMEOUT);
    }

    eprintln!("Restoring {} secret(s)...", state.secrets.len());
    for entry in &state.secrets {
        let args = format!("{} {} {}", entry.fuse_name, entry.host_path, entry.hash);
        match app.run_cli_command(fuse_protocol::cmd::ADD, &args) {
            Ok(_) => eprintln!("  Restored {}", entry.fuse_name),
            Err(e) => eprintln!("  Error restoring {}: {e}", entry.fuse_name),
        }
    }
    eprintln!("Server ready (v{}).", CLIENT_VERSION);
}

// Necessity: wrapper argv splitting (wparts[0], wparts[1..]) in the
// privileged kill path.
#[allow(unknown_lints)]
#[allow(inline_literal)]
fn restart_server(app: &App, log_path: Option<&str>) {
    use fuse_protocol::Response;

    let state = match read_state_file() {
        Some(s) => s,
        None => {
            eprintln!("Failed to read state file.");
            return ask_reset_anyway();
        }
    };

    let status_info = match app.run_cli_command_raw(fuse_protocol::cmd::STATUS, "") {
        Ok((_, raw)) => serde_json::from_slice::<Response>(&raw)
            .ok()
            .and_then(|r| match r {
                Response::Status { secrets, .. } => {
                    let names: Vec<&str> = secrets.iter().map(|s| s.name.as_str()).collect();
                    Some(format!("{} secret(s): {}", secrets.len(), names.join(", ")))
                }
                _ => None,
            })
            .unwrap_or_else(|| COULD_NOT_QUERY.to_string()),
        Err(_) => COULD_NOT_QUERY.to_string(),
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
            // Unnamed or pid-reused: ask the SOCKET who serves it.
            // The old form was a `pkill -f "--socket <path>"` child,
            // broken twice (live report 2026-10-13): a `--`-leading
            // argument parses as an OPTION ("unrecognized option",
            // rc 2) so NOTHING was ever signaled — and a substring
            // sweep would also have matched the client's own command
            // line. SO_PEERCRED hands us the listener's kernel-
            // verified pid: connect, ask, signal exactly that pid.
            if let Some(pid) = socket_listener_pid(Path::new(&socket)) {
                if let Some(w) = &state.runtime_wrapper {
                    // The privileged wrapper signals for us.
                    let wparts: Vec<&str> = w.split_whitespace().collect();
                    let mut kill_args: Vec<&str> = wparts[1..].to_vec();
                    let pid_str = pid.to_string();
                    kill_args.extend(&[SWEEP_SIGNAL, &pid_str]);
                    let _ = std::process::Command::new(wparts[0])
                        .args(&kill_args)
                        .output();
                } else {
                    let pid_t = pid as libc::pid_t;
                    let sig = libc::SIGTERM;
                    // SAFETY: one kernel-verified pid — the socket's
                    // own listener; no group or pattern semantics.
                    let _killed = unsafe { libc::kill(pid_t, sig) };
                }
            }
        }
    }

    // WAIT for the death before the successor spawns: the successor's
    // stale-socket probe refuses to run against a still-serving old
    // server ("Another server is running") — the live report's
    // "Server did not start within 10s". A signal returning has never
    // meant the target died; refusing to stop is a loud failure, not
    // something to walk the successor into.
    let stop_deadline = std::time::Instant::now() + STOP_DEADLINE;
    while app.server_running() {
        if std::time::Instant::now() > stop_deadline {
            eprintln!("Old server did not stop within 10s. Kill it manually and re-run.");
            std::process::exit(EXIT_FAILURE);
        }
        std::thread::sleep(SOCKET_IO_TIMEOUT);
    }

    // The mount survives the kill on purpose (#93 adopt-the-survivor):
    // the new server ADOPTS the still-connected daemon when versions
    // allow, and only its fresh-spawn branch clears a stale mount.
    // Pre-emptive fusermount -uz here would detach the live mount and
    // strand the surviving daemon as an unreachable orphan.
    let _ = std::fs::remove_file(&state.socket);
    std::thread::sleep(RESTART_GRACE);

    start_server_from_state(app, &state, log_path);
}

fn check_start_server(app: &App) {
    eprint!("Server is not running. Start it? [y/N] ");
    let _flushed = std::io::Write::flush(&mut std::io::stdout()).ok();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() { return; }
    if input.trim().to_lowercase() != CONFIRM_YES { return; }

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
    if input.trim().to_lowercase() == CONFIRM_YES {
        // #62 discipline here too: the reset kills through the same
        // precise spec as restart — a raw `pkill -f fuse-server` here
        // was the last bare sweep in the client, with the same blast
        // radius as the original incident (anything mentioning the
        // string, every stack on the machine).
        let state = read_state_file();
        let st = ServerStateFile {
            env: std::collections::HashMap::new(),
            version: String::new(),
            server_pid: 0,
            server_binary: String::new(),
            mount_point: String::new(),
            socket: fuse_protocol::DEFAULT_CMD_SOCKET.into(),
            log_level: DEFAULT_LOG_LEVEL.into(),
            pending_timeout: DEFAULT_PENDING_TIMEOUT,
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
                let _ = std::process::Command::new(PKILL_BIN)
                    .arg(PKILL_FULL)
                    .arg(&pat)
                    .output();
            }
        }
        eprintln!("Server killed. Re-run run-agent to start a fresh server.");
        std::process::exit(0);
    } else {
        eprintln!("Exiting without restarting.");
        std::process::exit(EXIT_FAILURE);
    }
}

// ── combined-CLI tests ─────────────────────────────────────────

#[test]
fn the_cli_tree_is_combined_from_the_protocols_and_locals() {
    let protocols = client_protocols();
    let cli = build_cli(&protocols);
    cli.clone().debug_assert();
    let names: Vec<&str> = cli.get_subcommands().map(|c| c.get_name()).collect();
    // every protocol command is a subcommand — including lockdown and
    // show-map, which the hand-written enum had silently omitted
    for p in &protocols {
        assert!(names.contains(&p.name), "{} missing from the CLI", p.name);
    }
    assert!(names.contains(&"restart") && names.contains(&"completions"));
    // and the pattern is live: add carries its typed flags
    let add = cli.find_subcommand("add").expect("add");
    let arg_names: Vec<&str> = add.get_arguments().map(|a| a.get_id().as_str()).collect();
    assert!(arg_names.contains(&"file") && arg_names.contains(&"hash"));
    // typed u64 pattern on grant
    let grant = cli.find_subcommand("grant").expect("grant");
    let err = grant
        .clone()
        .try_get_matches_from(["grant", "not-a-number"]);
    assert!(err.is_err(), "u64 pattern must reject garbage");
}

// ── completion unit tests ──────────────────────────────────────// ── completion unit tests ──────────────────────────────────────

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

    // ── issue #98: stale recorded server_binary ────────────────────

    /// A recorded binary that exists is used as-is.
    #[test]
    fn resolution_prefers_the_recorded_binary_when_it_exists() {
        let dir = tempfile::tempdir().unwrap();
        let rec = dir.path().join("fuse-server");
        std::fs::write(&rec, b"BIN").unwrap();
        let sibling_dir = tempfile::tempdir().unwrap();
        std::fs::write(sibling_dir.path().join("fuse-server"), b"BIN").unwrap();
        assert_eq!(
            resolve_server_binary(rec.to_str().unwrap(), Some(sibling_dir.path())),
            BinaryResolution::Recorded(rec.clone()),
            "an existing recorded path wins over the sibling"
        );
    }

    /// The recorded path gone + a sibling beside the client: the
    /// sibling substitutes, ANNOUNCED (not silently, not raw-ENOENT).
    #[test]
    fn resolution_falls_back_to_the_client_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let rec = dir.path().join("gone").join("fuse-server");
        let sibling_dir = tempfile::tempdir().unwrap();
        let sibling = sibling_dir.path().join("fuse-server");
        std::fs::write(&sibling, b"BIN").unwrap();
        assert_eq!(
            resolve_server_binary(rec.to_str().unwrap(), Some(sibling_dir.path())),
            BinaryResolution::SiblingSubstitute { recorded: rec.clone(), sibling },
            "a stale recorded path must fall back to the sibling"
        );
    }

    /// Neither exists: Missing — the caller must NAME it and stop,
    /// not remove the socket and fail at spawn with raw ENOENT.
    #[test]
    fn resolution_reports_missing_when_neither_exists() {
        let rec = "/nonexistent/checkout/target/debug/fuse-server";
        let sibling_dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            resolve_server_binary(rec, Some(sibling_dir.path())),
            BinaryResolution::Missing { .. }
        ));
    }

    /// The diagnosis must not say PATH for an absolute stale path,
    /// and must name the remediations (build the server / run-agent).
    #[test]
    fn diagnosis_names_staleness_and_remediation_not_path() {
        let res = BinaryResolution::Missing {
            recorded: "/gone/target/debug/fuse-server".into(),
            sibling: "/client/dir/fuse-server".into(),
        };
        let text = binary_diagnosis(&res);
        assert!(!text.contains("check PATH"), "misdiagnosis is the bug: {text}");
        assert!(text.contains("no longer exists"), "must name the stale path: {text}");
        assert!(
            text.contains("cargo build --bin fuse-server"),
            "must name the rebuild: {text}"
        );
        assert!(
            text.contains("run-agent"),
            "must name the fresh-state path: {text}"
        );
    }

    /// A BARE recorded name failing IS a PATH-flavored problem — the
    /// hint belongs there and only there.
    #[test]
    fn diagnosis_keeps_the_path_hint_for_bare_names() {
        let res = BinaryResolution::Missing {
            recorded: "fuse-server".into(),
            sibling: "/client/dir/fuse-server".into(),
        };
        let text = binary_diagnosis(&res);
        assert!(text.contains("check PATH"), "bare name: PATH hint applies: {text}");
    }
    use super::*;


    #[test]
    fn respawn_argv_carries_the_oracle_rendezvous() {
        // The #59 review finding: a stack running with --oracle-socket
        // must come back on the SAME rendezvous — the surviving data
        // daemon retries that socket forever, and a respawn on the
        // global default leaves an alive mount that never syncs again.
        let base = ServerStateFile {
            env: std::collections::HashMap::new(),
            version: "0.30.0".into(),
            server_pid: 7,
            server_binary: "/x/fuse-server".into(),
            mount_point: "/m".into(),
            socket: "/s".into(),
            log_level: DEFAULT_LOG_LEVEL.into(),
            pending_timeout: DEFAULT_PENDING_TIMEOUT,
            runtime_wrapper: None,
            oracle_socket: Some("/tmp/.tmpABC/oracle.sock".into()),
            secrets: vec![],
        };
        let argv = respawn_argv(&base);
        let i = argv
            .iter()
            .position(|a| a == fuse_protocol::ORACLE_SOCKET_FLAG)
            .expect("the rendezvous flag is present");
        assert_eq!(argv[i + 1], "/tmp/.tmpABC/oracle.sock");
        // and the global default stays implicit when unset
        let mut plain = base.clone();
        plain.oracle_socket = None;
        assert!(!respawn_argv(&plain).contains(&"--oracle-socket".to_string()));
    }
}

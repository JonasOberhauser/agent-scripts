use servyi_servatui::{Console, Plugin, Protocol, ShellAction};

use crate::protocol::{Command, PendingAccessInfo, Response};

// ═══════════════════════════════════════════════════════════════
// Response rendering
// ═══════════════════════════════════════════════════════════════

pub fn print_response(resp: &Response, out: &mut dyn Console) {
    match resp {
        Response::Ok => out.print_line("OK"),
        Response::Error { message } => out.print_error(message),
        Response::Status { secrets } => {
            if secrets.is_empty() {
                out.print_line("No secrets configured.");
            } else {
                out.print_line(&format!("{:<24} {:>8} {:>8}  HASH", "NAME", "READS", "SIZE"));
                for s in secrets {
                    let hash = if s.allowed_hash == crate::PENDING_ONLY_HASH {
                        "(manual approval only)"
                    } else {
                        &s.allowed_hash
                    };
                    out.print_line(&format!(
                        "{:<24} {:>8} {:>8}  {}",
                        s.name, s.access_count, s.size, hash
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
        Response::LogPath { path } => {
            out.print_line(&format!("Log path: {path}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Client-side Protocol definitions
//
// These use .server() with dummy closures (never called on the client).
// The server-side equivalents in fuse-server use .server_ctx() with
// real closures that access Arc<Mutex<ServerState>>.
//
// Wire types: Command (C→S) and Response (S→C).
// ═══════════════════════════════════════════════════════════════

fn cmd_protocol(
    name: &'static str,
    help: &'static str,
    parse_fn: impl Fn(&str) -> Result<Command, String> + Send + Sync + 'static,
) -> Protocol {
    Plugin::new(name, help)
        .parse(move |args| {
            let cmd = parse_fn(args)?;
            Ok(cmd)
        })
        .client(|cmd: Command, _out, _input| Ok(cmd))
        .server(|_cmd: Command| -> Result<Response, String> {
            unreachable!("server step is never called on the client side")
        })
        .client(|resp: Response, out, _input| {
            print_response(&resp, out);
            Ok(())
        })
        .finalize(|| Ok(ShellAction::Continue))
}

/// Shared, polled snapshot of the currently pending access requests.
/// A background poller in the client replaces the whole list on every
/// successful poll; completers and the pending panel read it without a
/// server round-trip.
pub type PendingIds = std::sync::Arc<std::sync::Mutex<Vec<PendingAccessInfo>>>;

/// Shared, polled snapshot of the server's secret names — the live
/// source for `reset`/`remove`/`rotate` argument completion. (The old
/// source, the orchestrator's startup-time state file, goes stale the
/// moment a secret is added or removed and is missing entirely when the
/// client runs standalone.)
pub type SecretNames = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// Test/constructor helper: a pending request with the given id.
pub fn pending_info(id: u64) -> PendingAccessInfo {
    PendingAccessInfo {
        id,
        secret_name: "s.yaml".into(),
        process_name: None,
        pid: id as u32,
        pid_hash: None,
        reason: "read request".into(),
        expires_at: 0,
    }
}


// ═══════════════════════════════════════════════════════════════
// Single command table — the one source of truth
// ═══════════════════════════════════════════════════════════════

/// Which live snapshot feeds first-argument completion (client TUI
/// nicety; never relevant on the wire).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Completer {
    None,
    /// `grant`/`deny`/`grant-forever` complete the pending request id.
    PendingIds,
    /// `reset`/`remove`/`rotate` complete the secret name.
    SecretNames {
        /// `reset NAME`/`remove NAME` suggest on empty prefix;
        /// `rotate NAME HASH` must not complete into the hash.
        after_space: bool,
    },
}

/// Offline (server-not-running) fallback renderer for CLI use.
pub type OfflineFn = fn(&str, &mut dyn Console) -> Result<(), String>;

/// ONE definition per wire command.  The client registry derives
/// parse/completion from here, the server registry derives its name
/// dispatch from here, and `handle_command`'s exhaustive match makes
/// the compiler enforce server logic for every variant.  Registry
/// drift between the two sides is structurally unrepresentable.
pub struct CommandSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub parse: fn(&str) -> Result<Command, String>,
    pub complete: Completer,
    pub offline: Option<OfflineFn>,
}

const NO_COMPLETE: Completer = Completer::None;

fn parse_status(_: &str) -> Result<Command, String> { Ok(Command::Status) }
fn parse_mounts(_: &str) -> Result<Command, String> { Ok(Command::ListMounts) }
fn parse_reset(args: &str) -> Result<Command, String> {
    Ok(Command::Reset { name: args.split_whitespace().next().map(|s| s.to_string()) })
}
fn parse_reset_all(_: &str) -> Result<Command, String> { Ok(Command::Reset { name: None }) }
fn parse_add(args: &str) -> Result<Command, String> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 3 {
        return Err("Usage: add NAME FILE HASH".into());
    }
    let content = std::fs::read(parts[1])
        .map_err(|e| format!("Error reading file: {e}"))?;
    // Snapshot the source file's permission bits so the FUSE view can
    // present them (masked read-only server-side).  Un-stat-able files
    // fall back to the conservative 0400.
    let mode = std::fs::metadata(parts[1])
        .map(|m| {
            use std::os::unix::fs::PermissionsExt;
            m.permissions().mode() & 0o777
        })
        .unwrap_or(0o400);
    Ok(Command::AddSecret {
        name: parts[0].to_string(),
        content,
        hash: parts[2].to_string(),
        mode,
    })
}
fn parse_remove(args: &str) -> Result<Command, String> {
    let name = args.trim();
    if name.is_empty() {
        return Err("Usage: remove NAME".into());
    }
    Ok(Command::RemoveSecret { name: name.to_string() })
}
fn parse_rotate(args: &str) -> Result<Command, String> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 2 {
        return Err("Usage: rotate NAME HASH".into());
    }
    Ok(Command::RotateHash { name: parts[0].to_string(), new_hash: parts[1].to_string() })
}
fn parse_pending(_: &str) -> Result<Command, String> { Ok(Command::ListPending) }
fn parse_grant(args: &str) -> Result<Command, String> {
    args.trim().parse::<u64>().map(|id| Command::Grant { id })
        .map_err(|_| "Usage: grant ID (ID must be a number)".into())
}
fn parse_grant_forever(args: &str) -> Result<Command, String> {
    args.trim().parse::<u64>().map(|id| Command::GrantForever { id })
        .map_err(|_| "Usage: grant-forever ID (ID must be a number)".into())
}
fn parse_deny(args: &str) -> Result<Command, String> {
    args.trim().parse::<u64>().map(|id| Command::Deny { id })
        .map_err(|_| "Usage: deny ID (ID must be a number)".into())
}
fn parse_version(_: &str) -> Result<Command, String> { Ok(Command::GetVersion) }
fn parse_logpath(_: &str) -> Result<Command, String> { Ok(Command::GetLogPath) }

fn offline_version(_args: &str, out: &mut dyn Console) -> Result<(), String> {
    out.print_line(&format!("Client version: {} (server not running)", crate::VERSION));
    Ok(())
}

/// The complete wire command set, in protocol order.
pub const COMMAND_TABLE: &[CommandSpec] = &[
    CommandSpec { name: "status", help: "Show all secrets and access counts", parse: parse_status, complete: NO_COMPLETE, offline: None },
    CommandSpec { name: "mounts", help: "List mounted secret files", parse: parse_mounts, complete: NO_COMPLETE, offline: None },
    CommandSpec { name: "reset", help: "Reset access counter for one or all secrets", parse: parse_reset, complete: Completer::SecretNames { after_space: true }, offline: None },
    CommandSpec { name: "reset-all", help: "Reset all access counters", parse: parse_reset_all, complete: NO_COMPLETE, offline: None },
    CommandSpec { name: "add", help: "Add a new secret from a file", parse: parse_add, complete: NO_COMPLETE, offline: None },
    CommandSpec { name: "remove", help: "Remove a secret", parse: parse_remove, complete: Completer::SecretNames { after_space: true }, offline: None },
    CommandSpec { name: "rotate", help: "Change the allowed binary hash", parse: parse_rotate, complete: Completer::SecretNames { after_space: false }, offline: None },
    CommandSpec { name: "pending", help: "Show pending access requests", parse: parse_pending, complete: NO_COMPLETE, offline: None },
    CommandSpec { name: "grant", help: "Grant a pending access request", parse: parse_grant, complete: Completer::PendingIds, offline: None },
    CommandSpec { name: "grant-forever", help: "Grant a pending access permanently (whitelists the observed package hash)", parse: parse_grant_forever, complete: Completer::PendingIds, offline: None },
    CommandSpec { name: "deny", help: "Deny a pending access request", parse: parse_deny, complete: Completer::PendingIds, offline: None },
    CommandSpec { name: "version", help: "Show server version", parse: parse_version, complete: NO_COMPLETE, offline: Some(offline_version) },
    CommandSpec { name: "logpath", help: "Show server log file path", parse: parse_logpath, complete: NO_COMPLETE, offline: None },
];

pub fn client_protocols() -> Vec<Protocol> {
    client_protocols_with_snapshots(
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
    )
}

/// Like [`client_protocols`], with live completion sources: `grant`/
/// `deny` complete the request ID from `pending` (see [`PendingIds`]);
/// `reset`/`remove`/`rotate` complete the secret name from `secrets`
/// (see [`SecretNames`]). Both are refreshed by the client's poller.
pub fn client_protocols_with_snapshots(pending: PendingIds, secrets: SecretNames) -> Vec<Protocol> {
    COMMAND_TABLE
        .iter()
        .map(|spec| {
            let proto = cmd_protocol(spec.name, spec.help, spec.parse);
            let proto = match spec.complete {
                Completer::None => proto,
                Completer::PendingIds => proto.complete(pending_completer(pending.clone())),
                Completer::SecretNames { after_space } => {
                    proto.complete(name_completer(secrets.clone(), after_space))
                }
            };
            match spec.offline {
                Some(offline) => proto.offline(offline),
                None => proto,
            }
        })
        .collect()
}

/// Complete the FIRST secret-name argument of `reset`/`remove`/`rotate`
/// from the orchestrator's state file (client-side, no server round-trip).
///
/// `complete_after_space`: `reset`/`remove` have the name as their only
/// argument, so an empty prefix (just typed the space) suggests all names.
/// `rotate NAME HASH` must NOT complete once the name is finished and the
/// hash has started — a trailing space means the hash is being typed.
pub(crate) fn complete_first_secret(
    candidates: &[String],
    confirmed: &str,
    complete_after_space: bool,
) -> Vec<String> {
    let mut tokens = confirmed.split_whitespace();
    let Some(cmd) = tokens.next() else {
        return Vec::new();
    };
    // The argument must have been started (a space after the command).
    if !confirmed.contains(' ') {
        return Vec::new();
    }
    let arg = tokens.next().unwrap_or("");
    if tokens.next().is_some() {
        return Vec::new(); // a second argument has started
    }
    if !complete_after_space && confirmed.ends_with(char::is_whitespace) {
        return Vec::new(); // e.g. `rotate NAME `: the hash is being typed
    }
    candidates
        .iter()
        .filter(|n| n.starts_with(arg))
        .map(|n| format!("{cmd} {n}"))
        .collect()
}

/// A completer closure over the shared secret-name snapshot: completes
/// the NAME argument of `reset`/`remove`/`rotate` from whatever the
/// poller last saw, without a server round-trip.
fn name_completer(
    secrets: SecretNames,
    complete_after_space: bool,
) -> impl Fn(&str) -> Vec<String> + Send + Sync + 'static {
    move |s| {
        let names = secrets.lock().unwrap().clone();
        complete_first_secret(&names, s, complete_after_space)
    }
}

/// A completer closure over the shared pending snapshot: completes the
/// numeric request-ID argument of `grant`/`deny` from whatever the poller
/// last saw, without a server round-trip.
fn pending_completer(
    pending: PendingIds,
) -> impl Fn(&str) -> Vec<String> + Send + Sync + 'static {
    move |s| {
        let ids: Vec<u64> = pending.lock().unwrap().iter().map(|p| p.id).collect();
        pending_completions(&ids, s)
    }
}

/// Complete the numeric request-ID argument of `grant`/`deny` from the
/// polled snapshot of active requests.
pub(crate) fn pending_completions(ids: &[u64], confirmed: &str) -> Vec<String> {
    let mut tokens = confirmed.split_whitespace();
    let Some(cmd) = tokens.next() else {
        return Vec::new();
    };
    if !confirmed.contains(' ') {
        return Vec::new();
    }
    let arg = tokens.next().unwrap_or("");
    if tokens.next().is_some() {
        return Vec::new(); // grant/deny take exactly one argument
    }
    ids.iter()
        .map(|id| id.to_string())
        .filter(|id| id.starts_with(arg))
        .map(|id| format!("{cmd} {id}"))
        .collect()
}

/// One full request/response exchange with the running server, speaking
/// the standard wire sequence (protocol name, payload, response, closing
/// sentinel) — the same conversation `run_cli_command` has.
pub fn run_command_once(
    socket: &std::path::Path,
    name: &str,
    cmd: &Command,
) -> Result<crate::Response, String> {
    use servyi_servatui::{RawConnection, TypedConnection};
    let mut conn = servyi_servatui::SocketConnection::connect(socket)?;
    conn.send_typed(&name.to_string())?;
    conn.send_typed(cmd)?;
    let raw = conn.recv_bytes()?;
    // Mirror the framework's client chain exactly (servatui protocol.rs):
    // server-side failures travel as the {"__error__": msg} envelope and
    // must surface as Err(msg) — not die in Response parsing.
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&raw) {
        if let Some(err) = val.get("__error__").and_then(|v| v.as_str()) {
            return Err(err.to_string());
        }
    }
    let resp: crate::Response =
        serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    conn.send_typed(&())?;
    Ok(resp)
}

/// One poll cycle returning the FULL pending request list.
pub fn poll_pending_info(socket: &std::path::Path) -> Result<Vec<PendingAccessInfo>, String> {
    match run_command_once(socket, "pending", &Command::ListPending)? {
        crate::Response::PendingList { pending } => Ok(pending),
        other => Err(format!("unexpected response to list_pending: {other:?}")),
    }
}

/// One poll cycle returning the server's secret NAMES (from `status`),
/// the live source for reset/remove/rotate completion.
pub fn poll_secret_names(socket: &std::path::Path) -> Result<Vec<String>, String> {
    match run_command_once(socket, "status", &Command::Status)? {
        crate::Response::Status { secrets } => {
            Ok(secrets.into_iter().map(|s| s.name).collect())
        }
        other => Err(format!("unexpected response to status: {other:?}")),
    }
}

/// One poll cycle: ask the running server for its pending access request
/// IDs. The caller keeps the previous snapshot when this errors (server
/// down, stale socket, ...). Connect failures already carry actionable
/// messages from the transport layer.
pub fn poll_pending_once(socket: &std::path::Path) -> Result<Vec<u64>, String> {
    Ok(poll_pending_info(socket)?.into_iter().map(|p| p.id).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn reset_completes_filtered_secret_names() {
        let p = names(&["p1_s0", "p2_s1"]);
        assert_eq!(
            complete_first_secret(&p, "reset p1", true),
            vec!["reset p1_s0".to_string()]
        );
        assert_eq!(
            complete_first_secret(&p, "reset ", true),
            vec!["reset p1_s0".to_string(), "reset p2_s1".to_string()]
        );
        // No space yet → the command itself is still being completed.
        assert!(complete_first_secret(&p, "reset", true).is_empty());
    }

    #[test]
    fn remove_completes_all_names_on_empty_prefix() {
        let p = names(&["p1_s0", "p2_s1"]);
        assert_eq!(
            complete_first_secret(&p, "remove ", true).len(),
            2
        );
    }

    #[test]
    fn rotate_stops_after_the_name() {
        let p = names(&["p1_s0"]);
        assert_eq!(
            complete_first_secret(&p, "rotate p", false),
            vec!["rotate p1_s0".to_string()]
        );
        // Name finished, hash being typed: no suggestions.
        assert!(complete_first_secret(&p, "rotate p1_s0 ", false).is_empty());
    }

    #[test]
    fn third_token_never_completes() {
        let p = names(&["p1_s0"]);
        assert!(complete_first_secret(&p, "reset p1_s0 x", true).is_empty());
    }

    #[test]
    fn empty_candidate_list_means_no_suggestions() {
        let p: Vec<String> = Vec::new();
        assert!(complete_first_secret(&p, "reset ", true).is_empty());
    }

    /// reset/remove/rotate complete their NAME argument from the LIVE
    /// snapshot the poller refreshes — the old state-file source went
    /// stale the moment a secret was added or removed after startup
    /// (and was missing entirely in standalone client runs).
    #[test]
    fn name_commands_complete_from_live_snapshot() {
        let secrets: SecretNames =
            std::sync::Arc::new(std::sync::Mutex::new(vec!["p1_s0".to_string()]));
        let protocols = client_protocols_with_snapshots(
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            secrets.clone(),
        );
        for name in ["reset", "remove", "rotate"] {
            let p = protocols.iter().find(|p| p.name == name).unwrap();
            let completer = p.completer().expect("completer registered");
            assert_eq!(
                completer(&format!("{name} p1")),
                vec![format!("{name} p1_s0")]
            );
            assert!(completer(&format!("{name} zz")).is_empty(), "prefix filters");
        }
        // rotate's NAME argument completes, but `rotate NAME ` (hash
        // being typed) does not.
        let p = protocols.iter().find(|p| p.name == "rotate").unwrap();
        let completer = p.completer().unwrap();
        assert!(completer("rotate p1_s0 ").is_empty(), "no completion for the hash");

        // The poller adds a secret: completion sees it immediately.
        *secrets.lock().unwrap() = vec!["p1_s0".to_string(), "p9_s8".to_string()];
        let p = protocols.iter().find(|p| p.name == "remove").unwrap();
        let completer = p.completer().unwrap();
        assert_eq!(completer("remove ").len(), 2, "live updates flow through");
    }

    #[test]
    fn name_commands_register_completers() {
        let protocols = client_protocols();
        for name in ["reset", "remove", "rotate"] {
            let p = protocols
                .iter()
                .find(|p| p.name == name)
                .unwrap_or_else(|| panic!("{name} missing"));
            assert!(p.completer().is_some(), "{name} must register a completer");
        }
        // Arg-less commands keep the builtin name completion only.
        for name in ["status", "mounts", "version"] {
            let p = protocols.iter().find(|p| p.name == name).unwrap();
            assert!(p.completer().is_none(), "{name} needs no completer");
        }
    }

    // ── pending-request ID completion (grant / deny) ─────────────

    #[test]
    fn pending_completions_filter_ids() {
        let ids = [4u64, 42, 7];
        assert_eq!(
            pending_completions(&ids, "grant 4"),
            vec!["grant 4".to_string(), "grant 42".to_string()]
        );
        assert_eq!(pending_completions(&ids, "deny 7"), vec!["deny 7".to_string()]);
        // Empty prefix right after the space: all IDs.
        assert_eq!(pending_completions(&ids, "grant ").len(), 3);
        // No space yet / second token: nothing.
        assert!(pending_completions(&ids, "grant").is_empty());
        assert!(pending_completions(&ids, "grant 4 x").is_empty());
    }


    #[test]
    fn grant_deny_complete_from_live_snapshot() {
        let shared: PendingIds = std::sync::Arc::new(std::sync::Mutex::new(vec![
            pending_info(5),
            pending_info(51),
        ]));
        let secrets: SecretNames = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let protocols = client_protocols_with_snapshots(shared.clone(), secrets.clone());
        for name in ["grant", "deny"] {
            // Fresh snapshot per command: the loop's last step mutates it.
            *shared.lock().unwrap() = vec![pending_info(5), pending_info(51)];
            let p = protocols.iter().find(|p| p.name == name).unwrap();
            let completer = p.completer().expect("completer registered");
            assert_eq!(completer("grant 5"), vec!["grant 5".to_string(), "grant 51".to_string()]);

            // The poller updates the snapshot — the completer sees new IDs.
            *shared.lock().unwrap() = vec![pending_info(9)];
            assert_eq!(completer("deny 9"), vec!["deny 9".to_string()]);
            assert!(completer("deny 5").is_empty(), "stale ID must be gone");
        }
    }

    #[test]
    fn poll_pending_once_round_trips_over_real_socket() {
        use std::io::{BufRead, BufReader, Write};
        let dir = std::env::temp_dir().join(format!("fuse-poll-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("poll.sock");
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            // The FIRST wire message is the protocol NAME (the server
            // dispatches on it); the command payload comes second.
            assert!(
                line.trim() == "\"pending\"",
                "first message must be the protocol name \"pending\", got: {line}"
            );
            line.clear();
            reader.read_line(&mut line).unwrap();
            assert!(
                line.contains("list_pending"),
                "second message must be the ListPending command, got: {line}"
            );
            let mut w = stream;
            let resp = crate::Response::PendingList {
                pending: vec![crate::PendingAccessInfo {
                    id: 77,
                    secret_name: "s".into(),
                    process_name: None,
                    pid: 1,
                    pid_hash: None,
                    reason: "r".into(),
                    expires_at: 0,
                }],
            };
            writeln!(w, "{}", serde_json::to_string(&resp).unwrap()).unwrap();
            // The client closes the conversation with the `()` sentinel;
            // a well-mannered server drains it before dropping the socket.
            line.clear();
            reader.read_line(&mut line).unwrap();
            assert!(line.trim() == "null", "closing sentinel must be (), got: {line}");
        });

        let ids = poll_pending_once(&path).expect("poll must succeed");
        assert_eq!(ids, vec![77]);
        server.join().unwrap();
    }

    #[test]
    fn poll_pending_once_missing_socket_errors() {
        assert!(poll_pending_once(std::path::Path::new("/no-such-fuse.sock")).is_err());
    }
}



use servyi_servatui::{Console, Plugin, Protocol, ShellAction};

use crate::protocol::{Command, Response};

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

/// Shared, polled snapshot of the currently active (pending) request IDs.
/// A background poller in the client replaces the whole list on every
/// successful poll; completers read it without a server round-trip.
pub type PendingIds = std::sync::Arc<std::sync::Mutex<Vec<u64>>>;

pub fn client_protocols() -> Vec<Protocol> {
    client_protocols_with_pending(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())))
}

/// Like [`client_protocols`], but `grant`/`deny` complete the request ID
/// from `pending` (see [`PendingIds`]).
pub fn client_protocols_with_pending(pending: PendingIds) -> Vec<Protocol> {
    vec![
        cmd_protocol("status", "Show all secrets and access counts",
            |_| Ok(Command::Status)),

        cmd_protocol("mounts", "List mounted secret files",
            |_| Ok(Command::ListMounts)),

        cmd_protocol("reset", "Reset access counter for one or all secrets",
            |args| {
                let name = args.split_whitespace().next().map(|s| s.to_string());
                Ok(Command::Reset { name })
            })
            .complete(|s| complete_first_secret(std::path::Path::new(crate::STATE_FILE), s, true)),

        cmd_protocol("reset-all", "Reset all access counters",
            |_| Ok(Command::Reset { name: None })),

        cmd_protocol("add", "Add a new secret from a file",
            |args| {
                let parts: Vec<&str> = args.split_whitespace().collect();
                if parts.len() < 3 {
                    return Err("Usage: add NAME FILE HASH".into());
                }
                let content = std::fs::read(parts[1])
                    .map_err(|e| format!("Error reading file: {e}"))?;
                Ok(Command::AddSecret {
                    name: parts[0].to_string(),
                    content,
                    hash: parts[2].to_string(),
                })
            }),

        cmd_protocol("remove", "Remove a secret",
            |args| {
                let name = args.trim();
                if name.is_empty() {
                    return Err("Usage: remove NAME".into());
                }
                Ok(Command::RemoveSecret { name: name.to_string() })
            })
            .complete(|s| complete_first_secret(std::path::Path::new(crate::STATE_FILE), s, true)),

        cmd_protocol("rotate", "Change the allowed binary hash",
            |args| {
                let parts: Vec<&str> = args.split_whitespace().collect();
                if parts.len() < 2 {
                    return Err("Usage: rotate NAME HASH".into());
                }
                Ok(Command::RotateHash {
                    name: parts[0].to_string(),
                    new_hash: parts[1].to_string(),
                })
            })
            .complete(|s| complete_first_secret(std::path::Path::new(crate::STATE_FILE), s, false)),

        cmd_protocol("pending", "Show pending access requests",
            |_| Ok(Command::ListPending)),

        cmd_protocol("grant", "Grant a pending access request",
            |args| {
                match args.trim().parse::<u64>() {
                    Ok(id) => Ok(Command::Grant { id }),
                    Err(_) => Err("Usage: grant ID (ID must be a number)".into()),
                }
            })
            .complete({
                let ids = pending.clone();
                move |s| {
                    let snapshot = ids.lock().unwrap().clone();
                    pending_completions(&snapshot, s)
                }
            }),

        cmd_protocol("deny", "Deny a pending access request",
            |args| {
                match args.trim().parse::<u64>() {
                    Ok(id) => Ok(Command::Deny { id }),
                    Err(_) => Err("Usage: deny ID (ID must be a number)".into()),
                }
            })
            .complete({
                let ids = pending.clone();
                move |s| {
                    let snapshot = ids.lock().unwrap().clone();
                    pending_completions(&snapshot, s)
                }
            }),

        cmd_protocol("version", "Show server version",
            |_| Ok(Command::GetVersion))
            .offline(|_args, out| {
                out.print_line(&format!("Client version: {} (server not running)", crate::VERSION));
                Ok(())
            }),

        cmd_protocol("logpath", "Show server log file path",
            |_| Ok(Command::GetLogPath)),
    ]
}

/// Complete the FIRST secret-name argument of `reset`/`remove`/`rotate`
/// from the orchestrator's state file (client-side, no server round-trip).
///
/// `complete_after_space`: `reset`/`remove` have the name as their only
/// argument, so an empty prefix (just typed the space) suggests all names.
/// `rotate NAME HASH` must NOT complete once the name is finished and the
/// hash has started — a trailing space means the hash is being typed.
pub(crate) fn complete_first_secret(
    state_path: &std::path::Path,
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
    let names: Vec<String> = std::fs::read(state_path)
        .ok()
        .and_then(|data| serde_json::from_slice::<crate::ServerStateFile>(&data).ok())
        .map(|state| state.secrets.iter().map(|s| s.fuse_name.clone()).collect())
        .unwrap_or_default();
    names
        .into_iter()
        .filter(|n| n.starts_with(arg))
        .map(|n| format!("{cmd} {n}"))
        .collect()
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

/// Extract the pending request IDs from a `ListPending` response.
pub(crate) fn pending_ids(resp: &crate::Response) -> Vec<u64> {
    match resp {
        crate::Response::PendingList { pending } => pending.iter().map(|p| p.id).collect(),
        _ => Vec::new(),
    }
}

/// One poll cycle: ask the running server for its pending access requests.
/// The caller keeps the previous snapshot when this errors (server down,
/// stale socket, ...). Connect failures already carry actionable messages
/// from the transport layer.
pub fn poll_pending_once(socket: &std::path::Path) -> Result<Vec<u64>, String> {
    use servyi_servatui::TypedConnection;
    let mut conn = servyi_servatui::SocketConnection::connect(socket)?;
    conn.send_typed(&Command::ListPending)?;
    let resp: crate::Response = conn.recv_typed()?;
    Ok(pending_ids(&resp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_file(names: &[&str]) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        // Unique per call: parallel tests must not share (and race on) one
        // file, and fs::write is not atomic.
        let dir = std::env::temp_dir().join(format!(
            "fuse-comp-test-{}-{seq}-{:?}",
            std::process::id(),
            names
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let json = format!(
            r#"{{"version":"0.20.0","server_pid":1,"server_binary":"","mount_point":"","socket":"","allow_other":false,"log_level":"info","pending_timeout":0,"runtime_wrapper":null,"secrets":[{}]}}"#,
            names
                .iter()
                .map(|n| format!(r#"{{"fuse_name":"{n}","host_path":"/x","hash":"h"}}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        std::fs::write(&path, json).unwrap();
        path
    }

    #[test]
    fn reset_completes_filtered_secret_names() {
        let p = state_file(&["p1_s0", "p2_s1"]);
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
        let p = state_file(&["p1_s0", "p2_s1"]);
        assert_eq!(
            complete_first_secret(&p, "remove ", true).len(),
            2
        );
    }

    #[test]
    fn rotate_stops_after_the_name() {
        let p = state_file(&["p1_s0"]);
        assert_eq!(
            complete_first_secret(&p, "rotate p", false),
            vec!["rotate p1_s0".to_string()]
        );
        // Name finished, hash being typed: no suggestions.
        assert!(complete_first_secret(&p, "rotate p1_s0 ", false).is_empty());
    }

    #[test]
    fn third_token_never_completes() {
        let p = state_file(&["p1_s0"]);
        assert!(complete_first_secret(&p, "reset p1_s0 x", true).is_empty());
    }

    #[test]
    fn missing_state_file_means_no_suggestions() {
        assert!(complete_first_secret(
            std::path::Path::new("/nonexistent-fuse-state.json"),
            "reset ",
            true
        )
        .is_empty());
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
    fn pending_ids_extracted_from_response() {
        let resp = crate::Response::PendingList {
            pending: vec![
                crate::PendingAccessInfo {
                    id: 11,
                    secret_name: "s".into(),
                    pid: 1,
                    pid_hash: None,
                    reason: "r".into(),
                    expires_at: 0,
                },
                crate::PendingAccessInfo {
                    id: 22,
                    secret_name: "s".into(),
                    pid: 2,
                    pid_hash: None,
                    reason: "r".into(),
                    expires_at: 0,
                },
            ],
        };
        assert_eq!(pending_ids(&resp), vec![11, 22]);
    }

    #[test]
    fn grant_deny_complete_from_live_snapshot() {
        let shared: PendingIds = std::sync::Arc::new(std::sync::Mutex::new(vec![5u64, 51]));
        let protocols = client_protocols_with_pending(shared.clone());
        for name in ["grant", "deny"] {
            // Fresh snapshot per command: the loop's last step mutates it.
            *shared.lock().unwrap() = vec![5u64, 51];
            let p = protocols.iter().find(|p| p.name == name).unwrap();
            let completer = p.completer().expect("completer registered");
            assert_eq!(completer("grant 5"), vec!["grant 5".to_string(), "grant 51".to_string()]);

            // The poller updates the snapshot — the completer sees new IDs.
            *shared.lock().unwrap() = vec![9u64];
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
            assert!(line.contains("list_pending"), "must ask for pending, got: {line}");
            let mut w = stream;
            let resp = crate::Response::PendingList {
                pending: vec![crate::PendingAccessInfo {
                    id: 77,
                    secret_name: "s".into(),
                    pid: 1,
                    pid_hash: None,
                    reason: "r".into(),
                    expires_at: 0,
                }],
            };
            writeln!(w, "{}", serde_json::to_string(&resp).unwrap()).unwrap();
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



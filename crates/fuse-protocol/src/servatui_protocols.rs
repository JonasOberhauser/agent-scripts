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

pub fn client_protocols() -> Vec<Protocol> {
    vec![
        cmd_protocol("status", "Show all secrets and access counts",
            |_| Ok(Command::Status)),

        cmd_protocol("mounts", "List mounted secret files",
            |_| Ok(Command::ListMounts)),

        cmd_protocol("reset", "Reset access counter for one or all secrets",
            |args| {
                let name = args.split_whitespace().next().map(|s| s.to_string());
                Ok(Command::Reset { name })
            }),

        cmd_protocol("reset-all", "Reset all access counters",
            |_| Ok(Command::Reset { name: None })),

        cmd_protocol("add", "Add a new secret from a file",
            |args| {
                let parts: Vec<&str> = args.trim().splitn(3, char::is_whitespace).collect();
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
            }),

        cmd_protocol("rotate", "Change the allowed binary hash",
            |args| {
                let parts: Vec<&str> = args.trim().splitn(2, char::is_whitespace).collect();
                if parts.len() < 2 {
                    return Err("Usage: rotate NAME HASH".into());
                }
                Ok(Command::RotateHash {
                    name: parts[0].to_string(),
                    new_hash: parts[1].to_string(),
                })
            }),

        cmd_protocol("pending", "Show pending access requests",
            |_| Ok(Command::ListPending)),

        cmd_protocol("grant", "Grant a pending access request",
            |args| {
                match args.trim().parse::<u64>() {
                    Ok(id) => Ok(Command::Grant { id }),
                    Err(_) => Err("Usage: grant ID (ID must be a number)".into()),
                }
            }),

        cmd_protocol("deny", "Deny a pending access request",
            |args| {
                match args.trim().parse::<u64>() {
                    Ok(id) => Ok(Command::Deny { id }),
                    Err(_) => Err("Usage: deny ID (ID must be a number)".into()),
                }
            }),

        cmd_protocol("version", "Show server version",
            |_| Ok(Command::GetVersion)),

        cmd_protocol("logpath", "Show server log file path",
            |_| Ok(Command::GetLogPath)),
    ]
}

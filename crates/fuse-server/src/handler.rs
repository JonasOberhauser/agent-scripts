use fuse_protocol::{Command, Response};

use crate::state::ServerState;

pub fn handle_command(cmd: Command, state: &ServerState, hub: &crate::oracle_service::OracleHub) -> Response {
    match cmd {
        Command::Reset { name } => {
            let n = state.reset(name.as_deref());
            if name.is_some() && n == 0 {
                Response::Error { message: "secret not found".into() }
            } else {
                Response::Ok
            }
        }

        Command::Status => {
            Response::Status { secrets: state.status() }
        }

        Command::AddSecret { name, path, hash, mode } => {
            // MR4: register by stat — the policy daemon holds the host
            // PATH and identity, never bytes (see register_secret).
            match register_secret(state, hub, &name, &path, &hash, mode) {
                Ok(inner) => Response::Added { inner },
                Err(e) => Response::Error { message: e },
            }
        }

        Command::RemoveSecret { name } => {
            if state.remove(&name) {
                hub.remove(&name);
                Response::Ok
            } else {
                Response::Error { message: "secret not found".into() }
            }
        }

        Command::RotateHash { name, new_hash } => {
            if state.rotate_hash(&name, &new_hash) {
                Response::Ok
            } else {
                Response::Error { message: "secret not found".into() }
            }
        }

        Command::ListMounts => {
            Response::MountList { mounts: state.list_mounts() }
        }

        Command::ListPending => {
            Response::PendingList { pending: state.list_pending() }
        }

        Command::Grant { id } => {
            if state.grant_pending(id) {
                Response::Ok
            } else {
                Response::Error { message: format!("pending access {id} not found or expired") }
            }
        }

        Command::GrantForever { id } => {
            // A pending created while hashd was down carries no hash and
            // a stale remediation snapshot. The operator has (hopefully)
            // started hashd since — retry the lookup live before
            // refusing, so following the printed fix actually works.
            if let Some(pid) = state.pending_pid_needing_hash(id) {
                let (pid_hash, hash_error) = crate::oracle_service::compute_pid_hash(pid);
                state.refresh_pending_hash(id, pid_hash, hash_error);
            }
            match state.grant_pending_forever(id) {
                Ok(()) => Response::Ok,
                Err(e) => {
                    tracing::warn!("grant-forever {id} rejected: {e}");
                    Response::Error { message: e }
                }
            }
        }

        Command::Deny { id } => {
            if state.deny_pending(id) {
                Response::Ok
            } else {
                Response::Error { message: format!("pending access {id} not found") }
            }
        }

        Command::GetVersion => Response::Version {
            version: fuse_protocol::VERSION.to_string(),
        },

        Command::GetLogPath => Response::LogPath {
            path: state.log_path.clone(),
        },
    }
}

/// Stat-register a secret (MR4): canonicalize the path, record its
/// host identity, tell the data daemon to serve the name. No client,
/// no server code path ever reads the content.
fn register_secret(
    state: &ServerState,
    hub: &crate::oracle_service::OracleHub,
    name: &str,
    path: &str,
    hash: &str,
    mode: u32,
) -> Result<String, String> {
    let host = std::fs::canonicalize(path)
        .map_err(|e| format!("cannot resolve {path}: {e}"))?;
    let md = std::fs::metadata(&host)
        .map_err(|e| format!("cannot stat {}: {e}", host.display()))?;
    if !md.is_file() {
        return Err(format!("{} is not a regular file", host.display()));
    }
    state.add_with_mode(name, host, md.len() as usize, hash, mode & 0o777);
    // Serve carries structure only — the identity's wire crossings
    // are StatOk (down) and Open (up), each with a job — plus the
    // anonymized container-view path (issue #47).
    let inner = fuse_protocol::anonymize_path(&state.anon_salt, name);
    hub.serve(name, &inner, mode & 0o777);
    Ok(inner)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn hub() -> crate::oracle_service::OracleHub {
        crate::oracle_service::OracleHub::new()
    }
    use crate::state::ReadOutcome;

    fn seeded() -> ServerState {
        let s = ServerState::new();
        s.add("a.yaml", "/tmp/host/a.yaml", 3, "hash_a");
        s.add("b.yaml", "/tmp/host/b.yaml", 3, "hash_b");
        s
    }

    #[test]
    fn reset_specific() {
        let s = seeded();
        s.attempt_read("a.yaml", 1, Some("hash_a"), 0, 1024);
        let resp = handle_command(Command::Reset { name: Some("a.yaml".into()) }, &s, &hub());
        assert_eq!(resp, Response::Ok);
        let out = s.attempt_read("a.yaml", 1, Some("hash_a"), 0, 1024);
        assert!(matches!(out, ReadOutcome::Granted));
    }

    #[test]
    fn reset_nonexistent_errors() {
        let s = seeded();
        let resp = handle_command(Command::Reset { name: Some("nope".into()) }, &s, &hub());
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[test]
    fn reset_all_ok() {
        let s = seeded();
        s.attempt_read("a.yaml", 1, Some("hash_a"), 0, 1024);
        let resp = handle_command(Command::Reset { name: None }, &s, &hub());
        assert_eq!(resp, Response::Ok);
    }

    #[test]
    fn status_reports_counts() {
        let s = seeded();
        s.attempt_read("a.yaml", 1, Some("hash_a"), 0, 1024);
        let resp = handle_command(Command::Status, &s, &hub());
        match resp {
            Response::Status { secrets } => {
                let a = secrets.iter().find(|e| e.name == "a.yaml").unwrap();
                assert_eq!(a.access_count, 1);
                assert_eq!(a.allowed_hashes.iter().map(|h| h.hash.as_str()).collect::<Vec<_>>(), vec!["hash_a"]);
                assert_eq!(a.size, 3);
            }
            _ => panic!("expected Status"),
        }
    }

    #[test]
    fn add_then_remove() {
        let s = ServerState::new();
        let src = std::env::temp_dir().join("mr4-new.bin");
        std::fs::write(&src, b"DATA").unwrap();
        let resp = handle_command(
            Command::AddSecret { name: "new".into(), path: src.to_str().unwrap().into(), hash: "h".into(), mode: 0o600 },
            &s,
            &hub(),
        );
        assert!(matches!(resp, Response::Added { .. }));

        // grant-forever round trip on a pending with a package hash
        s.add("k", "/tmp/host/k", 1, "h");
        let _ = handle_command(Command::GrantForever { id: 1 }, &s, &hub()); // unknown id -> error, no panic
        let id = {
            s.create_pending("k", 7, Some("pkg"), "mismatch", None);
            s.pending.iter().next().unwrap().id
        };
        let resp = handle_command(Command::GrantForever { id }, &s, &hub());
        assert_eq!(resp, Response::Ok);

        let resp = handle_command(Command::RemoveSecret { name: "new".into() }, &s, &hub());
        assert_eq!(resp, Response::Ok);
    }

    #[test]
    fn rotate_hash_flow() {
        let s = seeded();
        let resp = handle_command(
            Command::RotateHash { name: "a.yaml".into(), new_hash: "xyz".into() },
            &s,
            &hub(),
        );
        assert_eq!(resp, Response::Ok);
        let out = s.attempt_read("a.yaml", 1, Some("xyz"), 0, 1024);
        assert!(matches!(out, ReadOutcome::Granted));
    }

    #[test]
    fn list_mounts() {
        let s = seeded();
        let resp = handle_command(Command::ListMounts, &s, &hub());
        match resp {
            Response::MountList { mounts } => assert_eq!(mounts.len(), 2),
            _ => panic!("expected MountList"),
        }
    }
}

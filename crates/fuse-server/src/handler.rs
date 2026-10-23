#![cfg_attr(test, allow(unknown_lints, inline_literal))]
use fuse_protocol::{Command, Response};

use crate::state::ServerState;

/// One-off lockdown prose (issue #66 reference).
const MSG_LOCKDOWN_ARMED: &str = "lockdown armed (issue #66): current grants keep working; new unauthorized access is refused";

pub fn handle_command(cmd: Command, state: &ServerState, hub: &crate::oracle_service::OracleHub) -> Response {
    match cmd {
        Command::Reset { name } => {
            let n = state.reset(name.as_deref());
            if name.is_some() && n == 0 {
                Response::Error { message: crate::oracle_service::REASON_NOT_FOUND.into() }
            } else {
                Response::Ok
            }
        }

        Command::LockDown => {
            state.arm_lockdown();
            tracing::info!("{MSG_LOCKDOWN_ARMED}");
            Response::Ok
        }
        Command::Status => {
            Response::Status { secrets: state.status(), lockdown: state.lockdown() }
        }

        Command::ShowMap => Response::Map {
            entries: state
                .secrets
                .iter()
                .map(|e| fuse_protocol::MapEntry {
                    outer: e.key().clone(),
                    inner: fuse_protocol::anonymize_path(&state.anon_salt, e.key()),
                })
                .collect(),
        },

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
                Response::Error { message: crate::oracle_service::REASON_NOT_FOUND.into() }
            }
        }

        Command::RotateHash { name, new_hash } => {
            if state.rotate_hash(&name, &new_hash) {
                Response::Ok
            } else {
                Response::Error { message: crate::oracle_service::REASON_NOT_FOUND.into() }
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
                let (pid_hash, hash_error) = crate::oracle_service::compute_pid_hash(state, pid);
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
    state.add_with_mode(name, host, md.len() as usize, hash, mode & crate::oracle_service::MODE_MASK_PLAIN);
    // Serve carries structure only — the identity's wire crossings
    // are StatOk (down) and Open (up), each with a job — plus the
    // anonymized container-view path (issue #47).
    let inner = fuse_protocol::anonymize_path(&state.anon_salt, name);
    hub.serve(name, &inner, mode & crate::oracle_service::MODE_MASK_PLAIN);
    Ok(inner)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, Write as _};
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
            Response::Status { secrets, .. } => {
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
        // Issue #56: the mount seam must not be stubbed by absence —
        // a REAL control connection (as the oracle_service snapshot
        // test does it) must receive the Serve line for the add.
        let dir = tempfile::tempdir().unwrap();
        let oracle = dir.path().join("h56.sock");
        let s = std::sync::Arc::new(ServerState::new());
        let hub = crate::oracle_service::OracleHub::new();
        {
            let (st, hb, p) = (std::sync::Arc::clone(&s), hub.clone(), oracle.clone());
            std::thread::spawn(move || {
                let _ = crate::oracle_service::run_oracle_server(&p, st, hb);
            });
        }
        for _ in 0..200 {
            if oracle.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut conn = std::os::unix::net::UnixStream::connect(&oracle).unwrap();
        conn.write_all(b"{\"type\":\"hello\"}\n").unwrap();
        let mut reader = std::io::BufReader::new(conn.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap(); // Ok ack

        let src = std::env::temp_dir().join("mr4-new.bin");
        std::fs::write(&src, b"DATA").unwrap();
        let resp = handle_command(
            Command::AddSecret { name: "new".into(), path: src.to_str().unwrap().into(), hash: "h".into(), mode: 0o600 },
            &s,
            &hub,
        );
        assert!(matches!(resp, Response::Added { .. }));

        // The Serve line ARRIVES on the control connection (mount seam).
        line.clear();
        reader.read_line(&mut line).unwrap();
        let cmd: fuse_protocol::oracle::OracleCommand =
            serde_json::from_str(line.trim()).unwrap();
        assert!(
            matches!(
                &cmd,
                fuse_protocol::oracle::OracleCommand::Serve { name, .. } if name == "new"
            ),
            "the add must reach the mount seam: {cmd:?}"
        );

        // grant-forever round trip on a pending with a package hash
        s.add("k", "/tmp/host/k", 1, "h");
        let _ = handle_command(Command::GrantForever { id: 1 }, &s, &hub); // unknown id -> error, no panic
        let id = {
            s.create_pending("k", 7, Some("pkg"), "mismatch", None);
            s.pending.iter().next().unwrap().id
        };
        let resp = handle_command(Command::GrantForever { id }, &s, &hub);
        assert_eq!(resp, Response::Ok);

        let resp = handle_command(Command::RemoveSecret { name: "new".into() }, &s, &hub);
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

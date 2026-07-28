use fuse_protocol::{Command, Response};

use crate::state::ServerState;

pub fn handle_command(cmd: Command, state: &ServerState) -> Response {
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

        Command::AddSecret { name, content, hash } => {
            state.add(&name, content, hash);
            Response::Ok
        }

        Command::RemoveSecret { name } => {
            if state.remove(&name) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ReadOutcome;

    fn seeded() -> ServerState {
        let s = ServerState::new();
        s.add("a.yaml", b"AAA".to_vec(), "hash_a");
        s.add("b.yaml", b"BBB".to_vec(), "hash_b");
        s
    }

    #[test]
    fn reset_specific() {
        let s = seeded();
        s.attempt_read("a.yaml", 1, Some("hash_a"), 0, 1024);
        let resp = handle_command(Command::Reset { name: Some("a.yaml".into()) }, &s);
        assert_eq!(resp, Response::Ok);
        let out = s.attempt_read("a.yaml", 1, Some("hash_a"), 0, 1024);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn reset_nonexistent_errors() {
        let s = seeded();
        let resp = handle_command(Command::Reset { name: Some("nope".into()) }, &s);
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[test]
    fn reset_all_ok() {
        let s = seeded();
        s.attempt_read("a.yaml", 1, Some("hash_a"), 0, 1024);
        let resp = handle_command(Command::Reset { name: None }, &s);
        assert_eq!(resp, Response::Ok);
    }

    #[test]
    fn status_reports_counts() {
        let s = seeded();
        s.attempt_read("a.yaml", 1, Some("hash_a"), 0, 1024);
        let resp = handle_command(Command::Status, &s);
        match resp {
            Response::Status { secrets } => {
                let a = secrets.iter().find(|e| e.name == "a.yaml").unwrap();
                assert_eq!(a.access_count, 1);
                assert_eq!(a.allowed_hash, "hash_a");
                assert_eq!(a.size, 3);
            }
            _ => panic!("expected Status"),
        }
    }

    #[test]
    fn add_then_remove() {
        let s = ServerState::new();
        let resp = handle_command(
            Command::AddSecret { name: "new".into(), content: vec![9], hash: "h".into() },
            &s,
        );
        assert_eq!(resp, Response::Ok);

        let resp = handle_command(Command::RemoveSecret { name: "new".into() }, &s);
        assert_eq!(resp, Response::Ok);
    }

    #[test]
    fn rotate_hash_flow() {
        let s = seeded();
        let resp = handle_command(
            Command::RotateHash { name: "a.yaml".into(), new_hash: "xyz".into() },
            &s,
        );
        assert_eq!(resp, Response::Ok);
        let out = s.attempt_read("a.yaml", 1, Some("xyz"), 0, 1024);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn list_mounts() {
        let s = seeded();
        let resp = handle_command(Command::ListMounts, &s);
        match resp {
            Response::MountList { mounts } => assert_eq!(mounts.len(), 2),
            _ => panic!("expected MountList"),
        }
    }
}

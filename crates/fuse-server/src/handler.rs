use fuse_protocol::{Command, Response, SecretStatus};

use crate::state::ServerState;

/// Process a protocol [`Command`] against shared [`ServerState`], returning a
/// [`Response`].
///
/// This is deliberately a free function with no I/O so the entire CRUD logic
/// can be tested without mocking anything.
pub fn handle_command(cmd: Command, state: &mut ServerState) -> Response {
    match cmd {
        Command::Reset { name } => {
            let n = state.reset(name.as_deref());
            if name.is_some() && n == 0 {
                Response::Error {
                    message: "secret not found".into(),
                }
            } else {
                Response::Ok
            }
        }

        Command::Status => {
            let secrets = state
                .secrets
                .iter()
                .map(|(name, rec)| SecretStatus {
                    name: name.clone(),
                    access_count: rec.access_count,
                    allowed_hash: rec.allowed_hash.clone(),
                    size: rec.content.len(),
                })
                .collect();
            Response::Status { secrets }
        }

        Command::AddSecret {
            name,
            content,
            hash,
        } => {
            state.add(&name, content, hash);
            Response::Ok
        }

        Command::RemoveSecret { name } => {
            if state.remove(&name) {
                Response::Ok
            } else {
                Response::Error {
                    message: "secret not found".into(),
                }
            }
        }

        Command::RotateHash { name, new_hash } => {
            if state.rotate_hash(&name, &new_hash) {
                Response::Ok
            } else {
                Response::Error {
                    message: "secret not found".into(),
                }
            }
        }

        Command::ListMounts => {
            use fuse_protocol::MountEntry;
            let mounts = state
                .secrets
                .iter()
                .map(|(name, rec)| MountEntry {
                    name: name.clone(),
                    size: rec.content.len(),
                })
                .collect();
            Response::MountList { mounts }
        }

        Command::ListPending => {
            let pending = state.list_pending();
            Response::PendingList { pending }
        }

        Command::Grant { id } => {
            if state.grant_pending(id) {
                Response::Ok
            } else {
                Response::Error {
                    message: format!("pending access {id} not found or expired"),
                }
            }
        }

        Command::Deny { id } => {
            if state.deny_pending(id) {
                Response::Ok
            } else {
                Response::Error {
                    message: format!("pending access {id} not found"),
                }
            }
        }

        Command::GetVersion => Response::Version {
            version: fuse_protocol::VERSION.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded() -> ServerState {
        let mut s = ServerState::new();
        s.add("a.yaml", b"AAA".to_vec(), "hash_a");
        s.add("b.yaml", b"BBB".to_vec(), "hash_b");
        s
    }

    #[test]
    fn reset_specific() {
        let mut s = seeded();
        // simulate one read
        s.attempt_read("a.yaml", 1, Some("hash_a"), 0, 1024);
        let resp = handle_command(Command::Reset { name: Some("a.yaml".into()) }, &mut s);
        assert_eq!(resp, Response::Ok);
        // should be readable again
        let out = s.attempt_read("a.yaml", 1, Some("hash_a"), 0, 1024);
        assert!(matches!(out, crate::state::ReadOutcome::Granted(_)));
    }

    #[test]
    fn reset_nonexistent_errors() {
        let mut s = seeded();
        let resp = handle_command(
            Command::Reset {
                name: Some("nope".into()),
            },
            &mut s,
        );
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[test]
    fn reset_all_ok() {
        let mut s = seeded();
        s.attempt_read("a.yaml", 1, Some("hash_a"), 0, 1024);
        let resp = handle_command(Command::Reset { name: None }, &mut s);
        assert_eq!(resp, Response::Ok);
    }

    #[test]
    fn status_reports_counts() {
        let mut s = seeded();
        s.attempt_read("a.yaml", 1, Some("hash_a"), 0, 1024);
        let resp = handle_command(Command::Status, &mut s);
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
        let mut s = ServerState::new();
        let resp = handle_command(
            Command::AddSecret {
                name: "new".into(),
                content: vec![9],
                hash: "h".into(),
            },
            &mut s,
        );
        assert_eq!(resp, Response::Ok);
        assert!(s.secrets.contains_key("new"));

        let resp = handle_command(
            Command::RemoveSecret { name: "new".into() },
            &mut s,
        );
        assert_eq!(resp, Response::Ok);
        assert!(!s.secrets.contains_key("new"));
    }

    #[test]
    fn rotate_hash_flow() {
        let mut s = seeded();
        let resp = handle_command(
            Command::RotateHash {
                name: "a.yaml".into(),
                new_hash: "xyz".into(),
            },
            &mut s,
        );
        assert_eq!(resp, Response::Ok);
        let out = s.attempt_read("a.yaml", 1, Some("xyz"), 0, 1024);
        assert!(matches!(out, crate::state::ReadOutcome::Granted(_)));
    }

    #[test]
    fn list_mounts() {
        let mut s = seeded();
        let resp = handle_command(Command::ListMounts, &mut s);
        match resp {
            Response::MountList { mounts } => {
                assert_eq!(mounts.len(), 2);
            }
            _ => panic!("expected MountList"),
        }
    }
}

//! Protocol contract tests: both registries derive from the single
//! command table, and the typed one-shot client speaks the framework's
//! error envelope (`{"__error__": …}`) — server-side rejections must
//! surface as their real message, never as serde noise.
//!
//! The drift incident these guard against: a command present in one
//! hand-maintained registry but missing from the other answered
//! "Unknown command" as an untagged envelope, which `run_command_once`
//! parsed as `missing field type` — destroying the reason and costing
//! a day of debugging.

use std::sync::Arc;
use std::time::Duration;

use fuse_protocol::{client_protocols, run_command_once, Command, COMMAND_TABLE};
use fuse_server::{run_socket_server, server_protocols, ServerState};

fn wait_ready(socket: &std::path::Path) {
    for _ in 0..300 {
        if socket.exists() && std::os::unix::net::UnixStream::connect(socket).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("socket server never became ready at {}", socket.display());
}

/// Both derived registries carry exactly the table's names — the
/// single-source-of-truth guarantee.
#[test]
fn registries_derive_from_the_single_table() {
    let table: Vec<&str> = COMMAND_TABLE.iter().map(|s| s.name).collect();
    let client: Vec<&str> = client_protocols().iter().map(|p| p.name).collect();
    let server: Vec<&str> = server_protocols().iter().map(|p| p.name).collect();
    assert_eq!(client, table, "client registry must be the table, exactly");
    assert_eq!(server, table, "server registry must be the table, exactly");
}

/// Every command round-trips through the REAL socket server via the
/// typed one-shot client, and every server-side rejection surfaces its
/// actual message.
#[test]
fn typed_client_round_trips_every_command() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("contract.sock");
    let state = Arc::new(ServerState::new());
    let st = Arc::clone(&state);
    let sock = socket.clone();
    std::thread::spawn(move || {
        let _ = run_socket_server(&sock, st);
    });
    wait_ready(&socket);

    // Success sweep — one call per command that is safe on this state.
    let ok = |name: &str, cmd: Command| {
        let r = run_command_once(&socket, name, &cmd);
        assert!(r.is_ok(), "{name} must round-trip: {:?}", r.err());
    };
    ok("status", Command::Status);
    ok("mounts", Command::ListMounts);
    ok("pending", Command::ListPending);
    ok("version", Command::GetVersion);
    ok("logpath", Command::GetLogPath);
    ok("reset-all", Command::Reset { name: None });
    ok("add", Command::AddSecret {
        name: "t".into(),
        content: vec![1],
        hash: "h".into(),
        mode: 0o400,
    });
    ok("rotate", Command::RotateHash { name: "t".into(), new_hash: "h2".into() });
    ok("reset", Command::Reset { name: Some("t".into()) });
    ok("remove", Command::RemoveSecret { name: "t".into() });

    // Rejection sweep — the envelope contract.  Before the fix these
    // died as "missing field `type`", destroying the reason.
    let rejected = |name: &str, cmd: Command, needle: &str| {
        match run_command_once(&socket, name, &cmd) {
            Err(e) => {
                assert!(
                    e.contains(needle),
                    "{name} rejection must carry the server's reason ({needle}), got: {e}"
                );
                assert!(
                    !e.contains("missing field"),
                    "{name} must not die in Response parsing: {e}"
                );
            }
            Ok(_) => panic!("{name} should have been rejected"),
        }
    };
    rejected(
        "remove",
        Command::RemoveSecret { name: "ghost".into() },
        "not found",
    );
    rejected("grant", Command::Grant { id: 999 }, "not found");
    rejected("deny", Command::Deny { id: 999 }, "not found");
}

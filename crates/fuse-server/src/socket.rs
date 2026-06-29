use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use fuse_protocol::{Command, Response};
use tracing::{error, info};

use crate::handler::handle_command;
use crate::state::ServerState;

static CONN_ID: AtomicU64 = AtomicU64::new(0);

/// Run the CRUD socket server.  Blocks the calling thread.
///
/// Each accepted connection reads **one** newline-delimited JSON [`Command`],
/// processes it against the shared state, and writes one JSON [`Response`].
pub fn run_socket_server(
    socket_path: &Path,
    state: Arc<Mutex<ServerState>>,
) -> std::io::Result<()> {
    // Clean up any stale socket.
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    // World-accessible so non-root fuse-client can connect when the server
    // runs under sudo.  Security is enforced by the FUSE binary-hash check,
    // not by socket permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666))?;
    }

    info!("Socket server listening at {}", socket_path.display());

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    let conn_id = CONN_ID.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = handle_connection(&mut stream, state) {
                        error!("[{conn_id}] connection error: {e}");
                    }
                });
            }
            Err(e) => {
                error!("accept error: {e}");
            }
        }
    }
    Ok(())
}

fn handle_connection(
    stream: &mut std::os::unix::net::UnixStream,
    state: Arc<Mutex<ServerState>>,
) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Write};

    let reader = BufReader::new(stream.try_clone()?);
    let mut lines = reader.lines();

    if let Some(line) = lines.next() {
        let line = line?;
        let cmd: Command = match serde_json::from_str(&line) {
            Ok(c) => c,
            Err(e) => {
                let err = Response::Error {
                    message: format!("invalid command: {e}"),
                };
                let json = serde_json::to_string(&err)
                    .unwrap_or_else(|_| r#"{"type":"error","message":"internal error"}"#.into());
                writeln!(stream, "{json}")?;
                return Ok(());
            }
        };

        info!("Command received: {:?}", cmd);

        let resp = {
            let mut s = state
                .lock()
                .expect("ServerState mutex poisoned");
            handle_command(cmd, &mut s)
        };

        let json = serde_json::to_string(&resp)
            .map_err(std::io::Error::other)?;
        writeln!(stream, "{json}")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_protocol::Command;

    #[test]
    fn socket_round_trip_reset() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");
        let state = Arc::new(Mutex::new(ServerState::new()));
        state.lock().unwrap().add("s.yaml", b"DATA".to_vec(), "h1");

        // Start server thread.
        let sock2 = sock.clone();
        let state2 = Arc::clone(&state);
        let handle = std::thread::spawn(move || run_socket_server(&sock2, state2));

        // Wait for socket.
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Send a reset command.
        let mut client = std::os::unix::net::UnixStream::connect(&sock).unwrap();
        use std::io::{BufRead, BufReader, Write};
        let cmd = serde_json::to_string(&Command::Reset {
            name: Some("s.yaml".into()),
        })
        .unwrap();
        writeln!(client, "{cmd}").unwrap();
        let reader = BufReader::new(client.try_clone().unwrap());
        let resp_line = reader.lines().next().unwrap().unwrap();
        let resp: Response = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(resp, Response::Ok);

        // Query status.
        let mut client = std::os::unix::net::UnixStream::connect(&sock).unwrap();
        writeln!(client, "{}", serde_json::to_string(&Command::Status).unwrap()).unwrap();
        let reader = BufReader::new(client.try_clone().unwrap());
        let resp_line = reader.lines().next().unwrap().unwrap();
        let resp: Response = serde_json::from_str(&resp_line).unwrap();
        match resp {
            Response::Status { secrets } => {
                assert_eq!(secrets.len(), 1);
                assert_eq!(secrets[0].name, "s.yaml");
                assert_eq!(secrets[0].access_count, 0);
            }
            _ => panic!("expected Status"),
        }

        drop(handle); // thread runs until tempdir is cleaned up
    }

    #[test]
    fn socket_add_then_status() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test2.sock");
        let state = Arc::new(Mutex::new(ServerState::new()));

        let sock2 = sock.clone();
        let state2 = Arc::clone(&state);
        let _handle = std::thread::spawn(move || run_socket_server(&sock2, state2));

        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        use std::io::{BufRead, BufReader, Write};
        let mut client = std::os::unix::net::UnixStream::connect(&sock).unwrap();
        let cmd = Command::AddSecret {
            name: "new.yaml".into(),
            content: vec![1, 2, 3],
            hash: "abc".into(),
        };
        writeln!(client, "{}", serde_json::to_string(&cmd).unwrap()).unwrap();
        let resp_line = BufReader::new(client.try_clone().unwrap())
            .lines()
            .next()
            .unwrap()
            .unwrap();
        let resp: Response = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(resp, Response::Ok);

        assert!(state.lock().unwrap().secrets.contains_key("new.yaml"));
    }
}

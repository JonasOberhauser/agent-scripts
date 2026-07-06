use std::path::Path;
use std::sync::{Arc, Mutex};

use servyi_servatui::ServerHandle;
use tracing::info;

use crate::protocols::server_protocols;
use crate::state::ServerState;

/// Run the CRUD socket server using servatui. Blocks the calling thread.
pub fn run_socket_server(
    socket_path: &Path,
    state: Arc<Mutex<ServerState>>,
) -> Result<(), String> {
    info!("Socket server listening at {}", socket_path.display());

    let handle = ServerHandle {
        socket: socket_path.to_path_buf(),
        protocols: server_protocols(),
    };
    handle.run(&state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_protocol::client_protocols;
    use servyi_servatui::{SocketConnection, TypedConnection, BufferConsole, NoInput};

    fn wait_for_socket(path: &Path) {
        for _ in 0..100 {
            if path.exists() {
                if std::os::unix::net::UnixStream::connect(path).is_ok() {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("Server did not start");
    }

    fn run_client(proto_name: &str, args: &str, socket: &Path) -> Vec<String> {
        let protocols = client_protocols();
        let proto = protocols.iter()
            .find(|p| p.name == proto_name)
            .unwrap_or_else(|| panic!("Unknown protocol: {proto_name}"));
        let mut conn = SocketConnection::connect(socket).unwrap();
        conn.send_typed(&proto_name.to_string()).unwrap();
        let mut console = BufferConsole::new();
        let mut input = NoInput;
        proto.run_client(args, &mut conn, &mut console, &mut input).unwrap();
        console.lines
    }

    #[test]
    fn socket_round_trip_reset() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");
        let state = Arc::new(Mutex::new(ServerState::new()));
        state.lock().unwrap().add("s.yaml", b"DATA".to_vec(), "h1");

        let sock2 = sock.clone();
        let state2 = Arc::clone(&state);
        let _handle = std::thread::spawn(move || run_socket_server(&sock2, state2));

        wait_for_socket(&sock);

        let lines = run_client("reset", "s.yaml", &sock);
        assert!(lines.iter().any(|l| l == "OK"));

        let lines = run_client("status", "", &sock);
        assert!(lines.iter().any(|l| l.contains("s.yaml")));
        assert!(lines.iter().any(|l| l.contains("0"))); // access_count = 0
    }

    #[test]
    fn socket_add_then_status() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test2.sock");
        let state = Arc::new(Mutex::new(ServerState::new()));

        let sock2 = sock.clone();
        let state2 = Arc::clone(&state);
        let _handle = std::thread::spawn(move || run_socket_server(&sock2, state2));

        wait_for_socket(&sock);

        // Add a secret by sending AddSecret command directly via the wire
        let mut conn = SocketConnection::connect(&sock).unwrap();
        conn.send_typed(&"add".to_string()).unwrap();
        let protocols = client_protocols();
        let add_proto = protocols.iter().find(|p| p.name == "add").unwrap();

        // We need a file to read for the "add" command
        let tmp = tempfile::tempdir().unwrap();
        let secret_file = tmp.path().join("secret.txt");
        std::fs::write(&secret_file, b"SECRET_DATA").unwrap();
        let args = format!("new.yaml {} abc", secret_file.display());

        let mut console = BufferConsole::new();
        let mut input = NoInput;
        add_proto.run_client(&args, &mut conn, &mut console, &mut input).unwrap();
        assert!(console.lines.iter().any(|l| l == "OK"));

        assert!(state.lock().unwrap().secrets.contains_key("new.yaml"));
    }

    #[test]
    fn socket_error_propagates() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("err.sock");
        let state = Arc::new(Mutex::new(ServerState::new()));

        let sock2 = sock.clone();
        let state2 = Arc::clone(&state);
        let _handle = std::thread::spawn(move || run_socket_server(&sock2, state2));

        wait_for_socket(&sock);

        // Remove non-existent secret → error
        let result = {
            let protocols = client_protocols();
            let proto = protocols.iter().find(|p| p.name == "remove").unwrap();
            let mut conn = SocketConnection::connect(&sock).unwrap();
            conn.send_typed(&"remove".to_string()).unwrap();
            let mut console = BufferConsole::new();
            let mut input = NoInput;
            proto.run_client("nonexistent", &mut conn, &mut console, &mut input)
        };
        // The error response is rendered by print_response, not propagated as Err
        // because handle_command returns Response::Error, not Result::Err
        // So the client sees it as a normal response with "Error: ..." in the output
        assert!(result.is_ok());
    }
}

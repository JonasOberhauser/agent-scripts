use std::path::Path;
use std::sync::Arc;

use servyi_servatui::ServerHandle;
use tracing::info;

use crate::protocols::server_protocols;
use crate::state::ServerState;

/// Run the CRUD socket server using servatui. Blocks the calling thread.
pub fn run_socket_server(
    socket_path: &Path,
    state: Arc<ServerState>,
) -> Result<(), String> {
    info!("Socket server listening at {}", socket_path.display());

    let handle = ServerHandle {
        socket: socket_path.to_path_buf(),
        protocols: server_protocols(),
    };
    handle.run(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_protocol::client_protocols;
    use servyi_servatui::App;
    use std::sync::Arc;

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

    fn make_app(socket: &Path) -> App {
        App::builder(socket)
            .protocol_all(client_protocols())
            .build()
    }

    #[test]
    fn socket_round_trip_reset() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");
        let state = Arc::new(ServerState::new());
        state.add("s.yaml", b"DATA".to_vec(), "h1");

        let sock2 = sock.clone();
        let state2 = Arc::clone(&state);
        let _handle = std::thread::spawn(move || run_socket_server(&sock2, state2));

        wait_for_socket(&sock);

        let app = make_app(&sock);

        let lines = app.run_cli_command("reset", "s.yaml").unwrap();
        assert!(lines.iter().any(|l| l == "OK"));

        let lines = app.run_cli_command("status", "").unwrap();
        assert!(lines.iter().any(|l| l.contains("s.yaml")));
    }

    #[test]
    fn socket_add_then_status() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test2.sock");
        let state = Arc::new(ServerState::new());

        let sock2 = sock.clone();
        let state2 = Arc::clone(&state);
        let _handle = std::thread::spawn(move || run_socket_server(&sock2, state2));

        wait_for_socket(&sock);

        let tmp = tempfile::tempdir().unwrap();
        let secret_file = tmp.path().join("secret.txt");
        std::fs::write(&secret_file, b"SECRET_DATA").unwrap();

        let app = make_app(&sock);
        let args = format!("new.yaml {} abc", secret_file.display());
        let lines = app.run_cli_command("add", &args).unwrap();
        assert!(lines.iter().any(|l| l == "OK"));

        assert!(state.secrets.contains_key("new.yaml"));
    }

    #[test]
    fn socket_error_propagates() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("err.sock");
        let state = Arc::new(ServerState::new());

        let sock2 = sock.clone();
        let state2 = Arc::clone(&state);
        let _handle = std::thread::spawn(move || run_socket_server(&sock2, state2));

        wait_for_socket(&sock);

        let app = make_app(&sock);

        // Remove non-existent secret → error propagated as Err
        let result = app.run_cli_command("remove", "nonexistent");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }
}

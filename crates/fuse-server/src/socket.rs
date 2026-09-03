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
            if path.exists() && std::os::unix::net::UnixStream::connect(path).is_ok() {
                return;
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

    /// Regression: the TUI's background poller (`poll_pending_once`) must
    /// speak the REAL server wire protocol — protocol-name first, then the
    /// ListPending payload. It used to send the command as the first
    /// message, which the server's name dispatch rejects, so the poller
    /// errored forever and the pending badge never appeared.
    #[test]
    fn poll_pending_once_reads_real_server() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("poll.sock");
        let state = Arc::new(ServerState::new());
        state.add("s.yaml", b"DATA".to_vec(), "h1");
        let id_a =
            state.create_pending("s.yaml", 42, Some("h42"), "read request", Some("checker"));
        let id_b = state.create_pending("s.yaml", 43, None, "read request", None);

        let sock2 = sock.clone();
        let state2 = Arc::clone(&state);
        let _handle = std::thread::spawn(move || run_socket_server(&sock2, state2));

        wait_for_socket(&sock);

        let ids = fuse_protocol::poll_pending_once(&sock)
            .expect("poll must succeed against the real server dispatch");
        let mut want = vec![id_a, id_b];
        let mut got = ids;
        want.sort_unstable();
        got.sort_unstable();
        assert_eq!(got, want);

        // The full poll carries the requesting process's name when known.
        let list = fuse_protocol::poll_pending_info(&sock).unwrap();
        let a = list.iter().find(|p| p.id == id_a).unwrap();
        assert_eq!(a.process_name.as_deref(), Some("checker"), "got: {a:?}");
        let b = list.iter().find(|p| p.id == id_b).unwrap();
        assert_eq!(b.process_name, None);

        // Grant: the entry STAYS listed (granted=true) until the FUSE
        // reader consumes it — the badge disappearing on grant alone
        // would be wrong. Deny removes immediately.
        let app = make_app(&sock);
        let lines = app.run_cli_command("grant", &id_a.to_string()).unwrap();
        assert!(lines.iter().any(|l| l == "OK"), "got: {lines:?}");
        assert!(state.is_pending_granted(id_a), "grant must mark the entry");
        let ids = fuse_protocol::poll_pending_once(&sock).unwrap();
        let mut got = ids;
        got.sort_unstable();
        assert_eq!(got, want, "granted-but-unconsumed requests stay listed");

        let lines = app.run_cli_command("deny", &id_b.to_string()).unwrap();
        assert!(lines.iter().any(|l| l == "OK"), "got: {lines:?}");
        let ids = fuse_protocol::poll_pending_once(&sock).unwrap();
        assert_eq!(ids, vec![id_a], "denied requests disappear immediately");
    }
}

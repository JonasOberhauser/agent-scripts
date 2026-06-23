use std::path::Path;

use fuse_protocol::{Command, IoError, Response, SystemIo};

/// Check whether a fuse-server is listening at `socket_path`.
pub fn server_exists<S: SystemIo>(io: &S, socket_path: &Path) -> bool {
    io.try_unix_connect(socket_path)
}

/// Connect to the fuse-server, send one [`Command`], and read the [`Response`].
pub fn send_command<S: SystemIo>(
    io: &S,
    socket_path: &Path,
    cmd: Command,
) -> Result<Response, IoError> {
    let json = serde_json::to_vec(&cmd)?;
    let raw = io.unix_send_recv(socket_path, &json)?;
    let resp: Response = serde_json::from_slice(&raw)?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_command_uses_mock() {
        let mock = fuse_protocol::MockSystemIo::new()
            .with_unix_response(br#"{"type":"ok"}"#);
        let resp = send_command(
            &mock,
            std::path::Path::new("/sock"),
            Command::Status,
        )
        .unwrap();
        assert_eq!(resp, Response::Ok);
    }

    #[test]
    fn server_exists_false_when_not_connected() {
        let mock = fuse_protocol::MockSystemIo::new();
        assert!(!server_exists(&mock, std::path::Path::new("/sock")));
    }

    #[test]
    fn server_exists_true_when_connected() {
        let mut mock = fuse_protocol::MockSystemIo::new();
        mock.unix_connected = true;
        assert!(server_exists(&mock, std::path::Path::new("/sock")));
    }
}

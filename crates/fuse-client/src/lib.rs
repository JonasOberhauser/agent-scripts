use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use fuse_protocol::{Command, IoError, Response, SystemIo, Transport};

/// Connect to the fuse-server's Unix domain socket and run a single
/// command, returning the response.
pub fn send_command(socket_path: &Path, cmd: Command) -> Result<Response, IoError> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| IoError(format!("connect {}: {e}", socket_path.display())))?;
    let json = serde_json::to_string(&cmd)?;
    stream
        .write_all(json.as_bytes())
        .map_err(|e| IoError(format!("write: {e}")))?;
    stream
        .write_all(b"\n")
        .map_err(|e| IoError(format!("write: {e}")))?;
    stream
        .flush()
        .map_err(|e| IoError(format!("flush: {e}")))?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| IoError(format!("read: {e}")))?;
    let resp: Response = serde_json::from_str(line.trim())?;
    Ok(resp)
}

/// [`Transport`] wrapper around a [`UnixStream`] for clients that want the
/// generic send/recv interface rather than the one-shot [`send_command`].
pub struct UnixTransport {
    reader: BufReader<UnixStream>,
}

impl UnixTransport {
    pub fn connect(path: &Path) -> Result<Self, IoError> {
        let stream = UnixStream::connect(path)
            .map_err(|e| IoError(format!("connect {}: {e}", path.display())))?;
        Ok(Self {
            reader: BufReader::new(stream),
        })
    }
}

impl Transport<Command, Response> for UnixTransport {
    fn send(&mut self, msg: Command) -> Result<(), IoError> {
        let json = serde_json::to_string(&msg)?;
        let stream = self.reader.get_mut();
        stream.write_all(json.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Response, IoError> {
        let mut line = String::new();
        self.reader.read_line(&mut line)?;
        let resp: Response = serde_json::from_str(line.trim())?;
        Ok(resp)
    }
}

/// High-level helper: read a file from disk and add it as a secret on the
/// server via the socket.
pub fn add_secret_from_file<S: SystemIo>(
    io: &S,
    socket_path: &Path,
    name: &str,
    file_path: &Path,
    hash: &str,
) -> Result<Response, IoError> {
    let content = io.read_file(file_path)?;
    send_command(
        socket_path,
        Command::AddSecret {
            name: name.to_string(),
            content,
            hash: hash.to_string(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_protocol::{Command, Response};

    #[test]
    fn transport_send_recv_round_trip() {
        // We can't easily test UnixTransport without a real socket, so test
        // the serialization logic instead.
        let cmd = Command::Reset {
            name: Some("x".into()),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let parsed: Command = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, parsed);

        let resp = Response::Ok;
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn add_secret_from_file_uses_io() {
        let mock = fuse_protocol::MockSystemIo::new().with_file("/secret", b"DATA");
        let resp = add_secret_from_file(&mock, Path::new("/nonexistent.sock"), "s", Path::new("/secret"), "h");
        // Connection will fail since there's no real socket, but we verify
        // the file was read (no "file not found" error).
        assert!(resp.is_err());
        let err = resp.unwrap_err().0;
        assert!(err.contains("connect"), "got: {err}");
    }
}

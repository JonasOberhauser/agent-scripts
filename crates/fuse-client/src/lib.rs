use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use fuse_protocol::{Command, IoError, Response, Transport};

/// Connect to the fuse-server's Unix domain socket and run a single
/// command, returning the response.
pub fn send_command(socket_path: &Path, cmd: Command) -> Result<Response, IoError> {
    let mut transport = UnixTransport::connect(socket_path)?;
    transport.send(cmd)?;
    transport.recv()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_serialization_round_trip() {
        let cmd = Command::Reset {
            name: Some("x".into()),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let parsed: Command = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, parsed);
    }
}

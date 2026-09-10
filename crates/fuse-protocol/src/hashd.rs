//! Client side of the hashd lookup: `pid → package hash` over a unix
//! socket, with machine-readable failure kinds.
//!
//! No hashd is shipped: the lookup is expected to fail in every
//! deployment, and callers answer with a bare "not supported".

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Where the socket-activated (or manually started) hashd listens.
pub const DEFAULT_SOCK: &str = "/run/fuse-hashd.sock";

/// Reply classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashdError {
    /// hashd answered, but it is running without the capability the
    /// kernel demands (CAP_SYS_ADMIN/CAP_CHECKPOINT_RESTORE in the
    /// initial user namespace).
    Unprivileged(String),
    /// The target process vanished (exited or invisible).
    Gone(String),
    /// hashd answered with some other failure.
    Other(String),
    /// No hashd listening (or it did not answer in time).
    Unreachable(String),
}

impl std::fmt::Display for HashdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashdError::Unprivileged(why) => write!(f, "hashd: insufficient privileges — {why}"),
            HashdError::Gone(why) => write!(f, "hashd: process gone — {why}"),
            HashdError::Other(why) => write!(f, "hashd: {why}"),
            HashdError::Unreachable(why) => write!(f, "hashd unreachable — {why}"),
        }
    }
}

/// One question, one answer. Short timeout: callers sit on the read
/// path of a (blocked) secret read and must degrade quickly.
pub fn ask(socket: &str, pid: u32) -> Result<String, HashdError> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|e| HashdError::Unreachable(e.to_string()))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| HashdError::Unreachable(e.to_string()))?;
    stream
        .write_all(format!("hash {pid}\n").as_bytes())
        .map_err(|e| HashdError::Unreachable(e.to_string()))?;
    let _ = stream.flush();
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| HashdError::Unreachable(e.to_string()))?,
    );
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| HashdError::Unreachable(e.to_string()))?;
    parse_reply(line.trim())
}

/// Parse one reply line into a result.
pub fn parse_reply(line: &str) -> Result<String, HashdError> {
    if let Some(hash) = line.strip_prefix("ok ") {
        let hash = hash.trim();
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(hash.to_string());
        }
        return Err(HashdError::Other(format!("malformed hash in reply: {line:?}")));
    }
    if let Some(why) = line.strip_prefix("error unprivileged ") {
        return Err(HashdError::Unprivileged(why.to_string()));
    }
    if let Some(why) = line.strip_prefix("error gone ") {
        return Err(HashdError::Gone(why.to_string()));
    }
    if let Some(why) = line.strip_prefix("error ") {
        return Err(HashdError::Other(why.to_string()));
    }
    Err(HashdError::Other(format!("malformed reply: {line:?}")))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ok_hash() {
        let h = "a".repeat(64);
        assert_eq!(parse_reply(&format!("ok {h}")).unwrap(), h);
    }

    #[test]
    fn rejects_malformed_hash() {
        assert!(matches!(
            parse_reply("ok nothex"),
            Err(HashdError::Other(_))
        ));
    }

    #[test]
    fn classifies_error_kinds() {
        assert!(matches!(
            parse_reply("error unprivileged EPERM following map_files"),
            Err(HashdError::Unprivileged(msg)) if msg.contains("EPERM")
        ));
        assert!(matches!(
            parse_reply("error gone no such process"),
            Err(HashdError::Gone(_))
        ));
        assert!(matches!(
            parse_reply("error something else"),
            Err(HashdError::Other(_))
        ));
        assert!(matches!(
            parse_reply("garbage"),
            Err(HashdError::Other(_))
        ));
    }

    #[test]
    fn unreachable_when_no_socket() {
        let e = ask("/nonexistent-hashd.sock", 1).unwrap_err();
        assert!(matches!(e, HashdError::Unreachable(_)));
    }

    /// Full round trip against a live in-test hashd-like listener.
    #[test]
    fn round_trips_against_a_listener() {
        let dir = tempfile_dir();
        let path = dir.join("sock");
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let path2 = path.clone();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let reply = if line.trim() == "hash 7" {
                format!("ok {}\n", "b".repeat(64))
            } else {
                "error unprivileged EPERM\n".to_string()
            };
            conn.write_all(reply.as_bytes()).unwrap();
        });
        assert_eq!(
            ask(path2.to_str().unwrap(), 7).unwrap(),
            "b".repeat(64)
        );
        server.join().unwrap();
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("hashd-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}

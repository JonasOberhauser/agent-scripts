//! Client side of the hashd helper: `pid → package hash` over a unix
//! socket, with machine-readable failure kinds and the commands that
//! fix each failure, so pendings shown to a human are actionable.
//!
//! See the `hashd` binary crate for the protocol and deployment modes.

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
    /// initial user namespace). The actionable case: clients should
    /// print their remediation commands.
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

/// The transient start command (works until the next reboot) for a
/// hashd at `socket`, naming a concrete binary when the caller knows
/// one (the policy daemon looks for `hashd` next to its own binary —
/// cargo builds every workspace binary into the same target dir).
pub fn start_command(socket: &str, hashd_binary: &str) -> String {
    format!("sudo systemd-run --unit=fuse-hashd {hashd_binary} --socket {socket}")
}

/// The permanent install commands (one-time, root), run from the
/// repository directory that contains the hashd crate.
pub fn install_commands() -> String {
    "sudo install -m 644 fuse-hashd.socket fuse-hashd.service /etc/systemd/system/\n  \
     sudo systemctl daemon-reload && sudo systemctl enable --now fuse-hashd.socket"
        .to_string()
}

/// Error text fit for a pending shown to a human: unlike plain
/// [`Display`], it embeds the commands that FIX the failure.
///
/// * [`HashdError::Unreachable`] — nothing is listening: name the
///   runnable start command (and, for the default socket, the
///   permanent install).
/// * [`HashdError::Unprivileged`] — hashd answered but lacks the
///   capability: reinstall via the socket-activated unit (which grants
///   exactly one capability) or restart it privileged.
/// * everything else (process gone, other failure) — pass through;
///   there is nothing to start or re-privilege.
pub fn actionable_error(err: &HashdError, socket: &str, hashd_binary: Option<&str>) -> String {
    let binary = hashd_binary.unwrap_or("<hashd-binary>");
    match err {
        HashdError::Unreachable(_) => {
            let mut text = format!(
                "{err}. Start hashd now:\n  {}\n",
                start_command(socket, binary)
            );
            if socket == DEFAULT_SOCK {
                text.push_str(&format!(
                    "Or install it permanently (one-time, root):\n  {}",
                    install_commands()
                ));
            }
            text
        }
        HashdError::Unprivileged(_) => format!(
            "{err}\nReinstall via the socket-activated unit so hashd carries the \
             capability (one-time, root):\n  {}\nOr restart it privileged only \
             until its next restart:\n  {}",
            install_commands(),
            start_command(socket, binary)
        ),
        other => other.to_string(),
    }
}

/// Does an error message carry the unprivileged-hashd signature?
pub fn is_unprivileged_error(msg: &str) -> bool {
    msg.contains("hashd: insufficient privileges")
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

    #[test]
    fn actionable_unreachable_names_a_runnable_start_command() {
        let e = HashdError::Unreachable("connect: No such file or directory".into());
        let text = actionable_error(
            &e,
            "/run/fuse-hashd.sock",
            Some("/opt/agents/target/release/hashd"),
        );
        assert!(
            text.contains("Start hashd now")
                && text.contains(
                    "sudo systemd-run --unit=fuse-hashd /opt/agents/target/release/hashd \
                     --socket /run/fuse-hashd.sock"
                ),
            "must embed a copy-paste start command, got:\n{text}"
        );
        assert!(
            text.contains("sudo systemctl enable --now fuse-hashd.socket"),
            "the default socket must also offer the permanent install:\n{text}"
        );
    }

    #[test]
    fn actionable_unreachable_custom_socket_skips_install_hint() {
        let e = HashdError::Unreachable("refused".into());
        let text = actionable_error(&e, "/tmp/custom-hashd.sock", None);
        assert!(text.contains("<hashd-binary>"), "no known binary: placeholder, got:\n{text}");
        assert!(
            !text.contains("systemctl enable"),
            "custom socket: the unit files hard-code the default socket, so the \
             permanent install hint would be wrong:\n{text}"
        );
    }

    #[test]
    fn actionable_unprivileged_offers_capability_fixes() {
        let e = HashdError::Unprivileged("EPERM following map_files".into());
        let text = actionable_error(&e, DEFAULT_SOCK, None);
        assert!(text.starts_with("hashd: insufficient privileges"), "{text}");
        assert!(
            text.contains("systemctl enable --now fuse-hashd.socket")
                && text.contains("systemd-run --unit=fuse-hashd"),
            "must offer the reinstall and the transient restart:\n{text}"
        );
    }

    #[test]
    fn actionable_gone_and_other_stay_lean() {
        let gone = actionable_error(&HashdError::Gone("no such process".into()), DEFAULT_SOCK, None);
        assert_eq!(gone, "hashd: process gone — no such process");
        assert!(!gone.contains("sudo"), "nothing to start for a gone process: {gone}");
        let other = actionable_error(&HashdError::Other("disk on fire".into()), DEFAULT_SOCK, None);
        assert_eq!(other, "hashd: disk on fire");
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

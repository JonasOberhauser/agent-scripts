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
    /// hashd IS running but did not serve this ask in time (#38):
    /// either it accepted the connection but answered nothing while
    /// busy hashing (our 500ms read timeout surfaces as errno 11 —
    /// the exact error the operator saw mislabeled "unreachable"),
    /// or a non-blocking connect met a full accept backlog. Transient
    /// — a retry shortly will succeed; restarting hashd is the WRONG
    /// remediation.
    Busy(String),
}

impl std::fmt::Display for HashdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashdError::Unprivileged(why) => write!(f, "hashd: insufficient privileges — {why}"),
            HashdError::Gone(why) => write!(f, "hashd: process gone — {why}"),
            HashdError::Other(why) => write!(f, "hashd: {why}"),
            HashdError::Unreachable(why) => write!(f, "hashd unreachable — {why}"),
            HashdError::Busy(why) => write!(f, "hashd busy — {why}"),
        }
    }
}

/// One question, one answer. Short timeout: callers sit on the read
/// path of a (blocked) secret read and must degrade quickly.
pub fn ask(socket: &str, pid: u32) -> Result<String, HashdError> {
    let mut stream = connect_with_retry(socket)?;
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
    let _n = reader.read_line(&mut line).map_err(|e| {
        // The read timeout (500ms) surfaces as WouldBlock/errno 11:
        // hashd accepted us but is busy hashing something big and
        // answered nothing — NOT unreachable (#38).
        if e.kind() == std::io::ErrorKind::WouldBlock
            || e.raw_os_error() == Some(libc::EAGAIN)
        {
            HashdError::Busy(e.to_string())
        } else {
            HashdError::Unreachable(e.to_string())
        }
    })?;
    parse_reply(line.trim())
}

/// connect(2) to a unix stream socket whose accept backlog is full
/// fails EAGAIN on Linux — the daemon is UP, just not accepting while
/// it hashes (#38). Retry within a bounded window (concurrent asks
/// drain as the daemon accepts) before classifying; every other
/// connect error is genuinely unreachable. Note: only the CONNECT
/// step may classify EAGAIN this way — on the read path the same
/// errno comes from our own 500ms timeout and means "no answer".
fn connect_with_retry(socket: &str) -> Result<UnixStream, HashdError> {
    let deadline = std::time::Instant::now() + Duration::from_millis(400);
    loop {
        match UnixStream::connect(socket) {
            Ok(s) => return Ok(s),
            Err(e) => {
                let busy = e.raw_os_error() == Some(libc::EAGAIN); // EWOULDBLOCK is the same errno
                if !busy || std::time::Instant::now() >= deadline {
                    return Err(if busy {
                        HashdError::Busy(e.to_string())
                    } else {
                        HashdError::Unreachable(e.to_string())
                    });
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
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

/// Where the hashd binary belongs when a service runs it: a system
/// path, NOT the build dir. On enforcing Fedora (and any SELinux
/// default) a service may not execute binaries from user-writable
/// locations — `systemd-run .../home/.../hashd` dies with 203/EXEC
/// "Permission denied", so the remediation must install first.
pub const SYSTEM_PATH: &str = "/usr/local/bin/hashd";

/// The transient (re)start commands, valid in EVERY state: down,
/// running-but-unreachable, or a failed transient unit still occupying
/// the name. Clear the unit first, ship the binary to a
/// service-executable location (services cannot exec from $HOME on
/// SELinux-enforcing hosts — 203/EXEC), then start it. `hashd_binary`
/// is the concrete build output when the caller knows one.
pub fn start_commands(socket: &str, hashd_binary: Option<&str>) -> String {
    let source = match hashd_binary {
        Some(bin) if bin != SYSTEM_PATH => bin.to_string(),
        _ => "<hashd-binary>".to_string(),
    };
    format!(
        "sudo install -m 755 {source} {SYSTEM_PATH}\n  \
         sudo systemctl stop fuse-hashd.service 2>/dev/null; \
         sudo systemctl reset-failed fuse-hashd.service 2>/dev/null\n  \
         sudo systemd-run --unit=fuse-hashd {SYSTEM_PATH} --socket {socket}"
    )
}

/// The permanent install commands (one-time, root), run from the
/// repository directory that contains the hashd crate.
pub fn install_commands() -> String {
    "sudo install -m 755 target/{debug,release}/hashd /usr/local/bin/hashd\n  \
     sudo install -m 644 crates/hashd/fuse-hashd.socket crates/hashd/fuse-hashd.service /etc/systemd/system/\n  \
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
    match err {
        HashdError::Unreachable(_) => {
            let mut text = format!(
                "{err}. (Re)start hashd now:\n  {}\n",
                start_commands(socket, hashd_binary)
            );
            if socket == DEFAULT_SOCK {
                text.push_str(&format!(
                    "Or install it permanently (one-time, root):\n  {}",
                    install_commands()
                ));
            }
            text
        }
        HashdError::Busy(_) => format!(
            "{err} — hashd is running but busy (its accept backlog filled while it \
             hashed). A retry in a moment will succeed; restarting hashd is NOT \
             the fix."
        ),
        HashdError::Unprivileged(_) => format!(
            "{err}\nReinstall via the socket-activated unit so hashd carries the \
             capability (one-time, root):\n  {}\nOr restart it privileged only \
             until its next restart:\n  {}",
            install_commands(),
            start_commands(socket, hashd_binary)
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

    /// Bind a listener with an EXPLICIT tiny backlog and return its
    /// fd — std's bind() hardcodes 128 and cannot express "#38:
    /// backlog full". Raw socket(2)/bind(2)/listen(1) on a tempdir
    /// path we own; wrap with `UnixListener::from_raw_fd` to accept.
    fn tiny_backlog_listener(path: &std::path::Path) -> std::os::unix::io::RawFd {
        use std::os::unix::io::RawFd;
        // Plain socket(2)/bind(2)/listen(2) syscalls on a path we
        // own in a per-test tempdir; a leaked fd in a test process is
        // reclaimed at exit. One unsafe op per block, operands hoisted.
        let domain = libc::AF_UNIX;
        let ty = libc::SOCK_STREAM;
        let proto = 0;
        // SAFETY: constants only; an fd leak in a test process is
        // reclaimed at exit.
        let fd: RawFd = unsafe { libc::socket(domain, ty, proto) };
        assert!(fd >= 0, "socket(2) failed");
        // SAFETY: all-zero bytes are a valid `sockaddr_un`.
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_encoded_bytes();
        assert!(bytes.len() < addr.sun_path.len(), "tempdir path too long");
        // SAFETY: `[u8]` and `[c_char]` have the same layout.
        let char_bytes: &[libc::c_char] =
            unsafe { std::mem::transmute::<&[u8], &[libc::c_char]>(bytes) };
        addr.sun_path[..bytes.len()].copy_from_slice(char_bytes);
        let addr_ptr = &addr as *const _ as *const libc::sockaddr;
        let addr_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        // SAFETY: `fd` and `addr_ptr`/`addr_len` describe the tempdir
        // path owned by this test.
        let bound = unsafe { libc::bind(fd, addr_ptr, addr_len) };
        assert!(bound == 0, "bind(2) failed");
        let backlog = 1;
        // SAFETY: `fd` is the bound listener from the calls above.
        let listened = unsafe { libc::listen(fd, backlog) };
        assert!(listened == 0, "listen(2) failed");
        fd
    }

    #[test]
    fn unanswered_ask_is_busy_not_unreachable_and_names_no_restart() {
        // #38, the operator's exact case: hashd accepted the
        // connection (one holder occupies a queue slot — Linux's
        // AF_UNIX queue holds backlog+1, so listen(1) still admits
        // this ask) but answers nothing while busy hashing: the
        // 500ms read timeout surfaces as errno 11, which used to be
        // mislabeled "hashd unreachable — (Re)start hashd now". It
        // must classify as Busy with a retry remediation.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("busy.sock");
        let _fd = tiny_backlog_listener(&sock);
        // Connected, never accepted, never answered — hashd "busy".
        let _holder = UnixStream::connect(&sock).unwrap();
        let t0 = std::time::Instant::now();
        let e = ask(&sock.display().to_string(), 1).unwrap_err();
        assert!(
            matches!(e, HashdError::Busy(_)),
            "an unanswered (busy) ask must classify Busy, got: {e:?}"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "bounded retry window exceeded: {:?}",
            t0.elapsed()
        );
        let text = actionable_error(&e, &sock.display().to_string(), None);
        assert!(
            !text.contains("(Re)start"),
            "busy must not tell the user to restart hashd: {text}"
        );
        assert!(text.contains("retry"), "busy must name retry: {text}");
    }

    #[test]
    fn busy_backlog_retries_recover_when_a_slot_frees() {
        // The other half of #38: the EAGAIN is transient. A listener
        // with backlog 1 that accepts one connection every 30ms must
        // let concurrent asks through — the bounded retry absorbs the
        // EAGAINs, so every ask succeeds despite the tiny backlog.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("slow.sock");
        let fd = tiny_backlog_listener(&sock);
        let _server = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            use std::os::fd::FromRawFd;
            // SAFETY: the fd was created by tiny_backlog_listener and
            // is owned exclusively by this thread from here on; std
            // closes it when the listener drops.
            let listener =
                unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
            let reply = format!("ok {}\n", "a".repeat(64));
            for conn in listener.incoming().flatten() {
                let mut conn = conn;
                let mut line = String::new();
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                if reader.read_line(&mut line).is_err() {
                    break;
                }
                let _ = conn.write_all(reply.as_bytes());
                let _ = conn.flush();
                std::thread::sleep(Duration::from_millis(30));
            }
        });
        let sock_str = sock.display().to_string();
        let askers: Vec<_> = (0..3)
            .map(|_| {
                let s = sock_str.clone();
                std::thread::spawn(move || ask(&s, 1))
            })
            .collect();
        for a in askers {
            assert!(
                a.join().unwrap().is_ok(),
                "a transiently-busy backlog must not fail an ask — retry recovers"
            );
        }
    }

    #[test]
    fn unreachable_when_no_socket() {
        let e = ask("/nonexistent-hashd.sock", 1).unwrap_err();
        assert!(matches!(e, HashdError::Unreachable(_)));
    }

    #[test]
    fn actionable_unreachable_installs_to_a_system_path_before_running() {
        let e = HashdError::Unreachable("connect: No such file or directory".into());
        let text = actionable_error(
            &e,
            "/run/fuse-hashd.sock",
            Some("/home/jonas/ws/agents/target/debug/hashd"),
        );
        assert!(
            text.contains("(Re)start hashd now")
                && text.contains(
                    "sudo install -m 755 /home/jonas/ws/agents/target/debug/hashd \
                     /usr/local/bin/hashd"
                )
                && text.contains(
                    "sudo systemctl stop fuse-hashd.service 2>/dev/null; \
                     sudo systemctl reset-failed fuse-hashd.service 2>/dev/null"
                )
                && text.contains(
                    "sudo systemd-run --unit=fuse-hashd /usr/local/bin/hashd \
                     --socket /run/fuse-hashd.sock"
                ),
            "must install to a system path, clear a possibly-running/failed \
             unit, then start — services cannot exec from $HOME (203/EXEC); \
             got:\n{text}"
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
        assert!(text.contains("install -m 755 <hashd-binary> /usr/local/bin/hashd"), "no known binary: placeholder, got:\n{text}");
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
    fn install_commands_reference_the_units_from_the_repo_root() {
        let c = install_commands();
        assert!(
            c.contains("install -m 644 crates/hashd/fuse-hashd.socket")
                && c.contains("/usr/local/bin/hashd"),
            "permanent install must ship the binary to the system path and the \
             units from the repo root:\n{c}"
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
            let _n = reader.read_line(&mut line).unwrap();
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

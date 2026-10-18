//! A stand-in data daemon for the supervision seam (#94). Two modes:
//!
//! * **Stayer** (no `--oracle-socket`): ignores argv, runs until
//!   SIGTERM (default disposition) — the plain lifecycle prop.
//! * **Speaker**: behaves like the real `fused`'s control loop —
//!   connects to the oracle, sends `Hello { version }`, holds the
//!   connection reading lines, and RECONNECTS on loss. This is what
//!   adoption tests need: a daemon that survives its server and comes
//!   back to the next one (#93's adopt-the-survivor flow).
//!
//! `--advertise-version` overrides the Hello version (the
//! incompatible-vintage pin).


// Test-stub binary (the #116 convention): fixtures and wire stubs
// are the sanctioned test-code shape — inline literals carry no
// naming burden here.
#![allow(unknown_lints)]
#![allow(inline_literal)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

/// Env var overriding the advertised HELLO version.
const ENV_HELLO_VERSION: &str = "FUSE_FAKE_HELLO_VERSION";
/// Idle park + pacing between oracle lines.
const IDLE_FOREVER: std::time::Duration = std::time::Duration::from_secs(3600);
const PACE: std::time::Duration = std::time::Duration::from_secs(1);

// Necessity: argv walking (skip(1), flag matching loop).
#[allow(unknown_lints)]
#[allow(inline_literal)]
fn main() {
    let mut oracle: Option<String> = None;
    let mut version = std::env::var(ENV_HELLO_VERSION)
        .unwrap_or_else(|_| fuse_protocol::VERSION.to_string());
    let mut args = std::env::args().skip(1);
    let mut resumed = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--oracle-socket" => oracle = args.next(),
            "--advertise-version" => version = args.next().unwrap_or_default(),
            "--resume-fd" => {
                let _fd = args.next();
                resumed = true;
            }
            "--resume-fds-base" => {
                let _base = args.next();
            }
            "--resume-state" => {
                let _p = args.next();
            }
            _ => {}
        }
    }
    if resumed {
        eprintln!("fake-fused: resumed session (stand-in)");
    }
    match oracle {
        Some(path) => speak(&path, &version),
        None => loop {
            std::thread::sleep(IDLE_FOREVER);
        },
    }
}

/// First fuse inode number of a fresh session.
const NEXT_FINO_START: u64 = 1;
/// Kernel ABI a stand-in session claims.
const FUSE_PROTO_MAJOR: u32 = 7;
const FUSE_PROTO_MINOR: u32 = 9;

/// Surrender like the real daemon, with a STAND-IN fd (a temp file):
/// the transplant path on the server is fd-agnostic — this exercises
/// the wire (payload line + SCM_RIGHTS + retire) without /dev/fuse.
fn surrender(oracle: &str) -> Result<(), String> {
    use std::os::fd::AsRawFd as _;
    let f = tempfile::tempfile().map_err(|e| e.to_string())?;
    let fd = f.as_raw_fd();
    let state = fuse_mount::fs::TakeoverState {
        next_fino: NEXT_FINO_START,
        tree: Vec::new(),
        labels: Vec::new(),
        identities: Vec::new(),
        open_fds: Vec::new(),
        proto_major: FUSE_PROTO_MAJOR,
        proto_minor: FUSE_PROTO_MINOR,
    };
    let payload = fuse_protocol::oracle::OracleRequest::SurrenderPayload {
        session_schema: fuse_mount::fs::TAKEOVER_SESSION_SCHEMA,
        state: serde_json::to_value(&state).map_err(|e| e.to_string())?,
    };
    let line = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
    let conn = UnixStream::connect(oracle).map_err(|e| format!("connect: {e}"))?;
    let payload_bytes = format!("{line}\n");
    let iov = [std::io::IoSlice::new(payload_bytes.as_bytes())];
    let cmsg = nix::sys::socket::ControlMessage::ScmRights(&[fd]);
    let _sent = nix::sys::socket::sendmsg::<()>(
        conn.as_raw_fd(),
        &iov,
        &[cmsg],
        nix::sys::socket::MsgFlags::empty(),
        None,
    )
    .map_err(|e| format!("sendmsg: {e}"))?;
    std::mem::forget(f); // the dup lives in the receiver now
    eprintln!("fake-fused: surrendered a stand-in fd");
    Ok(())
}

/// The control loop: Hello, read forever, reconnect after 1s.
fn speak(oracle: &str, version: &str) {
    loop {
        if let Ok(conn) = UnixStream::connect(oracle) {
            let mut reader = BufReader::new(match conn.try_clone() {
                Ok(c) => c,
                Err(_) => {
                    std::thread::sleep(PACE);
                    continue;
                }
            });
            let mut w = conn;
            let hello = serde_json::to_string(&fuse_protocol::oracle::OracleRequest::Hello {
                version: Some(version.to_string()),
            })
            .unwrap_or_default();
            if w
                .write_all(format!("{hello}\n").as_bytes())
                .and_then(|_| w.flush())
                .is_err()
            {
                std::thread::sleep(PACE);
                continue;
            }
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        // the typed wire: OracleCommand covers every
                        // line the policy daemon may push (the
                        // string-grep this replaces could not see
                        // shapes, only substrings).
                        match serde_json::from_str::<fuse_protocol::oracle::OracleCommand>(&line) {
                            Ok(fuse_protocol::oracle::OracleCommand::Surrender) => {
                                if let Err(e) = surrender(oracle) {
                                    eprintln!("fake-fused: surrender failed: {e}");
                                }
                            }
                            Ok(fuse_protocol::oracle::OracleCommand::Retire) => {
                                eprintln!("fake-fused: retired — exiting 0");
                                std::process::exit(0);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        std::thread::sleep(PACE);
    }
}

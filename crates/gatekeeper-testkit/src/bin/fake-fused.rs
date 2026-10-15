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

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

fn main() {
    let mut oracle: Option<String> = None;
    let mut version = std::env::var("FUSE_FAKE_HELLO_VERSION")
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
            std::thread::sleep(std::time::Duration::from_secs(3600));
        },
    }
}

/// Surrender like the real daemon, with a STAND-IN fd (a temp file):
/// the transplant path on the server is fd-agnostic — this exercises
/// the wire (payload line + SCM_RIGHTS + retire) without /dev/fuse.
fn surrender(oracle: &str) -> Result<(), String> {
    use std::os::fd::AsRawFd as _;
    let f = tempfile::tempfile().map_err(|e| e.to_string())?;
    let fd = f.as_raw_fd();
    let payload = serde_json::json!({
        "type": "surrender_payload",
        "session_schema": 1,
        "state": {
            "next_fino": 1,
            "tree": [],
            "labels": [],
            "identities": [],
            "open_fds": [],
            "proto_major": 7,
            "proto_minor": 9
        }
    });
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
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    continue;
                }
            });
            let mut w = conn;
            let hello = format!(
                "{{\"type\":\"hello\",\"version\":\"{version}\"}}\n"
            );
            if w.write_all(hello.as_bytes()).and_then(|_| w.flush()).is_err() {
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if line.contains("\"surrender\"") && !line.contains("payload") {
                            if let Err(e) = surrender(oracle) {
                                eprintln!("fake-fused: surrender failed: {e}");
                            }
                        }
                        if line.contains("\"retire\"") {
                            eprintln!("fake-fused: retired — exiting 0");
                            std::process::exit(0);
                        }
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

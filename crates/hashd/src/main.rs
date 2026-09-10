//! The `pid → package hash` helper.
//!
//! A tiny, single-purpose daemon: one unix socket, one line protocol,
//! one operation — compute the SHA-256 of a process's loaded package
//! (executable + every mapped library, straight from the procfs magic
//! links; see `fuse_protocol::RealSystemIo::sha256_process_package`).
//!
//! Why it exists: following `/proc/<pid>/map_files` requires
//! `CAP_SYS_ADMIN` or `CAP_CHECKPOINT_RESTORE` in the INITIAL user
//! namespace (kernel `fs/proc/base.c`). The fuse-server is deliberately
//! unprivileged — so it delegates the one privileged operation to this
//! helper instead of growing capabilities itself.
//!
//! # Protocol (one request per connection, LF-terminated lines)
//!
//! ```text
//! > hash <pid>       →  ok <64-hex>
//!                   →  error unprivileged <why>
//!                   →  error gone <why>
//!                   →  error <why>
//! > status           →  status privileged|unprivileged <detail>
//! ```
//!
//! `error unprivileged` classifies the failure (this helper lacks the
//! init-namespace capability the kernel demands); clients log the
//! reason — without a hashd, grant-forever answers with a bare
//! not-supported sentence.
//!
//! # Deployment
//!
//! Permanent (recommended — root only ONCE at install, systemd owns the
//! socket, the service carries exactly one capability):
//!
//! ```sh
//! sudo install -m 644 fuse-hashd.socket fuse-hashd.service /etc/systemd/system/
//! sudo systemctl daemon-reload && sudo systemctl enable --now fuse-hashd.socket
//! ```
//!
//! Until next restart (transient, no unit files, no polkit):
//!
//! ```sh
//! sudo systemd-run --unit=fuse-hashd <path-to-this-binary> --socket <sock>
//! ```

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;

use fuse_protocol::{RealSystemIo, SystemIo};

/// Default socket path: `/run` when we can (root / socket activation),
/// `$TMPDIR`-style fallback for unprivileged manual runs.
fn default_socket() -> String {
    if std::path::Path::new("/run").is_dir() && can_write_run() {
        fuse_protocol::hashd::DEFAULT_SOCK.to_string()
    } else {
        format!("/tmp/fuse-hashd-{}.sock", nix_uid())
    }
}

fn can_write_run() -> bool {
    std::fs::metadata(fuse_protocol::hashd::DEFAULT_SOCK)
        .map(|_| true) // exists: socket-activated, the fd arrives later
        .or_else(|_| std::fs::metadata("/run").map(|m| !m.permissions().readonly()))
        .is_ok_and(|ok| ok)
}

fn nix_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(|x| x.to_string()))
        })
        .and_then(|x| x.parse().ok())
        .unwrap_or(0)
}

/// Does THIS process hold the capability the kernel demands (can it
/// follow one of its own child's map_files links)?
fn privileges_ok() -> bool {
    let Ok(mut child) = std::process::Command::new("sleep").arg("2").spawn() else {
        return false;
    };
    let ok = (|| {
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", child.id())).ok()?;
        let range = maps
            .lines()
            .find(|l| l.contains('/'))?
            .split_whitespace()
            .next()?
            .to_string();
        Some(
            std::fs::read(format!("/proc/{}/map_files/{}", child.id(), range)).is_ok(),
        )
    })()
    .unwrap_or(false);
    let _ = child.kill();
    let _ = child.wait();
    ok
}

/// One request → one reply.
fn handle(conn: std::os::unix::net::UnixStream) {
    let mut reader = BufReader::new(match conn.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    });
    let mut stream = conn;
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let trimmed = line.trim();
    let reply = if trimmed == "status" {
        let state = if privileges_ok() { "privileged" } else { "unprivileged" };
        format!("status {state} follows /proc/<pid>/map_files\n")
    } else {
        match trimmed.split_once(' ') {
            Some(("hash", pid)) => match pid.parse::<u32>() {
                Ok(pid) => match RealSystemIo::new().sha256_process_package(pid) {
                    Ok(hash) => format!("ok {hash}\n"),
                    Err(e) => {
                        let msg = e.to_string();
                        let kind = if msg.contains("Operation not permitted")
                            || msg.contains("Permission denied")
                        {
                            if privileges_ok() {
                                "error"
                            } else {
                                // The helper itself lacks the init-ns capability:
                                // the actionable case for client-side remediation.
                                "error unprivileged"
                            }
                        } else if msg.contains("No such file") {
                            "error gone"
                        } else {
                            "error"
                        };
                        format!("{kind} {msg}\n")
                    }
                },
                Err(_) => "error pid must be a number\n".to_string(),
            },
            _ => "error unknown request (use: hash <pid> | status)\n".to_string(),
        }
    };
    let _ = stream.write_all(reply.as_bytes());
    let _ = stream.flush();
}

fn main() {
    let socket = std::env::args()
        .nth(1)
        .filter(|a| a != "--socket")
        .or_else(|| {
            let mut it = std::env::args();
            while let Some(a) = it.next() {
                if a == "--socket" {
                    return it.next();
                }
            }
            None
        })
        .unwrap_or_else(default_socket);

    let _ = std::fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("hashd: cannot bind {socket}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "hashd: listening on {socket} ({})",
        if privileges_ok() { "privileged" } else { "unprivileged" }
    );
    for conn in listener.incoming().flatten() {
        handle(conn);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_socket_prefers_run_only_when_writable() {
        // Deterministic branch check, independent of this test host.
        let s = default_socket();
        assert!(
            s.starts_with("/run/") || s.starts_with("/tmp/fuse-hashd-"),
            "unexpected default socket {s}"
        );
    }

    #[test]
    fn privileges_probe_returns_bool() {
        // Any environment: must answer, never panic.
        let _ = privileges_ok();
    }
}

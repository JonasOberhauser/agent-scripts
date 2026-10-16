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
    while let Some(a) = args.next() {
        match a.as_str() {
            "--oracle-socket" => oracle = args.next(),
            "--advertise-version" => version = args.next().unwrap_or_default(),
            _ => {}
        }
    }
    match oracle {
        Some(path) => speak(&path, &version),
        None => loop {
            std::thread::sleep(IDLE_FOREVER);
        },
    }
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
            let hello = format!(
                "{{\"type\":\"hello\",\"version\":\"{version}\"}}\n"
            );
            if w.write_all(hello.as_bytes()).and_then(|_| w.flush()).is_err() {
                std::thread::sleep(PACE);
                continue;
            }
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
        std::thread::sleep(PACE);
    }
}

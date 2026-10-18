//! The seam-tier contract double (e2e_stub_fuse): a minimal
//! fuse-server stand-in speaking the command protocol run-agent must
//! consume. Built by CARGO (examples compile under `cargo test`),
//! so it links with whatever linker configuration the workspace
//! itself uses — no C compiler, no runtime rustc invocation (a bare
//! `rustc` spawn fails on hosts whose linker setup differs from
//! cargo's, e.g. gcc-less minimal hosts).
//!
//! Contract: one request line per connection. `add NAME ...` answers
//! `Added { inner: "stub-<name>" }` — the anonymized container-view
//! form (#47/#58) the caller must wire container paths to; anything
//! else answers Ok. Deterministic inner form so the tier can ASSERT
//! the caller followed the server-reported name.
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

/// argv/wire vocabulary of the stub.
const FLAG_SOCKET: &str = "--socket";
const CMD_ADD: &str = "add";
#[allow(unknown_lints)]
#[allow(inline_literal)]
const REPLY_OK: &str = "{\"type\":\"ok\"}\n";
const EXIT_USAGE: i32 = 2;
const EXIT_BIND: i32 = 3;

// Necessity: argv walking (skip(1), flag matching) and the WORD reply
// grammar (split(' ')) — a hand-rolled wire stub, not constants to name.
#[allow(unknown_lints)]
#[allow(inline_literal)]
fn main() {
    let mut path: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == FLAG_SOCKET {
            path = args.next().map(PathBuf::from);
        }
    }
    let Some(path) = path else {
        eprintln!("stub: --socket required");
        std::process::exit(EXIT_USAGE);
    };
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("stub: bind {}: {e}", path.display());
            std::process::exit(EXIT_BIND);
        }
    };
    eprintln!("stub-fuse-server: listening at {}", path.display());
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let mut w = conn;
        let mut reader = BufReader::new(w.try_clone().expect("clone stub conn"));
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            continue;
        }
            // request grammar: WORD args — plain split
            let mut words = line.split(' ');
            let reply = match (words.next(), words.next()) {
                (Some(CMD_ADD), Some(name)) => {
                    format!("{{\"type\":\"added\",\"inner\":\"stub-{name}\"}}\n")
                }
                _ => REPLY_OK.to_string(),
            };
        let _ = w.write_all(reply.as_bytes());
        let _ = w.flush();
    }
}

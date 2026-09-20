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

fn main() {
    let mut path: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--socket" {
            path = args.next().map(PathBuf::from);
        }
    }
    let Some(path) = path else {
        eprintln!("stub: --socket required");
        std::process::exit(2);
    };
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("stub: bind {}: {e}", path.display());
            std::process::exit(3);
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
            let reply = if line.starts_with("add ") {
                let name = line.split_whitespace().nth(1).unwrap_or_default();
                format!("{{\"type\":\"added\",\"inner\":\"stub-{name}\"}}\n")
            } else {
            "{\"type\":\"ok\"}\n".to_string()
        };
        let _ = w.write_all(reply.as_bytes());
        let _ = w.flush();
    }
}

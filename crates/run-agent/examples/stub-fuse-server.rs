//! The seam-tier contract double (e2e_stub_fuse): a minimal
//! fuse-server stand-in speaking the command protocol run-agent must
//! consume. Built by CARGO (examples compile under `cargo test`),
//! so it links with whatever linker configuration the workspace
//! itself uses — no C compiler, no runtime rustc invocation (a bare
//! `rustc` spawn fails on hosts whose linker setup differs from
//! cargo's, e.g. gcc-less minimal hosts).
//!
//! Wire contract (servyi_servatui TypedConnection framing): each
//! connection sends the command NAME as a JSON string line, then the
//! Command as a JSON object line; the reply is one JSON Response
//! line, and the client closes with a `null` line. `add_secret`
//! answers `Added { inner: "stub-<name>" }` — the anonymized
//! container-view form (#47/#58) the caller must wire container paths
//! to; `get_version` answers the real `fuse_protocol::VERSION`
//! (matching vintages, so the restart machinery stays out of the
//! way); everything else answers Ok. Deterministic inner form so the
//! tier can ASSERT the caller followed the server-reported name.
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

/// argv vocabulary of the stub.
const FLAG_SOCKET: &str = "--socket";
const EXIT_USAGE: i32 = 2;
const EXIT_BIND: i32 = 3;
/// JSON command tags the stub answers with substance.
const TAG_ADD_SECRET: &str = "add_secret";
const TAG_GET_VERSION: &str = "get_version";

// Necessity: argv walking (skip(1), flag matching) and the two-line
// JSON frame (name line, command line) — a hand-rolled wire stub.
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
        // Bounded reads: a client that dies mid-frame (or never sends
        // the closing null) must not wedge the accept loop — a CI
        // failure showed the NEXT connection never being served.
        let _ = w.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let mut reader = BufReader::new(match w.try_clone() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("stub: clone conn failed: {e}");
                continue;
            }
        });
        // Frame: name line, then the command object line.
        let mut name_line = String::new();
        if let Err(e) = reader.read_line(&mut name_line) {
            eprintln!("stub: name read failed: {e}");
            continue;
        }
        let mut cmd_line = String::new();
        if let Err(e) = reader.read_line(&mut cmd_line) {
            eprintln!("stub: command read failed: {e}");
            continue;
        }
        let reply = match serde_json::from_str::<serde_json::Value>(cmd_line.trim()) {
            Ok(cmd) => match cmd.get("type").and_then(|t| t.as_str()) {
                Some(TAG_ADD_SECRET) => {
                    let name = cmd
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or_default();
                    format!(
                        "{{\"type\":\"added\",\"inner\":\"stub-{name}\"}}\n"
                    )
                }
                Some(TAG_GET_VERSION) => {
                    format!(
                        "{{\"type\":\"version\",\"version\":\"{}\"}}\n",
                        fuse_protocol::VERSION
                    )
                }
                _ => "{\"type\":\"ok\"}\n".to_string(),
            },
            Err(_) => "{\"type\":\"ok\"}\n".to_string(),
        };
        let _ = w.write_all(reply.as_bytes());
        let _ = w.flush();
        // The client closes the frame with a null line; consume it so
        // the connection ends cleanly.  Bounded: a client that never
        // sends it (or dies first) must not hold the accept loop.
        let _ = w.set_read_timeout(Some(std::time::Duration::from_millis(500)));
        let mut tail = String::new();
        let _ = reader.read_line(&mut tail);
        let _ = name_line;
    }
}

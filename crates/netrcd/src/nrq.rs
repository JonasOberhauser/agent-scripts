//! `nrq` — the thin container-side client: send one typed request,
//! print the answer. Holds no credential, does no TLS.

use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::Parser;
use netrcd::exec::request_over_socket;
use netrcd::wire::{WireRequest, WireResponse};

#[derive(Parser)]
#[command(about = "Send one policy-checked request through netrcd")]
struct Cli {
    /// netrcd socket (default: $NETRCD_SOCK).
    #[arg(long, env = "NETRCD_SOCK")]
    socket: Option<PathBuf>,

    /// Include response status and headers in the output.
    #[arg(short = 'i')]
    include_headers: bool,

    method: String,
    machine: String,
    /// Absolute path (with optional query); the host comes from the
    /// machine.
    url: String,

    /// Request header `Name: value` (repeatable).
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// Literal request body (never a file).
    #[arg(short = 'd', long = "data")]
    data: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    let socket = cli.socket.unwrap_or_else(|| PathBuf::from("/netrcd/netrcd.sock"));

    let mut headers = BTreeMap::new();
    for h in &cli.headers {
        let Some((name, value)) = h.split_once(':') else {
            eprintln!("header {h:?} must be 'Name: value'");
            std::process::exit(2);
        };
        headers.insert(name.trim().to_string(), value.trim().to_string());
    }

    let frame = WireRequest {
        op: "request".into(),
        machine: cli.machine.clone(),
        method: cli.method.to_ascii_uppercase(),
        url: cli.url.clone(),
        headers,
        body: cli.data.clone(),
    };

    match request_over_socket(&socket, &frame) {
        Ok(WireResponse::Response { status, headers, body, truncated }) => {
            if cli.include_headers {
                println!("{status}");
                for (k, v) in &headers {
                    println!("{k}: {v}");
                }
                println!();
            } else {
                eprintln!("{status}");
            }
            print!("{body}");
            if truncated {
                eprintln!("\n[nrq: response truncated by machine policy]");
            }
            std::process::exit(if status < 400 { 0 } else { 1 });
        }
        Ok(WireResponse::Error { code, detail }) => {
            eprintln!("nrq: {code:?}: {detail}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("nrq: {e}");
            std::process::exit(1);
        }
    }
}

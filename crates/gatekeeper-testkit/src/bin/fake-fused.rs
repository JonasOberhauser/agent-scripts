//! A stand-in data daemon for the supervision seam (#94) with CUSTODY
//! semantics (#93 F2, PR thread: the seamless-restart design):
//!
//! - first boot: it opens `<mount>/custody.token` and writes a
//!   fixed-width (8-byte BE) generation counter at the fd's current
//!   position — generation 1 at position 0;
//! - `--resume-fd N --resume-state P`: it ADOPTS the inherited
//!   descriptor instead of opening anything, and writes generation
//!   `pos/8 + 1` at the inherited position — the shared file
//!   description carries the position, so a continuing lineage appends
//!   strictly monotonically while a REOPENED file restarts at zero.
//!   The file's counters are the test's continuity proof; the daemon
//!   itself never parses them (fixed-width arithmetic only).
//!
//! Surrender/Retire: on the Surrender control word it ships its fd
//! plus a session blob (`{"generations": n}`) as a SurrenderPayload
//! connection with SCM_RIGHTS — keeping its own copy; on Retire it
//! exits 0 (closing its copies last, the retirement contract).

use std::io::{BufRead as _, BufReader, Seek as _, Write as _};
use std::os::unix::io::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use serde::Serialize;

#[derive(clap::Parser)]
#[command(
    name = "fake-fused",
    about = "custody-capable data-daemon stand-in (#94 seam, #93 F2 handoff)"
)]
struct Cli {
    #[arg(long)]
    mount_point: PathBuf,
    #[arg(long)]
    oracle_socket: PathBuf,
    /// Adopt the mount-connection descriptor inherited at this number
    /// instead of opening the custody file (#93 F2 resume).
    #[arg(long)]
    resume_fd: Option<i32>,
    /// The serialized session state handed over by the old pair.
    #[arg(long)]
    resume_state: Option<PathBuf>,
}

/// The session schema this fake speaks (tests gate on it).
const SCHEMA: u32 = 1;

#[derive(Serialize)]
struct Session {
    generations: u64,
}

/// One fixed-width generation counter (8-byte BE), written AT the
/// descriptor's current position — position continuity IS the proof.
struct Custody {
    file: std::fs::File,
    generations: u64,
}

impl Custody {
    fn fresh(path: &std::path::Path) -> std::io::Result<Self> {
        // A FRESH mount owns the lineage file anew — truncate is the
        // point (adopt never truncates: the shared description IS the
        // continuity proof).
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(&1u64.to_be_bytes())?;
        Ok(Self {
            file,
            generations: 1,
        })
    }

    fn adopt(file: std::fs::File) -> std::io::Result<Self> {
        let mut c = Self {
            file,
            generations: 0,
        };
        let pos = c.file.stream_position()?;
        let generations = pos / 8;
        let next = generations + 1;
        c.file.write_all(&next.to_be_bytes())?;
        c.generations = next;
        Ok(c)
    }
}

fn main() {
    let cli = <Cli as clap::Parser>::parse();

    // Custody: adopt or open.
    let custody = if let (Some(fd), Some(state)) = (cli.resume_fd, &cli.resume_state) {
        // The inherited descriptor: taken over as an owned File. Its
        // position is the shared file description's — the lineage.
        // SAFETY: the descriptor number was placed at 3 by the
        // supervisor's pre_exec dup2 for exactly this adoption.
        let file = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        let _ = state; // the blob exists for the real daemon; the fake's is arithmetic
        match Custody::adopt(file) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("fake-fused: cannot adopt fd {fd}: {e}");
                std::process::exit(1);
            }
        }
    } else {
        match Custody::fresh(&cli.mount_point.join("custody.token")) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("fake-fused: custody file: {e}");
                std::process::exit(1);
            }
        }
    };

    // Control loop: Hello, then the lifecycle words. Reconnects like
    // the real daemon (the crash-path discipline).
    loop {
        if let Ok(conn) = UnixStream::connect(&cli.oracle_socket) {
            if run_control(conn, &cli.oracle_socket, &custody) {
                return; // Retire: exit 0
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// One control connection. Returns true on Retire.
fn run_control(conn: UnixStream, oracle: &std::path::Path, custody: &Custody) -> bool {
    let mut writer = match conn.try_clone() {
        Ok(w) => w,
        Err(_) => return false,
    };
    let hello = serde_json::json!({
        "type": "hello",
        "version": env!("CARGO_PKG_VERSION"),
    });
    if writeln!(writer, "{hello}")
        .and_then(|_| writer.flush())
        .is_err()
    {
        return false;
    }
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
        match line.trim() {
            l if l.contains("\"surrender\"") => {
                // Ship the custody fd + session blob, keep our copy.
                if let Err(e) = surrender(oracle, custody) {
                    eprintln!("fake-fused: surrender failed: {e}");
                }
            }
            l if l.contains("\"retire\"") => {
                eprintln!("fake-fused: retired — exiting 0");
                return true;
            }
            _ => {}
        }
        line.clear();
    }
    false
}

/// The SurrenderPayload connection: one line + SCM_RIGHTS\[fd\].
fn surrender(oracle: &std::path::Path, custody: &Custody) -> Result<(), String> {
    let conn = UnixStream::connect(oracle).map_err(|e| e.to_string())?;
    let session = Session {
        generations: custody.generations,
    };
    let state = serde_json::to_value(&session).map_err(|e| e.to_string())?;
    let payload = serde_json::json!({
        "type": "surrender_payload",
        "session_schema": SCHEMA,
        "state": state,
    });
    let line = format!("{payload}\n");
    let iov = [std::io::IoSlice::new(line.as_bytes())];
    let cmsg = [nix::sys::socket::ControlMessage::ScmRights(&[custody
        .file
        .as_raw_fd()])];
    let _sent = nix::sys::socket::sendmsg::<()>(
        conn.as_raw_fd(),
        &iov,
        &cmsg,
        nix::sys::socket::MsgFlags::empty(),
        None,
    )
    .map_err(|e| e.to_string())?;
    use std::io::Write as _;
    let _ = (&conn).flush();
    Ok(())
}



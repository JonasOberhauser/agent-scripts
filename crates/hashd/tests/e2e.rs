//! E2E: the REAL hashd binary over a REAL unix socket.
//!
//! `speaks_the_protocol_over_a_real_socket` runs anywhere there is a
//! build of hashd — any well-formed reply counts (the point is that
//! the daemon comes up and talks).
//!
//! `socket_is_connectable_by_unprivileged_clients` is the regression
//! test for the root-started-hashd bug: connect(2) needs WRITE
//! permission on the socket file, and bind(2) applies the umask, so a
//! root hashd was connectable by root only — every unprivileged
//! fuse-server got EACCES. It needs root to drop privileges, so it is
//! #[ignore]-gated like the other environment-dependent suites.

// Tests may hand-parse output/protocol lines: sanctioned by policy
// (test + allow), NOT available to production code. unknown_lints:
// the custom_parser lint exists only under the servyi driver.
#![allow(unknown_lints)]
#![allow(custom_parser)]
#![allow(clippy::unwrap_used, clippy::panic, unused_results)]


use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Hashd {
    child: Child,
    socket: std::path::PathBuf,
}

impl Drop for Hashd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn spawn_hashd(dir: &std::path::Path) -> Hashd {
    let socket = dir.join("hashd.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_hashd"))
        .arg("--socket")
        .arg(&socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn hashd binary");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if socket.exists() && UnixStream::connect(&socket).is_ok() {
            return Hashd { child, socket };
        }
        if child.try_wait().expect("poll hashd").is_some() {
            let _ = child.wait();
            panic!("hashd exited before becoming connectable");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("hashd never came up at {}", socket.display());
}

fn ask(socket: &std::path::Path, request: &str) -> String {
    let mut stream = UnixStream::connect(socket).expect("connect to hashd");
    stream
        .write_all(format!("{request}\n").as_bytes())
        .expect("send request");
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).expect("read reply");
    line
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .is_some_and(|uid| uid == "0")
}

#[test]
fn speaks_the_protocol_over_a_real_socket() {
    let dir = tempfile::tempdir().unwrap();
    let hashd = spawn_hashd(dir.path());

    let reply = ask(&hashd.socket, "status");
    let st: serde_json::Value =
        serde_json::from_str(reply.trim()).expect("status reply is JSON: {reply:?}");
    assert!(
        st.get("status").is_some_and(|v| v == "privileged" || v == "unprivileged"),
        "any well-formed status reply counts, got: {reply:?}"
    );

    // Hash a real process: in a privileged context this must be a
    // 64-hex digest; unprivileged contexts fail classified. Either way
    // the reply is well-formed — never garbage, never silence.
    let reply = ask(
        &hashd.socket,
        &format!("hash {}", std::process::id()),
    );
    let v: serde_json::Value =
        serde_json::from_str(reply.trim()).expect("hash reply is JSON: {reply:?}");
    if let Some(h) = v.get("ok").and_then(|x| x.as_str()) {
        assert_eq!(h.len(), 64, "digest must be sha256 hex: {reply:?}");
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit()),
            "digest must be hex: {reply:?}"
        );
    } else {
        let kind = v
            .get("error")
            .and_then(|e| e.get("kind"))
            .and_then(|k| k.as_str())
            .unwrap_or("");
        assert!(
            ["unprivileged", "gone", "generic"].contains(&kind),
            "hash failures must be classified, got: {reply:?}"
        );
    }

    let reply = ask(&hashd.socket, "nonsense");
    let v: serde_json::Value =
        serde_json::from_str(reply.trim()).expect("unknown-request reply is JSON: {reply:?}");
    assert!(
        v.get("error").is_some(),
        "unknown requests must be answered, not dropped: {reply:?}"
    );
}

#[test]
#[ignore = "needs root (privilege drop) plus setpriv+python3; run with --ignored in a root container"]
fn socket_is_connectable_by_unprivileged_clients() {
    assert!(
        is_root(),
        "refusing to skip: this regression test must run as root to drop privileges"
    );
    for tool in ["setpriv", "python3"] {
        assert!(
            Command::new(tool).arg("--version").output().is_ok_and(|o| o.status.success()),
            "refusing to skip: needs {tool} on PATH"
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let hashd = spawn_hashd(dir.path());

    // Connect as an unprivileged uid — exactly what the fuse-server
    // does. Before the SocketMode fix this died with EACCES.
    let client = r#"
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(sys.argv[1])
    s.sendall(b"status\n")
    print(s.recv(4096).decode(errors="replace").strip())
except Exception as e:
    sys.exit(f"unprivileged client failed: {type(e).__name__}: {e}")
"#;
    let out = Command::new("setpriv")
        .args(["--reuid=65534", "--regid=65534", "--clear-groups"])
        .arg("python3")
        .arg("-c")
        .arg(client)
        .arg(&hashd.socket)
        .output()
        .expect("run unprivileged client");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.starts_with("status "),
        "an unprivileged client must be able to ask hashd (connect(2) needs \
         write permission on the socket file):\nstdout: {stdout}\nstderr: {stderr}"
    );
}

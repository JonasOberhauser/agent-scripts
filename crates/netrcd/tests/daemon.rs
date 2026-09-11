//! Daemon-level integration tests: real unix socket, real wire
//! protocol, stubbed upstream executor. Covers the lifecycle
//! scenarios that matter: restart between commands, SIGHUP reload
//! flipping permissions, malformed/oversized frames, and the typed
//! refusals.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use netrcd::daemon::{Daemon, DaemonConfig};
use netrcd::exec::{ExecError, Executor, OutboundRequest, UpstreamResponse};
use netrcd::wire::{ErrorCode, WireRequest, WireResponse};

#[derive(Default)]
struct StubExecutor {
    calls: Mutex<Vec<OutboundRequest>>,
    replies: Mutex<VecDeque<Result<UpstreamResponse, ExecError>>>,
}

impl StubExecutor {
    fn with(replies: Vec<Result<UpstreamResponse, ExecError>>) -> Arc<StubExecutor> {
        Arc::new(StubExecutor {
            calls: Mutex::default(),
            replies: Mutex::new(replies.into()),
        })
    }
}

impl Executor for StubExecutor {
    fn execute(&self, req: &OutboundRequest) -> Result<UpstreamResponse, ExecError> {
        self.calls.lock().unwrap().push(req.clone());
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(UpstreamResponse {
                status: 200,
                headers: Default::default(),
                body: b"ok".to_vec(),
                truncated: false,
            }))
    }
}

fn ok_response() -> Result<UpstreamResponse, ExecError> {
    Ok(UpstreamResponse {
        status: 200,
        headers: Default::default(),
        body: b"payload".to_vec(),
        truncated: false,
    })
}

struct Fixture {
    _profiles: tempfile::TempDir,
    _grants: tempfile::TempDir,
    dir: PathBuf,
}

fn write_grant(dir: &std::path::Path, content: &str) {
    std::fs::write(dir.join("m.toml"), content).unwrap();
}

fn setup(grant_toml: &str, exec: Arc<dyn Executor>) -> (Fixture, Daemon) {
    let profiles = tempfile::tempdir().unwrap();
    let grants = tempfile::tempdir().unwrap();
    std::fs::write(
        profiles.path().join("m.toml"),
        "[[machine]]\nname = \"api.x.com\"\nauth = \"bearer\"\n",
    )
    .unwrap();
    write_grant(grants.path(), grant_toml);
    let daemon = Daemon::start(DaemonConfig {
        socket: grants.path().join("sock/netrcd.sock"),
        profiles_dir: profiles.path().to_path_buf(),
        grants_dir: grants.path().to_path_buf(),
        netrc_texts: vec![("netrc".into(), "machine api.x.com login u password sekrit".into())],
        executor: exec,
    })
    .unwrap();
    (
        Fixture {
            _profiles: profiles,
            _grants: grants,
            dir: daemon.socket_path().to_path_buf(),
        },
        daemon,
    )
}

fn get(socket: &std::path::Path, url: &str) -> Result<WireResponse, String> {
    frame(socket, "GET", url, None)
}

fn frame(
    socket: &std::path::Path,
    method: &str,
    url: &str,
    body: Option<&str>,
) -> Result<WireResponse, String> {
    netrcd::exec::request_over_socket(
        socket,
        &WireRequest {
            op: "request".into(),
            machine: "api.x.com".into(),
            method: method.into(),
            url: url.into(),
            headers: Default::default(),
            body: body.map(|b| b.to_string()),
        },
    )
}

fn err_code(resp: &WireResponse) -> ErrorCode {
    match resp {
        WireResponse::Error { code, .. } => *code,
        WireResponse::Response { .. } => panic!("expected error, got {resp:?}"),
    }
}

#[test]
fn roundtrip_reaches_the_stub_with_credential_injected() {
    let exec = StubExecutor::with(vec![ok_response()]);
    let (_f, _d) = setup(
        "[[machine]]\nname = \"api.x.com\"\n[[machine.allow]]\nmethod = \"GET\"\nurl = '/zen'\n",
        exec.clone(),
    );
    match get(&_f.dir, "/zen").unwrap() {
        WireResponse::Response { status, body, .. } => {
            assert_eq!(status, 200);
            assert_eq!(body, "payload");
        }
        other => panic!("{other:?}"),
    }
    let calls = exec.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].url, "https://api.x.com/zen");
    assert!(calls[0].headers.iter().any(|(k, v)| k == "Authorization" && v == "Bearer sekrit"));
}

#[test]
fn refused_requests_never_reach_the_executor() {
    let exec = Arc::new(StubExecutor::default());
    let (_f, _d) = setup(
        "[[machine]]\nname = \"api.x.com\"\n[[machine.allow]]\nmethod = \"GET\"\nurl = '/zen'\n",
        exec.clone(),
    );
    let resp = get(&_f.dir, "/forbidden").unwrap();
    assert_eq!(err_code(&resp), ErrorCode::NotAllowed);
    assert!(exec.calls.lock().unwrap().is_empty());
}

/// The named scenario: a daemon crash/restart between two commands is
/// a typed error, and recovery is transparent — same socket path, new
/// listener, in-flight state irrelevant because there is none.
#[test]
fn restart_between_two_commands() {
    // Build the fixture manually so we can stop and restart on the
    // same directories and socket path.
    let profiles = tempfile::tempdir().unwrap();
    let grants = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(grants.path().join("sock")).unwrap();
    std::fs::write(
        profiles.path().join("m.toml"),
        "[[machine]]\nname = \"api.x.com\"\nauth = \"bearer\"\n",
    )
    .unwrap();
    write_grant(grants.path(), "[[machine]]\nname = \"api.x.com\"\n[[machine.allow]]\nmethod = \"GET\"\nurl = '/zen'\n");
    let socket = grants.path().join("sock/netrcd.sock");
    let cfg = |exec: Arc<dyn Executor>| DaemonConfig {
        socket: socket.clone(),
        profiles_dir: profiles.path().to_path_buf(),
        grants_dir: grants.path().to_path_buf(),
        netrc_texts: vec![("netrc".into(), "machine api.x.com login u password sekrit".into())],
        executor: exec,
    };

    let exec1 = StubExecutor::with(vec![ok_response()]);
    let d1 = Daemon::start(cfg(exec1.clone())).unwrap();
    assert!(matches!(get(&socket, "/zen").unwrap(), WireResponse::Response { .. }));

    // "Crash": daemon gone between two commands.
    drop(d1);
    let mid = get(&socket, "/zen");
    assert!(mid.is_err(), "daemon down must be a transport error: {mid:?}");

    // Restart on the same path — the stale socket file is stolen and
    // clients reconnect transparently.
    let exec2 = StubExecutor::with(vec![ok_response()]);
    let _d2 = Daemon::start(cfg(exec2)).unwrap();
    assert!(matches!(get(&socket, "/zen").unwrap(), WireResponse::Response { .. }));
}

#[test]
fn sighup_reload_flips_permission_atomically() {
    let exec = Arc::new(StubExecutor::default());
    let grants = tempfile::tempdir().unwrap();
    let profiles = tempfile::tempdir().unwrap();
    std::fs::write(
        profiles.path().join("m.toml"),
        "[[machine]]\nname = \"api.x.com\"\nauth = \"bearer\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(grants.path().join("sock")).unwrap();
    write_grant(grants.path(), "[[machine]]\nname = \"api.x.com\"\n[[machine.allow]]\nmethod = \"GET\"\nurl = '/zen'\n");
    let daemon = Daemon::start(DaemonConfig {
        socket: grants.path().join("sock/netrcd.sock"),
        profiles_dir: profiles.path().to_path_buf(),
        grants_dir: grants.path().to_path_buf(),
        netrc_texts: vec![("netrc".into(), "machine api.x.com login u password sekrit".into())],
        executor: exec,
    })
    .unwrap();
    let socket = daemon.socket_path().to_path_buf();
    assert!(matches!(get(&socket, "/zen").unwrap(), WireResponse::Response { .. }));

    // Revoke the grant, SIGHUP, expect the flip.
    write_grant(grants.path(), "[[machine]]\nname = \"api.x.com\"\n");
    daemon.request_reload();
    assert!(daemon.wait_reload_processed(std::time::Duration::from_secs(5)));
    // The accept loop processes the reload on its next tick.
    std::thread::sleep(std::time::Duration::from_millis(100));
    let resp = get(&socket, "/zen").unwrap();
    assert_eq!(err_code(&resp), ErrorCode::NotAllowed);
}

#[test]
fn refused_machine_does_not_take_down_the_rest() {
    let profiles = tempfile::tempdir().unwrap();
    let grants = tempfile::tempdir().unwrap();
    // Two machines in the profile; one has an internal conflict
    // (auth declared twice in the SAME file — always a mistake).
    std::fs::write(
        profiles.path().join("m.toml"),
        "[[machine]]\nname = \"good.com\"\nauth = \"bearer\"\n[[machine]]\nname = \"bad.com\"\nauth = \"bearer\"\n",
    )
    .unwrap();
    // Conflict for bad.com comes from a second file.
    std::fs::write(
        profiles.path().join("n.toml"),
        "[[machine]]\nname = \"bad.com\"\nauth = \"basic\"\n",
    )
    .unwrap();
    std::fs::write(
        grants.path().join("m.toml"),
        "[[machine]]\nname = \"good.com\"\n[[machine.allow]]\nmethod = \"GET\"\nurl = '/x'\n",
    )
    .unwrap();
    let exec = Arc::new(StubExecutor::default());
    let daemon = Daemon::start(DaemonConfig {
        socket: grants.path().join("netrcd.sock"),
        profiles_dir: profiles.path().to_path_buf(),
        grants_dir: grants.path().to_path_buf(),
        netrc_texts: vec![(
            "netrc".into(),
            "machine good.com login u password p1\nmachine bad.com login v password p2".into(),
        )],
        executor: exec,
    })
    .unwrap();
    let socket = daemon.socket_path();
    // good.com serves.
    let resp = netrcd::exec::request_over_socket(
        socket,
        &WireRequest {
            op: "request".into(),
            machine: "good.com".into(),
            method: "GET".into(),
            url: "/x".into(),
            headers: Default::default(),
            body: None,
        },
    )
    .unwrap();
    assert!(matches!(resp, WireResponse::Response { .. }));
}

#[test]
fn malformed_frame_is_a_typed_error_not_a_crash() {
    let exec = Arc::new(StubExecutor::default());
    let (_f, _d) = setup(
        "[[machine]]\nname = \"api.x.com\"\n[[machine.allow]]\nmethod = \"GET\"\nurl = '/zen'\n",
        exec,
    );
    let mut stream = std::os::unix::net::UnixStream::connect(&_f.dir).unwrap();
    use std::io::Write as _;
    stream.write_all(b"this is not json\n").unwrap();
    let mut line = String::new();
    use std::io::BufRead as _;
    std::io::BufReader::new(stream).read_line(&mut line).unwrap();
    let resp: WireResponse = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(err_code(&resp), ErrorCode::BadRequest);
}

#[test]
fn pony_method_over_the_wire_is_rejected_with_vocabulary() {
    let exec = Arc::new(StubExecutor::default());
    let (_f, _d) = setup(
        "[[machine]]\nname = \"api.x.com\"\n[[machine.allow]]\nmethod = \"GET\"\nurl = '/zen'\n",
        exec,
    );
    let resp = frame(&_f.dir, "pony", "/zen", None).unwrap();
    assert_eq!(err_code(&resp), ErrorCode::BadRequest);
    match resp {
        WireResponse::Error { detail, .. } => assert!(detail.contains("GET") && detail.contains('*'), "{detail}"),
        _ => unreachable!(),
    }
}

#[test]
fn unknown_machine_and_no_credentials_are_typed() {
    let exec = Arc::new(StubExecutor::default());
    let profiles = tempfile::tempdir().unwrap();
    let grants = tempfile::tempdir().unwrap();
    std::fs::write(
        profiles.path().join("m.toml"),
        "[[machine]]\nname = \"configured.com\"\nauth = \"bearer\"\n",
    )
    .unwrap();
    let daemon = Daemon::start(DaemonConfig {
        socket: grants.path().join("netrcd.sock"),
        profiles_dir: profiles.path().to_path_buf(),
        grants_dir: grants.path().to_path_buf(),
        // no netrc for configured.com at all
        netrc_texts: vec![("netrc".into(), "machine other.com login u password p".into())],
        executor: exec,
    })
    .unwrap();
    let socket = daemon.socket_path();
    let resp = netrcd::exec::request_over_socket(
        socket,
        &WireRequest {
            op: "request".into(),
            machine: "nowhere.com".into(),
            method: "GET".into(),
            url: "/x".into(),
            headers: Default::default(),
            body: None,
        },
    )
    .unwrap();
    assert_eq!(err_code(&resp), ErrorCode::UnknownMachine);

    let resp = netrcd::exec::request_over_socket(
        socket,
        &WireRequest {
            op: "request".into(),
            machine: "configured.com".into(),
            method: "GET".into(),
            url: "/x".into(),
            headers: Default::default(),
            body: None,
        },
    )
    .unwrap();
    assert_eq!(err_code(&resp), ErrorCode::NoCredentials);
}

#[test]
fn oversized_frame_closes_with_typed_error() {
    let exec = Arc::new(StubExecutor::default());
    let (_f, _d) = setup(
        "[[machine]]\nname = \"api.x.com\"\nmax_req = \"1 MiB\"\n[[machine.allow]]\nmethod = \"POST\"\nurl = '/.*'\n",
        exec,
    );
    // A body far beyond max_req — refused before it could ever be sent.
    let resp = frame(&_f.dir, "POST", "/x", Some(&"x".repeat(2 << 20))).unwrap();
    assert_eq!(err_code(&resp), ErrorCode::TooLarge);
}

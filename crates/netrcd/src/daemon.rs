//! The daemon: a unix socket (0666 — connect(2) needs write
//! permission), one JSON line per connection, `SIGHUP` reloads the
//! policy atomically. Channel access is deliberately unconditional:
//! authorization happens per request, in the policy.

use std::io::{BufRead as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::engine::{adjudicate, RateState};
use crate::exec::{ExecError, Executor};
use crate::loader::{load_runtime, Level, Runtime};
use crate::wire::{self, ErrorCode, WireRequest, WireResponse};

/// Set by the OS signal handler; consumed by the daemon that owns
/// the signal (the first started in this process — normally the only
/// one). Instance-level reload requests are separate, so coexisting
/// daemons (tests) never steal each other's signals.
static SIGNAL_RELOAD: AtomicBool = AtomicBool::new(false);
static SIGNAL_REGISTERED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sighup(_sig: libc::c_int) {
    SIGNAL_RELOAD.store(true, Ordering::SeqCst);
}

pub struct DaemonConfig {
    pub socket: PathBuf,
    pub profiles_dir: PathBuf,
    pub grants_dir: PathBuf,
    /// (display-name, text) pairs — read by the caller so it can feed
    /// fuse-mounted one-read files without the daemon racing mounts.
    pub netrc_texts: Vec<(String, String)>,
    pub executor: Arc<dyn Executor>,
}

struct Shared {
    runtime: Mutex<Arc<Runtime>>,
    rates: Mutex<RateState>,
    executor: Arc<dyn Executor>,
}

pub struct Daemon {
    socket: PathBuf,
    running: Arc<AtomicBool>,
    reload: Arc<AtomicBool>,
    accept_thread: Option<std::thread::JoinHandle<()>>,
}

impl Daemon {
    /// Bind the socket (stealing any stale file left by a crashed
    /// predecessor), open it to every client, and start serving.
    pub fn start(cfg: DaemonConfig) -> std::io::Result<Daemon> {
        if let Some(parent) = cfg.socket.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(&cfg.socket);
        let listener = UnixListener::bind(&cfg.socket)?;
        // connect(2) needs WRITE permission on the socket file; the
        // umask would otherwise leave clients out in the cold.
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = std::fs::metadata(&cfg.socket)?.permissions();
            perms.set_mode(0o666);
            std::fs::set_permissions(&cfg.socket, perms)?;
        }
        listener.set_nonblocking(true)?;

        let (runtime, diagnostics) = reload_from(&cfg);
        log_diagnostics(&diagnostics);

        let shared = Arc::new(Shared {
            runtime: Mutex::new(Arc::new(runtime)),
            rates: Mutex::new(RateState::default()),
            executor: cfg.executor,
        });
        let running = Arc::new(AtomicBool::new(true));
        let reload = Arc::new(AtomicBool::new(false));
        let signal_owner = !SIGNAL_REGISTERED.swap(true, Ordering::SeqCst);
        unsafe {
            libc::signal(libc::SIGHUP, on_sighup as *const () as usize);
        }

        let thread_cfg = ThreadCfg {
            profiles: cfg.profiles_dir,
            grants: cfg.grants_dir,
            netrc_texts: Arc::new(cfg.netrc_texts),
            reload: Arc::clone(&reload),
            signal_owner,
        };

        let accept_running = Arc::clone(&running);
        let accept_shared = Arc::clone(&shared);
        let handle = std::thread::spawn(move || {
            accept_loop(listener, thread_cfg, accept_shared, accept_running);
        });

        Ok(Daemon {
            socket: cfg.socket,
            running,
            reload,
            accept_thread: Some(handle),
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    /// Ask for a policy reload on the next loop tick (what SIGHUP
    /// does process-wide, but scoped to THIS daemon).
    pub fn request_reload(&self) {
        self.reload.store(true, Ordering::SeqCst);
    }

    /// Wait until a pending reload has been picked up (bounded).
    pub fn wait_reload_processed(&self, deadline: Duration) -> bool {
        let start = std::time::Instant::now();
        while self.reload.load(Ordering::SeqCst) {
            if start.elapsed() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
        // Leave the socket file in place: a bind-mounted FILE pins the
        // inode, so containers must mount the DIRECTORY — removing the
        // file would only orphan their view. The next start() steals
        // the path anyway.
    }
}

struct ThreadCfg {
    profiles: PathBuf,
    grants: PathBuf,
    netrc_texts: Arc<Vec<(String, String)>>,
    reload: Arc<AtomicBool>,
    signal_owner: bool,
}

fn reload_from(cfg: &DaemonConfig) -> (Runtime, Vec<crate::loader::Diagnostic>) {
    let rt = load_runtime(&cfg.profiles_dir, &cfg.grants_dir, &cfg.netrc_texts);
    let diagnostics = rt.diagnostics.clone();
    (rt, diagnostics)
}

fn log_diagnostics(diagnostics: &[crate::loader::Diagnostic]) {
    for d in diagnostics {
        match d.level {
            Level::Warn => tracing::warn!("{}", d.msg),
            Level::Error => tracing::error!("{}", d.msg),
        }
    }
}

fn accept_loop(
    listener: UnixListener,
    cfg: ThreadCfg,
    shared: Arc<Shared>,
    running: Arc<AtomicBool>,
) {
    while running.load(Ordering::SeqCst) {
        let want_reload = cfg.reload.swap(false, Ordering::SeqCst)
            || (cfg.signal_owner && SIGNAL_RELOAD.swap(false, Ordering::SeqCst));
        if want_reload {
            let rt = load_runtime(&cfg.profiles, &cfg.grants, &cfg.netrc_texts);
            log_diagnostics(&rt.diagnostics);
            // Atomic swap: in-flight requests finish under the old rules.
            *shared.runtime.lock().unwrap() = Arc::new(rt);
            tracing::info!("policy reloaded");
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || handle_conn(stream, shared));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                tracing::error!("accept: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Read one line, capped. `None` = the line exceeded the cap (caller
/// answers BadRequest and closes); `Some("")`-ish at EOF closes
/// quietly. Never allocates past `cap + buffer chunk`.
fn read_capped_line(stream: &UnixStream, cap: usize) -> std::io::Result<Option<String>> {
    let mut reader = std::io::BufReader::new(stream.try_clone()?);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break; // EOF
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let take = newline.map(|i| i + 1).unwrap_or(available.len());
        if buf.len() + take > cap {
            return Ok(None);
        }
        buf.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            break;
        }
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// One connection: read one capped line, validate, adjudicate,
/// execute, answer. Malformed or oversized input closes the
/// connection — a hostile client can only lose its own request.
fn handle_conn(stream: UnixStream, shared: Arc<Shared>) {
    let mut stream = stream;
    if stream.set_read_timeout(Some(Duration::from_secs(10))).is_err() {
        return;
    }
    let line = match read_capped_line(&stream, wire::WIRE_MAX) {
        Ok(Some(l)) => l,
        Ok(None) => {
            let _ = writeln!(
                stream,
                "{}",
                serde_json::to_string(&WireResponse::error(
                    ErrorCode::BadRequest,
                    format!("frame exceeds {} bytes — connection closed", wire::WIRE_MAX),
                ))
                .unwrap_or_default()
            );
            return;
        }
        Err(_) => return,
    };
    let response = match serde_json::from_str::<WireRequest>(line.trim_end()) {
        Err(e) => WireResponse::error(ErrorCode::BadRequest, format!("malformed frame: {e}")),
        Ok(frame) => serve(&shared, &frame),
    };
    let _ = stream.write_all(
        format!("{}\n", serde_json::to_string(&response).unwrap_or_default()).as_bytes(),
    );
    let _ = stream.flush();
}

fn serve(shared: &Shared, frame: &WireRequest) -> WireResponse {
    let request = match wire::validate(frame) {
        Err(resp) => return resp,
        Ok(r) => r,
    };
    let runtime = Arc::clone(&shared.runtime.lock().unwrap());
    let mut rates = shared.rates.lock().unwrap();
    match adjudicate(&runtime, &mut rates, &request) {
        crate::engine::Verdict::Deny(code, detail) => WireResponse::error(code, detail),
        crate::engine::Verdict::Allow(out) => {
            match shared.executor.execute(&out) {
                Ok(up) => WireResponse::Response {
                    status: up.status,
                    headers: up
                        .headers
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    body: String::from_utf8_lossy(&up.body).into_owned(),
                    truncated: up.truncated,
                },
                Err(e) => match e {
                    ExecError::PinMismatch => WireResponse::error(
                        ErrorCode::PinMismatch,
                        "TLS pin mismatch — possible MITM, or a site CA rotation; refusing",
                    ),
                    ExecError::Tls(d) => WireResponse::error(ErrorCode::UpstreamTls, d),
                    ExecError::Io(d) => WireResponse::error(ErrorCode::Upstream, d),
                },
            }
        }
    }
}

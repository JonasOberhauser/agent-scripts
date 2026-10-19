//! End-to-end test: `run-agent` as a naive user on a pristine machine —
//! the project was just downloaded and built, podman runs on pure distro
//! defaults, and no container/TTY magic exists beyond what run-agent
//! itself does.
//!
//! Guards issue #1 (Crash on startup depending on podman config): with
//! distro-default podman short-name resolution and no TTY on stdin,
//! container creation must not die an opaque death:
//!
//! ```text
//! Failed to create container: exit 125
//! stderr: Error: short-name resolution enforced but cannot prompt without a TTY
//! ```
//!
//! Isolation for the machine running the tests (must not change podman's
//! default behavior — a naive user configures nothing):
//! * `HOME`/`XDG_*` → temp (no user-level overrides or alias cache)
//! * `CONTAINERS_STORAGE_CONF` → temp graphroot/runroot (zero local images)
//! * `FUSE_GATEKEEPER_STATE` → temp (live state file not clobbered)
//! * socket and FUSE mount point → temp
//!
//! Requires a real `podman`, `/dev/fuse` (like `fuse-server`'s `fuse_e2e`),
//! and a built `fuse-server` binary.  Missing requirements FAIL the tests
//! (a vacuous pass would hide real-system regressions) — except network
//! egress, which only the fully-qualified control test needs:
//!
//! ```sh
//! cargo build -p fuse-server
//! cargo test -p run-agent --test e2e_empty_os -- --nocapture
//! ```
//!
//! To run inside a container, it must be started with device and mount
//! capabilities, e.g.:
//!
//! ```sh
//! podman run --device /dev/fuse --cap-add SYS_ADMIN ...
//! ```
// Tests may hand-parse output/protocol lines: sanctioned by policy
// (test + allow), NOT available to production code. unknown_lints:
// the custom_parser lint exists only under the servyi driver.
#![allow(unknown_lints)]
#![allow(custom_parser, inline_literal)]

#![allow(clippy::unwrap_used, clippy::panic, unused_results)]

use std::io::Write as _;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ── bounded commands (triage for the CI hang of #120) ──────────
//
// The #52-contract e2e tier is the FIRST CI exercise of reading the
// bind-mounted FUSE fs from inside a rootless container — the first
// run hung there for 23 minutes, ate the step's 25-minute budget,
// and (because libtest prints failure output only at the END) also
// swallowed the sibling test's panic text. A tier that can block on
// a container syscall must bound every blocking command: on expiry
// the command is killed and the harness FAILS IN SECONDS carrying
// whatever output the pipes still gave.

/// Poll pace while waiting for a bounded command.
const BOUNDED_POLL: Duration = Duration::from_millis(100);
/// Grace for draining a killed command's pipes: grandchildren
/// (conmon, container processes) may hold the write ends forever —
/// a full read would hang the harness again.
const BOUNDED_DRAIN_GRACE: Duration = Duration::from_secs(2);
/// Image builds pull base layers on CI (~3 minutes observed).
const BOUND_BUILD: Duration = Duration::from_secs(600);
/// A run-agent session: the other tests return within ~30 seconds.
const BOUND_RUN_AGENT: Duration = Duration::from_secs(120);
/// The safety bound for the pre-existing tests (unchanged behavior
/// in practice; the step budget is 1500s).
const BOUND_RUN_AGENT_SAFETY: Duration = Duration::from_secs(900);
/// podman queries and one-shot execs inside the container.
const BOUND_PODMAN_QUERY: Duration = Duration::from_secs(30);
const BOUND_PODMAN_START: Duration = Duration::from_secs(60);
const BOUND_PODMAN_EXEC: Duration = Duration::from_secs(60);

/// Run `cmd` to completion, but never longer than `limit`: on expiry
/// the child is killed and the test FAILS immediately with the
/// command's identity and whatever output was drained — the triage
/// shape (evidence in seconds instead of a job corpse in 25 minutes).
fn bounded_output(mut cmd: Command, limit: Duration, what: &str) -> std::process::Output {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {what}: {e}"));
    let deadline = Instant::now() + limit;
    loop {
        if let Some(_status) = child.try_wait().expect("poll bounded child") {
            return child.wait_with_output().expect("collect bounded output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(BOUNDED_POLL);
    }
    // Killed on expiry: drain the pipes with a grace (readers EOF on
    // their own when no survivor holds the write end) and fail with
    // the evidence.
    let out = drain_slot(child.stdout.take(), BOUNDED_DRAIN_GRACE);
    let err = drain_slot(child.stderr.take(), BOUNDED_DRAIN_GRACE);
    panic!(
        "TRIAGE: `{what}` exceeded {limit:?} and was killed \
         (the command never finished — see the captured output and \
         the run-agent session text in the assertion above it, if \
         any)\n--- killed stdout ---\n{}\n--- killed stderr ---\n{}",
        out.as_deref().unwrap_or("(pipe still held by a survivor)"),
        err.as_deref().unwrap_or("(pipe still held by a survivor)"),
    );
}

/// Read a killed child's pipe to EOF within `grace`, returning what
/// arrived. A survivor process (conmon, the container) may hold the
/// write end forever — `None` then, rather than a second hang.
fn drain_slot<R: std::io::Read + Send + 'static>(pipe: Option<R>, _grace: Duration) -> Option<String> {
    let mut file = pipe?;
    let slot = Arc::new(Mutex::new(None));
    let reader = {
        let slot = Arc::clone(&slot);
        std::thread::spawn(move || {
            let mut buf = String::new();
            let drained = file.read_to_string(&mut buf).is_ok();
            *slot.lock().expect("drain slot") = drained.then_some(buf);
        })
    };
    let deadline = Instant::now() + BOUNDED_DRAIN_GRACE;
    loop {
        if let Some(got) = slot.lock().expect("drain slot").take() {
            return Some(got);
        }
        if Instant::now() >= deadline || reader.is_finished() {
            return None;
        }
        std::thread::sleep(BOUNDED_POLL);
    }
}

// ── availability probes ────────────────────────────────────────

/// These suites drive real podman against the host's kernel. Inside a
/// toolbox that is NESTED rootless podman: no subordinate IDs of its
/// own (the toolbox image carries no /etc/subuid entry), while
/// `/run/user/<uid>` is shared with the host session — a nested run
/// poisons the host's podman runtime state until reboot. Refuse.
fn refuse_inside_toolbox() {
    if Path::new("/.toolboxenv").exists() {
        panic!(
            "refusing to run real-podman tests inside a toolbox: nested podman \
             is subid-less and shares /run/user with the host session, which \
             corrupts the host's podman runtime state until reboot"
        );
    }
}

fn podman_available() -> bool {
    Command::new("podman")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
}

fn find_fuse_server() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("FUSE_SERVER_BIN") {
        return Some(PathBuf::from(p));
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    [
        manifest.join("../../target/debug/fuse-server"),
        manifest.join("../../target/release/fuse-server"),
    ]
    .into_iter()
    .find(|c| c.exists())
}

fn registry_reachable() -> bool {
    use std::net::ToSocketAddrs;
    match ("quay.io", 443).to_socket_addrs() {
        Ok(mut addrs) => addrs
            .next()
            .is_some_and(|a| TcpStream::connect_timeout(&a, Duration::from_secs(3)).is_ok()),
        Err(_) => false,
    }
}

// ── "empty OS" harness ─────────────────────────────────────────

struct EmptyOs {
    /// Held only to keep the tempdir alive until `Drop`.
    _dir: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    xdg_runtime: PathBuf,
    socket: PathBuf,
    oracle_socket: PathBuf,
    policy_store: PathBuf,
    containers_conf: PathBuf,
    mount_point: PathBuf,
}

impl EmptyOs {
    fn new(tag: &str) -> EmptyOs {
        refuse_inside_toolbox();
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join(tag);
        let home = root.join("home");

        let containers_cfg = home.join(".config/containers");
        std::fs::create_dir_all(&containers_cfg).expect("create config dir");

        // Private XDG_RUNTIME_DIR: podman's pause/infra and libpod state
        // live there, and the login session's real podman shares it — an
        // unisolated run clobbers the host's pause state and poisons
        // every later `podman unshare` until reboot. 0700, as podman
        // demands of its runtime dir.
        let xdg_runtime = root.join("xdg-run");
        std::fs::create_dir_all(&xdg_runtime).expect("create xdg runtime dir");
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&xdg_runtime, std::fs::Permissions::from_mode(0o700))
                .expect("chmod xdg runtime dir");
        }

        // Isolated image store: a fresh machine has no local images (and the
        // developer running the test keeps their real store untouched).
        // No containers.conf/registries.conf are written: a naive user runs
        // on pure distro defaults, which is exactly what issue #1 depends on.
        let storage_conf = root.join("storage.conf");
        // Rootless builds on sessionless hosts (CI runners): crun's
        // sd-bus scope creation fails with "Interactive authentication
        // required" unless the cgroupfs manager is pinned — and the
        // harness overrides XDG_CONFIG_HOME, so a runner-global
        // containers.conf is INVISIBLE to the isolated stack. Pin the
        // config explicitly via CONTAINERS_CONF.
        let containers_conf = root.join("containers.conf");
        std::fs::write(
            &containers_conf,
            "[engine]\ncgroup_manager = \"cgroupfs\"\n",
        )
        .expect("write containers.conf");
        std::fs::write(
            &storage_conf,
            format!(
                "[storage]\ndriver = \"overlay\"\nrunroot = \"{}\"\ngraphroot = \"{}\"\n",
                root.join("runroot").display(),
                root.join("graphroot").display(),
            ),
        )
        .expect("write storage.conf");

        let mount_point = root.join("fuse-mnt");
        std::fs::create_dir_all(&mount_point).expect("create mount point");

        let socket = root.join("gatekeeper.sock");
        // Full per-test isolation (the field-reported collision: a
        // global default oracle rendezvous meant every spawned server
        // died as "Another server is running" whenever a live
        // gatekeeper held the default path). Oracle socket, MR5 grant
        // store, state file, sockets, mount: all inside the tempdir.
        let oracle_socket = root.join("oracle.sock");
        let policy_store = root.join("policy.json");
        EmptyOs {
            _dir: dir,
            root,
            home,
            xdg_runtime,
            socket,
            oracle_socket,
            policy_store,
            containers_conf,
            mount_point,
        }
    }

    /// Apply the empty-OS environment to a command (podman sees only this).
    fn env<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_CACHE_HOME", self.home.join(".cache"))
            .env("XDG_DATA_HOME", self.home.join(".local/share"))
            .env("XDG_RUNTIME_DIR", &self.xdg_runtime)
            .env("CONTAINERS_CONF", &self.containers_conf)
            .env("CONTAINERS_STORAGE_CONF", self.root.join("storage.conf"))
            .env(fuse_protocol::ENV_STATE_FILE, self.root.join("state.json"))
            .env(fuse_protocol::ENV_POLICY_FILE, &self.policy_store)
            .env("RUST_LOG", "error")
    }

    /// Run the real run-agent binary inside this empty OS, with no TTY on
    /// stdin — exactly how the orchestrator spawns it in production.
    /// `image=None` keeps the naive-user default (`agentbox`): a local-only
    /// image no registry can resolve, as in issue #1.
    fn run_agent(&self, image: Option<&str>, extra_args: &[&str]) -> std::process::Output {
        self.run_agent_within(BOUND_RUN_AGENT_SAFETY, image, extra_args)
    }

    /// run-agent with an explicit bound (the triage tier must fail in
    /// seconds, not eat the job's 25-minute budget).
    fn run_agent_within(
        &self,
        limit: Duration,
        image: Option<&str>,
        extra_args: &[&str],
    ) -> std::process::Output {
        let ws = self.root.join("ws");
        std::fs::create_dir_all(&ws).expect("create workspace");
        let fuse_server = find_fuse_server().expect("fuse-server binary");

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_run-agent"));
        self.env(&mut cmd)
            .args([
                "e2e-agent",
                "--runtime",
                "podman",
                "--memory",
                "512M",
                "--cpus",
                "1",
                "--fuse-server",
            ])
            .arg(&fuse_server)
            .arg("--socket")
            .arg(&self.socket)
            .arg("--oracle-socket")
            .arg(&self.oracle_socket)
            .arg("--mount-point")
            .arg(&self.mount_point);
        if let Some(img) = image {
            cmd.arg("--image").arg(img);
        }
        cmd.args(extra_args)
            .current_dir(&ws)
            .stdin(Stdio::null());
        bounded_output(cmd, limit, "run-agent e2e-agent session")
    }

    fn podman(&self, args: &[&str]) -> std::process::Output {
        let mut cmd = Command::new("podman");
        self.env(&mut cmd).args(args).stdin(Stdio::null());
        cmd.output().expect("spawn podman")
    }

    /// podman with an explicit bound — used by the #52 triage tier.
    fn podman_within(
        &self,
        limit: Duration,
        what: &str,
        args: &[&str],
    ) -> std::process::Output {
        let mut cmd = Command::new("podman");
        self.env(&mut cmd).args(args).stdin(Stdio::null());
        bounded_output(cmd, limit, what)
    }
}

impl Drop for EmptyOs {
    fn drop(&mut self) {
        // Best effort: release the FUSE mount and socket held by the
        // independently-spawned fuse-server daemon before the tempdir goes.
        for bin in ["fusermount3", "fusermount"] {
            if Command::new(bin)
                .arg("-uz")
                .arg(&self.mount_point)
                .stdin(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
            {
                break;
            }
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Requirements are NOT skipped silently: a vacuous pass is worse than a
/// red test.  If the environment cannot run the real flow, fail loudly
/// with the exact remediation.
fn require_environment(test: &str) {
    let mut missing = Vec::new();
    if !podman_available() {
        missing.push("podman on PATH".to_string());
    }
    if !fuse_available() {
        missing.push(
            "/dev/fuse (mount-capable kernel access: containers must be started with \
             `--device /dev/fuse --cap-add SYS_ADMIN`)"
                .to_string(),
        );
    }
    if find_fuse_server().is_none() {
        missing.push("fuse-server binary (cargo build -p fuse-server, or set FUSE_SERVER_BIN)".to_string());
    }
    assert!(
        missing.is_empty(),
        "{test}: refusing to skip — environment lacks {}.\n\
         These tests exist to catch real-system regressions; silently passing \
         without exercising podman/FUSE would hide them.",
        missing.join("; ")
    );
}

fn output_text(out: &std::process::Output) -> String {
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    s
}

// ── naive user: short image name, no TTY (issue #1) ─────────────

#[test]
#[ignore = "needs real podman + /dev/fuse; run with --ignored on a capable host"]
fn e2e_short_image_name_survives_headless_on_empty_os() {
    require_environment("e2e_short_image_name_survives_headless_on_empty_os");
    let os = EmptyOs::new("repro");

    // No --image: the naive user keeps the default `agentbox`, which no
    // registry can resolve — exactly the reporter's invocation.
    let out = os.run_agent(None, &[]);
    let text = output_text(&out);

    // Desired behavior, distro-agnostic: on a naive fresh install (distro
    // default podman config), a short image name and no TTY on stdin must
    // not kill run-agent with an opaque podman failure.  On distros whose
    // podman resolves short names interactively (e.g. Fedora defaults),
    // this is exactly the crash of issue #1 and the assert fails until
    // run-agent handles it.  On distros that resolve short names
    // non-interactively the crash cannot manifest and the assert passes.
    assert!(
        !text.contains("cannot prompt without a TTY"),
        "run-agent crashed headless on a short image name (issue #1):\n{text}"
    );
    assert!(
        out.status.success() || !text.contains("Failed to create container: exit 125"),
        "run-agent failed to create the container with a raw podman exit 125 \
         and no actionable diagnostic:\n{text}"
    );

    let _ = std::io::stderr().write_all(text.as_bytes());
}

// ── control: fully-qualified name, same empty OS ───────────────
//
// Isolates the variable: identical environment and flow, only the image
// reference is fully qualified.  Container creation must succeed (the
// later interactive exec still fails headless — run-agent is designed
// for TTY use — so the assertion is on creation, not overall exit).

#[test]
#[ignore = "needs real podman + /dev/fuse; run with --ignored on a capable host"]
fn e2e_fully_qualified_image_creates_container_on_empty_os() {
    require_environment("e2e_fully_qualified_image_creates_container_on_empty_os");
    assert!(
        registry_reachable(),
        "e2e_fully_qualified_image_creates_container_on_empty_os: refusing to skip — \
         cannot reach quay.io:443; the control test must pull a fully-qualified \
         image to be meaningful"
    );
    let os = EmptyOs::new("control");

    // Since the missing-image fix, run-agent refuses to create a container
    // for an absent image — pre-pull so this test exercises the
    // image-present creation path.
    let pull = os.podman(&["pull", "quay.io/libpod/alpine:latest"]);
    assert!(
        pull.status.success(),
        "pre-pull failed:\n{}{}",
        String::from_utf8_lossy(&pull.stdout),
        String::from_utf8_lossy(&pull.stderr),
    );

    let out = os.run_agent(Some("quay.io/libpod/alpine:latest"), &[]);
    let text = output_text(&out);

    let ps = os.podman(&["ps", "-a", "--format", "{{.Names}}"]);
    let names = String::from_utf8_lossy(&ps.stdout).into_owned();
    let created = names
        .lines()
        .any(|l| l.trim_start_matches('\'').trim_end_matches('\'').starts_with("agentbox-"));

    let _ = os.podman(&["rm", "-f", "--all"]);

    assert!(
        created,
        "fully-qualified image was not created; run-agent output:\n{text}\npodman ps -a:\n{names}"
    );
}

// ── --yes auto-build: passes only on real success ──────────────
//
// No timeout short-circuit: the embedded Dockerfile must be built, the
// agentbox image must exist in the isolated store afterwards, and the
// container must have been created.

#[test]
#[ignore = "needs real podman + /dev/fuse; run with --ignored on a capable host"]
fn e2e_auto_build_creates_image_and_container() {
    require_environment("e2e_auto_build_creates_image_and_container");
    assert!(
        registry_reachable(),
        "refusing to skip: building the embedded Dockerfile pulls ubuntu:24.04"
    );
    let os = EmptyOs::new("autobuild");

    let out = os.run_agent(None, &["--yes"]);
    let text = output_text(&out);

    let probe = os.podman(&["image", "exists", "agentbox"]);
    assert!(
        probe.status.success(),
        "auto-build did not produce the agentbox image; run-agent output:\n{text}"
    );

    let ps = os.podman(&["ps", "-a", "--format", "{{.Names}}"]);
    let names = String::from_utf8_lossy(&ps.stdout).into_owned();
    let _ = os.podman(&["rm", "-f", "--all"]);
    assert!(
        names.lines().any(|l| l.trim_start_matches('\'').starts_with("agentbox-")),
        "container was not created; run-agent output:\n{text}\npodman ps -a:\n{names}"
    );
}


// ── issue #51: the TERM sweep actually TERMs container processes ──
//
// Behavioral counterpart of the argv-ordering mock tests: a process
// inside the container traps SIGTERM and drops a marker into /root —
// the named `{agent}_home` volume, which survives the rm/recreate of
// --restart-container.  Only the sweep TERMs non-init processes
// directly (`podman stop` signals pid 1; the trap lives in a child
// started via `exec -d`), so the marker on the volume after a restart
// proves the sweep reached it BEFORE the stop/rm, on a real /proc.
#[test]
#[ignore = "needs real podman + /dev/fuse; run with --ignored on a capable host"]
fn e2e_restart_terms_trapped_container_processes() {
    require_environment("e2e_restart_terms_trapped_container_processes");
    assert!(
        registry_reachable(),
        "e2e_restart_terms_trapped_container_processes: refusing to skip —          cannot reach quay.io:443 to pull the alpine control image"
    );
    let os = EmptyOs::new("termsweep");

    // run-agent hardcodes --workdir /workspace (no such dir in
    // debian-slim) and a `sleep infinity` container command (GNU
    // coreutils only — busybox sleep rejects 'infinity', see the
    // logs in this test's CI history).  One layer on debian-slim
    // fixes both.
    let df = os.root.join("Dockerfile");
    std::fs::write(&df, "FROM docker.io/library/debian:bookworm-slim\nRUN mkdir -p /workspace\n")
        .expect("write Dockerfile");
    let image = "localhost/termsweep-test:latest";
    let build = os.podman(&[
        "build", "-t", image, "-f", &df.to_string_lossy(), &os.root.to_string_lossy(),
    ]);
    assert!(build.status.success(), "image build failed: {}", {
        let mut t = String::from_utf8_lossy(&build.stdout).into_owned();
        t.push_str(&String::from_utf8_lossy(&build.stderr));
        t
    });

    // Session 1: create the persistent container.  The headless exec
    // afterwards fails by design (run-agent is a TTY tool), and the
    // session-end teardown stops the container — start it back up: the
    // victim must be alive IN it for the sweep to find it.
    let session1 = os.run_agent(Some(image), &[]);
    let session1_text = output_text(&session1);

    let named = os.podman(&["ps", "-a", "--format", "{{.Names}}|{{.State}}|{{.Status}}"]);
    let ps_text = String::from_utf8_lossy(&named.stdout).into_owned();
    let container = ps_text
        .lines()
        .next()
        .and_then(|l| l.split('|').next())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("no container after session 1:\nps:\n{ps_text}\nsession:\n{session1_text}"));
    let start = os.podman(&["start", &container]);
    assert!(
        start.status.success(),
        "precondition: could not start {container}: {}{}",
        String::from_utf8_lossy(&start.stdout),
        String::from_utf8_lossy(&start.stderr),
    );

    // Diagnostics when the container refuses to stay up: the whole
    // point of this test is a REAL /proc inside a running container.
    let running = os.podman_within(
        BOUND_PODMAN_QUERY,
        "podman ps (must_start)",
        &["ps", "--format", "{{.Names}}"],
    );
    let is_up = String::from_utf8_lossy(&running.stdout)
        .lines()
        .any(|l| l.trim() == container);
    if !is_up {
        let inspect = os.podman(&[
            "inspect", "--format",
            "state={{.State.State}} exit={{.State.ExitCode}} err={{.State.Error}}",
            &container,
        ]);
        let logs = os.podman(&["logs", &container]);
        panic!(
            "container {container} is not RUNNING after `podman start` — the TERM \
             sweep test needs a live /proc.\nps -a:\n{ps_text}\ninspect: {}{}\nlogs: \
             {}{}\nsession 1 output:\n{session1_text}",
            String::from_utf8_lossy(&inspect.stdout),
            String::from_utf8_lossy(&inspect.stderr),
            String::from_utf8_lossy(&logs.stdout),
            String::from_utf8_lossy(&logs.stderr),
        );
    }

    // The victim: a non-init process that marks on TERM.
    let exec = os.podman(&[
        "exec", "-d", &container, "sh", "-c",
        "trap 'touch /root/termed' TERM; sleep 9999",
    ]);
    assert!(
        exec.status.success(),
        "spawning the trapped victim failed: {}{}",
        String::from_utf8_lossy(&exec.stdout),
        String::from_utf8_lossy(&exec.stderr),
    );

    // Session 2: --restart-container runs gentle_stop (the /proc sweep)
    // BEFORE stop/rm; the volume-backed marker must survive into the
    // recreated container.  Session-end stops that one too — start it
    // before probing.
    let _ = os.run_agent(Some(image), &["--restart-container"]);
    let _ = os.podman(&["start", &container]);

    let marker = os.podman(&["exec", &container, "test", "-f", "/root/termed"]);
    let probe_text = {
        let mut t = String::from_utf8_lossy(&marker.stdout).into_owned();
        t.push_str(&String::from_utf8_lossy(&marker.stderr));
        t
    };
    assert!(
        marker.status.success(),
        "the trapped process never saw SIGTERM — the TERM sweep did not reach          non-init container processes on a real /proc (issue #51).\n{probe_text}"
    );
}


// ── issue #52: the container contract, observed FROM INSIDE ──────
//
// The unit tier asserts flag PRESENCE (-v /fuse, seccomp=…, --pid
// host); the properties those flags exist to produce were verified
// nowhere.  These read /fuse, exercise namespaces, and inspect /proc
// from inside a real container on a real stack.

fn build_workspace_image(os: &EmptyOs, tag: &str) {
    // run-agent hardcodes --workdir /workspace and a `sleep infinity`
    // container command (GNU coreutils): one layer on debian-slim.
    let df = os.root.join("Dockerfile");
    std::fs::write(
        &df,
        "FROM docker.io/library/debian:bookworm-slim\nRUN mkdir -p /workspace\n",
    )
    .expect("write Dockerfile");
    let build = os.podman_within(
        BOUND_BUILD,
        "podman build (workspace image)",
        &["build", "-t", tag, "-f", &df.to_string_lossy(), &os.root.to_string_lossy()],
    );
    assert!(
        build.status.success(),
        "image build failed: {}{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr),
    );
}

fn sole_container(os: &EmptyOs) -> String {
    let named = os.podman_within(
        BOUND_PODMAN_QUERY,
        "podman ps -a (sole container)",
        &["ps", "-a", "--format", "{{.Names}}"],
    );
    String::from_utf8_lossy(&named.stdout)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
        .expect("a container must exist")
}

fn must_start(os: &EmptyOs, container: &str) {
    let running = os.podman(&["ps", "--format", "{{.Names}}"]);
    let is_up = String::from_utf8_lossy(&running.stdout)
        .lines()
        .any(|l| l.trim() == container);
    if !is_up {
        let start = os.podman_within(
            BOUND_PODMAN_START,
            "podman start (must_start)",
            &["start", container],
        );
        assert!(
            start.status.success(),
            "could not start {container}: {}{}",
            String::from_utf8_lossy(&start.stdout),
            String::from_utf8_lossy(&start.stderr),
        );
    }
}

/// A secret's BYTES reach a reader inside the container through /fuse,
/// and the shipped seccomp profile still admits namespace syscalls
/// (`unshare -Ur true` — what nested rootless podman needs).
#[test]
#[ignore = "needs real podman + /dev/fuse; run with --ignored on a capable host"]
fn e2e_container_reads_secret_bytes_from_fuse() {
    require_environment("e2e_container_reads_secret_bytes_from_fuse");
    let os = EmptyOs::new("fusecontract");
    let image = "localhost/fuse-contract:latest";
    build_workspace_image(&os, image);

    let secret_path = os.home.join("secret.json");
    let secret_bytes = br#"{"token":"the-e2e-contract-bytes"}"#;
    std::fs::write(&secret_path, secret_bytes).expect("write secret");

    // Wildcard hash (the kit's own tier uses it): every reader is
    // permitted — the point here is the /fuse reachability contract,
    // not the approval flow.
    //
    // The trailing `/bin/true` is the session COMMAND: after setup,
    // run-agent exec's INTERACTIVELY into the container (that session
    // IS the product), and a headless harness must hand it a command
    // that terminates. Without it the exec'd bash sits at its prompt
    // on a pty forever — the `-t` allocation never forwards our
    // null-stdin EOF — which is exactly how this test hung its first
    // CI run for 25 minutes (the triage capture showed the prompt).
    let out = os.run_agent_within(
        BOUND_RUN_AGENT,
        Some(image),
        &[
            "--secret",
            &secret_path.to_string_lossy(),
            "/root/secret.json",
            "--hash",
            "*",
            "/bin/true",
        ],
    );
    let text = output_text(&out);

    let container = sole_container(&os);
    must_start(&os, &container);

    // The container-side name is the INNER name the server reported
    // (issue #47) — read it from the state file, not our own argv.
    let state_bytes = std::fs::read(os.root.join("state.json"))
        .unwrap_or_else(|e| panic!("state file unreadable ({e}); session:\n{text}"));
    let state: serde_json::Value =
        serde_json::from_slice(&state_bytes).expect("state file parses");
    let fuse_name = state["secrets"][0]["fuse_name"]
        .as_str()
        .expect("state file records the inner fuse_name")
        .to_string();

    let cat = os.podman_within(
        BOUND_PODMAN_EXEC,
        "podman exec cat /fuse/<inner-name> — the #52 reachability contract",
        &["exec", &container, "cat", &format!("/fuse/{fuse_name}")],
    );
    assert!(
        cat.status.success(),
        "cat /fuse/{fuse_name} failed: {}{}\nsession:\n{text}",
        String::from_utf8_lossy(&cat.stdout),
        String::from_utf8_lossy(&cat.stderr),
    );
    assert_eq!(
        cat.stdout,
        secret_bytes.to_vec(),
        "bytes through /fuse must be the host secret's, exactly"
    );

    let unshare = os.podman_within(
        BOUND_PODMAN_EXEC,
        "podman exec unshare -Ur true — seccomp namespace admission",
        &["exec", &container, "unshare", "-Ur", "true"],
    );
    assert!(
        unshare.status.success(),
        "the shipped seccomp profile denies namespace syscalls \
         (unshare -Ur true): {}{}",
        String::from_utf8_lossy(&unshare.stdout),
        String::from_utf8_lossy(&unshare.stderr),
    );
}

/// --pidns-host's observable contract: /proc inside the container is
/// the HOST pid namespace — pid 1 is the host's init, not the
/// container's `sleep`.  Probed via `/proc/1/comm`, which is
/// world-readable: `/proc/1/exe` is gated by ptrace-may-access, and
/// the host's init runs as REAL root while the rootless container's
/// root is the mapped unprivileged user — pid 1 is *visible* but its
/// exe is *not resolvable* from inside (empty `readlink` output, a
/// /proc permission property, not a broken --pidns-host).  The
/// run-agent use case reads the exe of SAME-uid agent processes, to
/// which the gate does not apply.
#[test]
#[ignore = "needs real podman + /dev/fuse; run with --ignored on a capable host"]
fn e2e_pidns_host_shows_the_host_proc() {
    require_environment("e2e_pidns_host_shows_the_host_proc");
    let os = EmptyOs::new("pidnshost");
    let image = "localhost/fuse-pidns:latest";
    build_workspace_image(&os, image);

    // Trailing session command (see e2e_container_reads: the
    // interactive exec IS the product; headless tests must give it a
    // terminating command instead of relying on podman's no-command
    // error path).
    let out = os.run_agent_within(BOUND_RUN_AGENT, Some(image), &["--pidns-host", "/bin/true"]);
    let text = output_text(&out);

    let container = sole_container(&os);
    must_start(&os, &container);

    let comm = os.podman_within(
        BOUND_PODMAN_EXEC,
        "podman exec cat /proc/1/comm — the --pidns-host observable",
        &["exec", &container, "cat", "/proc/1/comm"],
    );
    let pid1 = String::from_utf8_lossy(&comm.stdout).trim().to_string();
    assert!(
        comm.status.success() && !pid1.is_empty(),
        "/proc/1/comm must be readable inside a --pidns-host container: \
         {pid1:?}\n{}\nsession:\n{text}",
        String::from_utf8_lossy(&comm.stderr),
    );
    assert_ne!(
        pid1, "sleep",
        "pid 1 inside the container is the container's own sleep — this is \
         a PRIVATE pidns, not --pidns-host (comm: {pid1})"
    );
}

// ── bounded_output self-tests (no podman needed; guard the guard) ──

/// A fast command runs to completion through the bounded path.
#[test]
fn bounded_output_returns_a_fast_command() {
    let mut probe = Command::new("echo");
    probe.arg("probe");
    let out = bounded_output(probe, BOUND_PODMAN_QUERY, "echo probe");
    assert!(out.status.success(), "echo must succeed");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "probe\n");
}

/// A stuck command is killed at the deadline and FAILS with the
/// TRIAGE marker — the 25-minute job corpse of #120's first CI run
/// becomes a seconds-fast failure carrying the marker and whatever
/// output drained.
#[test]
#[should_panic(expected = "TRIAGE: `sleep probe` exceeded")]
fn bounded_output_kills_a_stuck_command() {
    let mut cmd = Command::new("sleep");
    cmd.arg("60");
    bounded_output(cmd, Duration::from_secs(1), "sleep probe");
}

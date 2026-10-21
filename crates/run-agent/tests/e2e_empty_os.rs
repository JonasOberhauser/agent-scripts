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
use std::time::Duration;

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



    /// The shared run-agent invocation: argv, environment, cwd. The
    /// session POLICY (stdin shape, wall bound, diagnostics) is the
    /// caller's choice — review on #124: one builder, no duplication.
    fn base_run_agent_command(
        &self,
        image: Option<&str>,
        extra_args: &[&str],
    ) -> Command {
        let ws = self.root.join("ws");
        std::fs::create_dir_all(&ws).expect("create workspace");
        let fuse_server = find_fuse_server().expect("fuse-server binary");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_run-agent"));
        self.env(&mut cmd)
            .args(["e2e-agent", "--runtime", "podman", "--memory", "512M", "--cpus", "1", "--fuse-server"])
            .arg(&fuse_server)
            .arg("--socket").arg(&self.socket)
            .arg("--oracle-socket").arg(&self.oracle_socket)
            .arg("--mount-point").arg(&self.mount_point);
        if let Some(img) = image {
            cmd.arg("--image").arg(img);
        }
        cmd.args(extra_args).current_dir(&ws);
        cmd
    }

    /// Unbounded legacy shape: null stdin, wait for exit (the original
    /// `run_agent`; kept for callers that assert on the raw Output).
    fn run_agent(&self, image: Option<&str>, extra_args: &[&str]) -> std::process::Output {
        self.base_run_agent_command(image, extra_args)
            .stdin(Stdio::null())
            .output()
            .expect("spawn run-agent")
    }

    /// Session-shaped run: stdin is a pipe fed `exit\n` after the
    /// grace (the harness's user leaves the shell), a hard wall bound
    /// fails with stall diagnostics instead of eating the CI step
    /// (ps tree, podman ps, the state file), and the combined
    /// stdout+stderr text is the return.
    fn run_session(&self, image: Option<&str>, extra_args: &[&str], what: &str) -> String {
        let mut cmd = self.base_run_agent_command(image, extra_args);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn run-agent");
        {
            let feed = child.stdin.take().expect("stdin");
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(25));
                use std::io::Write;
                let mut feed = feed;
                let _ = feed.write_all(b"exit\n");
                let _ = feed.flush();
            });
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(150);
        loop {
            if let Some(_status) = child.try_wait().expect("try wait") {
                let mut out = child.stdout.take().expect("stdout");
                let mut err = child.stderr.take().expect("stderr");
                let mut o = String::new();
                let mut e = String::new();
                use std::io::Read;
                out.read_to_string(&mut o).expect("read stdout");
                err.read_to_string(&mut e).expect("read stderr");
                return format!("{o}{e}");
            }
            if std::time::Instant::now() >= deadline {
                let ps = std::process::Command::new("ps")
                    .args(["-eo", "pid,ppid,stat,etime,args", "--forest"])
                    .output()
                    .expect("ps");
                panic!(
                    "{what}: run-agent still running after 150s — stall diagnostics:\n\
                     process tree:\n{}\npodman ps -a:\n{}\nstate file:\n{}\n",
                    String::from_utf8_lossy(&ps.stdout),
                    String::from_utf8_lossy(
                        &self.podman(&["ps", "-a", "--format", "{{.Names}}|{{.State}}|{{.Status}}"]).stdout
                    ),
                    std::fs::read_to_string(self.root.join("state.json"))
                        .unwrap_or_else(|_| "(unreadable)".into()),
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn podman(&self, args: &[&str]) -> std::process::Output {
        let mut cmd = Command::new("podman");
        self.env(&mut cmd)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("spawn podman")
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
    let running = os.podman(&["ps", "--format", "{{.Names}}"]);
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
    let build = os.podman(&[
        "build", "-t", tag, "-f", &df.to_string_lossy(), &os.root.to_string_lossy(),
    ]);
    assert!(
        build.status.success(),
        "image build failed: {}{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr),
    );
}

fn sole_container(os: &EmptyOs) -> String {
    let named = os.podman(&["ps", "-a", "--format", "{{.Names}}"]);
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
        let start = os.podman(&["start", container]);
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
    let out = os.run_agent(
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

    let cat = os.podman(&["exec", &container, "cat", &format!("/fuse/{fuse_name}")]);
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

    let unshare = os.podman(&["exec", &container, "unshare", "-Ur", "true"]);
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
    let out = os.run_agent(Some(image), &["--pidns-host", "/bin/true"]);
    let text = output_text(&out);

    let container = sole_container(&os);
    must_start(&os, &container);

    let comm = os.podman(&["exec", &container, "cat", "/proc/1/comm"]);
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



/// Issue #53: `stopped_container_is_started_not_recreated` matches argv
/// tokens; the behavior those tokens stand for is that DATA and the
/// /fuse binds survive a session boundary — a re-run must START the
/// same container (named volume keeps the marker) and the secret must
/// still read through /fuse afterwards.
#[test]
#[ignore = "needs real podman + /dev/fuse; run with --ignored on a capable host"]
fn e2e_rerun_starts_the_same_container_and_fuse_still_reads() {
    require_environment("e2e_rerun_starts_the_same_container_and_fuse_still_reads");
    let os = EmptyOs::new("rerun");
    let image = "localhost/fuse-rerun:latest";
    build_workspace_image(&os, image);

    let secret_path = os.home.join("secret.json");
    let secret_bytes = br#"{"token":"survives-the-rerun"}"#;
    std::fs::write(&secret_path, secret_bytes).expect("write secret");

    // Session 1: full stack + secret.
    let first = os.run_session(Some(image),
        &[
            "--secret",
            &secret_path.to_string_lossy(),
            "/root/secret.json",
            "--hash",
            "*",
        ],
        "session 1",
    );
    let text1 = first;
    let _ = std::io::stderr().write_all(text1.as_bytes());
    let container = sole_container(&os);
    must_start(&os, &container);

    // The state file pins the session-1 identity; capture it to prove
    // the SAME container (not a recreate) serves session 2.
    let state1: serde_json::Value = serde_json::from_slice(
        &std::fs::read(os.root.join("state.json"))
            .unwrap_or_else(|e| panic!("state file after session 1: {e}; session:\n{text1}")),
    )
    .expect("state parses");

    // Plant a marker in the agent-home named volume.
    let mark = os.podman(&["exec", &container, "touch", "/root/data-marker"]);
    assert!(
        mark.status.success(),
        "planting the marker failed: {}{}",
        String::from_utf8_lossy(&mark.stdout),
        String::from_utf8_lossy(&mark.stderr),
    );

    // Session 2: plain re-run against the existing stack.
    let second = os.run_session(Some(image), &[], "session 2");
    let text2 = second;
    let container2 = sole_container(&os);
    assert_eq!(
        container, container2,
        "a re-run must reuse the existing container, not recreate it"
    );
    must_start(&os, &container2);

    // The marker survived the session boundary (data preserved).
    let survived = os.podman(&["exec", &container, "test", "-f", "/root/data-marker"]);
    assert!(
        survived.status.success(),
        "the data marker did not survive the re-run — the container was \
         recreated (or the volume lost): {}{}\nsession 2:\n{text2}",
        String::from_utf8_lossy(&survived.stdout),
        String::from_utf8_lossy(&survived.stderr),
    );

    // And /fuse still serves the secret after the re-run.
    let state2: serde_json::Value = serde_json::from_slice(
        &std::fs::read(os.root.join("state.json"))
            .unwrap_or_else(|e| panic!("state file after session 2: {e}")),
    )
    .expect("state parses");
    let fuse_name = state2["secrets"][0]["fuse_name"]
        .as_str()
        .or_else(|| state1["secrets"][0]["fuse_name"].as_str())
        .expect("inner fuse_name")
        .to_string();
    let cat = os.podman(&["exec", &container, "cat", &format!("/fuse/{fuse_name}")]);
    assert!(
        cat.status.success(),
        "cat /fuse/{fuse_name} failed after the re-run: {}{}\nsession 2:\n{text2}",
        String::from_utf8_lossy(&cat.stdout),
        String::from_utf8_lossy(&cat.stderr),
    );
}


/// Issue #53, real-stack version: the /fuse probe is bounded in WALL
/// TIME. The unit tier fakes exit 124; the stub tier cannot host it
/// (its fake mount never passes the startup check for a path-shaped
/// secret — rounds 1-4 of the fault probe). Here the real stack's
/// startup check passes (real mount, real inner), and the container's
/// `stat` is a shim that sleeps far beyond the probe deadline: the
/// session must abort within the bound with the TIMEOUT diagnostic.
#[test]
#[ignore = "needs real podman + /dev/fuse; run with --ignored on a capable host"]
fn e2e_probe_is_bounded_in_wall_time_on_a_hung_stat() {
    require_environment("e2e_probe_is_bounded_in_wall_time_on_a_hung_stat");
    let os = EmptyOs::new("hungstat");
    // debian + /workspace + a sleeping `stat` (60s >> the 3s deadline
    // x4 retries).
    let df = os.root.join("Dockerfile");
    std::fs::write(
        &df,
        "FROM docker.io/library/debian:bookworm-slim\n\
         RUN mkdir -p /workspace \\\n\
         && printf '#!/bin/sh\\nsleep 60\\n' > /usr/local/bin/stat \\\n\
         && chmod +x /usr/local/bin/stat\n",
    )
    .expect("write Dockerfile");
    let image = "localhost/fuse-hungstat:latest";
    let build = os.podman(&[
        "build", "-t", image, "-f", &df.to_string_lossy(), &os.root.to_string_lossy(),
    ]);
    assert!(
        build.status.success(),
        "image build failed: {}{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr),
    );

    let secret_path = os.home.join("secret.json");
    std::fs::write(&secret_path, br#"{"t":"hung"}"#).expect("write secret");

    let started = std::time::Instant::now();
    let out = os.run_session(Some(image),
        &[
            "--secret",
            &secret_path.to_string_lossy(),
            "/root/secret.json",
            "--hash",
            "*",
        ],
        "hung-stat session",
    );
    let wall = started.elapsed();
    let _ = std::io::stderr().write_all(out.as_bytes());

    assert!(
        wall < Duration::from_secs(90),
        "the probe ran unbounded in wall time ({wall:?}) — a hung stat \
         must be cut off at the timeout deadline, not slept through:\n{out}"
    );
    // Bounded-abort diagnostics on the probe path: the preflight tier
    // ("did not answer a stat within") or the orchestrator's heal path
    // ("bind is stale and a stop/start did not heal" — which costs at
    // least two full bounded probe rounds).  The ENOENT startup escape
    // ("not visible in the FUSE mount") must stay excluded.
    assert!(
        out.contains("did not answer a stat within")
            || out.contains("bind is stale and a stop/start did not heal"),
        "a persistently hung mount must abort via a bounded probe path:\n{out}"
    );
}


/// Issue #54: run-agent's startup recovery against a GENUINELY dead
/// mount — SIGKILL the real `fused` between sessions; session 2 must
/// clear the leftover (the mock models it as ENOTCONN + EEXIST) and
/// bring a fresh stack that still serves the secret's bytes.
#[test]
#[ignore = "needs real podman + /dev/fuse; run with --ignored on a capable host"]
fn e2e_startup_recovery_after_a_killed_data_daemon() {
    require_environment("e2e_startup_recovery_after_a_killed_data_daemon");
    let os = EmptyOs::new("deadmount");
    let image = "localhost/fuse-deadmount:latest";
    build_workspace_image(&os, image);

    let secret_path = os.home.join("secret.json");
    let secret_bytes = br#"{"token":"survives-the-daemon-kill"}"#;
    std::fs::write(&secret_path, secret_bytes).expect("write secret");

    let text1 = os.run_session(
        Some(image),
        &[
            "--secret",
            &secret_path.to_string_lossy(),
            "/root/secret.json",
            "--hash",
            "*",
        ],
        "session 1",
    );
    let _ = std::io::stderr().write_all(text1.as_bytes());

    // Session 2 runs WITHOUT --secret: its state file records nothing
    // to re-add — the server's policy store is the persistence.  Pin
    // the inner name from SESSION 1's state.
    let state1: serde_json::Value = serde_json::from_slice(
        &std::fs::read(os.root.join("state.json"))
            .unwrap_or_else(|e| panic!("state file after session 1: {e}")),
    )
    .expect("state parses");
    let fuse_name = state1["secrets"][0]["fuse_name"]
        .as_str()
        .expect("inner fuse_name in session-1 state")
        .to_string();

    // Kill the data daemon hard: the kernel keeps the dead mount —
    // exactly the leftover state the mock models.
    let pat = format!("fused.*{}", regex_escape(&os.mount_point.to_string_lossy()));
    let pgrep = std::process::Command::new("pgrep")
        .arg("-f")
        .arg(&pat)
        .output()
        .expect("pgrep fused");
    let pids: Vec<String> = String::from_utf8_lossy(&pgrep.stdout)
        .split_whitespace()
        .map(str::to_string)
        .collect();
    assert!(
        !pids.is_empty(),
        "the data daemon must be running after session 1 (pattern {pat})"
    );
    for pid in &pids {
        let _ = std::process::Command::new("kill").arg("-9").arg(pid).status();
    }

    // Session 2 against the genuinely dead mount: recovery must run
    // (lazy unmount, fresh stack) and the secret must read again.
    let text2 = os.run_session(Some(image), &["/bin/true"], "session 2 (dead mount)");
    let _ = std::io::stderr().write_all(text2.as_bytes());

    let container = sole_container(&os);
    must_start(&os, &container);
    let cat = os.podman(&["exec", &container, "cat", &format!("/fuse/{fuse_name}")]);
    if !cat.status.success() {
        // Name the killer: is the HOST mount alive, is the data
        // daemon alive, what does the container's bind point at?
        let host_stat = std::fs::metadata(&os.mount_point);
        let fused = std::process::Command::new("pgrep")
            .args(["-af", "fused"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let inspect = os.podman(&[
            "inspect", "--format",
            "{{range .Mounts}}{{.Source}} -> {{.Destination}} ({{.Type}}){{println}}{{end}}",
            &container,
        ]);
        panic!(
            "cat /fuse/{fuse_name} failed after recovery: {}{}\n\
             host mount metadata: {host_stat:?}\nfused processes:\n{fused}\n\
             container mounts: {}{}\nsession 2:\n{text2}",
            String::from_utf8_lossy(&cat.stdout),
            String::from_utf8_lossy(&cat.stderr),
            String::from_utf8_lossy(&inspect.stdout),
            String::from_utf8_lossy(&inspect.stderr),
        );
    }
    assert_eq!(cat.stdout, secret_bytes.to_vec(), "bytes must survive the kill+recovery");
}

/// Escape regex metacharacters in a path for `pgrep -f` patterns.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if !c.is_ascii_alphanumeric() && c != '/' && c != '_' && c != '-' && c != '.' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

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

use std::io::Write as _;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

// ── availability probes ────────────────────────────────────────

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
    socket: PathBuf,
    mount_point: PathBuf,
}

impl EmptyOs {
    fn new(tag: &str) -> EmptyOs {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join(tag);
        let home = root.join("home");

        let containers_cfg = home.join(".config/containers");
        std::fs::create_dir_all(&containers_cfg).expect("create config dir");

        // Isolated image store: a fresh machine has no local images (and the
        // developer running the test keeps their real store untouched).
        // No containers.conf/registries.conf are written: a naive user runs
        // on pure distro defaults, which is exactly what issue #1 depends on.
        let storage_conf = root.join("storage.conf");
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
        EmptyOs {
            _dir: dir,
            root,
            home,
            socket,
            mount_point,
        }
    }

    /// Apply the empty-OS environment to a command (podman sees only this).
    fn env<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_CACHE_HOME", self.home.join(".cache"))
            .env("XDG_DATA_HOME", self.home.join(".local/share"))
            .env("CONTAINERS_STORAGE_CONF", self.root.join("storage.conf"))
            .env("FUSE_GATEKEEPER_STATE", self.root.join("state.json"))
            .env("RUST_LOG", "error")
    }

    /// Run the real run-agent binary inside this empty OS, with no TTY on
    /// stdin — exactly how the orchestrator spawns it in production.
    /// `image=None` keeps the naive-user default (`agentbox`): a local-only
    /// image no registry can resolve, as in issue #1.
    fn run_agent(&self, image: Option<&str>, extra_args: &[&str]) -> std::process::Output {
        let ws = self.root.join("ws");
        std::fs::create_dir_all(&ws).expect("create workspace");
        let fuse_server = find_fuse_server().expect("fuse-server binary");

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_run-agent"));
        self.env(&mut cmd)
            .args([
                "*",
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
            .arg("--mount-point")
            .arg(&self.mount_point);
        if let Some(img) = image {
            cmd.arg("--image").arg(img);
        }
        cmd.args(extra_args)
            .current_dir(&ws)
            .stdin(Stdio::null())
            .output()
            .expect("spawn run-agent")
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
        !(!out.status.success() && text.contains("Failed to create container: exit 125")),
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

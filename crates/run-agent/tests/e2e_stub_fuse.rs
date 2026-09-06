//! Seam E2E: the real `run-agent` binary runs its complete orchestration
//! (workspace dirs → fuse-server spawn → socket wait → state file →
//! runtime probe → `inspect` → `run`) against the REAL podman, with only
//! one seam stubbed — and it is run-agent's own plugin point, not a fake
//! of an external system:
//!
//! * `--fuse-server` points at a tiny C stub compiled at test time (a C
//!   compiler is always present where this workspace builds).  With zero
//!   secrets run-agent performs no protocol round-trip against a freshly
//!   spawned server — it only waits for the socket to accept connections.
//!
//! * podman is real, isolated to a temp HOME/store (naive-user defaults,
//!   zero local images — nothing on the test machine is touched).  This
//!   sandbox cannot hold images or start containers (no user namespaces),
//!   which is exactly the empty-OS condition of issue #1: `podman run`
//!   with the local-only default image `agentbox` fails with the
//!   config-dependent exit 125.
//!
//! No `/dev/fuse`, no fake binaries — runs anywhere with podman, and
//! MUST NOT skip.
//!
//! `missing_default_image_fails_fast_before_podman_run` is the issue-#1
//! regression test: it encodes the DESIRED behavior (probe
//! `podman image exists`; on miss, fail with build instructions BEFORE
//! invoking headless `podman run`) and therefore FAILS on the current
//! code, as AGENTS.md requires.  The image-present scenario cannot be
//! instantiated where the runtime cannot hold images; it is covered by
//! `e2e_empty_os` (control test, real machines) and the `MockSystemIo`
//! unit tests of the orchestrator.
//!
//! ```sh
//! cargo test -p run-agent --test e2e_stub_fuse -- --nocapture
//! ```

use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ── stub fuse-server (compiled at test time) ────────────────────

const STUB_C: &str = r#"
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv) {
    const char *path = NULL;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--socket") && i + 1 < argc)
            path = argv[i + 1];
    if (!path) { fprintf(stderr, "stub: --socket required\n"); return 2; }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    unlink(path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 3;
    if (listen(fd, 16) < 0) return 4;
    fcntl(fd, F_SETFL, O_NONBLOCK);

    /* Accept and hold the socket for up to 60s so no detached stub
     * outlives the test session. */
    for (int t = 0; t < 600; t++) {
        int c = accept(fd, NULL, NULL);
        if (c >= 0) close(c);
        usleep(100000);
    }
    return 0;
}
"#;

fn compile_stub_fuse_server(dir: &Path) -> PathBuf {
    let src = dir.join("stub-fuse-server.c");
    std::fs::write(&src, STUB_C).expect("write stub source");
    let bin = dir.join("stub-fuse-server");
    let cc = ["cc", "gcc"]
        .into_iter()
        .find(|c| Command::new(c).arg("--version").output().is_ok())
        .unwrap_or_else(|| panic!("refusing to skip: no C compiler found for the fuse stub"));
    let out = Command::new(cc)
        .arg("-O2")
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        .output()
        .expect("compile stub fuse-server");
    assert!(
        out.status.success(),
        "stub compilation failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    bin
}

// ── shared runner ───────────────────────────────────────────────

struct RunOutcome {
    code: Option<i32>,
    /// stdout + stderr: tracing logs go to stdout, podman output is
    /// embedded in the error message — assertions must see both.
    combined: String,
}

/// The seam harness: temp workspace/socket/mount/state, compiled fuse
/// stub, and an isolated naive-user podman environment (real podman,
/// zero local images, distro-default config — nothing global touched).
struct Seam {
    ws: PathBuf,
    fuse_server: PathBuf,
    socket: PathBuf,
    mount_point: PathBuf,
    state: PathBuf,
    home: PathBuf,
    storage_conf: PathBuf,
}

impl Seam {
    fn new(dir: &tempfile::TempDir, tag: &str) -> Seam {
        let root = dir.path().join(tag);
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).expect("create ws");
        let mount_point = root.join("mnt");
        std::fs::create_dir_all(&mount_point).expect("create mount point");
        let home = root.join("home");
        std::fs::create_dir_all(home.join(".config/containers")).expect("create home");
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
        Seam {
            fuse_server: compile_stub_fuse_server(dir.path()),
            ws,
            socket: root.join("socket"),
            mount_point,
            state: root.join("state.json"),
            home,
            storage_conf,
        }
    }

    fn podman(&self, args: &[&str]) -> std::process::Output {
        let mut cmd = Command::new("podman");
        cmd.env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_CACHE_HOME", self.home.join(".cache"))
            .env("XDG_DATA_HOME", self.home.join(".local/share"))
            .env("CONTAINERS_STORAGE_CONF", &self.storage_conf)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("spawn podman")
    }

    fn run(
        &self,
        image: Option<&str>,
        timeout_secs: u64,
    ) -> RunOutcome {
        self.run_with(image, timeout_secs, &[], None)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_with(
        &self,
        image: Option<&str>,
        timeout_secs: u64,
        extra_args: &[&str],
        dockerfile_override: Option<&Path>,
    ) -> RunOutcome {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_run-agent"));
        cmd.args([
            "*",
            "seam",
            "--runtime",
            "podman",
            "--memory",
            "512M",
            "--cpus",
            "1",
        ])
        .arg("--fuse-server")
        .arg(&self.fuse_server)
        .arg("--socket")
        .arg(&self.socket)
        .arg("--mount-point")
        .arg(&self.mount_point)
        .env("HOME", &self.home)
        .env("XDG_CONFIG_HOME", self.home.join(".config"))
        .env("XDG_CACHE_HOME", self.home.join(".cache"))
        .env("XDG_DATA_HOME", self.home.join(".local/share"))
        .env("CONTAINERS_STORAGE_CONF", &self.storage_conf)
        .env("FUSE_GATEKEEPER_STATE", &self.state)
        .env("RUST_LOG", "error")
        .current_dir(&self.ws)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        if let Some(img) = image {
            cmd.arg("--image").arg(img);
        }
        cmd.args(extra_args);
        if let Some(df) = dockerfile_override {
            cmd.env("RUN_AGENT_TEST_DOCKERFILE", df);
        }
        let mut child = cmd.spawn().expect("spawn run-agent");

        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        let status = loop {
            if let Some(s) = child.try_wait().expect("try_wait") {
                break s;
            }
            assert!(
                Instant::now() < deadline,
                "run-agent did not terminate within {timeout_secs}s"
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        let mut out = String::new();
        let mut err = String::new();
        if let Some(mut s) = child.stdout.take() {
            s.read_to_string(&mut out).expect("read stdout");
        }
        if let Some(mut s) = child.stderr.take() {
            s.read_to_string(&mut err).expect("read stderr");
        }
        RunOutcome {
            code: status.code(),
            combined: format!("{out}{err}"),
        }
    }
}

// ── tests ───────────────────────────────────────────────────────

#[test]
fn missing_default_image_fails_fast_before_podman_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let seam = Seam::new(&dir, "missing");

    // No --image: faithful to issue #1 — the naive user runs with the
    // local-only default image `agentbox`, which no registry resolves.
    let out = seam.run(None, 60);

    // ── DESIRED behavior (this test FAILS until the fix lands) ──
    // A missing image must never be delegated to headless `podman run`
    // (which crashes with the config-dependent exit 125 of issue #1);
    // run-agent must fail fast, before `run`, with actionable remediation.
    assert!(out.code != Some(0), "run-agent unexpectedly succeeded");
    assert!(
        out.combined.contains("agentbox") && out.combined.contains("podman build"),
        "error must name the missing image and how to build it:\n{}",
        out.combined
    );
    assert!(
        !out.combined.contains("Failed to create container"),
        "a missing image must fail before podman run is invoked:\n{}",
        out.combined
    );

    // The state file is written before container handling either way.
    let state_text = std::fs::read_to_string(&seam.state).unwrap_or_default();
    assert!(
        state_text.contains("\"version\""),
        "state file missing or malformed: {state_text}"
    );
    let _ = std::io::stderr().write_all(out.combined.as_bytes());
}

#[test]
fn fully_qualified_missing_image_handled_diagnosably() {
    assert!(
        Command::new("podman")
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        "refusing to skip: this test needs a real podman on PATH"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let seam = Seam::new(&dir, "real");

    // Fully-qualified but absent from the empty store: podman attempts a
    // real pull (network) before failing.  Valid both before the fix
    // (creation failure surfaced verbatim) and after it (fail-fast with a
    // pull hint) — the contract is: a real, diagnosable podman outcome,
    // never a silent or opaque one.
    let out = seam.run(Some("quay.io/libpod/alpine:latest"), 300);

    assert!(
        out.code != Some(0),
        "run-agent unexpectedly created a container: {}",
        out.combined
    );
    assert!(
        out.combined.contains("Failed to create container")
            || out.combined.contains("Failed to start container")
            || (out.combined.contains("alpine") && out.combined.contains("podman pull")),
        "podman outcome not surfaced diagnosably:\n{}",
        out.combined
    );
    let _ = std::io::stderr().write_all(out.combined.as_bytes());
}

// ── --yes with a trivial image: fast, real build ───────────────
//
// Substitutes a `FROM scratch` Dockerfile via the debug-only
// RUN_AGENT_TEST_DOCKERFILE seam: the build is instant and needs no
// network, so the full accept-remedial-action path (build → re-probe →
// container creation) runs for real in seconds.  Creation outcome
// depends on the machine: on restricted runtimes it fails diagnosably
// ("Failed to create container"), on capable ones the container exists.

#[test]
fn auto_yes_builds_trivial_image_and_reaches_creation() {
    assert!(
        Command::new("podman")
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        "refusing to skip: this test needs a real podman on PATH"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let dockerfile = dir.path().join("trivial.Dockerfile");
    std::fs::write(&dockerfile, "FROM scratch\nCMD [\"true\"]\n").expect("write trivial Dockerfile");
    let seam = Seam::new(&dir, "trivial");

    let out = seam.run_with(None, 120, &["--yes"], Some(&dockerfile));
    let _ = std::io::stderr().write_all(out.combined.as_bytes());

    // The trivial image must now exist in the isolated store.
    let probe = seam.podman(&["image", "exists", "agentbox"]);
    assert!(
        probe.status.success(),
        "auto-build did not produce the agentbox image:\n{}",
        out.combined
    );

    // And the flow must have reached container creation (any outcome).
    assert!(
        out.combined.contains("Failed to create container")
            || out.combined.contains("Creating persistent container")
            || out.combined.contains("Container created"),
        "flow did not reach creation:\n{}",
        out.combined
    );
}

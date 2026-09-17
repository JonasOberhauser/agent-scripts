//! Pre-flight checks for every hosted secret, run after the secrets are
//! loaded into the FUSE server and **before** exec'ing into the container.
//!
//! The failure mode this prevents: a stale or dead FUSE mount (server
//! restarted, mount left behind, propagation to the container broken).
//! Reads inside the container then block forever — nobody answers the FUSE
//! request — and the agentbox hangs with no diagnostic.  These checks
//! convert that into a fast, actionable error before the session starts.
//!
//! Per secret we verify:
//! 1. `source-file` — the host-side source file still exists.
//! 2. `fuse-mount`  — the FUSE mount answers a `stat` of the hosted file
//!    within a bounded time (run via `timeout(1)` so a dead mount cannot
//!    wedge the orchestrator itself).

use std::fmt;
use std::path::Path;

use fuse_protocol::SystemIo;

/// How long the FUSE mount may take to answer a `stat` before we declare
/// it dead.  A healthy local FUSE fs answers in microseconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 3;

/// A freshly spawned data daemon can take a moment to mount — adds land
/// through the socket instantly, the mount lags.  Before declaring an
/// exit-1 stat a hard failure, retry this often …  Bounded tightly: the
/// retry must never turn a broken stack into an apparent hang (PR #37
/// review), and a root that already lists OTHER names means the mount
/// is up and the name is genuinely missing — no retry can help.
const MOUNT_APPEAR_RETRIES: usize = 4;
/// … waiting this long between tries.
const MOUNT_APPEAR_WAIT_MS: u64 = 250;

/// Outcome of one check for one secret.
pub struct CheckResult {
    pub fuse_name: String,
    pub host_path: String,
    pub check: &'static str,
    pub ok: bool,
    pub detail: String,
}

impl fmt::Display for CheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] {} (source: {}): {}",
            if self.ok { "✓" } else { "✗" },
            self.fuse_name,
            self.check,
            self.host_path,
            self.detail
        )
    }
}

/// Run all checks for every loaded secret.
pub fn run<S: SystemIo>(
    io: &S,
    secrets: &[crate::orchestrator::LoadedSecret],
    mount_point: &Path,
    timeout_secs: u64,
) -> Vec<CheckResult> {
    let mut out = Vec::with_capacity(secrets.len() * 2);
    for s in secrets {
        out.push(check_source(io, s));
        out.push(check_mount(io, s, mount_point, timeout_secs));
    }
    out
}

/// The host-side source file must still exist — the FUSE server reads it
/// on demand, and a missing source surfaces inside the box as a confusing
/// EIO instead of a clear error.
fn check_source<S: SystemIo>(io: &S, s: &crate::orchestrator::LoadedSecret) -> CheckResult {
    let ok = io.file_exists(&s.host_path);
    CheckResult {
        fuse_name: s.fuse_name.clone(),
        host_path: s.host_path.display().to_string(),
        check: "source-file",
        ok,
        detail: if ok {
            "exists".into()
        } else {
            format!(
                "source file {} no longer exists on the host — moved, deleted, or unreadable",
                s.host_path.display()
            )
        },
    }
}

/// The FUSE mount must answer a `stat` of the hosted file within a bounded
/// time.  The stat runs under `timeout(1)`: a dead mount never answers, and
/// without the watchdog the orchestrator would hang exactly like the box.
///
/// `stat` exit code 1 covers three distinct real-world failures
/// (observed in the wild on issue #23, PR #37):
///
/// - `No such file or directory` — name missing: server/mount out of sync
/// - `Transport endpoint is not connected` — dead mount answering
///   instantly; a dead mount only hangs (exit 124) when the daemon is
///   stuck alive
///
/// The failure detail therefore carries stat's stderr verbatim plus a
/// listing of the mount root, instead of guessing one cause.
fn check_mount<S: SystemIo>(
    io: &S,
    s: &crate::orchestrator::LoadedSecret,
    mount_point: &Path,
    timeout_secs: u64,
) -> CheckResult {
    let mount_side = mount_point.join(&s.fuse_name);
    let secs = timeout_secs.to_string();
    let mount_side_str = mount_side.display().to_string();

    let mut last_stderr;
    let mut attempts = 0usize;
    let (ok, detail) = loop {
        attempts += 1;
        let res = io.run_command(
            "timeout",
            &[&secs, "stat", "-c", "%s", &mount_side_str],
        );
        match &res {
            Ok(o) if o.success() => break (true, "mount answers".into()),
            Ok(o) if o.status == Some(124) => {
                break (
                    false,
                    format!(
                        "FUSE mount did not answer a stat within {timeout_secs}s — the container \
                         would HANG reading this file. The mount is stale or dead; unmount it \
                         (fusermount3 -u {} or sudo umount {}) and rerun",
                        mount_point.display(),
                        mount_point.display()
                    ),
                );
            }
            Ok(o) if o.status == Some(1) => {
                last_stderr = o.stderr.trim().to_string();
                let root = probe_mount_root(io, mount_point, timeout_secs);
                // Mount up and serving OTHER names?  The name is
                // genuinely missing — retrying cannot conjure it.
                if matches!(root, RootProbe::Entries(_))
                    || attempts >= MOUNT_APPEAR_RETRIES
                {
                    break (
                        false,
                        mount_one_failure_detail(&mount_side_str, &last_stderr, attempts, root),
                    );
                }
                // Empty or unreachable root: the mount may still be
                // coming up after a (re)spawn — retry briefly.
                io.sleep_ms(MOUNT_APPEAR_WAIT_MS);
                continue;
            }
            Ok(o) => {
                break (
                    false,
                    format!(
                        "probe failed unexpectedly: stat exited with {:?} (stderr: {})",
                        o.status, o.stderr
                    ),
                );
            }
            Err(e) => {
                break (
                    false,
                    format!("pre-flight could not run `timeout stat` ({e}) — is coreutils installed?"),
                );
            }
        }
    };

    CheckResult {
        fuse_name: s.fuse_name.clone(),
        host_path: s.host_path.display().to_string(),
        check: "fuse-mount",
        ok,
        detail,
    }
}

/// What a `timeout ls -a` of the mount root showed.
enum RootProbe {
    /// The mount is up and lists these entries beyond `.`/`..`.
    Entries(String),
    /// The mount answers but lists nothing — empty store (sync
    /// problem, or the data daemon is still starting).
    Empty,
    /// The root itself cannot be listed — dead or inaccessible mount.
    Failed(String),
}

fn probe_mount_root<S: SystemIo>(
    io: &S,
    mount_point: &Path,
    timeout_secs: u64,
) -> RootProbe {
    let secs = timeout_secs.to_string();
    let root_str = mount_point.display().to_string();
    match io.run_command("timeout", &[&secs, "ls", "-a", &root_str]) {
        Ok(o) if o.success() => {
            let names: Vec<&str> = o
                .stdout
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && *l != "." && *l != "..")
                .collect();
            if names.is_empty() {
                RootProbe::Empty
            } else {
                RootProbe::Entries(names.join(" "))
            }
        }
        Ok(o) => RootProbe::Failed(format!(
            "mount root itself failed (ls exit {:?}: {}) — dead or inaccessible mount",
            o.status,
            o.stderr.trim()
        )),
        Err(e) => RootProbe::Failed(format!("mount root could not be probed ({e})")),
    }
}

/// Human-readable detail for a persistent exit-1 stat: the actual stat
/// error plus what the mount root said — entries-but-not-ours points at
/// a sync/naming problem, an empty root at an empty store, a failing
/// root at a dead or inaccessible mount.
fn mount_one_failure_detail(
    mount_side: &str,
    stat_stderr: &str,
    attempts: usize,
    root: RootProbe,
) -> String {
    let root_part = match root {
        RootProbe::Entries(names) => format!("mount root lists: {names}"),
        RootProbe::Empty => "mount root lists NOTHING (empty store — sync problem or data daemon still starting)".into(),
        RootProbe::Failed(why) => why,
    };
    format!(
        "not visible in the FUSE mount at {mount_side} after {attempts} tries.\
         \nstat said: {stat_stderr}\n{root_part}"
    )
}

/// If any check failed, build the abort error listing every failure.
pub fn failure_summary(results: &[CheckResult]) -> Option<String> {
    let failures: Vec<&CheckResult> = results.iter().filter(|r| !r.ok).collect();
    if failures.is_empty() {
        return None;
    }
    let mut msg = format!(
        "pre-flight checks failed — aborting before container start ({} failure{}):\n",
        failures.len(),
        if failures.len() == 1 { "" } else { "s" }
    );
    for f in failures {
        msg.push_str(&format!("  {f}\n"));
    }
    msg.push_str("Resolve the above and rerun run-agent.");
    Some(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::LoadedSecret;
    use fuse_protocol::MockSystemIo;
    use std::path::PathBuf;

    fn secret(host: &str) -> LoadedSecret {
        LoadedSecret {
            fuse_name: "p100_s0".into(),
            container: PathBuf::from("/root/.config/app/auth.json"),
            host_path: PathBuf::from(host),
        }
    }

    fn mount_point() -> PathBuf {
        PathBuf::from("/tmp/fgk-mnt")
    }

    #[test]
    fn healthy_secret_all_checks_ok() {
        let mock = MockSystemIo::new().with_file("/host/auth.json", b"DATA");
        let loaded = vec![secret("/host/auth.json")];
        let results = run(&mock, &loaded, &mount_point(), DEFAULT_TIMEOUT_SECS);
        assert!(!results.is_empty());
        assert!(
            results.iter().all(|r| r.ok),
            "got: {results:?}",
            results = results.iter().map(|r| r.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn source_missing_fails() {
        let mock = MockSystemIo::new(); // no files at all
        let loaded = vec![secret("/gone/auth.json")];
        let results = run(&mock, &loaded, &mount_point(), DEFAULT_TIMEOUT_SECS);
        let src = results
            .iter()
            .find(|r| r.check == "source-file")
            .expect("source-file check must run");
        assert!(!src.ok, "got: {src}");
        assert!(
            src.detail.contains("/gone/auth.json"),
            "detail should name the path: {src}"
        );
    }

    #[test]
    fn mount_timeout_would_hang() {
        // `timeout` exit code 124 = the stat was killed for not answering.
        let mock = MockSystemIo::new()
            .with_file("/host/auth.json", b"DATA")
            .with_command_result("timeout", Some(124));
        let loaded = vec![secret("/host/auth.json")];
        let results = run(&mock, &loaded, &mount_point(), DEFAULT_TIMEOUT_SECS);
        let mnt = results
            .iter()
            .find(|r| r.check == "fuse-mount")
            .expect("fuse-mount check must run");
        assert!(!mnt.ok, "got: {mnt}");
        assert!(
            mnt.detail.to_lowercase().contains("hang"),
            "must warn about the hang: {mnt}"
        );
        assert!(
            mnt.detail.contains("fusermount"),
            "must point at the fix: {mnt}"
        );
    }

    #[test]
    fn mount_enoent_reports_out_of_sync() {
        // `stat` exit code 1 = path not visible in the mount.
        let mock = MockSystemIo::new()
            .with_file("/host/auth.json", b"DATA")
            .with_command_result("timeout", Some(1));
        let loaded = vec![secret("/host/auth.json")];
        let results = run(&mock, &loaded, &mount_point(), DEFAULT_TIMEOUT_SECS);
        let mnt = results
            .iter()
            .find(|r| r.check == "fuse-mount")
            .expect("fuse-mount check must run");
        assert!(!mnt.ok, "got: {mnt}");
        assert!(
            mnt.detail.contains("/tmp/fgk-mnt/p100_s0"),
            "should name the mount-side path: {mnt}"
        );
        assert!(
            mnt.detail.contains(&format!("after {MOUNT_APPEAR_RETRIES} tries")),
            "should have retried before failing: {mnt}"
        );
    }

    #[test]
    fn mount_exit1_carries_stat_stderr_and_dead_root() {
        // PR #37 field report: exit 1 must not be guessed at — the
        // detail carries stat's actual stderr (here: a DEAD mount
        // answering instantly) and the mount-root probe's outcome.
        let mock = MockSystemIo::new()
            .with_file("/host/auth.json", b"DATA")
            .with_command_stderr(
                "stat: cannot statx '/tmp/fgk-mnt/p100_s0': Transport endpoint is not connected",
            )
            // ls probe of the mount root: also fails (dead mount)
            .with_command_result_when("timeout", "/tmp/fgk-mnt", Some(1))
            // stat of the secret: persistent failure (added last = wins
            // on stat calls; the ls rule still applies to ls calls)
            .with_command_result_when_n("timeout", "p100_s0", Some(1), MOUNT_APPEAR_RETRIES);
        let loaded = vec![secret("/host/auth.json")];
        let results = run(&mock, &loaded, &mount_point(), DEFAULT_TIMEOUT_SECS);
        let mnt = results
            .iter()
            .find(|r| r.check == "fuse-mount")
            .expect("fuse-mount check must run");
        assert!(!mnt.ok, "got: {mnt}");
        assert!(
            mnt.detail.contains("Transport endpoint is not connected"),
            "must quote stat's stderr verbatim: {mnt}"
        );
        assert!(
            mnt.detail.contains("mount root itself failed"),
            "must report the mount-root probe: {mnt}"
        );
    }

    #[test]
    fn mount_exit1_lists_root_contents() {
        // The out-of-sync variant: the mount answers, the NAME is
        // missing — the detail shows what the root does list.
        let mock = MockSystemIo::new()
            .with_file("/host/auth.json", b"DATA")
            .with_command_stdout(".\n..\np9_s0_somebody_else")
            // ls of the root succeeds (default/0)
            .with_command_result_when("timeout", "/tmp/fgk-mnt", Some(0))
            // stat of the secret: persistent ENOENT
            .with_command_result_when_n("timeout", "p100_s0", Some(1), MOUNT_APPEAR_RETRIES);
        let loaded = vec![secret("/host/auth.json")];
        let results = run(&mock, &loaded, &mount_point(), DEFAULT_TIMEOUT_SECS);
        let mnt = results
            .iter()
            .find(|r| r.check == "fuse-mount")
            .expect("fuse-mount check must run");
        assert!(!mnt.ok, "got: {mnt}");
        assert!(
            mnt.detail.contains("mount root lists"),
            "must include the root listing: {mnt}"
        );
        assert!(
            mnt.detail.contains("p9_s0_somebody_else"),
            "the listing must show the actually-present names: {mnt}"
        );
    }

    #[test]
    fn populated_root_fails_fast_without_retries() {
        // Mount up and listing OTHER names: the missing name is a sync
        // problem — retrying (or rebuilding) cannot conjure it, so the
        // check must NOT burn the appear-retries (PR #37 review: the
        // waits made broken stacks feel like hangs).
        let mock = MockSystemIo::new()
            .with_file("/host/auth.json", b"DATA")
            .with_command_stdout("p9_s0_somebody_else")
            .with_command_result_when("timeout", "/tmp/fgk-mnt", Some(0))
            .with_command_result_when_n("timeout", "p100_s0", Some(1), MOUNT_APPEAR_RETRIES);
        let loaded = vec![secret("/host/auth.json")];
        let results = run(&mock, &loaded, &mount_point(), DEFAULT_TIMEOUT_SECS);
        let mnt = results
            .iter()
            .find(|r| r.check == "fuse-mount")
            .expect("fuse-mount check must run");
        assert!(!mnt.ok, "got: {mnt}");
        assert!(
            mnt.detail.contains("after 1 tries"),
            "must fail on the first try: {mnt}"
        );
        assert!(
            mock.sleeps.borrow().is_empty(),
            "no appear-retry waits may run when the mount already lists names"
        );
    }

    #[test]
    fn mount_appears_late_retries_then_ok() {
        // A fresh mount can lag behind the socket: retry instead of
        // declaring failure (the run-agent-level twin asserts no
        // rebuild happens).
        let mock = MockSystemIo::new()
            .with_file("/host/auth.json", b"DATA")
            .with_command_result_when_n("timeout", "p100_s0", Some(1), 2);
        let loaded = vec![secret("/host/auth.json")];
        let results = run(&mock, &loaded, &mount_point(), DEFAULT_TIMEOUT_SECS);
        let mnt = results
            .iter()
            .find(|r| r.check == "fuse-mount")
            .expect("fuse-mount check must run");
        assert!(mnt.ok, "got: {mnt}");
        assert_eq!(
            mock.sleeps.borrow().len(),
            2,
            "one wait per failed attempt before the successful one"
        );
    }

    #[test]
    fn probe_argv_uses_timeout_stat_and_mount_path() {
        // AGENTS.md: mocks must let tests assert the real argv.  The probe
        // MUST go through `timeout` — a direct stat on a dead mount would
        // wedge the orchestrator itself, recreating the bug we're fixing.
        let mock = MockSystemIo::new().with_file("/host/auth.json", b"DATA");
        let loaded = vec![secret("/host/auth.json")];
        run(&mock, &loaded, &mount_point(), 7);
        let calls = mock.command_calls.borrow();
        let probe = calls
            .iter()
            .find(|(prog, _)| prog == "timeout")
            .expect("probe must use `timeout`");
        assert!(
            probe.1.contains(&"stat".to_string()),
            "probe must stat, got: {probe:?}"
        );
        assert!(
            probe.1.contains(&"7".to_string()),
            "timeout value must be passed, got: {probe:?}"
        );
        assert!(
            probe.1.contains(&"/tmp/fgk-mnt/p100_s0".to_string()),
            "must stat the mount-side secret path, got: {probe:?}"
        );
    }

    #[test]
    fn failure_summary_lists_every_failure() {
        let mock = MockSystemIo::new()
            .with_file("/host/a.json", b"A")
            .with_file("/host/b.json", b"B")
            .with_command_result("timeout", Some(124));
        let loaded = vec![
            LoadedSecret {
                fuse_name: "p100_s0".into(),
                container: PathBuf::from("/root/a.json"),
                host_path: PathBuf::from("/host/a.json"),
            },
            LoadedSecret {
                fuse_name: "p100_s1".into(),
                container: PathBuf::from("/root/b.json"),
                host_path: PathBuf::from("/host/b.json"),
            },
        ];
        let results = run(&mock, &loaded, &mount_point(), DEFAULT_TIMEOUT_SECS);
        let summary =
            failure_summary(&results).expect("failures must produce a summary");
        assert!(
            summary.contains("p100_s0") && summary.contains("p100_s1"),
            "summary must list both secrets: {summary}"
        );
        assert!(
            summary.to_lowercase().contains("aborting"),
            "summary must say the session is aborted: {summary}"
        );
    }

    #[test]
    fn failure_summary_none_when_all_ok() {
        let mock = MockSystemIo::new().with_file("/host/auth.json", b"DATA");
        let loaded = vec![secret("/host/auth.json")];
        let results = run(&mock, &loaded, &mount_point(), DEFAULT_TIMEOUT_SECS);
        assert!(failure_summary(&results).is_none());
    }
}

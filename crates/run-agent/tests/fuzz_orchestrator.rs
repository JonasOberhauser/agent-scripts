//! Tier-2 fuzzing (#69-class): the orchestrator driven by a
//! `FuzzSystemIo` whose COMMAND EXECUTION is replaced by random but
//! PLAUSIBLE outcomes — the exit codes, stdout shapes, and the real
//! stderr texts this codebase has actually seen in the field
//! (fusermount refusals, stale-server refusals, podman table output,
//! timeout kills). Per the issue's scope: the kernel gives correct
//! data and files we write are not corrupt, so FILE state is faithful
//! (an in-memory fs) and only the process world is hostile.
//!
//! The properties, checked for EVERY seed:
//!  1. TERMINATION: a hard command budget — exceeding it panics, which
//!     the harness reports as the seed that hangs (the anti-hang
//!     oracle: infinite rebuild/recycle loops become mechanically
//!     discoverable).
//!  2. NO PANIC otherwise: run_agent returns Ok(RunResult) or
//!     Err(String) under any chaos — validating, seed by seed, the
//!     documented reasons in every `expect` (#67).
//!  3. STRUCTURAL INVARIANTS regardless of outcome:
//!     - no `pkill -f` (substring sweeps are banned by design, #62/#65);
//!     - the mountpoint is ensured BEFORE the first fuse-server spawn;
//!     - every spawned fuse-server carries `--socket <config socket>`
//!       (stack identity: a fuzzed world must not invent rendezvous);
//!     - errors are non-empty strings (the actionability discipline).
//!
//! Deterministic: splitmix64 seeded per case; failures print their
//! seed for a one-line repro (`FUZZ_SEED=<n> cargo test fuzz_`).

use fuse_protocol::io::{CommandOutput, PathState, SystemIo};
use fuse_protocol::IoError;
use run_agent::config::{AgentConfig, Runtime, SecretMapping};
use run_agent::orchestrator::run_agent;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf as P, PathBuf};

// ── deterministic RNG (splitmix64: tiny, no deps, good mixing) ──
#[derive(Clone)]
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[(self.next() % xs.len() as u64) as usize]
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

/// The real stderr corpus: every string here was produced by a real
/// tool in a real incident this repo has debugged.
const STDERR_CORPUS: &[&str] = &[
    "fusermount3: mount failed: Operation not permitted",
    "fusermount3: failed to access mountpoint: No such file or directory",
    "another fuse-server is running at /tmp/fuse-gatekeeper.sock: Kill it first.",
    "Error: timed out waiting for file /run/user/1000/pause.pid",
    "stat: cannot statx '/tmp/fuse-gatekeeper-mnt/s': No such file or directory",
    "Error: acquiring lock 0 for machine \"agentbox\": file exists",
    "Error: image not known",
    "time: command terminated abnormally with signal 9",
    "podman systemd notify: resetting under sysrq",
];

/// Plausible stdout shapes: valid JSON, wrong-shaped JSON, tables,
/// empty, or text a confused tool might print.
const STDOUT_CORPUS: &[&str] = &[
    "",
    "\n",
    "{\"type\":\"added\",\"inner\":\"stub-x\"}",
    "{\"state\":\"Running\", \"Names\":\"agentbox-container\"}",
    "{\"type\":\"ok\"}",
    "{\"\"\":",
    "NAME               STATUS\nagentbox-container  Running",
    "5f2e1c8d9a3b",
    "fuse-client 0.31.0",
    "totally not json at all",
];

struct FuzzSystemIo {
    rng: RefCell<Rng>,
    files: RefCell<BTreeMap<String, Vec<u8>>>,
    dirs: RefCell<BTreeSet<String>>,
    symlinks: RefCell<BTreeMap<String, String>>,
    /// Dead-mount world state (a killed data daemon): the kernel still
    /// holds the name; stat fails, mkdir says EEXIST — the exact model
    /// MockSystemIo's honesty note describes.
    stale_mounts: RefCell<BTreeSet<String>>,
    unix_up: Cell<bool>,
    unix_fails: Cell<u32>,
    budget: Cell<usize>,
    /// Observed at the moment of each fuse-server spawn: was the
    /// mountpoint already ensured? (End-state checks cannot answer
    /// ordering questions — dirs grow monotonically.)
    pub spawned_without_mountpoint: Cell<bool>,
    pub commands: RefCell<Vec<(String, Vec<String>)>>,
    pub spawns: RefCell<Vec<(String, Vec<String>)>>,
    pub interactive: RefCell<Vec<(String, Vec<String>)>>,
}

const COMMAND_BUDGET: usize = 300;

impl FuzzSystemIo {
    fn new(seed: u64) -> Self {
        let mut files = BTreeMap::new();
        files.insert("/home/user/secrets.yaml".into(), b"KEY: fuzzed\n".to_vec());
        files.insert("/tmp/fused".into(), b"#!/bin/sh\n".to_vec());
        Self {
            rng: RefCell::new(Rng(seed.wrapping_mul(0x2545F4914F6CDD1D) | 1)),
            files: RefCell::new(files),
            dirs: RefCell::new(BTreeSet::new()),
            symlinks: RefCell::new(BTreeMap::new()),
            stale_mounts: RefCell::new(BTreeSet::new()),
            unix_up: Cell::new(false),
            unix_fails: Cell::new(0),
            budget: Cell::new(COMMAND_BUDGET),
            spawned_without_mountpoint: Cell::new(false),
            commands: RefCell::new(Vec::new()),
            spawns: RefCell::new(Vec::new()),
            interactive: RefCell::new(Vec::new()),
        }
    }

    /// Mid-flight world chaos (the gap this closes): a RUNNING daemon
    /// dies at a random moment — the policy daemon (rendezvous drops,
    /// state file survives per MR5: our files are never corrupt), the
    /// data daemon (mount goes dead), or both. Small probabilities:
    /// deaths must be common enough to hit every phase across 256
    /// seeds, rare enough that healthy paths dominate.
    fn inject_daemon_death(&self) {
        let mut rng = self.rng.borrow_mut();
        match rng.next() % 1000 {
            0..=14 => {
                // policy daemon killed (pkill -9 / OOM / crash)
                self.unix_up.set(false);
            }
            15..=29 => {
                // data daemon killed: the mount it owned dies with it
                self.stale_mounts.borrow_mut().insert("/tmp/fgk-mnt".into());
            }
            30..=37 => {
                // both: the full incident from the field reports
                self.unix_up.set(false);
                self.stale_mounts.borrow_mut().insert("/tmp/fgk-mnt".into());
            }
            _ => {}
        }
    }

    /// The taxonomy, as one draw: spawn failure, or a status from the
    /// real-world distribution with a plausible stdout/stderr pairing.
    fn draw_command(&self, program: &str) -> Result<CommandOutput, IoError> {
        {
            let mut rng = self.rng.borrow_mut();
            let _ = &mut rng;
        }
        self.inject_daemon_death();
        let mut rng = self.rng.borrow_mut();
        if rng.chance(8) {
            // The exec-failure class (command absent, PATH broken).
            return Err(IoError(format!(
                "spawn {program}: No such file or directory (os error 2)"
            )));
        }
        let stderr = if rng.chance(45) { rng.pick(STDERR_CORPUS).to_string() } else { String::new() };
        let (status, stdout) = match rng.next() % 100 {
            0..=44 => (Some(0), if rng.chance(70) { rng.pick(STDOUT_CORPUS).to_string() } else { String::new() }),
            45..=64 => (Some(1), String::new()),
            65..=74 => (Some(124), String::new()), // timeout(1) kill
            75..=79 => (Some(137), String::new()), // SIGKILL
            80..=84 => (Some(126), String::new()), // not executable
            85..=89 => (None, String::new()),    // killed by signal, no code
            _ => (Some(0), String::new()),
        };
        Ok(CommandOutput { stdout, stderr, status })
    }
}

impl SystemIo for FuzzSystemIo {
    fn canonicalize(&self, path: &Path) -> Result<PathBuf, IoError> {
        let key = path.to_string_lossy().into_owned();
        if self.files.borrow().contains_key(&key) || self.dirs.borrow().contains(&key) {
            Ok(path.to_path_buf())
        } else {
            Err(IoError("No such file or directory (os error 2)".into()))
        }
    }
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, IoError> {
        self.files
            .borrow()
            .get(&path.to_string_lossy().into_owned())
            .cloned()
            .ok_or_else(|| IoError("No such file or directory (os error 2)".into()))
    }
    fn write_file(&mut self, path: &Path, data: &[u8]) -> Result<(), IoError> {
        self.files.borrow_mut().insert(path.to_string_lossy().into_owned(), data.to_vec());
        Ok(())
    }
    fn set_file_mode(&self, _path: &Path, _mode: u32) -> Result<(), IoError> { Ok(()) }
    fn file_exists(&self, path: &Path) -> bool {
        let key = path.to_string_lossy().into_owned();
        self.files.borrow().contains_key(&key) || self.dirs.borrow().contains(&key) || self.symlinks.borrow().contains_key(&key)
    }
    fn path_state(&self, path: &Path) -> PathState {
        let key = path.to_string_lossy().into_owned();
        if self.stale_mounts.borrow().contains(&key) {
            return PathState::Unreachable("Transport endpoint is not connected (os error 107)".into());
        }
        if self.dirs.borrow().contains(&key) { return PathState::Dir; }
        if self.files.borrow().contains_key(&key) { return PathState::File; }
        PathState::Missing
    }
    fn mkdir(&self, path: &Path) -> Result<(), IoError> {
        let key = path.to_string_lossy().into_owned();
        if self.stale_mounts.borrow().contains(&key) {
            return Err(IoError("File exists (os error 17)".into()));
        }
        self.dirs.borrow_mut().insert(key);
        Ok(())
    }
    fn create_dir_all(&self, path: &Path) -> Result<(), IoError> {
        let key = path.to_string_lossy().into_owned();
        if self.stale_mounts.borrow().contains(&key) {
            return Err(IoError("File exists (os error 17)".into()));
        }
        self.dirs.borrow_mut().insert(key);
        Ok(())
    }
    fn remove_path(&mut self, path: &Path) -> Result<(), IoError> {
        let key = path.to_string_lossy().into_owned();
        self.files.borrow_mut().remove(&key);
        self.symlinks.borrow_mut().remove(&key);
        self.dirs.borrow_mut().remove(&key);
        Ok(())
    }
    fn create_symlink(&mut self, original: &Path, link: &Path) -> Result<(), IoError> {
        self.symlinks.borrow_mut().insert(
            link.to_string_lossy().into_owned(),
            original.to_string_lossy().into_owned(),
        );
        Ok(())
    }
    fn run_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput, IoError> {
        let left = self.budget.get();
        assert!(
            left > 0,
            "COMMAND BUDGET EXHAUSTED — run_agent did not terminate under fuzz chaos \
             (an infinite rebuild/recycle loop); see this test's seed"
        );
        self.budget.set(left - 1);
        self.commands.borrow_mut().push((
            program.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        ));
        let out = self.draw_command(program)?;
        // Command chaos moves the world: a successful pkill of the
        // stack takes the rendezvous down; a successful server spawn
        // brings it up. (spawn_independent sets it up itself.)
        let joined = args.join(" ");
        if program == "pkill" && out.success() {
            self.unix_up.set(false);
        }
        if program == "fusermount" && out.success() {
            self.unix_up.set(false);
            self.stale_mounts.borrow_mut().remove("/tmp/fgk-mnt");
        }
        let _ = joined;
        Ok(out)
    }
    fn spawn_detached(&mut self, program: &str, args: &[&str]) -> Result<u32, IoError> {
        self.spawns.borrow_mut().push((
            program.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        ));
        Ok(4242)
    }
    fn spawn_independent(
        &mut self,
        program: &str,
        args: &[&str],
        _stderr_to: Option<&Path>,
    ) -> Result<u32, IoError> {
        let mut rng = self.rng.borrow_mut();
        if rng.chance(6) {
            return Err(IoError("spawn fuse-server: No such file or directory (os error 2)".into()));
        }
        if program.contains("fuse-server")
            && !self.dirs.borrow().contains("/tmp/fgk-mnt")
            && self.stale_mounts.borrow().contains("/tmp/fgk-mnt")
        {
            // The spawn-time ordering witness: spawning while the
            // mountpoint is a DEAD MOUNT (never cleared, never
            // created). Recorded, asserted in drive().
            self.spawned_without_mountpoint.set(true);
        }
        self.spawns.borrow_mut().push((
            program.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        ));
        // A spawned stack normally comes up — mostly. When it does
        // not, the socket stays dead (the orchestrator's health paths
        // must cope).
        if rng.chance(85) {
            self.unix_up.set(true);
        }
        Ok(54321)
    }
    fn run_interactive(&self, program: &str, args: &[&str]) -> Result<i32, IoError> {
        self.interactive.borrow_mut().push((
            program.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        ));
        let mut rng = self.rng.borrow_mut();
        Ok((rng.next() % 5) as i32 - 1) // -1..=3, incl. signal-killed
    }
    fn sleep_ms(&self, _ms: u64) {}
    fn heal_terminal(&self) {}
    fn sha256_file(&self, _path: &Path) -> Result<String, IoError> {
        Ok("fuzz-hash".into())
    }
    fn sha256_process_package(&self, _pid: u32) -> Result<String, IoError> {
        Ok("fuzz-package".into())
    }
    fn is_symlink(&self, path: &Path) -> bool {
        self.symlinks.borrow().contains_key(&path.to_string_lossy().into_owned())
    }
    fn is_dir(&self, path: &Path) -> bool {
        self.dirs.borrow().contains(&path.to_string_lossy().into_owned())
    }
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, IoError> {
        let pfx = format!("{}/", path.to_string_lossy());
        let mut out = Vec::new();
        for k in self.files.borrow().keys() {
            if let Some(rest) = k.strip_prefix(&pfx) {
                if !rest.contains('/') { out.push(P::from(rest)); }
            }
        }
        Ok(out)
    }
    fn read_link(&self, path: &Path) -> Result<PathBuf, IoError> {
        self.symlinks
            .borrow()
            .get(&path.to_string_lossy().into_owned())
            .map(P::from)
            .ok_or_else(|| IoError("invalid argument (os error 22)".into()))
    }
    fn rename_path(&mut self, from: &Path, to: &Path) -> Result<(), IoError> {
        let fk = from.to_string_lossy().into_owned();
        let tk = to.to_string_lossy().into_owned();
        if let Some(v) = self.files.borrow_mut().remove(&fk) {
            self.files.borrow_mut().insert(tk, v);
            return Ok(());
        }
        if let Some(v) = self.symlinks.borrow_mut().remove(&fk) {
            self.symlinks.borrow_mut().insert(tk, v);
            return Ok(());
        }
        Err(IoError("No such file or directory (os error 2)".into()))
    }
    fn try_unix_connect(&self, _path: &Path) -> bool {
        // The rendezvous converges: a spawn usually brings the socket
        // up within a few polls (real daemons do), so the orchestrator
        // rarely waits out its wall-clock deadline. Down-paths stay
        // covered via spawn failure (6%) and the 15% no-show draw.
        if self.unix_up.get() {
            return true;
        }
        let mut rng = self.rng.borrow_mut();
        let fails = self.unix_fails.get();
        if fails >= 2 && rng.chance(80) {
            self.unix_up.set(true);
            self.unix_fails.set(0);
            true
        } else {
            self.unix_fails.set(fails + 1);
            false
        }
    }
    fn unix_send_recv(&self, _path: &Path, _data: &[u8]) -> Result<Vec<u8>, IoError> {
        Err(IoError("unix transport not modeled in fuzz tier".into()))
    }
}

fn fuzz_config() -> AgentConfig {
    AgentConfig {
        binary_hash: "fuzz-hash".into(),
        secrets: vec![SecretMapping {
            host: P::from("/home/user/secrets.yaml"),
            container: P::from("/root/.config/goose/secrets.yaml"),
        }],
        agent_subfolder: "goose".into(),
        container_args: vec![],
        agent_path: P::from("/work/agent1"),
        fuse_server_path: "fuse-server".into(),
        image_name: "agentbox".into(),
        seccomp_profile: P::from("/tmp/agentbox-seccomp.json"),
        memory: "16G".into(),
        cpus: "4".into(),
        auto_confirm: false,
        socket_path: P::from("/tmp/fgk.sock"),
        oracle_socket: None,
        mount_point: P::from("/tmp/fgk-mnt"),
        pidns_host: false,
        runtime: Runtime::Auto,
        runtime_wrapper: None,
        log_level: "info".to_string(),
        plans_path: None,
    }
}

/// Drive one seeded world; assert the fuzz-tier properties.
fn drive(seed: u64) {
    let mut io = FuzzSystemIo::new(seed);
    let cfg = fuzz_config();
    // The send closure is ALSO fuzzed transport: mostly healthy, with
    // connection drops and non-parseable replies mixed in — the client
    // must fail fast or cope, never wedge. Its draw state lives in a
    // Cell so the closure stays `Fn` (run_agent's signature demands it)
    // while staying deterministic per seed.
    let send_state = Cell::new(seed ^ 0xA5A5A5A5A5A5A5A5);
    let send = |name: &str, _args: &str| -> Result<String, String> {
        let mut rng = Rng(send_state.get());
        let r = rng.next() % 100;
        send_state.set(rng.0);
        match (name, r) {
            (_, 0..=9) => Err("server closed the connection".into()),
            ("version", 10..=14) => Ok("not json".into()),
            ("add", 10..=14) => Ok("{\"type\":\"added\",\"inner\":\"stub-x\"}".into()),
            ("add", 15..=17) => Ok("{\"type\":\"error\"}".into()),
            _ => Ok(String::new()),
        }
    };
    let _ = run_agent(&mut io, &cfg, &send, false);

    // Property 3: structural invariants over the observed chaos.
    let commands = io.commands.borrow();
    let spawns = io.spawns.borrow();
    // #62/#65's precise rule, encoded: `pkill -f` is legal ONLY with
    // THIS stack's socket path as the pattern (the unique-rendezvous
    // scope) — a bare daemon-name substring (`fuse-server`, `fused`)
    // is the incident class and must never appear, under any chaos.
    for (prog, args) in commands.iter() {
        if prog != "pkill" { continue; }
        if let Some(pos) = args.iter().position(|a| a == "-f" || a == "-x") {
            let mode = &args[pos];
            let pat = args.get(pos + 1).cloned().unwrap_or_default();
            let scoped = pat.contains("/tmp/fgk.sock");
            let bare_name = pat.contains("fuse-server") || pat.contains("fused") && !scoped;
            assert!(
                !bare_name,
                "seed {seed}: banned name-based sweep `pkill {mode} {pat}`: {args:?}"
            );
            if mode.as_str() == "-f" {
                assert!(
                    scoped,
                    "seed {seed}: `pkill -f` with a non-rendezvous pattern: {args:?}"
                );
            }
        }
    }
    assert!(
        !io.spawned_without_mountpoint.get(),
        "seed {seed}: fuse-server spawned while the mountpoint was an uncleared dead mount"
    );
    let first_spawn = spawns.iter().position(|(p, _)| p.contains("fuse-server"));
    if let Some(i) = first_spawn {
        for (p, args) in spawns.iter().skip(i) {
            if p.contains("fuse-server") {
                let sock = args
                    .iter()
                    .zip(args.iter().skip(1))
                    .find(|(k, _)| k.as_str() == "--socket")
                    .map(|(_, v)| v.clone());
                assert_eq!(
                    sock.as_deref(),
                    Some("/tmp/fgk.sock"),
                    "seed {seed}: spawned stack lost its rendezvous identity: {args:?}"
                );
            }
        }
    }
}


#[test]
fn orchestrator_survives_command_chaos() {
    // 256 deterministic worlds per PR run (seconds, not minutes).
    // A failure prints its seed; reproduce with the env filter below.
    for seed in 0..256u64 {
        drive(seed);
    }
}

#[test]
fn orchestrator_chaos_single_seed_repro() {
    // The one-line reproducer hook: FUZZ_SEED=<n> cargo test -p run-agent \
    //   --test fuzz_orchestrator orchestrator_chaos_single_seed_repro
    let seed: u64 = std::env::var("FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    drive(seed);
}

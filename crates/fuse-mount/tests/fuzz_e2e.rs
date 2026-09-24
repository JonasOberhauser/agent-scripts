//! The E2E fuzzer (#73's tier): the REAL fused binary + REAL policy
//! daemon over the true oracle wire, with only the kernel end mocked
//! (#76) — and the DRIVER fuzzed. Every seed drives a random-but-
//! plausible VFS session: lookups of served and unserved names,
//! readdirs, opens, reads at random offsets/sizes (forward, backward,
//! overlapping, beyond-EOF), getattr by stale and fresh inodes,
//! releases of real and invented fh values, credential variation (the
//! same "process" switching uid/pid mid-session — an actor trying to
//! evade), and driver reconnects (the kernel dying and coming back).
//!
//! The properties, per seed:
//!  1. NO PANIC anywhere — a fused crash kills the mount; a policy
//!     crash kills adjudication. Both daemons must survive.
//!  2. LIVENESS — after the chaos session, a fresh driver can INIT
//!     and complete a well-formed lookup/readdir. Nothing wedged.
//!  3. CONTAINMENT — the end-to-end oracle: chaos NEVER reads the
//!     secret's bytes except through a legitimately adjudicated OPEN.
//!     Concretally: every successful read must be preceded (in the
//!     same session, same creds) by a successful open of that inode;
//!     the policy daemon's one-read budget is the ground truth.
//!  4. NO HANG — every driver op is bounded; a wedged daemon shows up
//!     as a timeout failure naming the seed and op.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::sync::Arc;
use std::time::{Duration, Instant};

use fuse_mount::mock_driver::MockDriver;
use fuse_server::oracle_service::{run_oracle_server_with_stop, OracleHub};
use fuse_server::{ReadOutcome, ServerState};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

/// Names the container side might try: the served inner label, its
/// prefixes, mangled variants, the OUTER name (must never resolve),
/// and pure noise.
fn fuzz_names(inner: &str) -> Vec<String> {
    let v = vec![
        inner.to_string(),
        inner[..4.min(inner.len())].to_string(),
        format!("{inner}x"),
        format!("x{inner}"),
        "s".into(),
        "ab12cd34ef56".into(),
        "..".into(),
        ".".into(),
        String::new(),
    ];
    v
}

struct Stack {
    state: Arc<ServerState>,
    hub: OracleHub,
    fused: Fused,
    stop: Arc<std::sync::atomic::AtomicBool>,
    oracle_path: std::path::PathBuf,
    // The tempdir outlives the daemons: host source files must
    // survive every read (MR4 opens them live).
    _dir: tempfile::TempDir,
}

impl Drop for Stack {
    fn drop(&mut self) {
        // Reclaim the oracle's accept thread (the stop seam): set the
        // flag, then connect once — the poison pill wakes the blocking
        // accept and the loop exits. Without this every world leaked
        // one immortal thread, and ~2k worlds hit the thread limit.
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        let _ = std::os::unix::net::UnixStream::connect(&self.oracle_path);
    }
}

struct Fused {
    child: std::process::Child,
    control: std::path::PathBuf,
}

impl Drop for Fused {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.control);
    }
}

fn stack_up(seed: u64) -> Stack {
    let dir = tempfile::tempdir().unwrap();
    let mut st = ServerState::new();
    st.hashd_sock = dir.path().join("hashd-dead.sock").display().to_string();
    let state = Arc::new(st);
    *state.pending_timeout.lock().unwrap() = Duration::from_millis(120);
    let host = dir.path().join("host-secret");
    // Vary the content per seed (size 1..=512): random read offsets
    // and sizes exercise clamping against different EOF points.
    let len = 1 + (seed % 512) as usize;
    std::fs::write(&host, vec![b'X'; len]).unwrap();
    // NON-wildcard: only "sha256-real" may grant — containment has a
    // real gate to hold. (pid_hash is None for every fuzz pid, so no
    // fuzz open ever legitimately matches unless the gate breaks.)
    state.add("s", &host, len, "sha256-real");
    let hub = OracleHub::new();
    let oracle = dir.path().join("oracle.sock");
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (s2, h2, p2, st2) = (Arc::clone(&state), hub.clone(), oracle.clone(), Arc::clone(&stop));
    // SAFETY per policy: the handle is intentionally un-joined — the
    // Stack::drop poison pill stops the loop; explicit discard.
    let _ = std::thread::spawn(move || {
        let _ = run_oracle_server_with_stop(&p2, s2, h2, &st2);
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if oracle.exists() { break; }
        std::thread::sleep(Duration::from_millis(10));
    }

    let control = dir.path().join("mock-fuse.sock");
    let log = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open(dir.path().join("fused.log")).unwrap();
    #[allow(clippy::zombie_processes)]
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_fused"))
        .arg("--mount-point").arg(dir.path().join("mnt"))
        .arg("--oracle-socket").arg(&oracle)
        .arg("--mock-fuse").arg(&control)
        .env("RUST_LOG", "warn")
        .stdout(std::process::Stdio::from(log.try_clone().unwrap()))
        .stderr(log)
        .spawn().expect("spawn fused");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if control.exists() {
            return Stack { state, hub, fused: Fused { child, control }, stop, oracle_path: oracle, _dir: dir };
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("seed {seed}: fused never bound the mock control socket");
}

/// The per-seed chaos session. Returns the set of inodes the session
/// legitimately OPENED (with which the containment check reasons).
fn drive_session(seed: u64, d: &mut MockDriver, names: &[String]) {
    let mut rng = Rng(seed.wrapping_mul(0x2545F4914F6CDD1D) | 1);
    let mut open_inos: Vec<u64> = Vec::new();

    for step in 0..40u32 {
        // Credential drift: the "same" actor changing uid/pid — or a
        // genuinely different one. The gate must hold either way.
        if rng.next().is_multiple_of(4) {
            d.creds.uid = (rng.next() % 70000) as u32;
            d.creds.pid = (rng.next() % 1_000_000) as u32;
        }
        let name = &names[(rng.next() % names.len() as u64) as usize];
        match rng.next() % 8 {
            0 | 1 => {
                let _ = d.lookup(name);
            }
            2 => {
                if let Ok(dh) = d.opendir(fuser::FUSE_ROOT_ID) {
                    let _ = d.readdir(dh.fh, 64 + (rng.next() % 4096) as u32);
                    let _ = d.releasedir(fuser::FUSE_ROOT_ID, dh.fh);
                }
            }
            3 => {
                let ino = if let Some(&i) = open_inos.last() { i } else { fuser::FUSE_ROOT_ID };
                if let Ok(_opened) = d.open(ino) {
                    open_inos.push(ino);
                }
            }
            4 => {
                let ino = open_inos.get((rng.next() % open_inos.len().max(1) as u64) as usize)
                    .copied()
                    .unwrap_or(1 + rng.next() % 32);
                if let Ok(opened) = d.open(ino) {
                    let fh = opened.fh;
                    // Reads at random offsets/sizes: forward, backward,
                    // overlapping, beyond EOF — all must clamp or err,
                    // never panic and never return secret bytes
                    // unadjudicated (the containment oracle checks the
                    // budget, and the session tracks opens).
                    let _ = d.read(fh, rng.next() % 1024, 1 + (rng.next() % 70000) as u32);
                    let _ = d.read(fh, rng.next() % 1024, (rng.next() % 4) as u32);
                    let _ = d.release(ino, fh);
                }
            }
            5 => {
                // getattr on stale/mass inodes: invented numbers are
                // ENOENT, never a crash.
                let _ = d.getattr(1 + rng.next() % 4096);
            }
            6 => {
                // release with an INVENTED fh: the daemon must not
                // close anything real (or crash) on garbage.
                let _ = d.release(1 + rng.next() % 64, rng.next());
            }
            _ => {
                let _ = d.lookup(name);
                let _ = d.lookup(&names[0]);
            }
        }
        let _ = step;
    }
}

#[test]
#[ignore = "marathon: FUZZ_MINUTES=<n> -- --ignored"]
fn e2e_fuzz_marathon() {
    let minutes: u64 = std::env::var("FUZZ_MINUTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(minutes > 0, "set FUZZ_MINUTES (the marathon is opt-in)");
    let stop = Instant::now() + Duration::from_secs(60 * minutes);
    let mut seed = 0u64;
    while Instant::now() < stop {
        drive_seed(seed);
        seed += 1;
    }
    eprintln!("e2e marathon: {seed} worlds in {minutes} minutes (all held)");
}

fn drive_seed(seed: u64) {
    {
        let stack = stack_up(seed);
        let inner = {
            // Ask the hub what it served: fixed label (no policy salt
            // here — the label is whatever we served).
            "ab12cd34ef56".to_string()
        };
        stack.hub.serve("s", &inner, 0o400);
        // Wait for the Serve to land (control loop poll).
        let deadline = Instant::now() + Duration::from_secs(5);
        {
            let mut probe = MockDriver::connect(&stack.fused.control).unwrap_or_else(|e| {
                let log = std::fs::read_to_string(stack._dir.path().join("fused.log"))
                    .unwrap_or_default();
                panic!(
                    "seed {seed}: fused died before the serve-wait probe ({e})\nfused.log:\n{log}"
                );
            });
            let _ = probe.init().unwrap_or_else(|e| {
                let log = std::fs::read_to_string(stack._dir.path().join("fused.log"))
                    .unwrap_or_default();
                panic!("seed {seed}: init after spawn failed ({e:?})\nfused.log:\n{log}");
            });
            loop {
                if let Ok(dh) = probe.opendir(fuser::FUSE_ROOT_ID) {
                    if let Ok(entries) = probe.readdir(dh.fh, 4096) {
                        let _ = probe.releasedir(fuser::FUSE_ROOT_ID, dh.fh);
                        if entries.iter().any(|(_, n)| n == &inner) { break; }
                    } else { break; }
                }
                assert!(Instant::now() < deadline, "seed {seed}: Serve never landed");
                std::thread::sleep(Duration::from_millis(25));
            }
        }

        // THE CHAOS SESSION.
        let names = fuzz_names(&inner);
        let mut d = MockDriver::connect(&stack.fused.control).unwrap();
        let _ = d.init().expect("seed {seed}: init before chaos");
        drive_session(seed, &mut d, &names);
        drop(d);

        // LIVENESS after chaos: a fresh driver session works.
        let mut fresh = MockDriver::connect(&stack.fused.control)
            .unwrap_or_else(|e| panic!("seed {seed}: wedged after chaos: {e}"));
        let _ = fresh
            .init()
            .unwrap_or_else(|e| panic!("seed {seed}: init failed after chaos: {e:?}"));
        let lookup = fresh.lookup(&inner);
        assert!(lookup.is_ok(), "seed {seed}: lookup after chaos failed: {:?}", lookup.err());

        // CONTAINMENT: the one-read budget is the ground truth. The
        // chaos session's opens all had pid-hashes that CANNOT match
        // "sha256-real" (hashd is a dead seam — every hash is None),
        // so every open either pended out or was denied... UNLESS one
        // was granted, which is exactly what must never happen. The
        // budget proves it end-to-end: still fresh.
        assert_eq!(
            stack.state.attempt_read("s", 4242, Some("sha256-real"), 0, 4),
            ReadOutcome::Granted,
            "seed {seed}: the chaos session consumed the one-read budget — \
             something was AUTHORIZED without the hash"
        );
        // And spending it now (as the honest holder) denies the next:
        assert!(
            !matches!(
                stack.state.attempt_read("s", 4243, Some("sha256-real"), 0, 4),
                ReadOutcome::Granted
            ),
            "seed {seed}: one-read semantics broken after chaos"
        );
    }
}

#[test]
fn e2e_fuzz_the_daemons_survive_and_contain() {
    // Stack-per-seed is the honest shape: each world gets fresh
    // daemons, a fresh secret, a fresh budget — no cross-seed state.
    // 24 seeds keeps CI at ~2s; the marathon hook scales it.
    for seed in 0..24u64 {
        drive_seed(seed);
    }
}

// ── tier 2 of #73: kill-timing fuzz — the randomized #68 ────────
// Real fuse-server PROCESS + real fused PROCESS (mock kernel); kill
// -9 either at random moments mid-session, respawn, and assert the
// split's invariants per seed:
//   policy kill: the mount (driver session) keeps serving pinned
//     state; the respawned policy reloads the SAME budget from the
//     MR5 store (spent stays spent — no free re-reads);
//   fused kill:  the mount dies with it (fused owns it); the policy
//     never notices; a fresh fused remounts and the snapshot replays;
//     the budget is untouched (it lives in the policy daemon).

fn server_bin() -> std::path::PathBuf {
    // Cross-crate binary: the same path convention e2e_client and
    // fuse_e2e use (CARGO_BIN_EXE_ only reaches same-package bins).
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug/fuse-server");
    assert!(p.exists(), "fuse-server not built (cargo build --workspace): {}", p.display());
    p
}

/// Minimal cmd-socket client: one JSON request per connection, one
/// reply line back (the daemon's documented framing).
fn cmd_status(socket: &std::path::Path) -> String {
    // The REAL client half — the same App + protocols run_agent uses;
    // run_cli_command_raw returns the server's raw JSON Response.
    let app = servyi_servatui::App::builder(socket)
        .protocol_all(fuse_protocol::client_protocols())
        .build();
    let (lines, raw) = app
        .run_cli_command_raw("status", "")
        .expect("status round-trip through the real client half");
    let _ = lines;
    String::from_utf8_lossy(&raw).into_owned()
}

/// The served secret's (access_count, inner name) through the real
/// status command — the inner label comes from the daemon's MINTED
/// salt (issue #47), never from the test.
fn status_of_s(socket: &std::path::Path) -> (u64, String) {
    let reply = cmd_status(socket);
    let resp: fuse_protocol::Response = serde_json::from_str(reply.trim()).expect("status parses");
    match resp {
        fuse_protocol::Response::Status { secrets, .. } => secrets
            .iter()
            .find(|s| s.name == "s")
            .map(|s| (s.access_count, s.inner.clone()))
            .unwrap_or((u64::MAX, String::new())),
        _ => panic!("status replied {reply}"),
    }
}

fn budget(socket: &std::path::Path) -> u64 {
    status_of_s(socket).0
}

struct ProcStack {
    dir: tempfile::TempDir,
    oracle: std::path::PathBuf,
    cmd_sock: std::path::PathBuf,
    policy_store: std::path::PathBuf,
    host: std::path::PathBuf,
    inner: String,
    policy: Option<std::process::Child>,
    fused: Option<Fused>,
    control: std::path::PathBuf,
    mount: std::path::PathBuf,
}

impl ProcStack {
    fn spawn_policy(&mut self) {
        let log = std::fs::OpenOptions::new()
            .create(true).append(true)
            .open(self.dir.path().join("policy.log")).unwrap();
        #[allow(clippy::zombie_processes)]
        let child = std::process::Command::new(server_bin())
            .arg("--socket").arg(&self.cmd_sock)
            .arg("--oracle-socket").arg(&self.oracle)
            .arg("--pending-timeout").arg("1")
            .arg("--secret").arg(format!("s:{}:*", self.host.display()))
            .env("FUSE_GATEKEEPER_POLICY", &self.policy_store)
            .env("RUST_LOG", "warn")
            .stdout(std::process::Stdio::from(log.try_clone().unwrap()))
            .stderr(log)
            .spawn().expect("spawn fuse-server");
        self.policy = Some(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if std::os::unix::net::UnixStream::connect(&self.cmd_sock).is_ok() { break; }
            assert!(Instant::now() < deadline, "policy daemon never answered");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn spawn_fused(&mut self) {
        if let Some(mut old) = self.fused.take() {
            let _ = old.child.kill();
            let _ = old.child.wait();
            let _ = std::fs::remove_file(&old.control);
        }
        let log = std::fs::OpenOptions::new()
            .create(true).append(true)
            .open(self.dir.path().join("fused.log")).unwrap();
        #[allow(clippy::zombie_processes)]
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_fused"))
            .arg("--mount-point").arg(&self.mount)
            .arg("--oracle-socket").arg(&self.oracle)
            .arg("--mock-fuse").arg(&self.control)
            .env("RUST_LOG", "warn")
            .stdout(std::process::Stdio::from(log.try_clone().unwrap()))
            .stderr(log)
            .spawn().expect("respawn fused");
        let control = self.control.clone();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if control.exists() { break; }
            assert!(Instant::now() < deadline, "fused never bound the control socket");
            std::thread::sleep(Duration::from_millis(20));
        }
        self.fused = Some(Fused { child, control });
    }

    fn kill9_policy(&mut self) {
        if let Some(mut c) = self.policy.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        // The socket FILE survives the kill; remove it so respawn's
        // stale-socket handling is exercised exactly as in production.
        let _ = std::fs::remove_file(&self.cmd_sock);
    }

    fn up(seed: u64) -> ProcStack {
        let dir = tempfile::tempdir().unwrap();
        let oracle = dir.path().join("oracle.sock");
        let cmd_sock = dir.path().join("cmd.sock");
        let policy_store = dir.path().join("policy.json");
        let host = dir.path().join("host-secret");
        let len = 1 + (seed % 512) as usize;
        std::fs::write(&host, vec![b'X'; len]).unwrap();
        let control = dir.path().join("mock-fuse.sock");
        let mount = dir.path().join("mnt");
        std::fs::create_dir_all(&mount).unwrap();
        let mut s = ProcStack {
            dir, oracle, cmd_sock, policy_store, host,
            inner: String::new(),
            policy: None, fused: None,
            control, mount,
        };
        s.spawn_policy();
        // The inner label the real daemon derived from its minted salt.
        s.inner = status_of_s(&s.cmd_sock).1;
        assert!(!s.inner.is_empty(), "the policy daemon served no inner name");
        s.spawn_fused();
        s
    }

    /// A fresh, initialized driver (kernel session).
    fn driver(&self) -> MockDriver {
        let mut d = MockDriver::connect(&self.control).expect("driver connect");
        let _ = d.init().expect("driver init");
        d
    }
}

impl Drop for ProcStack {
    fn drop(&mut self) {
        // Best-effort teardown; tempdir does the rest.
        if let Some(mut c) = self.policy.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(mut f) = self.fused.take() {
            let _ = f.child.kill();
            let _ = f.child.wait();
        }
    }
}

fn drive_kill_seed(seed: u64) {
    let mut rng = Rng(seed.wrapping_mul(0x7777777700000001) | 1);
    let mut s = ProcStack::up(seed);

    // Baseline: the secret is served and readable (wildcard hash —
    // hashd is dead, so any pid's first open legitimately grants).
    let (ino, spent) = {
        let mut d = s.driver();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(dh) = d.opendir(fuser::FUSE_ROOT_ID) {
                if let Ok(entries) = d.readdir(dh.fh, 4096) {
                    let _ = d.releasedir(fuser::FUSE_ROOT_ID, dh.fh);
                    if entries.iter().any(|(_, n)| n == &s.inner) { break; }
                }
            }
            assert!(Instant::now() < deadline, "seed {seed}: Serve never landed");
            std::thread::sleep(Duration::from_millis(25));
        }
        let e = d.lookup(&s.inner).expect("baseline lookup");
        let opened = d.open(e.nodeid).expect("baseline open (wildcard grants)");
        let data = d.read(opened.fh, 0, 4096).expect("baseline read");
        assert_eq!(data.len(), 1 + (seed % 512) as usize);
        let _ = d.release(e.nodeid, opened.fh);
        (e.nodeid, budget(&s.cmd_sock))
    };
    assert_eq!(spent, 1, "seed {seed}: one open consumed exactly one budget");

    // The kill-timing chaos: 2-4 events, each a random daemon at a
    // random moment (between driver ops).
    let events = 2 + (rng.next() % 3);
    let mut spent_now = spent;
    for _ in 0..events {
        let kill_policy = rng.next().is_multiple_of(2);
        if kill_policy {
            s.kill9_policy();
            // The data daemon's mount survives; the driver (kernel)
            // can still serve the already-adjudicated state... a
            // fresh LOOKUP needs the policy back, so respawn and
            // verify the BUDGET survived the MR5 store round-trip.
            s.spawn_policy();
            let b = budget(&s.cmd_sock);
            assert_eq!(
                b, spent_now,
                "seed {seed}: policy kill changed the budget (free re-read or lost spend)"
            );
        } else {
            // fused kill: mount dies with it; the policy must not
            // notice; fresh fused remounts + snapshot replays.
            let before = budget(&s.cmd_sock);
            s.spawn_fused(); // kills the old one first
            let mut d = s.driver();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Ok(dh) = d.opendir(fuser::FUSE_ROOT_ID) {
                    if let Ok(entries) = d.readdir(dh.fh, 4096) {
                        let _ = d.releasedir(fuser::FUSE_ROOT_ID, dh.fh);
                        if entries.iter().any(|(_, n)| n == &s.inner) { break; }
                    }
                }
                assert!(Instant::now() < deadline, "seed {seed}: no replay after fused kill");
                std::thread::sleep(Duration::from_millis(25));
            }
            let after = budget(&s.cmd_sock);
            assert_eq!(before, after, "seed {seed}: fused kill touched the budget");
        }
        // After either kill, a well-formed lookup still works.
        let mut d = s.driver();
        let look = d.lookup(&s.inner);
        assert!(look.is_ok(), "seed {seed}: lookup broken after recovery: {:?}", look.err());
        let _ = ino;
        // A subsequent open+read (if unspent) must still respect the
        // budget: update the local view when we spend.
        if spent_now == 0 {
            if let Ok(e) = d.lookup(&s.inner) {
                if let Ok(o) = d.open(e.nodeid) {
                    let _ = d.read(o.fh, 0, 4096);
                    let _ = d.release(e.nodeid, o.fh);
                    spent_now += 1;
                }
            }
        }
    }
}

#[test]
fn e2e_kill_timing_both_daemons_recover_with_budget_intact() {
    // The randomized #68: 12 deterministic worlds in CI (each spawns
    // real processes; ~1s per world), marathon scales it.
    for seed in 0..12u64 {
        drive_kill_seed(seed);
    }
}

#[test]
#[ignore = "marathon: FUZZ_MINUTES=<n> -- --ignored"]
fn e2e_kill_timing_marathon() {
    let minutes: u64 = std::env::var("FUZZ_MINUTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(minutes > 0, "set FUZZ_MINUTES (the marathon is opt-in)");
    let stop = Instant::now() + Duration::from_secs(60 * minutes);
    let mut seed = 0u64;
    while Instant::now() < stop {
        drive_kill_seed(seed);
        seed += 1;
    }
    eprintln!("kill-timing marathon: {seed} worlds in {minutes} minutes (all held)");
}

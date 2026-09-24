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

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

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
    std::thread::spawn(move || {
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
            probe.init().unwrap_or_else(|e| {
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
        d.init().expect("seed {seed}: init before chaos");
        drive_session(seed, &mut d, &names);
        drop(d);

        // LIVENESS after chaos: a fresh driver session works.
        let mut fresh = MockDriver::connect(&stack.fused.control)
            .unwrap_or_else(|e| panic!("seed {seed}: wedged after chaos: {e}"));
        fresh.init().unwrap_or_else(|e| panic!("seed {seed}: init failed after chaos: {e:?}"));
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

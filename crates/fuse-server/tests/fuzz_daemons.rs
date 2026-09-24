//! Fuzzing the DAEMONS (gaps 2+3 of the fuzz tier): the cmd socket
//! (`fuse-client`'s command surface) and the oracle socket (the
//! container's random-access surface), fed random and mutated but
//! PLAUSIBLE input. The properties:
//!
//!  1. NO PANIC: arbitrary lines — garbage, wrong-typed JSON, valid
//!     shapes with hostile field values — never crash a handler.
//!  2. LIVENESS: after chaos, the daemon still answers well-formed
//!     requests promptly (nothing wedged).
//!  3. CONTAINMENT UNDER CHAOS — the security payoff: no random input
//!     ever AUTHORIZES anything. After every chaos sequence, a read
//!     with the wrong package hash is denied and a read with the right
//!     hash still works exactly once: the one-read semantics and the
//!     hash gate survive arbitrary client behavior.
#![allow(clippy::unwrap_used, clippy::panic, unused_results)]

use fuse_protocol::oracle::OracleReply;
use fuse_protocol::Command;
use fuse_server::oracle_service::OracleHub;
use fuse_server::{ReadOutcome, ServerState};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// #69 discipline: a dead per-run hashd socket, so a hashd running on
/// THIS machine (production /run/fuse-hashd.sock) is never asked to
/// hash the fuzzed random pids. Assigned on the `mut` local before the
/// state is shared, exactly as the oracle_service harness does.
fn dead_hashd_sock() -> String {
    std::env::temp_dir().join(format!(
        "fuzz-hashd-dead-{}.sock",
        std::process::id()
    )).display().to_string()
}

// ── deterministic RNG (splitmix64, same as the orchestrator tier) ──
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

/// Hostile-but-plausible field values for random command fill-ins.
const NAMES: &[&str] = &[
    "", "s", "../..", "a/b/../../../c", "root", "\u{1F512}", "\0bad",
    "very-long-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "HOME=/x", "-x", "--socket", "p42_s0_x",
];
const HASHES: &[&str] = &["", "*", "sha256-real",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "\u{7F}"];

/// Random JSON-ish payloads: valid shapes with random fields, wrong
/// types, truncated valid JSON, and pure garbage.
fn random_line(rng: &mut Rng) -> String {
    match rng.next() % 8 {
        0 => format!(
            "{{\"type\":\"add-secret\",\"name\":\"{}\",\"path\":\"{}\",\"hash\":\"{}\",\"mode\":{}}}",
            NAMES[(rng.next() % NAMES.len() as u64) as usize],
            NAMES[(rng.next() % NAMES.len() as u64) as usize],
            HASHES[(rng.next() % HASHES.len() as u64) as usize],
            rng.next() % 8
        ),
        1 => format!(
            "{{\"type\":\"rotate\",\"name\":\"{}\",\"new_hash\":\"{}\"}}",
            NAMES[(rng.next() % NAMES.len() as u64) as usize],
            HASHES[(rng.next() % HASHES.len() as u64) as usize],
        ),
        2 => format!(
            "{{\"type\":\"grant\",\"id\":{}}}",
            rng.next() % 1_000_000
        ),
        3 => format!("{{\"type\":\"reset\",\"name\":\"{}\"}}", NAMES[(rng.next() % NAMES.len() as u64) as usize]),
        4 => "{\"type\":\"status\",\"extra_field\":[1,2,{\"x\":null}]}".into(),
        5 => "{\"type\":\"add-secret\",\"name\":42}".into(), // wrong types
        6 => "{\"type\":\"add-secret\",\"name\":\"x\"".into(), // truncated
        _ => String::from_utf8_lossy(&[
            (rng.next() % 256) as u8, b'{', (rng.next() % 256) as u8, b'}', b'\n', 0u8,
        ])
        .into_owned(),
    }
}

// ── gap 2: the cmd socket (fuse-client's surface), in-process ──

#[test]
#[ignore = "marathon: opt-in via FUZZ_MINUTES; runs until the budget expires"]
fn daemon_chaos_marathon() {
    let minutes: u64 = std::env::var("FUZZ_MINUTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(minutes > 0, "set FUZZ_MINUTES (the marathon is opt-in)");
    let stop = std::time::Instant::now() + Duration::from_secs(60 * minutes);
    let mut seed = 0u64;
    while Instant::now() < stop {
        let mut rng = Rng(seed | 1);
        let mut state = ServerState::new();
        state.hashd_sock = dead_hashd_sock();
        // ONE host file reused across seeds (zero disk footprint — a
        // per-seed file filled a disk in an earlier marathon).
        let host = std::env::temp_dir().join("fuzz-m-host-reused");
        let _ = std::fs::write(&host, b"FUZZ-DATA");
        state.add("s", &host, 9, "sha256-real");
        let hub = OracleHub::new();
        for _ in 0..24 {
            let line = random_line(&mut rng);
            if let Ok(cmd) = serde_json::from_str::<Command>(&line) {
                let _ = fuse_server::handler::handle_command(cmd, &state, &hub);
            }
        }
        if matches!(state.attempt_read("s", 4242, Some("sha256-wrong"), 0, 4), ReadOutcome::Granted)
        {
            panic!("seed {seed}: chaos AUTHORIZED a wrong-hash read");
        }
        seed += 1;
    }
    eprintln!("cmd-socket marathon: {seed} seeds in {minutes} minutes (all held)");
}

#[test]
fn command_socket_chaos_never_panics_and_never_authorizes() {
    // ONE host file reused across seeds (zero disk footprint — the
    // first marathon leaked one file per seed until the disk filled).
    let host = std::env::temp_dir().join("fuzz-cmd-host-reused");
    std::fs::write(&host, b"FUZZ-DATA").unwrap();
    for seed in 0..512u64 {
        let mut rng = Rng(seed | 1);
        let mut state = ServerState::new();
        state.hashd_sock = dead_hashd_sock();
        // NON-wildcard: only "sha256-real" may ever grant.
        state.add("s", &host, 9, "sha256-real");
        let hub = OracleHub::new();

        for _ in 0..24 {
            let line = random_line(&mut rng);
            if let Ok(cmd) = serde_json::from_str::<Command>(&line) {
                let _ = fuse_server::handler::handle_command(cmd, &state, &hub);
            }
            // Unparsable lines are the daemon's loud-parse path —
            // nothing to call; the socket layer already handles them.
        }

        // Containment after chaos: wrong hash NEVER granted, right
        // hash granted exactly once (one-read), then denied.
        if matches!(state.attempt_read("s", 4242, Some("sha256-wrong"), 0, 4), ReadOutcome::Granted)
        {
            panic!("seed {seed}: chaos on the command socket AUTHORIZED a wrong-hash read")
        }
        assert_eq!(
            state.attempt_read("s", 4242, Some("sha256-real"), 0, 4),
            ReadOutcome::Granted,
            "seed {seed}: the right hash must still grant after chaos"
        );
        if matches!(state.attempt_read("s", 4242, Some("sha256-real"), 0, 4), ReadOutcome::Granted)
        {
            panic!("seed {seed}: one-read semantics broken after chaos")
        }
    }
}

// ── gap 3: the oracle socket (the container's random-access surface),
// against a LIVE daemon over a real socket ──

/// The kit-backed oracle environment (issue #63): per-stack root,
/// real oracle wire. Keep the HANDLE — dropping it tears the stack
/// (root and socket with it); the old harness keep()d its dir for
/// exactly as long.
fn oracle_env_kit(
    tag: &str,
    state: Arc<ServerState>,
) -> (std::path::PathBuf, gatekeeper_testkit::StackHandle) {
    let handle =
        gatekeeper_testkit::Stack::from_state(tag, state, OracleHub::new());
    (handle.oracle_socket().to_path_buf(), handle)
}

fn send_line(path: &Path, line: &str) -> Option<String> {
    let mut c = UnixStream::connect(path).ok()?;
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(format!("{line}\n").as_bytes()).ok()?;
    let mut reader = BufReader::new(c);
    let mut out = String::new();
    reader.read_line(&mut out).ok()?;
    Some(out)
}

#[test]
fn oracle_socket_random_access_stays_alive_and_contained() {
    // Host files for the seeds live under ONE kit root (teardown
    // cleans it; no shared-temp fixed paths — issue #63).
    let file_stack = gatekeeper_testkit::Stack::new("fuzz-oracle-files").spawn_in_process();
    let oracle_scratch = file_stack.scratch("");
    for seed in 0..40u64 {
        let mut rng = Rng(seed.wrapping_mul(7919) | 1);
        let mut st = ServerState::new();
        st.hashd_sock = gatekeeper_testkit::DEAD_HASHD.to_string();
        let state = Arc::new(st);
        // Short pendings: a wrong-hash ask BLOCKS as a pending (the
        // product) — 150ms keeps the containment probe fast while the
        // pend-out-and-deny flow remains exercised.
        *state.pending_timeout.lock().unwrap() = Duration::from_millis(150);
        let host = oracle_scratch.join(format!("fuzz-oracle-host-{seed}"));
        std::fs::write(&host, b"FUZZ-DATA").unwrap();
        state.add("s", &host, 9, "sha256-real"); // non-wildcard
        let (sock, _keep) = oracle_env_kit(&format!("fuzz-oracle-{seed}"), Arc::clone(&state));

        // Chaos: 32 random requests on fresh connections — the
        // container doing random accesses (valid-shaped Asks with
        // random pids/offsets/sizes, Opens, Hellos, garbage). A hello
        // first line legitimately becomes a held-open CONTROL
        // connection (no reply, by design) — send those without
        // expecting a reply line; everything else must answer or
        // close promptly (the read timeout converts a wedge into a
        // test failure).
        for _ in 0..32 {
            let line = match rng.next() % 6 {
                0 => format!(
                    "{{\"type\":\"ask\",\"name\":\"{}\",\"pid\":{},\"offset\":{},\"size\":{}}}",
                    ["s", "", "other", "../x"][(rng.next() % 4) as usize],
                    rng.next() % 1_000_000,
                    rng.next() % 1_000_000,
                    rng.next() % 70000,
                ),
                1 => format!(
                    "{{\"type\":\"open\",\"name\":\"s\",\"pid\":{},\"kdev\":{},\"kino\":{}}}",
                    rng.next() % 1_000_000, rng.next(), rng.next()
                ),
                2 => "{\"type\":\"hello\"}".into(),
                3 => "{\"type\":\"stat\",\"name\":\"s\"}".into(),
                4 => "{\"type\":\"ask\",\"name\":\"s\",\"pid\":\"not-a-number\"}".into(),
                _ => String::from_utf8_lossy(&[(rng.next() % 256) as u8; 8]).into_owned(),
            };
            if line.contains("hello") {
                let mut c = match UnixStream::connect(&sock) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let _ = c.write_all(format!("{line}\n").as_bytes());
                drop(c); // the daemon registers then notices the close
            } else {
                let _ = send_line(&sock, &line);
            }
        }

        // LIVENESS after chaos: stat is unadjudicated — it must answer
        // instantly. (An ask would block in a pending by design.)
        let reply = send_line(&sock, "{\"type\":\"stat\",\"name\":\"s\"}")
        .unwrap_or_else(|| panic!("seed {seed}: oracle wedged after chaos (stat unanswered)"));
        let parsed: OracleReply = serde_json::from_str(reply.trim())
        .unwrap_or_else(|e| panic!("seed {seed}: unreadable reply after chaos: {reply} ({e})"));
        assert!(
            matches!(parsed, OracleReply::StatOk { .. }),
            "seed {seed}: stat degraded after chaos: {reply}"
        );

        // CONTAINMENT: a wrong-hash ask (a pid with no verified
        // package) pends out its 1s and is DENIED — never Allow, no
        // matter what chaos preceded it.
        let reply = send_line(
            &sock,
            "{\"type\":\"ask\",\"name\":\"s\",\"pid\":999999,\"offset\":0,\"size\":4}",
        )
        .unwrap_or_else(|| panic!("seed {seed}: containment probe unanswered"));
        let parsed: OracleReply = serde_json::from_str(reply.trim())
        .unwrap_or_else(|e| panic!("seed {seed}: unreadable containment reply: {reply} ({e})"));
        assert!(
            !matches!(parsed, OracleReply::Allow),
            "seed {seed}: random access was AUTHORIZED (hash gate broken): {reply}"
        );
    }
}

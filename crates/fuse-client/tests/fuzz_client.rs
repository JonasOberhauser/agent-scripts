//! Fuzzing the REAL fuse-client BINARY (#73's client axis): random
//! commands against a fake policy daemon whose REPLIES are hostile —
//! valid wire shapes carrying hostile field values (huge names,
//! control characters and ANSI escapes the panel must neutralize,
//! enormous counters, empty strings), malformed JSON, truncated
//! frames, oversized lines, and — per the mixed-vintage field
//! history — an "out-of-date server" mode that answers the fixed
//! wire part (the version handshake) with stale version STRINGS and
//! everything else with random garbage.
//!
//! The properties, per seed:
//!  1. TERMINATION: the client exits within the deadline (a wedged
//!     client is a finding — the daemon cannot hang it);
//!  2. GRACEFUL DEGRADATION: the exit is a normal code, not a panic
//!     (101) and not a death by signal — garbage from the daemon may
//!     error, never crash;
//!  3. The machine is untouched: the state file is redirected via
//!     FUSE_GATEKEEPER_STATE into the tempdir, so `restart` (which
//!     reads it and pkills by ITS socket path — unique per tempdir)
//!     stays sandboxed.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// splitmix64, the house RNG.
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

/// Field values the panel must render safely or reject: control
/// characters, ANSI escapes (terminal-injection), separators, depth,
/// size, and emptiness.
const HOSTILE: &[&str] = &[
    "s", "", "\u{1b}[31mRED\u{1b}[0m", "\u{1b}]0;title\u{07}",
    "\u{7}", "\r\nCRLF-injected", "\u{2028}",
    "a/b/../../../../c", "..",
    "very-long-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "\u{1F916}", "\u{1F512}", "HOME=/x", "$(rm -rf /)", "`id`", "; reboot",
];

const GARBAGE: &[&str] = &[
    "not json", "{", "{\"type\":", "{\"type\":\"Status\",\"secrets\":42}",
    "{\"type\":\"unknown-variant\"}", "[]", "null", "\"bare string\"",
    "{\"type\":\"Version\",\"version\":99}",
];

/// An out-of-date daemon's version strings — every historical minor,
/// garbage, and empty (the mixed-vintage #37/#48 class).
const STALE_VERSIONS: &[&str] = &[
    "0.26.0", "0.27.0", "0.28.0", "0.29.0", "0.30.0", "0.31.0",
    "0.32.0-major-bump", "", "not a version", "999.999.999",
];

fn json_s(rng: &mut Rng) -> String {
    serde_json::to_string(rng.pick(HOSTILE)).unwrap()
}

/// One hostile-but-plausible reply line. `vintage` marks the
/// out-of-date-daemon mode.
fn random_reply(rng: &mut Rng, vintage: bool) -> String {
    if vintage && rng.chance(70) {
        // Old daemon: random strings on every non-fixed message.
        return format!(
            "{{\"type\":\"{}\",\"value\":\"{}\"}}",
            rng.pick(&["garbage", "ok", "err", "status", "\u{1b}[2J"]),
            rng.pick(HOSTILE)
        );
    }
    match rng.next() % 8 {
        0 => {
            let secrets: Vec<String> = (0..rng.next() % 4)
                .map(|_| {
                    format!(
                        "{{\"name\":{},\"access_count\":{},\"allowed_hashes\":[],\"size\":{},\"unlimited\":{},\"inner\":{}}}",
                        json_s(rng),
                        rng.next() % u64::MAX,
                        rng.next() % (1 << 40),
                        rng.chance(10),
                        json_s(rng)
                    )
                })
                .collect();
            format!(
                "{{\"type\":\"Status\",\"secrets\":[{}],\"lockdown\":{}}}",
                secrets.join(","),
                rng.chance(20)
            )
        }
        1 => format!(
            "{{\"type\":\"MountList\",\"mounts\":[{{\"name\":{},\"size\":{}}}]}}",
            json_s(rng),
            rng.next() % (1 << 40)
        ),
        2 => {
            let pend: Vec<String> = (0..rng.next() % 3)
                .map(|_| {
                    let proc = if rng.chance(70) {
                        format!("\"{}\"", rng.pick(HOSTILE).replace('"', ""))
                    } else {
                        "null".to_string()
                    };
                    let hash_err = if rng.chance(30) {
                        format!("\"{}\"", rng.pick(HOSTILE).replace('"', ""))
                    } else {
                        "null".to_string()
                    };
                    format!(
                        "{{\"id\":{},\"secret_name\":{},\"process_name\":{},\"pid\":{},\"pid_hash\":null,\"pid_hash_error\":{},\"reason\":{},\"expired\":{}}}",
                        rng.next() % 1_000_000,
                        json_s(rng),
                        proc,
                        rng.next() % 4_000_000_000,
                        hash_err,
                        json_s(rng),
                        rng.chance(15)
                    )
                })
                .collect();
            format!("{{\"type\":\"PendingList\",\"pending\":[{}]}}", pend.join(","))
        }
        3 => format!("{{\"type\":\"Added\",\"inner\":{}}}", json_s(rng)),
        4 => format!(
            "{{\"type\":\"Version\",\"version\":{}}}",
            serde_json::to_string(if vintage {
                rng.pick(STALE_VERSIONS)
            } else {
                env!("CARGO_PKG_VERSION")
            })
            .unwrap()
        ),
        5 => format!("{{\"type\":\"Error\",\"message\":{}}}", json_s(rng)),
        6 => rng.pick(GARBAGE).to_string(),
        _ => {
            // oversized: a 1MB field value — the client must not
            // choke or blow the stack rendering it.
            let big = "x".repeat(1 << 20);
            format!(
                "{{\"type\":\"Status\",\"secrets\":[{{\"name\":\"{}\",\"access_count\":0,\"allowed_hashes\":[],\"size\":0,\"unlimited\":false,\"inner\":\"{}\"}}],\"lockdown\":false}}",
                big, big
            )
        }
    }
}

/// The command surface: every word in the table with plausible and
/// hostile argument shapes.
fn random_argv(rng: &mut Rng) -> Vec<String> {
    let hostile = |rng: &mut Rng| rng.pick(HOSTILE).to_string();
    let id = |rng: &mut Rng| (rng.next() % 1_000_000).to_string();
    let mut v = match rng.next() % 12 {
        0 => vec!["status".to_string()],
        1 => vec!["mounts".to_string()],
        2 => vec!["pending".to_string()],
        3 => vec!["reset".to_string(), hostile(rng)],
        4 => vec!["reset-all".to_string()],
        5 => vec!["remove".to_string(), hostile(rng)],
        6 => vec!["rotate".to_string(), hostile(rng), hostile(rng)],
        7 => vec!["grant".to_string(), id(rng)],
        8 => vec!["deny".to_string(), id(rng)],
        9 => vec!["lockdown".to_string()],
        _ => vec!["show-map".to_string()],
    };
    if rng.chance(25) {
        v.push(hostile(rng));
    }
    v
}

/// The fake daemon: one servatui step round per connection — read the
/// client's Command line, reply, read the finalize sentinel, close.
/// The reply draw is seeded per-connection for reproducibility.
fn fake_daemon(listener: UnixListener, seed0: u64, vintage: bool) {
    // Nonblocking accept + idle deadline: the thread RECLAIMS itself
    // once its world goes quiet (an immortal accept loop leaks one
    // thread per seed and exhausts the marathon — the same class the
    // oracle stop seam fixed, handled locally here).
    use std::io::ErrorKind;
    listener.set_nonblocking(true).expect("nonblocking listener");
    let mut conn_n = 0u64;
    let idle_after = Duration::from_secs(3);
    let mut last_activity = Instant::now();
    loop {
        match listener.accept() {
            Ok((conn, _)) => {
                last_activity = Instant::now();
                conn_n += 1;
                let mut rng = Rng(seed0 ^ conn_n.wrapping_mul(0x9E3779B97F4A7C15));
                let Ok(stream) = conn.try_clone() else { continue };
                let mut w = conn;
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
                    continue;
                }
                // The version handshake is the FIXED wire part: an old
                // daemon answers it with a stale version STRING (or
                // its garbage take); everything else is drawn from
                // the taxonomy.
                let version_probe = line.contains("Version") || line.contains("version");
                let lies = vintage || rng.chance(15);
                let reply = if version_probe && !lies {
                    format!(
                        "{{\"type\":\"Version\",\"version\":\"{}\"}}",
                        env!("CARGO_PKG_VERSION")
                    )
                } else {
                    random_reply(&mut rng, vintage)
                };
                let _ = writeln!(w, "{reply}");
                let _ = w.flush();
                let mut sentinel = String::new();
                let _ = reader.read_line(&mut sentinel);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if last_activity.elapsed() > idle_after {
                    break; // world done — reclaim
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
}

fn client_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fuse-client"))
}

/// Spawn the real client; return Some(exit_code) or None on a
/// deadline kill (a hang finding).
fn run_client(socket: &std::path::Path, state_file: &std::path::Path, argv: &[String]) -> Option<i32> {
    let mut cmd = Command::new(client_bin());
    let _ = cmd
        .arg("--socket")
        .arg(socket)
        .args(argv)
        .env("FUSE_GATEKEEPER_STATE", state_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => panic!("spawn fuse-client: {e}"),
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => return status.code(),
            None => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

fn drive_seed(seed: u64, vintage: bool) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("client.sock");
    let state_file = dir.path().join("state.json");
    std::fs::write(&state_file, "{}").unwrap();
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let (l, s) = (listener, seed);
        // Explicit discard: the thread self-reclaims on its idle
        // deadline (nonblocking accept).
        let _ = std::thread::spawn(move || fake_daemon(l, s, vintage));
    }

    let mut rng = Rng(seed.wrapping_mul(0x5DEECE66D) | 1);
    for _ in 0..3 {
        let argv = random_argv(&mut rng);
        let mode = if vintage { "vintage" } else { "fresh" };
        let code = run_client(&sock, &state_file, &argv);
        assert!(
            code.is_some(),
            "seed {seed} ({mode}): fuse-client HUNG on {argv:?} — the daemon wedged the client"
        );
        let c = code.unwrap();
        assert_ne!(
            c, 101,
            "seed {seed} ({mode}): fuse-client PANICKED on {argv:?} — daemon garbage must degrade gracefully"
        );
        assert!(
            c >= 0,
            "seed {seed} ({mode}): fuse-client died by signal ({c}) on {argv:?}"
        );
    }
}

#[test]
fn client_chaos_degrades_gracefully() {
    for seed in 0..64u64 {
        drive_seed(seed, false);
    }
}

#[test]
fn client_chaos_out_of_date_daemon_degrades_gracefully() {
    // The #37/#48 mixed-vintage class, generalized: stale version
    // strings on the fixed wire part, random strings everywhere else.
    for seed in 0..64u64 {
        drive_seed(seed, true);
    }
}

#[test]
#[ignore = "marathon: FUZZ_MINUTES=<n> -- --ignored"]
fn client_chaos_marathon() {
    let minutes: u64 = std::env::var("FUZZ_MINUTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(minutes > 0, "set FUZZ_MINUTES (the marathon is opt-in)");
    let stop = Instant::now() + Duration::from_secs(60 * minutes);
    let mut seed = 0u64;
    while Instant::now() < stop {
        drive_seed(seed, seed.is_multiple_of(2));
        seed += 1;
    }
    eprintln!("client-chaos marathon: {seed} worlds in {minutes} minutes (all held)");
}

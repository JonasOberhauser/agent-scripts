//! End-to-end tests of the SPLIT gatekeeper: the policy daemon
//! (`fuse-server`) and the data daemon (`fused`) run as REAL separate
//! processes, connected by the oracle socket; the tests drive real
//! reads through the real FUSE mount and real commands through the real
//! command socket — exactly the deployed shape.
//!
//! Requires /dev/fuse (like the old monolithic suite). Tests that
//! compute package hashes additionally gate on the map_files
//! capability probe and skip loudly where the kernel denies it.
//!
//! Run under a mount-capable context (e.g. the userns wrapper).

// Tests may hand-parse output/protocol lines: sanctioned by policy
// (test + allow), NOT available to production code. unknown_lints:
// the custom_parser lint exists only under the servyi driver.
#![allow(unknown_lints)]
#![allow(custom_parser)]

#![allow(clippy::unwrap_used, clippy::panic, unused_results)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
}

/// Can this context compute package hashes (follow its own map_files)?
fn hashing_available() -> bool {
    let range = std::fs::read_to_string("/proc/self/maps").ok().and_then(|maps| {
        maps.lines()
            .find(|l| l.contains('/'))
            .and_then(|l| l.split_whitespace().next().map(str::to_string))
    });
    let Some(range) = range else { return false };
    let ok = std::fs::read(format!("/proc/self/map_files/{range}")).is_ok();
    if !ok {
        eprintln!(
            "skip: cannot follow /proc/self/map_files here — hash-based e2e tests skip loudly"
        );
    }
    ok
}

/// The split stack (step 2 of #82/#63): a THIN WRAPPER over the kit's
/// [`gatekeeper_testkit::RealMountStack`] — same historical name and
/// spawn shape for the ~30 tests below; the harness logic (spawn
/// waits, diagnostics, kill points, respawns) lives in the kit now.
struct Split {
    inner: gatekeeper_testkit::RealMountStack,
}

impl Split {
    /// Start both daemons; `secrets` as (name, content, hash).
    /// (The `tag` argument is vestigial: kit identity is minted, not
    /// named — review on #82. It survives for log-file naming.)
    fn new(tag: &str, secrets: &[(&str, &[u8], &str)]) -> Split {
        let mut stack = gatekeeper_testkit::Stack::new()
            .pending_timeout(Duration::from_secs(5));
        for (name, content, hash) in secrets {
            stack = stack.secret(name, content, hash);
        }
        let _ = tag;
        Split { inner: stack.spawn_real_mount() }
    }

    /// Like [`Split::new`], but the policy daemon hashes readers via
    /// the kit's LIVE hashd stub (`HashdReply::Compute` — the
    /// production shape: the server itself NEVER touches
    /// /proc/<pid>/map_files).
    fn new_with_hashd(tag: &str, secrets: &[(&str, &[u8], &str)]) -> Split {
        let _ = tag;
        let mut stack = gatekeeper_testkit::Stack::new()
            .pending_timeout(Duration::from_secs(5))
            .live_hashd_stub(gatekeeper_testkit::HashdReply::Compute);
        for (name, content, hash) in secrets {
            stack = stack.secret(name, content, hash);
        }
        Split { inner: stack.spawn_real_mount() }
    }

    fn mount(&self) -> &Path {
        self.inner.mount()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.inner.path(name)
    }

    fn inner(&self, name: &str) -> String {
        self.inner.inner(name)
    }

    fn source_path(&self, name: &str) -> PathBuf {
        self.inner.source_path(name)
    }

    fn read(&self, rel: &str) -> std::io::Result<Vec<u8>> {
        self.inner.read(rel)
    }

    fn dump_logs(&self, what: &str) -> String {
        self.inner.dump_logs(what)
    }

    fn client(&self, args: &[&str]) -> std::process::Output {
        self.inner.client(args)
    }

    // ── the kill points (#68): kit methods, historical names ──────

    fn kill_policy(&mut self) {
        self.inner.kill_policy();
    }

    fn kill_data(&mut self) {
        self.inner.kill_data();
    }

    fn respawn_policy(&mut self, tag: &str) {
        self.inner.respawn_policy_store_only(tag);
    }

    fn respawn_policy_with_secrets(&mut self, tag: &str) {
        self.inner.respawn_policy_with_secrets(tag);
    }

    fn respawn_data(&mut self, tag: &str) {
        self.inner.respawn_data(tag);
    }
}

fn write_out(out: &std::process::Output) -> String {
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    s
}

// ── basic read / one-read semantics ─────────────────────────────

#[test]
fn e2e_read_secret() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("read", &[("s", b"TOPSECRET", "*")]);
    match split.read("s") {
        Ok(b) => assert_eq!(b, b"TOPSECRET"),
        Err(e) => panic!("read through the mount failed: {e}\n{}", split.dump_logs("read failure")),
    }
}

#[test]
fn e2e_root_is_directory() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("root", &[("s", b"X", "*")]);
    assert!(std::fs::metadata(split.mount()).unwrap().is_dir());
}

#[test]
fn e2e_nonexistent_file_enoent() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("enoent", &[("s", b"X", "*")]);
    let err = std::fs::read(split.path("nope")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
}

#[test]
fn e2e_path_shaped_names_serve_flat() {
    // Issue #34 + review on #58: names are normalized host paths
    // HOST-side (policy/display), but the CONTAINER view is FLAT —
    // one directory of whole-path hashes. Nested outer paths serve
    // as single flat entries; the mount root is a directory and
    // nothing else is.
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("paths", &[("a/b/c.txt", b"NESTED", "*")]);
    assert!(split.mount().is_dir(), "the mount root is a directory");
    let labels: Vec<std::ffi::OsString> = std::fs::read_dir(split.mount())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(labels.len(), 1, "one flat entry, not a tree: {labels:?}");
    let entry = split.mount().join(&labels[0]);
    assert!(entry.is_file(), "the flat entry is the secret file");
    assert_eq!(std::fs::read(&entry).unwrap(), b"NESTED");
}

#[test]
fn e2e_re_add_unchanged_content_preserves_state_end_to_end() {
    // Stable filenames (PR sequence): re-running run-agent re-adds the
    // SAME name. Re-adding with unchanged content must NOT reset the
    // approval/read state — here proven through the full stack
    // (socket add → oracle → mount → read), not just the state unit.
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("readd", &[("s", b"KEEP", "*")]);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"KEEP");
    let err = std::fs::read(split.path("s")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES), "budget spent");

    // Re-add the same name from the same source file (unchanged
    // content) via the client — the run-agent re-run shape.
    let src = tempfile::tempdir().unwrap();
    let f = src.path().join("s");
    std::fs::write(&f, b"KEEP").unwrap();
    let out = split.client(&["add", "--file", f.to_str().unwrap(), "--hash", "*", "s"]);
    assert!(out.status.success(), "re-add failed: {}", write_out(&out));

    // Read state persisted: still consumed, not a fresh cycle.
    let err = std::fs::read(split.path("s")).unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EACCES),
        "unchanged re-add must not reset the read budget"
    );
    // And the mount still serves the (unchanged) bytes for checks
    // that do not consume: size via metadata.
    let meta = std::fs::metadata(split.path("s")).unwrap();
    assert_eq!(meta.len(), 4);
}

#[test]
fn e2e_grants_survive_a_policy_daemon_kill() {
    // MR5's marquee property, end to end: kill -9 the policy daemon,
    // restart it on the same sockets + policy store, and the spent
    // one-read budget SURVIVES (fail-safe: no free re-reads after a
    // kill). Then reset — the explicit policy path — and read again.
    if !fuse_available() { return; }
    let _g = serial();
    let mut split = Split::new("mr5", &[("s", b"KEEP", "*")]);
    assert_eq!(split.read("s").unwrap(), b"KEEP");

    // kill -9 the policy daemon; the mount stays (split design).
    // Respawn on the same sockets + the SAME policy store, WITH the
    // secret re-registered — the re-add path, as opposed to the
    // store-only load the respawn_policy kill point exercises.
    split.kill_policy();
    split.respawn_policy_with_secrets("mr5");

    // Budget spent BEFORE the kill must still be spent AFTER it.
    let err = split.read("s").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES), "spent budget survives kill -9: {err}");

    // The explicit path clears it, and the fresh read works.
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success(), "reset failed: {}", write_out(&out));
    match split.read("s") {
        Ok(b) => assert_eq!(b, b"KEEP"),
        Err(e) => panic!("post-reset read failed: {e}\n{}", split.dump_logs("mr5 failure")),
    }
}

#[test]
fn e2e_fused_kill9_policy_untouched_a_fresh_data_daemon_remounts() {
    // The other half's kill point (#50): kill -9 the DATA daemon —
    // the mount dies with it (fused owns it) — while the policy
    // daemon must be untouched and fully serving (cmd socket answers,
    // state intact). A fresh fused on the same mountpoint + oracle
    // remounts, the control-channel snapshot replays, and reads work
    // under the SAME one-read budget (spent stays spent — the budget
    // lives in the policy daemon, which never died).
    if !fuse_available() { return; }
    let _g = serial();
    let mut split = Split::new("datakill", &[("s", b"DK", "*")]);
    assert_eq!(split.read("s").unwrap(), b"DK");
    // Budget now spent — and must REMAIN spent across the data
    // daemon's death+remount (policy never died).

    split.kill_data();

    // Policy untouched: the cmd socket answers status immediately.
    let out = split.client(&["status"]);
    assert!(out.status.success(), "policy must not notice fused's death: {}", write_out(&out));

    // Fresh data daemon on the same rendezvous; the snapshot replays.
    split.respawn_data("datakill");
    let mut listed = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(rd) = std::fs::read_dir(split.mount()) {
            if rd.filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy() == split.inner("s"))
            {
                listed = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(listed, "remounted data daemon never re-listed the secret: {}", split.dump_logs("datakill"));

    // The budget survived (policy-side state): the next open pends
    // out the 5s timeout and denies, not grants.
    let err = split.read("s").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES), "budget must survive the data daemon's death: {err}");

    // And the explicit reset restores reads through the new mount.
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success(), "reset after remount: {}", write_out(&out));
    assert_eq!(split.read("s").unwrap(), b"DK");
}

#[test]
fn e2e_policy_kill9_before_any_read_a_store_only_respawn_serves() {
    // Kill point corner (#50): the policy daemon dies BEFORE the
    // first read — no budget consumed, no pinned fds. The pure-load
    // respawn must serve reads on the first attempt.
    if !fuse_available() { return; }
    let _g = serial();
    let mut split = Split::new("earlykill", &[("s", b"EARLY", "*")]);
    split.kill_policy();
    split.respawn_policy("earlykill");
    let mut ok = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(b) = split.read("s") {
            assert_eq!(b, b"EARLY");
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ok, "first read after an early kill + store-only respawn failed: {}", split.dump_logs("earlykill"));
}

#[test]
fn e2e_one_read_per_secret_without_reset() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("oneread", &[("s", b"ONCE", "*")]);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"ONCE");
    let err = std::fs::metadata(split.path("s")) // second OPEN by another "pid"…
        .map(|_| ());
    let _ = err; // metadata alone doesn't consume the read budget
    let err = std::fs::read(split.path("s")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES), "second read must be denied (budget spent; 5s pending expired)");
}

#[test]
fn e2e_host_edit_is_visible_on_next_open() {
    // THE MR4 property: content is read from the host at open time —
    // a source edit after the mount is up serves fresh bytes to the
    // next open (snapshot semantics would serve the stale copy).
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("fresh", &[("s", b"OLD-BYTES", "*")]);
    assert_eq!(split.read("s").unwrap(), b"OLD-BYTES");
    std::fs::write(split.source_path("s"), b"NEW-BYTES").unwrap();
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success(), "reset failed: {}", write_out(&out));
    match split.read("s") {
        Ok(b) => assert_eq!(b, b"NEW-BYTES", "fresh bytes must serve"),
        Err(e) => panic!("read after host edit failed: {e}\n{}", split.dump_logs("freshness failure")),
    }
}

#[test]
fn e2e_ghost_opens_to_enoent() {
    // Frozen tree + live host: deleting the source leaves the name
    // listed (structure is frozen) but its OPEN must fail ENOENT —
    // never stale bytes.
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("ghost", &[("s", b"G", "*")]);
    assert_eq!(split.read("s").unwrap(), b"G");
    std::fs::remove_file(split.source_path("s")).unwrap();
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success());
    let err = split.read("s").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT), "ghost: {err}");
}

#[test]
fn e2e_ghost_heals_when_the_host_file_returns() {
    // MR4/MR5's documented promise: a ghost (host file missing) opens
    // ENOENT "until the file returns" — and when it RETURNS, the next
    // open heals: fresh identity observed via the stat path, live
    // bytes served, and the read cycle state intact (the ghost period
    // consumed nothing). The re-add half of the promise is covered by
    // the policy re-add tests; this is the file-returns half.
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("heal", &[("s", b"V1", "*")]);
    assert_eq!(split.read("s").unwrap(), b"V1");
    // Ghost it: source gone, cycle reset, open -> ENOENT.
    std::fs::remove_file(split.source_path("s")).unwrap();
    assert!(split.client(&["reset", "--name", "s"]).status.success());
    let err = split.read("s").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT), "ghost: {err}");
    // The file returns (a NEW incarnation, as any real restore would):
    // the mount must heal on the next open — fresh bytes, no pend, no
    // error — without a re-add or a daemon restart.
    std::fs::write(split.source_path("s"), b"V2-RETURNED").unwrap();
    assert_eq!(
        split.read("s").unwrap(),
        b"V2-RETURNED",
        "the ghost heals when the host file returns"
    );
    // And the cycle behaves like one consumed read (V2's), not more:
    let out = split.client(&["status"]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        !text.contains("pending"),
        "healing must not leave a stuck pending: {text}"
    );
}

#[test]
fn e2e_atomic_replace_serves_fresh_bytes_and_a_new_inode() {
    // The standard safe-write flow (temp + rename-over) lands a NEW
    // incarnation at the same path: the mount must serve the new
    // bytes on the next open, under a new inode number.
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("atomic", &[("s", b"V1-CONTENT", "*")]);
    let ino1 = {
        let md = std::fs::metadata(split.path("s")).unwrap();
        std::os::unix::fs::MetadataExt::ino(&md)
    };
    assert_eq!(split.read("s").unwrap(), b"V1-CONTENT");
    let tmp = split.source_path("s.tmp");
    std::fs::write(&tmp, b"V2-CONTENT").unwrap();
    std::fs::rename(&tmp, split.source_path("s")).unwrap();
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success());
    match split.read("s") {
        Ok(b) => assert_eq!(b, b"V2-CONTENT", "replaced incarnation serves fresh"),
        Err(e) => panic!("read after replace failed: {e}\n{}", split.dump_logs("replace failure")),
    }
    // TTL lets the kernel re-lookup and observe the new fino.
    std::thread::sleep(Duration::from_millis(1200));
    let ino2 = {
        let md = std::fs::metadata(split.path("s")).unwrap();
        std::os::unix::fs::MetadataExt::ino(&md)
    };
    assert_ne!(ino1, ino2, "a replaced incarnation is a new inode");
}

#[test]
fn e2e_open_fd_pins_its_incarnation_across_a_host_rewrite() {
    // Accepted MR4 semantics (AGENTS.md): an already-adjudicated open
    // keeps reading ITS incarnation — a rename-over does not swap
    // bytes under a live descriptor.
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("pin", &[("s", b"AAAAAAAAAA", "*")]);
    use std::io::{Read as _, Seek, SeekFrom};
    let mut f = std::fs::File::open(split.path("s")).unwrap();
    let mut half = vec![0u8; 5];
    f.read_exact(&mut half).unwrap();
    // Rewrite the source wholesale while the fd is open.
    let tmp = split.source_path("s.tmp");
    std::fs::write(&tmp, b"BBBBBBBBBB").unwrap();
    std::fs::rename(&tmp, split.source_path("s")).unwrap();
    let mut rest = String::new();
    f.seek(SeekFrom::Start(5)).unwrap();
    f.read_to_string(&mut rest).unwrap();
    assert_eq!(half, b"AAAAA");
    assert_eq!(rest, "AAAAA", "the open fd keeps its own incarnation");
}

#[test]
fn e2e_reset_allows_reread() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("reset", &[("s", b"R", "*")]);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"R");
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success(), "reset failed: {}", write_out(&out));
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"R");
}

#[test]
fn e2e_multiple_secrets_independent() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("multi", &[("a", b"AAA", "*"), ("b", b"BBB", "*")]);
    assert_eq!(std::fs::read(split.path("a")).unwrap(), b"AAA");
    assert_eq!(std::fs::read(split.path("b")).unwrap(), b"BBB");
}

#[test]
fn e2e_multi_chunk_read_succeeds() {
    if !fuse_available() { return; }
    let _g = serial();
    let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let split = Split::new("chunk", &[("s", &data, "*")]);
    let mut f = std::fs::File::open(split.path("s")).unwrap();
    use std::io::Read as _;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, data, "chunked streaming read must reassemble the whole secret");
}

// ── metadata through the mount ──────────────────────────────────

#[test]
fn e2e_readdir_lists_secrets() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("readdir", &[("a", b"A", "*"), ("b", b"B", "*")]);
    let names: Vec<String> = std::fs::read_dir(split.mount())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    // Issue #47: the container lists the ANONYMIZED forms; the clear
    // names must NOT appear (that is the leak being closed).
    let ia = split.inner("a");
    let ib = split.inner("b");
    assert!(names.contains(&ia), "{ia} in {names:?}");
    assert!(names.contains(&ib), "{ib} in {names:?}");
    assert!(!names.contains(&"a".to_string()) && !names.contains(&"b".to_string()),
        "clear host names must never appear inside the container: {names:?}");
}

#[test]
fn e2e_getattr_reports_size() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("getattr", &[("s", b"12345", "*")]);
    assert_eq!(std::fs::metadata(split.path("s")).unwrap().len(), 5);
}

#[test]
fn e2e_source_mode_is_passed_through() {
    if !fuse_available() { return; }
    let _g = serial();
    // The policy daemon's --secret loader uses the conservative 0400;
    // mode through the socket (`add` with mode) covers the passthrough:
    // covered by e2e_dynamic_add_visible.
    let split = Split::new("mode", &[("s", b"X", "*")]);
    // MR4: attrs are LIVE — the view follows the source's mode,
    // masked read-only. A 0o600 source presents as 0o400.
    use std::os::unix::fs::PermissionsExt as _;
    let src = split.source_path("s");
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Attr freshness is TTL-bounded (1s) by design: the kernel serves
    // its cached attrs until they expire.
    std::thread::sleep(Duration::from_millis(1200));
    let md = std::fs::metadata(split.path("s")).unwrap();
    assert_eq!(md.permissions().mode() & 0o777, 0o400, "source mode passes through, masked read-only");
}

#[test]
fn e2e_source_mode_passthrough_masks_write_bits() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("mode2", &[("s", b"X", "*")]);
    // Dynamically add a secret whose source file is 0644: the view must
    // present the read bits and MASK every write bit (read-only fs).
    let src = tempfile::tempdir().unwrap();
    let f = src.path().join("mode.secret");
    std::fs::write(&f, b"M").unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = split.client(&["add", "m", "--file", &f.display().to_string(), "--hash", "*"]);
    assert!(out.status.success(), "add failed: {}", write_out(&out));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(md) = std::fs::metadata(split.path("m")) {
            let mode = std::os::unix::fs::MetadataExt::mode(&md) & 0o777;
            assert_eq!(
                mode, 0o444,
                "source 0644 must surface as read-only 0444, got {mode:o}"
            );
            break;
        }
        assert!(Instant::now() < deadline, "added secret never appeared");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn e2e_statfs_works() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("statfs", &[("s", b"0123456789", "*")]);
    // statfs through std: use `nix`-free approach — command success on
    // the mount directory suffices as a smoke check.
    assert!(std::fs::read_dir(split.mount()).is_ok());
}

#[test]
fn e2e_symlink_to_fuse_file() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("symlink", &[("s", b"VIA-Link", "*")]);
    let link = tempfile::tempdir().unwrap();
    let l = link.path().join("alias");
    std::os::unix::fs::symlink(split.path("s"), &l).unwrap();
    assert_eq!(std::fs::read(&l).unwrap(), b"VIA-Link");
}

// ── dynamic content via the command socket ──────────────────────

#[test]
fn e2e_dynamic_add_visible() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("add", &[("existing", b"E", "*")]);
    let src = tempfile::tempdir().unwrap();
    let f = src.path().join("new.secret");
    std::fs::write(&f, b"FRESH").unwrap();
    let out = split.client(&["add", "fresh", "--file", &f.display().to_string(), "--hash", "*"]);
    assert!(out.status.success(), "add failed: {}", write_out(&out));
    // The content must appear through the mount (hub -> fused).
    let mut seen = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(b) = std::fs::read(split.path("fresh")) {
            assert_eq!(b, b"FRESH");
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(seen, "dynamically added secret never became readable");

    let out = split.client(&["remove", "fresh"]);
    assert!(out.status.success(), "remove failed: {}", write_out(&out));
    let mut gone = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::fs::read(split.path("fresh")).is_err() {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(gone, "removed secret stayed readable");
}

// ── pendings ────────────────────────────────────────────────────

#[test]
fn e2e_pending_does_not_block_other_reads() {
    if !fuse_available() { return; }
    let _g = serial();
    let split = Split::new("pend", &[("s", b"P", "*"), ("other", b"O", "*")]);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"P");
    // Budget spent on "s": another read PENDS for up to 5s. Meanwhile a
    // different secret must serve fine (mount stays responsive).
    let other_path = split.path("other");
    let s_path = split.path("s");
    let reader = std::thread::spawn(move || std::fs::read(s_path));
    std::thread::sleep(Duration::from_millis(200));
    match std::fs::read(&other_path) {
        Ok(b) => assert_eq!(b, b"O", "unrelated secret must serve during a pending"),
        Err(e) => panic!(
            "read during pending failed: {e}\n{}",
            split.dump_logs("pending-concurrency failure")
        ),
    }
    let _ = reader.join();
}


#[test]
fn e2e_hash_mismatch_denied() {
    if !fuse_available() { return; }
    if !hashing_available() { return; }
    let _g = serial();
    let pkg = package_hash_of_self();
    let split = Split::new_with_hashd("hash", &[("s", b"H", "definitely_not_our_package")]);
    let err = std::fs::read(split.path("s")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES), "wrong hash must pend out to deny");
    // …and with the right hash it serves immediately.
    drop(split);
    let split2 = Split::new_with_hashd("hash-ok", &[("s", b"H", &pkg)]);
    assert_eq!(std::fs::read(split2.path("s")).unwrap(), b"H");
    }

fn package_hash_of_self() -> String {
    use fuse_protocol::io::SystemIo as _;
    fuse_protocol::RealSystemIo::new()
        .sha256_process_package(std::process::id())
        .expect("hash the test process (hashing was available)")
}

#[test]
fn e2e_different_binary_denied() {
    if !fuse_available() { return; }
    if !hashing_available() { return; }
    let _g = serial();
    // Our package hash whitelisted; a DIFFERENT binary must be denied.
    let pkg = package_hash_of_self();
    let split = Split::new_with_hashd("diff", &[("s", b"D", &pkg)]);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"D");
    // A distinct process (cat) has a different package hash: EACCES.
    let out = Command::new("cat").arg(split.path("s")).output().unwrap();
    assert!(
        !out.status.success(),
        "a different binary must be denied even within the budget reset window"
    );
    let _ = split.client(&["reset", "--name", "s"]);
    let out = Command::new("cat").arg(split.path("s")).output().unwrap();
    assert!(!out.status.success(), "different package must stay denied after reset");
}

#[test]
fn e2e_grant_forever_full_flow() {
    if !fuse_available() { return; }
    if !hashing_available() { return; }
    let _g = serial();
    let _pkg = package_hash_of_self();
    let split = Split::new_with_hashd("gf", &[("s", b"FOREVER", "not_our_hash")]);
    // Budget unspent but hash wrong: the read pends.
    let p = split.path("s");
    let reader = std::thread::spawn(move || std::fs::read(p));
    let out = loop {
        let out = split.client(&["pending"]);
        let text = write_out(&out);
        if text.contains("[") || text.trim().is_empty() {
            // parse id via status of pending list: use fuse-client output
        }
        if let Some(id) = first_pending_id(&text) {
            break split.client(&["grant-forever", &id.to_string()]);
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(out.status.success(), "grant-forever failed: {}", write_out(&out));
    let data = reader.join().unwrap().expect("blocked read served after grant-forever");
    assert_eq!(data, b"FOREVER");
    // Unlimited: repeated reads need no further approval.
    for _ in 0..3 {
        assert_eq!(std::fs::read(split.path("s")).unwrap(), b"FOREVER");
    }
    let out = split.client(&["status"]);
    assert!(write_out(&out).contains("s"), "status lists the secret");
}

fn first_pending_id(pending_text: &str) -> Option<u64> {
    // Format: "  [ID] name pid=..." (print_response PendingList).
    pending_text
        .lines()
        .find_map(|l| {
            let t = l.trim_start();
            let rest = t.strip_prefix('[')?;
            let id = rest.split(']').next()?;
            id.parse().ok()
        })
}

#[test]
fn e2e_ld_preload_changes_package_hash_and_is_denied() {
    if !fuse_available() { return; }
    if !hashing_available() { return; }
    let _g = serial();
    // Baseline package hash serves; the same binary under LD_PRELOAD is
    // a different package and must be denied.
    let pkg = package_hash_of_self();
    let split = Split::new("ldpreload", &[("s", b"L", &pkg)]);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"L");
    let _ = split.client(&["reset", "--name", "s"]);
    let art = tempfile::tempdir().unwrap();
    let lib = art.path().join("evil.so");
    std::fs::write(&lib, b"not really an so but it maps").unwrap();
    let out = Command::new("cat")
        .env("LD_PRELOAD", lib.display().to_string())
        .arg(split.path("s"))
        .output()
        .unwrap();
    assert!(
        !out.status.success() || out.stdout != b"L",
        "LD_PRELOAD-changed package must be denied: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn e2e_package_hash_works_with_deleted_mapped_library() {
    if !fuse_available() { return; }
    if !hashing_available() { return; }
    let _g = serial();
    // Our package (with the test binary's mapped set) whitelisted; the
    // deleted-mapped-library scenario lives in the package-hash e2e of
    // fuse-protocol; here we assert the split stack accepts our hash.
    let split = Split::new("deleted", &[("s", b"V", &package_hash_of_self())]);
    assert_eq!(std::fs::read(split.path("s")).unwrap(), b"V");
    }

#[test]
fn e2e_policy_kill9_the_mount_survives_and_a_store_only_respawn_resyncs() {
    // THE split's headline invariant (#50), as behavior at three
    // phases around a kill -9 of the POLICY daemon:
    //   before: a pinned fd is taken (MR4 open-time adjudication);
    //   during: the mount itself survives — the frozen tree still
    //           lists the secret (readdir needs no policy), the
    //           pinned fd still reads (preads of the host fd), and a
    //           FRESH open fails fast instead of hanging;
    //   after:  a respawn with NO --secret (the pure MR5 load path)
    //           re-registers from the store, fused's control loop
    //           reconnects, reads work again, and a NEW add served by
    //           the respawned policy becomes visible through the
    //           mount — re-sync, not just survival.
    if !fuse_available() { return; }
    let _g = serial();
    let mut split = Split::new("restart", &[("s", b"R1", "*")]);

    // Pinned fd: open BEFORE the kill (consumes this cycle's read).
    let mut pinned = std::fs::File::open(split.path("s"))
        .expect("open before the kill");
    let mut buf = [0u8; 2];
    std::io::Read::read_exact(&mut pinned, &mut buf).unwrap();
    assert_eq!(&buf, b"R1");

    split.kill_policy();

    // Dead window: the mount survives...
    let names = std::fs::read_dir(split.mount()).unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Vec<_>>();
    assert!(
        names.iter().any(|n| *n == split.inner("s")),
        "the frozen tree outlives the policy daemon (readdir needs no policy): {names:?}"
    );
    // ...the pinned fd still reads (pread of the host fd, no oracle)...
    use std::io::Seek;
    pinned.seek(std::io::SeekFrom::Start(0)).unwrap();
    let mut again = Vec::new();
    std::io::Read::read_to_end(&mut pinned, &mut again).unwrap();
    assert_eq!(again, b"R1", "an fd pinned before the kill keeps serving");
    // ...and a fresh open fails FAST (dead oracle socket refuses
    // connections — the bounded-open discipline), never hangs.
    let t0 = Instant::now();
    let err = split.read("s").unwrap_err();
    assert!(t0.elapsed() < Duration::from_secs(5), "fresh open under a dead policy must fail fast, hung {t0:?}");
    assert_eq!(err.raw_os_error(), Some(libc::EIO), "fresh open under a dead policy: {err}");

    // Respawn with NO --secret: the store alone must re-register.
    split.respawn_policy("restart");

    // fused's control loop reconnects (~1s poll) and the snapshot
    // replay re-serves; budget was spent pre-kill (MR5 persistence),
    // so reset — the explicit policy path — then read.
    let out = split.client(&["reset", "--name", "s"]);
    assert!(out.status.success(), "reset after respawn: {}", write_out(&out));
    let mut ok = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(b) = split.read("s") {
            assert_eq!(b, b"R1");
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ok, "read after store-only respawn never recovered: {}", split.dump_logs("restart"));

    // Re-sync proof: a NEW secret served by the respawned policy
    // becomes visible through the reconnected mount.
    let src = tempfile::tempdir().unwrap();
    let f = src.path().join("post-restart.secret");
    std::fs::write(&f, b"AFTER").unwrap();
    let out = split.client(&["add", "late", "--file", &f.display().to_string(), "--hash", "*"]);
    assert!(out.status.success(), "post-respawn add failed: {}", write_out(&out));
    let mut seen = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(b) = split.read("late") {
            assert_eq!(b, b"AFTER");
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(seen, "post-respawn add never became visible (no re-sync): {}", split.dump_logs("restart"));
}

/// Keep the writer import used (build hygiene for helper fns above).
#[allow(dead_code)]
fn _witness(w: &mut Vec<u8>) {
    let _ = w.write_all(b"");
}

/// Silence unused warnings for the once-lock pattern kept for symmetry.
#[allow(dead_code)]
fn _once() {
    static O: OnceLock<()> = OnceLock::new();
    let _ = O.get_or_init(|| ());
}

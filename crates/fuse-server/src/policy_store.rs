//! MR5 (issue #34): policy persistence. The permitted-hash sets with
//! provenance, the served names and their host paths, and the
//! one-read access state survive daemon death — `kill -9` has no
//! shutdown hook, so persistence is WRITE-THROUGH on every mutation,
//! never a shutdown flush.
//!
//! The file is daemon-owned (the CLI is the editor; hand-edits are
//! the stop-daemon → edit → start escape hatch — restart IS the
//! reload). Load happens once, at startup, before any socket accepts
//! a request; a grant decided against unloaded state is the bug
//! class this module exists to kill.
//!
//! Location: `$FUSE_GATEKEEPER_POLICY` override, else
//! `$XDG_STATE_HOME/gatekeeper/policy.json`, else
//! `~/.local/state/gatekeeper/policy.json` — state, not config
//! (never hand-edited concurrently, not portable), and never /tmp
//! (tmpfiles/tmpfs wipe on reboot would defeat the point).

use std::io::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::state::{PermittedHash, SecretRecord, ServerState};

use crate::oracle_service::OracleHub;

/// The on-disk shape. Access state persists as `access_count` and
/// `unlimited` only: `reading_pid`/`read_progress` describe a live
/// stream, and no fd survives a restart.
#[derive(Serialize, Deserialize)]
struct PolicyFile {
    version: String,
    /// Per-install anonymization salt (issue #47), hex. Absent in
    /// pre-#47 files: minted on first save after the load.
    #[serde(default)]
    salt: String,
    secrets: Vec<PolicySecret>,
}

#[derive(Serialize, Deserialize)]
struct PolicySecret {
    name: String,
    host_path: PathBuf,
    mode: u32,
    #[serde(default)]
    hashes: Vec<PolicyHash>,
    #[serde(default)]
    access_count: u64,
    #[serde(default)]
    unlimited: bool,
}

#[derive(Serialize, Deserialize)]
struct PolicyHash {
    hash: String,
    by: Option<String>,
}

/// Resolved persistence location (see module docs).
pub fn policy_path() -> PathBuf {
    if let Some(p) = std::env::var_os(fuse_protocol::ENV_POLICY_FILE) {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").unwrap_or_default();
            PathBuf::from(home).join(".local").join("state")
        });
    base.join("gatekeeper").join("policy.json")
}

/// Load policy into `state` (and announce the tree to a connected
/// data daemon) — startup only, before sockets accept.
///
/// - missing file → fresh start (first boot)
/// - unparsable file → renamed aside (`.corrupt-<ts>`) and a FRESH
///   start, loudly: losing grants fails SAFE (reads pend again);
///   never resurrect half-parsed ones
/// - UNREADABLE file (any non-`NotFound` error: wrong owner, EISDIR,
///   …) → PERSISTENCE REFUSES TO ARM: the daemon serves fresh but
///   never writes, so the first mutation cannot rename OVER a store
///   we could not read — evidence and recoverable grants survive
///   until a human looks. (Review #57: arming after an unreadable
///   load used to silently destroy the file.)
/// - host file missing → the secret loads as a GHOST: policy (hashes,
///   provenance, budget) survives, the name is served with identity
///   no identity, opens answer ENOENT until the file returns or run-agent
///   re-adds (plain overwrite joins the hash set — nothing lost)
pub fn load(state: &mut ServerState, hub: &OracleHub) -> LoadReport {
    let path = state
        .policy_path
        .clone()
        .unwrap_or_else(policy_path);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("policy store {}: no file — fresh start", path.display());
            persist_locked(state);
            return LoadReport::default();
        }
        Err(e) => {
            tracing::error!(
                "policy store {}: unreadable ({e}) — starting FRESH with persistence                  DISARMED: nothing will overwrite a store this daemon cannot read.                  Fix the file (ownership?) and restart to re-arm.",
                path.display()
            );
            state.policy_path = None;
            return LoadReport { unreadable: true, ..Default::default() };
        }
    };
    // A policy store is small (names + hashes). Anything huge is
    // damage (truncation-into-sparse, a dd typo): classify as
    // corrupt rather than attempt a multi-GB parse.
    const MAX_POLICY_BYTES: usize = 8 << 20;
    if data.len() > MAX_POLICY_BYTES {
        tracing::error!(
            "policy store {}: {} bytes exceeds the {} sanity bound — treating as corrupt",
            path.display(),
            data.len(),
            MAX_POLICY_BYTES
        );
        persist_locked(state);
        return LoadReport { corrupted: true, ..Default::default() };
    }
    let file: PolicyFile = match serde_json::from_slice(&data) {
        Ok(f) => f,
        Err(e) => {
            let aside = path.with_extension(format!(
                "corrupt-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            ));
            tracing::error!(
                "policy store {}: unparsable ({e}) — renamed aside to {} and starting \
                 FRESH. Lost grants fail safe: affected reads will pend again.",
                path.display(),
                aside.display()
            );
            let _ = std::fs::rename(&path, &aside);
            persist_locked(state);
            return LoadReport { corrupted: true, ..Default::default() };
        }
    };
    if file.version != fuse_protocol::VERSION {
        tracing::warn!(
            "policy store written by v{} (daemon v{}); loading anyway",
            file.version,
            fuse_protocol::VERSION
        );
    }
    // Anonymization salt (issue #47): from the store when present
    // (stable container-view names across restarts); minted on the
    // first #47 boot — pre-#47 stores have no salt, and their inner
    // names did not exist yet, so nothing rotates that mattered.
    // The salt TYPE is non-empty by construction: a stored salt is
    // adopted, an absent one keeps the freshly generated salt the
    // state was born with. mint_salt_if_needed is gone — the type
    // does the enforcing now (review on #58).
    if let Some(salt) = fuse_protocol::Salt::from_bytes(hex_to_bytes(&file.salt)) {
        state.anon_salt = salt;
    } else {
        tracing::info!("policy store: no salt stored — keeping the freshly minted one (issue #47)");
        persist_locked(state);
    }
    let mut report = LoadReport::default();
    for s in file.secrets {
        // A live host file re-registers with its CURRENT identity
        // (the MR4 stat path); a missing one becomes a ghost with
        // no identity. Either way the loaded POLICY lands intact.
        // A live host file re-registers with its CURRENT identity
        // (the MR4 stat path); a missing one is a GHOST: announced
        // with NO identity — absence is Option, not an in-band (0,0)
        // sentinel — until the first stat-on-lookup discovers it.
        let (size, live) = match std::fs::metadata(&s.host_path) {
            Ok(md) if md.is_file() => (md.len() as usize, true),
            _ => (0, false),
        };
        let ghost = !live;
        if ghost {
            report.ghosts += 1;
        } else {
            report.restored += 1;
        }
        state.secrets.insert(
            s.name.clone(),
            std::sync::Arc::new(std::sync::Mutex::new(SecretRecord {
                host_path: s.host_path.clone(),
                size,
                allowed_hashes: s
                    .hashes
                    .into_iter()
                    .map(|h| PermittedHash { hash: h.hash, by: h.by })
                    .collect(),
                access_count: s.access_count,
                reading_pid: None,
                read_progress: 0,
                mode: s.mode,
                unlimited_reads: s.unlimited,
            })),
        );
        let inner = fuse_protocol::anonymize_path(&state.anon_salt, &s.name);
        hub.serve(&s.name, &inner, s.mode);
    }
    report
}

/// What the startup load found.
#[derive(Default)]
pub struct LoadReport {
    pub restored: usize,
    pub ghosts: usize,
    pub corrupted: bool,
    /// The store existed but could not be read: persistence refused
    /// to arm — nothing will overwrite it.
    pub unreadable: bool,
}

/// Write the policy atomically: temp file in the same directory,
/// fsync, rename. Callers treat failure as loud-but-nonfatal — a
/// grant that fails to persist is lost on restart, but failing the
/// operation would turn a full disk into "you may not approve
/// anything".
pub fn persist(state: &ServerState) {
    let _pl = state.persist_lock.lock().unwrap();
    persist_locked(state);
}

/// Snapshot + atomic write, assuming the caller holds the mutation
/// lock (every mutating method does — mutation then persistence in
/// program order, snapshots totally ordered).
pub(crate) fn persist_locked(state: &ServerState) {
    let Some(path) = state.policy_path.clone() else {
        return; // persistence not armed (tests, harnesses)
    };
    let mut file = PolicyFile {
        version: fuse_protocol::VERSION.to_string(),
        salt: bytes_to_hex(state.anon_salt.as_bytes()),
        secrets: Vec::new(),
    };
    for entry in state.secrets.iter() {
        let rec = crate::state::lock_secret(entry.value(), entry.key());
        file.secrets.push(PolicySecret {
            name: entry.key().clone(),
            host_path: rec.host_path.clone(),
            mode: rec.mode,
            hashes: rec
                .allowed_hashes
                .iter()
                .map(|ph| PolicyHash { hash: ph.hash.clone(), by: ph.by.clone() })
                .collect(),
            access_count: rec.access_count,
            unlimited: rec.unlimited_reads,
        });
    }
    let json = match serde_json::to_vec_pretty(&file) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("policy store {}: serialization failed: {e}", path.display());
            return;
        }
    };
    if let Err(e) = write_atomic(&path, &json) {
        tracing::error!(
            "policy store {}: write failed ({e}) — the change lives in memory only \
             and will be lost on restart",
            path.display()
        );
    }
}


fn hex_to_bytes(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .filter_map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(dir)?;
    // Exclusive-create, 0600 FROM THE FIRST BYTE (review: the old
    // path wrote content world-readable and chmod'ed afterwards), and
    // collision-proof (tempfile owns exclusivity — the hand-rolled
    // pid-suffixed name collided between same-process threads).
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    // persist() renames over the target; on any failure the temp is
    // dropped (unlinked) — no leaked `.tmp-*` litter (review).
    tmp.persist(path)
        .map_err(|e| e.error)?;
    // Directory fsync: durability of the rename by construction
    // instead of per-filesystem arguments (review). Some filesystems
    // reject directory fsync — that refusal is not an error here.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

// ── MR5: policy persistence ────────────────────────────────────

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::state::ServerState;

    fn temp_store(tag: &str) -> (std::path::PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(format!("policy-{tag}.json"));
        (p.clone(), dir)
    }

    fn armed_state(path: &std::path::Path) -> ServerState {
        let mut s = ServerState::new();
        s.policy_path = Some(path.to_path_buf());
        s
    }

    /// Read the persisted store back and return its salt field.
    fn persisted_salt(p: &std::path::Path) -> String {
        let f: PolicyFile =
            serde_json::from_slice(&std::fs::read(p).unwrap()).expect("store parses");
        assert!(!f.salt.is_empty(), "the salt must never persist empty");
        f.salt
    }

    #[test]
    fn salt_is_minted_and_persisted_on_fresh_boot() {
        // Claim (#58): fresh boot (no store file) mints a salt and
        // persists it IMMEDIATELY — the first registration derives
        // inner names from it, so the store must already carry it.
        let (p, _d) = temp_store("salt-fresh");
        let mut s = armed_state(&p);
        let hub = crate::oracle_service::OracleHub::new();
        assert!(!p.exists(), "no store yet");
        load(&mut s, &hub);
        assert!(!s.anon_salt.as_bytes().is_empty(), "salt minted in memory");
        assert_eq!(persisted_salt(&p), bytes_to_hex(s.anon_salt.as_bytes()),
            "the minted salt is persisted before any registration");
    }

    #[test]
    fn salt_is_minted_on_corrupt_aside_and_differs_from_the_lost_one() {
        // Claim: a corrupt store is renamed aside and the fresh start
        // mints its OWN salt (nothing from the corrupt file can be
        // trusted, including its salt).
        let (p, _d) = temp_store("salt-corrupt");
        let old_salt = "deadbeef".repeat(8);
        // Unparsable content that still references the lost salt.
        std::fs::write(&p, format!("<garbage salt={old_salt} not json")).unwrap();
        let mut s = armed_state(&p);
        let hub = crate::oracle_service::OracleHub::new();
        let report = load(&mut s, &hub);
        assert!(report.corrupted, "aside happened");
        assert_eq!(persisted_salt(&p), bytes_to_hex(s.anon_salt.as_bytes()),
            "fresh salt minted and persisted after the aside");
        assert_ne!(persisted_salt(&p), old_salt,
            "the corrupt file's salt is never resurrected");
    }

    #[test]
    fn salt_is_minted_for_pre47_stores_without_one() {
        // Claim: a pre-#47 store (no salt field) loads its grants and
        // mints a salt — the inner names did not exist before, so
        // nothing rotates that mattered.
        let (p, _d) = temp_store("salt-pre47");
        let host = _d.path().join("h.bin");
        std::fs::write(&host, b"DATA").unwrap();
        std::fs::write(
            &p,
            serde_json::json!({
                "version": "0.28.0",
                "secrets": [{
                    "name": "s", "host_path": host.to_string_lossy(),
                    "mode": 384, "hashes": [{"hash": "*", "by": null}],
                    "access_count": 0, "unlimited": false
                }]
            })
            .to_string(),
        )
        .unwrap();
        let mut s = armed_state(&p);
        let hub = crate::oracle_service::OracleHub::new();
        let report = load(&mut s, &hub);
        assert_eq!(report.restored, 1, "pre-#47 grants load");
        assert!(!s.anon_salt.as_bytes().is_empty(), "salt minted for the old store");
        assert_eq!(persisted_salt(&p), bytes_to_hex(s.anon_salt.as_bytes()));
    }

    #[test]
    fn salt_and_inner_names_are_stable_across_restarts() {
        // Claim: names are stable across restarts because the salt is
        // persisted — the container's symlinks and bind-mounts survive
        // daemon churn.
        let (p, _d) = temp_store("salt-stable");
        let host = _d.path().join("h.bin");
        std::fs::write(&host, b"DATA").unwrap();
        let hub = crate::oracle_service::OracleHub::new();
        // Production flow: every daemon LOADS at startup before any
        // registration (main.rs calls policy_store::load first) — the
        // load is what mints the salt. Registering on a state that
        // never loaded would derive from an empty salt (unsalted!);
        // that path does not exist in production and the never-empty
        // test pins the load paths.
        let inner1 = {
            let mut s = armed_state(&p);
            let hub0 = crate::oracle_service::OracleHub::new();
            let _ = load(&mut s, &hub0);
            s.add("var/secrets/h.bin", &host, 4, "*");
            fuse_protocol::anonymize_path(&s.anon_salt, "var/secrets/h.bin")
        };
        // A "restart": a fresh state loads the same store.
        let mut s2 = armed_state(&p);
        let report = load(&mut s2, &hub);
        assert_eq!(report.restored, 1);
        let inner2 = fuse_protocol::anonymize_path(&s2.anon_salt, "var/secrets/h.bin");
        assert_eq!(inner1, inner2,
            "the container-view name must not rotate across a restart");
    }

    #[test]
    fn salt_is_never_empty_on_any_state_that_serves() {
        // The trust anchor of #47: an empty salt quietly unsalts every
        // inner name (dictionary-reversible). Every load path that can
        // serve a registration must leave a non-empty salt behind.
        let (p, _d) = temp_store("salt-never");
        let hub = crate::oracle_service::OracleHub::new();
        for label in ["fresh", "corrupt"] {
            let mut s = armed_state(&p);
            let _ = std::fs::remove_file(&p);
            if label == "corrupt" {
                std::fs::write(&p, "not json").unwrap();
            }
            let _ = load(&mut s, &hub);
            assert!(!s.anon_salt.as_bytes().is_empty(), "{label}: salt must exist before serving");
        }
    }

    #[test]
    fn round_trips_grants_provenance_and_access_state() {
        let (p, _d) = temp_store("roundtrip");
        let host = _d.path().join("real-host.bin");
        std::fs::write(&host, b"123456789").unwrap();
        {
            let s = armed_state(&p);
            s.add("s", &host, 9, "sha256-pkg");
            assert!(s.rotate_hash("s", "sha256-a"));
            // grant-forever records provenance + unlimited
            let id = s.create_pending("s", 4242, Some("sha256-b"), "mismatch", Some("goose"));
            s.grant_pending_forever(id).unwrap();
            // consume a read cycle
            let _ = s.attempt_read("s", 100, Some("sha256-a"), 0, 1024);
        }
        // daemon dies; a fresh state loads
        let mut s2 = armed_state(&p);
        let report = crate::policy_store::load(&mut s2, &OracleHub::new());
        assert_eq!(report.restored, 1);
        let rec = s2.secrets.get("s").unwrap();
        let r = lock_secret(rec.value(), "s");
        let hashes: Vec<&str> = r.allowed_hashes.iter().map(|h| h.hash.as_str()).collect();
        assert!(hashes.contains(&"sha256-a"), "{hashes:?}");
        assert!(hashes.contains(&"sha256-b"), "grant-forever hash survived: {hashes:?}");
        let by = r.allowed_hashes.iter().find(|h| h.hash == "sha256-b").unwrap().by.clone();
        assert_eq!(by.as_deref(), Some("goose"), "provenance survived");
        assert!(r.unlimited_reads, "grant-forever survived");
        assert!(r.access_count >= 1, "budget spent stays spent");
        drop(r);
    }

    #[test]
    fn ghost_entries_preserve_grants_when_host_file_missing() {
        let (p, _d) = temp_store("ghost");
        {
            let s = armed_state(&p);
            s.add("ghost/s", "/nonexistent/host/file", 5, "*");
            assert!(s.rotate_hash("ghost/s", "sha256-x"));
        }
        let mut s2 = armed_state(&p);
        let report = crate::policy_store::load(&mut s2, &OracleHub::new());
        assert_eq!(report.ghosts, 1, "missing host file loads as ghost");
        let rec = s2.secrets.get("ghost/s").expect("policy survived");
        let r = lock_secret(rec.value(), "ghost/s");
        assert_eq!(r.allowed_hashes[0].hash, "sha256-x");
    }

    #[test]
    fn corrupt_file_renamed_aside_and_starts_fresh() {
        let (p, _d) = temp_store("corrupt");
        std::fs::write(&p, b"{ this is not json").unwrap();
        let mut s = armed_state(&p);
        let report = crate::policy_store::load(&mut s, &OracleHub::new());
        assert!(report.corrupted);
        assert!(s.secrets.is_empty(), "fresh start, never half-resurrected");
        let aside = std::fs::read_dir(p.parent().unwrap()).unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().contains("corrupt-"));
        assert!(aside.is_some(), "the corrupt file was renamed aside");
    }

    #[test]
    fn mutations_persist_write_through() {
        let (p, _d) = temp_store("writethrough");
        let s = armed_state(&p);
        s.add("w", "/tmp/host/w", 3, "h1");
        // the file exists and parses with the mutation
        let d = std::fs::read(&p).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&d)
            .expect("write-through produced parsable JSON");
        assert!(parsed["secrets"][0]["name"] == "w", "mutation is IN the file");
        s.remove("w");
        let mut s2 = armed_state(&p);
        let report = crate::policy_store::load(&mut s2, &OracleHub::new());
        assert_eq!(report.restored, 0, "removal persisted too");
    }

    #[test]
    fn unreadable_store_refuses_to_arm_and_is_never_overwritten() {
        // Review finding on #57: an unreadable store (wrong owner,
        // EISDIR, …) used to fresh-start WITH persistence armed, so
        // the first mutation renamed OVER it — grants and evidence
        // gone. Now persistence refuses to arm: the file must survive
        // untouched until a human looks.
        // The store path is a DIRECTORY: read() fails with EISDIR
        // regardless of privileges (deterministic for root and
        // non-root alike).
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("policy.json");
        std::fs::create_dir_all(&p).unwrap();
        let mut s = ServerState::new();
        s.policy_path = Some(p.clone());
        let report = crate::policy_store::load(&mut s, &OracleHub::new());
        assert!(report.unreadable);
        assert!(s.policy_path.is_none(), "persistence disarmed");
        // A mutation succeeds in memory but must NOT touch the store.
        s.add("x", "/tmp/host/x", 1, "h");
        assert!(s.secrets.contains_key("x"));
        assert!(p.is_dir(), "the unreadable store was not overwritten (rename would have replaced it with a file)");
    }

    #[test]
    fn re_add_of_an_existing_name_persists_the_joined_hash() {
        // Review blocker on #57: the existing-name branch of
        // add_with_mode mutated memory (joined hash, new host_path)
        // and returned WITHOUT persisting — kill the daemon and the
        // second container's approval is gone: exactly the
        // "grants survive kill -9" headline failing on re-add.
        let (p, d) = temp_store("readd");
        let host = d.path().join("h.bin");
        std::fs::write(&host, b"X").unwrap();
        {
            // Production shape: ONE daemon process — first add, then
            // the re-add whose hash JOINS the set (MR2), same state.
            let s = armed_state(&p);
            s.add("s", &host, 1, "hash-a");
            s.add("s", &host, 1, "hash-b");
        }
        let mut s2 = armed_state(&p);
        crate::policy_store::load(&mut s2, &OracleHub::new());
        let rec = s2.secrets.get("s").unwrap();
        let r = lock_secret(rec.value(), "s");
        let hashes: Vec<&str> = r.allowed_hashes.iter().map(|h| h.hash.as_str()).collect();
        assert!(
            hashes.contains(&"hash-a") && hashes.contains(&"hash-b"),
            "re-add join must DURABLY survive: {hashes:?}"
        );
    }

    #[test]
    fn concurrent_mutations_all_survive_persistence() {
        // Review blocker on #57: persist() was unsynchronized —
        // concurrent mutators could interleave snapshots so a stale
        // one lands LAST, silently reverting an already-durable
        // mutation (resurrecting a spent budget: fail-OPEN). Hammer
        // it: N threads mutate DISTINCT secrets; every final state
        // must be present after reload.
        let (p, _d) = temp_store("stress");
        // ONE daemon state shared by the mutator threads — the lock
        // under test serializes mutation+persist store-wide.
        let shared = std::sync::Arc::new(armed_state(&p));

        const THREADS: usize = 8;
        const ROTATIONS: usize = 40;
        let mut handles = Vec::new();
        for t in 0..THREADS {
            let s = std::sync::Arc::clone(&shared);
            handles.push(std::thread::spawn(move || {
                let name = format!("t{t}");
                s.add(&name, "/tmp/host/x", 1, "h0");
                for i in 1..=ROTATIONS {
                    s.rotate_hash(&name, &format!("h{i}"));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let mut s2 = armed_state(&p);
        crate::policy_store::load(&mut s2, &OracleHub::new());
        for t in 0..THREADS {
            let name = format!("t{t}");
            let rec = s2.secrets.get(&name).expect("{name} lost entirely");
            let r = lock_secret(rec.value(), &name);
            assert_eq!(
                r.allowed_hashes[0].hash,
                format!("h{ROTATIONS}"),
                "{name}: last rotation reverted (stale snapshot landed last)"
            );
        }
    }

    #[test]
    fn persistence_failure_does_not_fail_the_operation() {
        // parent path is a FILE: every write fails; the mutation must
        // still succeed in memory.
        let blocker = tempfile::NamedTempFile::new().unwrap();
        let p = blocker.path().join("policy.json");
        let mut s = ServerState::new();
        s.policy_path = Some(p);
        s.add("x", "/tmp/host/x", 1, "h");
        assert!(s.secrets.contains_key("x"), "operation succeeded despite unwritable store");
    }

    #[test]
    fn unarmed_state_never_touches_disk() {
        // policy_path None (the default): hermetic — the whole
        // existing suite depends on this.
        let s = ServerState::new();
        s.add("n", "/tmp/host/n", 1, "h");
        assert!(s.policy_path.is_none());
    }

    use crate::state::lock_secret;
}

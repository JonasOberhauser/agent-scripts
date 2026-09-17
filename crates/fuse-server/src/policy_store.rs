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
    if let Some(p) = std::env::var_os("FUSE_GATEKEEPER_POLICY") {
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
/// - host file missing → the secret loads as a GHOST: policy (hashes,
///   provenance, budget) survives, the name is served with identity
///   (0,0), opens answer ENOENT until the file returns or run-agent
///   re-adds (plain overwrite joins the hash set — nothing lost)
pub fn load(state: &ServerState, hub: &OracleHub) -> LoadReport {
    let path = state
        .policy_path
        .clone()
        .unwrap_or_else(policy_path);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("policy store {}: no file — fresh start", path.display());
            return LoadReport::default();
        }
        Err(e) => {
            tracing::error!("policy store {}: unreadable ({e}) — fresh start", path.display());
            return LoadReport::default();
        }
    };
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
    let mut report = LoadReport::default();
    for s in file.secrets {
        // A live host file re-registers with its CURRENT identity
        // (the MR4 stat path); a missing one becomes a ghost with
        // identity (0,0). Either way the loaded POLICY lands intact.
        // A live host file re-registers with its CURRENT identity
        // (the MR4 stat path); a missing one is a GHOST: announced
        // with NO identity — absence is Option, not an in-band (0,0)
        // sentinel — until the first stat-on-lookup discovers it.
        let (size, identity) = match std::fs::metadata(&s.host_path) {
            Ok(md) if md.is_file() => {
                use std::os::unix::fs::MetadataExt;
                let id = fuse_protocol::HostIdentity {
                    kdev: fuse_protocol::KDev(md.dev()),
                    kino: fuse_protocol::Kino(md.ino()),
                };
                (md.len() as usize, Some(id))
            }
            _ => (0, None),
        };
        let ghost = identity.is_none();
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
        hub.serve(&s.name, identity, s.mode);
    }
    report
}

/// What the startup load found.
#[derive(Default)]
pub struct LoadReport {
    pub restored: usize,
    pub ghosts: usize,
    pub corrupted: bool,
}

/// Write the policy atomically: temp file in the same directory,
/// fsync, rename. Callers treat failure as loud-but-nonfatal — a
/// grant that fails to persist is lost on restart, but failing the
/// operation would turn a full disk into "you may not approve
/// anything".
pub fn persist(state: &ServerState) {
    let Some(path) = state.policy_path.clone() else {
        return; // persistence not armed (tests, harnesses)
    };
    let mut file = PolicyFile {
        version: fuse_protocol::VERSION.to_string(),
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

fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    std::fs::rename(&tmp, path)
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
        let s2 = armed_state(&p);
        let report = crate::policy_store::load(&s2, &OracleHub::new());
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
        let s2 = armed_state(&p);
        let report = crate::policy_store::load(&s2, &OracleHub::new());
        assert_eq!(report.ghosts, 1, "missing host file loads as ghost");
        let rec = s2.secrets.get("ghost/s").expect("policy survived");
        let r = lock_secret(rec.value(), "ghost/s");
        assert_eq!(r.allowed_hashes[0].hash, "sha256-x");
    }

    #[test]
    fn corrupt_file_renamed_aside_and_starts_fresh() {
        let (p, _d) = temp_store("corrupt");
        std::fs::write(&p, b"{ this is not json").unwrap();
        let s = armed_state(&p);
        let report = crate::policy_store::load(&s, &OracleHub::new());
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
        let s2 = armed_state(&p);
        let report = crate::policy_store::load(&s2, &OracleHub::new());
        assert_eq!(report.restored, 0, "removal persisted too");
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

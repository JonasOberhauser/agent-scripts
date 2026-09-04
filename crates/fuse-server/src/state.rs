use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::error;

/// One secret file tracked by the gatekeeper.
#[derive(Debug, Clone)]
pub struct SecretRecord {
    pub content: Vec<u8>,
    pub allowed_hash: String,
    pub access_count: u64,
    pub reading_pid: Option<u32>,
    pub read_progress: usize,
}

/// A pending access request waiting for manual approval.
#[derive(Debug, Clone)]
pub struct PendingAccess {
    pub id: u64,
    pub secret_name: String,
    pub process_name: Option<String>,
    pub pid: u32,
    pub pid_hash: Option<String>,
    pub reason: String,
    pub expires_at: Instant,
    pub granted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReadOutcome {
    Granted(Vec<u8>),
    AlreadyAccessed,
    HashMismatch { got: String, expected: String },
    NotFound,
}

impl ReadOutcome {
    /// Human-readable reason for the outcomes that create a pending
    /// request; `None` for Granted and NotFound (handled before any
    /// pending flow, without a reason string).
    pub fn denial_reason(&self) -> Option<String> {
        match self {
            ReadOutcome::AlreadyAccessed => Some("exceeded access limit".to_string()),
            ReadOutcome::HashMismatch { got, expected } => {
                Some(format!("hash mismatch: got {got}, expected {expected}"))
            }
            ReadOutcome::Granted(_) | ReadOutcome::NotFound => None,
        }
    }
}

/// Lock a per-secret Mutex. On poisoning, reset to deny-all state:
/// access_count=1, reading_pid=None, read_progress=0.
/// This makes the secret permanently inaccessible until explicit `reset`.
pub fn lock_secret<'a>(rec: &'a Mutex<SecretRecord>, name: &str) -> MutexGuard<'a, SecretRecord> {
    match rec.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            guard.access_count = 1;
            guard.reading_pid = None;
            guard.read_progress = 0;
            error!("Secret '{name}' mutex poisoned — access revoked. Use 'reset {name}' to re-enable.");
            guard
        }
    }
}

/// Shared state behind the FUSE filesystem and the socket server.
/// No global Mutex — each secret has its own Mutex for fine-grained locking.
#[derive(Debug)]
pub struct ServerState {
    pub secrets: DashMap<String, Arc<Mutex<SecretRecord>>>,
    pub pending: DashMap<u64, PendingAccess>,
    pub next_pending_id: AtomicU64,
    pub pending_timeout: Mutex<Duration>,
    pub log_path: String,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            secrets: DashMap::new(),
            pending: DashMap::new(),
            next_pending_id: AtomicU64::new(1),
            pending_timeout: Mutex::new(Duration::from_secs(300)),
            log_path: String::new(),
        }
    }
}

impl ServerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, name: impl Into<String>, content: Vec<u8>, allowed_hash: impl Into<String>) {
        self.secrets.insert(
            name.into(),
            Arc::new(Mutex::new(SecretRecord {
                content,
                allowed_hash: allowed_hash.into(),
                access_count: 0,
                reading_pid: None,
                read_progress: 0,
            })),
        );
    }

    pub fn remove(&self, name: &str) -> bool {
        self.secrets.remove(name).is_some()
    }

    pub fn attempt_read(
        &self,
        name: &str,
        pid: u32,
        pid_hash: Option<&str>,
        offset: usize,
        size: usize,
    ) -> ReadOutcome {
        let rec_arc = match self.secrets.get(name) {
            Some(entry) => Arc::clone(entry.value()),
            None => return ReadOutcome::NotFound,
        };
        let mut rec = lock_secret(&rec_arc, name);

        if rec.reading_pid == Some(pid) {
            if offset < rec.read_progress {
                return ReadOutcome::AlreadyAccessed;
            }
            let end = offset.saturating_add(size).min(rec.content.len());
            rec.read_progress = rec.read_progress.max(end);
            return ReadOutcome::Granted(rec.content[offset..end].to_vec());
        }

        if rec.access_count > 0 {
            return ReadOutcome::AlreadyAccessed;
        }

        let hash_ok = match pid_hash {
            Some(_) if rec.allowed_hash == "*" => true,
            Some(h) if h == rec.allowed_hash => true,
            _ => rec.allowed_hash == "*",
        };

        if hash_ok {
            rec.access_count += 1;
            rec.reading_pid = Some(pid);
            let end = offset.saturating_add(size).min(rec.content.len());
            rec.read_progress = end;
            ReadOutcome::Granted(rec.content[offset..end].to_vec())
        } else {
            ReadOutcome::HashMismatch {
                got: pid_hash.unwrap_or("<unknown>").to_string(),
                expected: rec.allowed_hash.clone(),
            }
        }
    }

    pub fn reset(&self, name: Option<&str>) -> usize {
        match name {
            Some(n) => {
                if let Some(entry) = self.secrets.get(n) {
                    let rec_arc = Arc::clone(entry.value());
                    drop(entry);
                    let mut rec = lock_secret(&rec_arc, n);
                    rec.access_count = 0;
                    rec.reading_pid = None;
                    rec.read_progress = 0;
                    1
                } else {
                    0
                }
            }
            None => {
                let entries: Vec<(String, Arc<Mutex<SecretRecord>>)> = self.secrets
                    .iter()
                    .map(|e| (e.key().clone(), Arc::clone(e.value())))
                    .collect();
                let count = entries.len();
                for (name, rec_arc) in &entries {
                    let mut rec = lock_secret(rec_arc, name);
                    rec.access_count = 0;
                    rec.reading_pid = None;
                    rec.read_progress = 0;
                }
                count
            }
        }
    }

    pub fn rotate_hash(&self, name: &str, new_hash: &str) -> bool {
        if let Some(entry) = self.secrets.get(name) {
            let rec_arc = Arc::clone(entry.value());
            drop(entry);
            let mut rec = lock_secret(&rec_arc, name);
            rec.allowed_hash = new_hash.to_string();
            true
        } else {
            false
        }
    }

    pub fn create_pending(
        &self,
        secret_name: &str,
        pid: u32,
        pid_hash: Option<&str>,
        reason: &str,
        process_name: Option<&str>,
    ) -> u64 {
        let id = self.next_pending_id.fetch_add(1, Ordering::SeqCst);
        self.pending.insert(id, PendingAccess {
            id,
            secret_name: secret_name.to_string(),
            process_name: process_name.map(|s| s.to_string()),
            pid,
            pid_hash: pid_hash.map(|s| s.to_string()),
            reason: reason.to_string(),
            expires_at: Instant::now() + *self.pending_timeout.lock().unwrap(),
            granted: false,
        });
        id
    }

    pub fn grant_pending(&self, id: u64) -> bool {
        if let Some(mut entry) = self.pending.get_mut(&id) {
            if entry.expires_at > Instant::now() {
                entry.granted = true;
                return true;
            }
        }
        false
    }

    pub fn deny_pending(&self, id: u64) -> bool {
        self.pending.remove(&id).is_some()
    }

    pub fn is_pending_granted(&self, id: u64) -> bool {
        self.pending.get(&id)
            .map(|p| p.granted && p.expires_at > Instant::now())
            .unwrap_or(false)
    }

    pub fn remove_pending(&self, id: u64) {
        self.pending.remove(&id);
    }

    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.pending.retain(|_, p| p.expires_at > now);
    }

    pub fn list_pending(&self) -> Vec<fuse_protocol::PendingAccessInfo> {
        self.cleanup_expired();
        let now = Instant::now();
        let unix_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.pending
            .iter()
            .filter(|p| p.expires_at > now)
            .map(|p| {
                let remaining = p.expires_at.duration_since(now).as_secs();
                fuse_protocol::PendingAccessInfo {
                    id: p.id,
                    secret_name: p.secret_name.clone(),
                    process_name: p.process_name.clone(),
                    pid: p.pid,
                    pid_hash: p.pid_hash.clone(),
                    reason: p.reason.clone(),
                    expires_at: unix_now + remaining,
                }
            })
            .collect()
    }

    pub fn force_grant_read(
        &self,
        name: &str,
        pid: u32,
        offset: usize,
        size: usize,
    ) -> Option<Vec<u8>> {
        let entry = self.secrets.get(name)?;
        let rec_arc = Arc::clone(entry.value());
        drop(entry);
        let mut rec = lock_secret(&rec_arc, name);
        rec.access_count += 1;
        rec.reading_pid = Some(pid);
        let end = offset.saturating_add(size).min(rec.content.len());
        rec.read_progress = rec.read_progress.max(end);
        Some(rec.content[offset..end].to_vec())
    }

    pub fn status(&self) -> Vec<fuse_protocol::SecretStatus> {
        let entries: Vec<(String, Arc<Mutex<SecretRecord>>)> = self.secrets
            .iter()
            .map(|e| (e.key().clone(), Arc::clone(e.value())))
            .collect();

        entries.iter().map(|(name, rec_arc)| {
            let rec = lock_secret(rec_arc, name);
            fuse_protocol::SecretStatus {
                name: name.clone(),
                access_count: rec.access_count,
                allowed_hash: rec.allowed_hash.clone(),
                size: rec.content.len(),
            }
        }).collect()
    }

    pub fn list_mounts(&self) -> Vec<fuse_protocol::MountEntry> {
        let entries: Vec<(String, Arc<Mutex<SecretRecord>>)> = self.secrets
            .iter()
            .map(|e| (e.key().clone(), Arc::clone(e.value())))
            .collect();

        entries.iter().map(|(name, rec_arc)| {
            let rec = lock_secret(rec_arc, name);
            fuse_protocol::MountEntry {
                name: name.clone(),
                size: rec.content.len(),
            }
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> ServerState {
        let s = ServerState::new();
        s.add("secrets.yaml", b"TOPSECRET".to_vec(), "abc123");
        s
    }

    fn get_rec(s: &ServerState, name: &str) -> (u64, Option<u32>, usize) {
        let entry = s.secrets.get(name).unwrap();
        let rec = lock_secret(entry.value(), name);
        (rec.access_count, rec.reading_pid, rec.read_progress)
    }

    #[test]
    fn first_read_with_correct_hash_grants() {
        let s = sample_state();
        let out = s.attempt_read("secrets.yaml", 100, Some("abc123"), 0, 1024);
        assert_eq!(out, ReadOutcome::Granted(b"TOPSECRET".to_vec()));
    }

    #[test]
    fn second_read_from_different_pid_denied() {
        let s = sample_state();
        s.attempt_read("secrets.yaml", 100, Some("abc123"), 0, 1024);
        let out = s.attempt_read("secrets.yaml", 200, Some("abc123"), 0, 1024);
        assert_eq!(out, ReadOutcome::AlreadyAccessed);
    }

    #[test]
    fn wrong_hash_denied() {
        let s = sample_state();
        let out = s.attempt_read("secrets.yaml", 100, Some("wrong"), 0, 1024);
        assert_eq!(
            out,
            ReadOutcome::HashMismatch { got: "wrong".into(), expected: "abc123".into() }
        );
    }

    #[test]
    fn none_hash_denied() {
        let s = sample_state();
        let out = s.attempt_read("secrets.yaml", 100, None, 0, 1024);
        assert!(matches!(out, ReadOutcome::HashMismatch { .. }));
    }

    #[test]
    fn reset_allows_second_read() {
        let s = sample_state();
        s.attempt_read("secrets.yaml", 100, Some("abc123"), 0, 1024);
        s.reset(Some("secrets.yaml"));
        let out = s.attempt_read("secrets.yaml", 100, Some("abc123"), 0, 1024);
        assert_eq!(out, ReadOutcome::Granted(b"TOPSECRET".to_vec()));
    }

    #[test]
    fn reset_all_clears_everyone() {
        let s = sample_state();
        s.add("other", b"x".to_vec(), "h");
        s.attempt_read("secrets.yaml", 100, Some("abc123"), 0, 1024);
        assert_eq!(s.reset(None), 2);
    }

    #[test]
    fn rotate_hash_changes_access() {
        let s = sample_state();
        assert!(s.rotate_hash("secrets.yaml", "newhash"));
        let out = s.attempt_read("secrets.yaml", 100, Some("abc123"), 0, 1024);
        assert!(matches!(out, ReadOutcome::HashMismatch { .. }));
        let out = s.attempt_read("secrets.yaml", 100, Some("newhash"), 0, 1024);
        assert_eq!(out, ReadOutcome::Granted(b"TOPSECRET".to_vec()));
    }

    #[test]
    fn missing_secret_not_found() {
        let s = sample_state();
        assert_eq!(s.attempt_read("nope", 100, Some("abc123"), 0, 1024), ReadOutcome::NotFound);
    }

    #[test]
    fn multi_chunk_forward_reads_allowed() {
        let s = sample_state();
        let out1 = s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 4);
        assert!(matches!(out1, ReadOutcome::Granted(_)));
        let out2 = s.attempt_read("secrets.yaml", 42, Some("abc123"), 4, 4);
        assert!(matches!(out2, ReadOutcome::Granted(_)));
        let out3 = s.attempt_read("secrets.yaml", 42, Some("abc123"), 8, 4);
        assert!(matches!(out3, ReadOutcome::Granted(_)));
        let (count, _, progress) = get_rec(&s, "secrets.yaml");
        assert_eq!(count, 1);
        assert_eq!(progress, 9);
    }

    #[test]
    fn multi_chunk_backward_read_denied() {
        let s = sample_state();
        s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 4);
        let out = s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 4);
        assert_eq!(out, ReadOutcome::AlreadyAccessed);
    }

    #[test]
    fn multi_chunk_overlap_denied() {
        let s = sample_state();
        s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 6);
        let out = s.attempt_read("secrets.yaml", 42, Some("abc123"), 3, 6);
        assert_eq!(out, ReadOutcome::AlreadyAccessed);
    }

    #[test]
    fn multi_chunk_read_beyond_eof_allowed() {
        let s = sample_state();
        s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 9);
        let out = s.attempt_read("secrets.yaml", 42, Some("abc123"), 9, 4);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn multi_chunk_same_pid_no_hash_recheck() {
        let s = sample_state();
        s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 4);
        let out = s.attempt_read("secrets.yaml", 42, Some("totally_wrong"), 4, 4);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn cross_pid_read_after_first_denied() {
        let s = sample_state();
        s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 1024);
        let out = s.attempt_read("secrets.yaml", 99, Some("abc123"), 0, 1024);
        assert_eq!(out, ReadOutcome::AlreadyAccessed);
    }

    #[test]
    fn reset_clears_read_progress() {
        let s = sample_state();
        s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 4);
        let (_, _, progress) = get_rec(&s, "secrets.yaml");
        assert_eq!(progress, 4);
        s.reset(Some("secrets.yaml"));
        let (_, _, progress) = get_rec(&s, "secrets.yaml");
        assert_eq!(progress, 0);
        let out = s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 4);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn many_forward_reads_same_pid_still_one_count() {
        let s = sample_state();
        for i in 0..9 {
            let out = s.attempt_read("secrets.yaml", 7, Some("abc123"), i, 1);
            assert!(matches!(out, ReadOutcome::Granted(_)), "failed at offset {i}");
        }
        let (count, _, _) = get_rec(&s, "secrets.yaml");
        assert_eq!(count, 1);
    }

    #[test]
    fn wildcard_allows_known_hash() {
        let s = ServerState::new();
        s.add("s", b"DATA".to_vec(), "*");
        let out = s.attempt_read("s", 100, Some("any_hash_value"), 0, 1024);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn wildcard_allows_unknown_hash() {
        let s = ServerState::new();
        s.add("s", b"DATA".to_vec(), "*");
        let out = s.attempt_read("s", 100, None, 0, 1024);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn wildcard_still_enforces_one_read() {
        let s = ServerState::new();
        s.add("s", b"DATA".to_vec(), "*");
        s.attempt_read("s", 100, None, 0, 1024);
        let out = s.attempt_read("s", 200, None, 0, 1024);
        assert_eq!(out, ReadOutcome::AlreadyAccessed);
    }

    #[test]
    fn wildcard_still_enforces_forward_only() {
        let s = ServerState::new();
        s.add("s", b"0123456789".to_vec(), "*");
        s.attempt_read("s", 42, None, 0, 4);
        let out = s.attempt_read("s", 42, None, 0, 4);
        assert_eq!(out, ReadOutcome::AlreadyAccessed);
        let out = s.attempt_read("s", 42, None, 4, 4);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn non_wildcard_denies_unknown_hash() {
        let s = sample_state();
        let out = s.attempt_read("secrets.yaml", 100, None, 0, 1024);
        assert!(matches!(out, ReadOutcome::HashMismatch { .. }));
    }
}

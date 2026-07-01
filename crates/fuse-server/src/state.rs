use std::collections::HashMap;
use std::time::{Duration, Instant};

/// One secret file tracked by the gatekeeper.
#[derive(Debug, Clone)]
pub struct SecretRecord {
    pub content: Vec<u8>,
    pub allowed_hash: String,
    pub access_count: u64,
    /// PID that is currently mid-read (started reading but not yet reset).
    /// Allows multi-chunk reads from the same process without re-checking
    /// the hash or re-incrementing the counter.
    pub reading_pid: Option<u32>,
    /// Highest byte offset served so far to `reading_pid`.
    /// Only **forward** reads (`offset >= read_progress`) are allowed;
    /// re-reading already-served bytes is denied with `AlreadyAccessed`.
    pub read_progress: usize,
}

/// A pending access request waiting for manual approval.
#[derive(Debug, Clone)]
pub struct PendingAccess {
    pub id: u64,
    pub secret_name: String,
    pub pid: u32,
    pub pid_hash: Option<String>,
    pub reason: String,
    pub expires_at: Instant,
    pub granted: bool,
}

/// Result of a FUSE read attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum ReadOutcome {
    /// Content served successfully; counter was incremented.
    Granted(Vec<u8>),
    /// Counter already > 0, or re-reading already-served bytes.
    AlreadyAccessed,
    /// Process hash did not match.
    HashMismatch { got: String, expected: String },
    /// No such secret.
    NotFound,
}

/// Shared mutable state behind the FUSE filesystem and the socket server.
#[derive(Debug)]
pub struct ServerState {
    pub secrets: HashMap<String, SecretRecord>,
    pub pending: Vec<PendingAccess>,
    pub next_pending_id: u64,
    pub pending_timeout: Duration,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            secrets: HashMap::new(),
            pending: Vec::new(),
            next_pending_id: 1,
            pending_timeout: Duration::from_secs(300),
        }
    }
}

impl ServerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, name: impl Into<String>, content: Vec<u8>, allowed_hash: impl Into<String>) {
        self.secrets.insert(
            name.into(),
            SecretRecord {
                content,
                allowed_hash: allowed_hash.into(),
                access_count: 0,
                reading_pid: None,
                read_progress: 0,
            },
        );
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.secrets.remove(name).is_some()
    }

    /// Attempt to read a secret.
    ///
    /// # Parameters
    ///
    /// - `pid` — PID of the reading process, used for multi-chunk detection.
    /// - `pid_hash` — SHA-256 of the reading process's executable, or `None`
    ///   if it could not be determined (in which case access is **denied**).
    /// - `offset` — byte offset of the requested read.
    /// - `size` — number of bytes requested.
    ///
    /// # Policy
    ///
    /// 1. **First read** (counter == 0): verify the process hash. If it
    ///    matches, grant access, set `reading_pid`, and advance
    ///    `read_progress`.
    /// 2. **Subsequent reads from the same PID**: allowed only if
    ///    `offset >= read_progress` (forward-only). Re-reading
    ///    already-served bytes is denied. The hash is **not** re-checked
    ///    because it was verified on the first read.
    /// 3. **Reads from a different PID**: always denied after the first
    ///    read.
    pub fn attempt_read(
        &mut self,
        name: &str,
        pid: u32,
        pid_hash: Option<&str>,
        offset: usize,
        size: usize,
    ) -> ReadOutcome {
        let Some(rec) = self.secrets.get_mut(name) else {
            return ReadOutcome::NotFound;
        };

        // Multi-chunk: same PID already started reading.
        if rec.reading_pid == Some(pid) {
            // Forward-only: deny re-reading already-served bytes.
            if offset < rec.read_progress {
                return ReadOutcome::AlreadyAccessed;
            }
            // Advance progress to cover this read (clamped to content length).
            let end = offset.saturating_add(size).min(rec.content.len());
            rec.read_progress = rec.read_progress.max(end);
            return ReadOutcome::Granted(rec.content.clone());
        }

        // A *different* process already consumed this secret.
        if rec.access_count > 0 {
            return ReadOutcome::AlreadyAccessed;
        }

        // First read: verify hash.
        // "*" as allowed_hash = wildcard: allow any process, even when the
        // hash can't be determined (e.g., container processes whose
        // /proc/{pid}/exe is invisible to the FUSE server).
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
            ReadOutcome::Granted(rec.content.clone())
        } else {
            ReadOutcome::HashMismatch {
                got: pid_hash.unwrap_or("<unknown>").to_string(),
                expected: rec.allowed_hash.clone(),
            }
        }
    }

    /// Reset the access counter for one secret (or all when `name` is `None`).
    /// Returns the number of counters that were reset.
    pub fn reset(&mut self, name: Option<&str>) -> usize {
        match name {
            Some(n) => {
                if let Some(rec) = self.secrets.get_mut(n) {
                    rec.access_count = 0;
                    rec.reading_pid = None;
                    rec.read_progress = 0;
                    1
                } else {
                    0
                }
            }
            None => {
                let count = self.secrets.len();
                for rec in self.secrets.values_mut() {
                    rec.access_count = 0;
                    rec.reading_pid = None;
                    rec.read_progress = 0;
                }
                count
            }
        }
    }

    /// Replace the allowed binary hash for a secret.
    pub fn rotate_hash(&mut self, name: &str, new_hash: &str) -> bool {
        if let Some(rec) = self.secrets.get_mut(name) {
            rec.allowed_hash = new_hash.to_string();
            true
        } else {
            false
        }
    }

    // ── pending access management ───────────────────────────────

    /// Create a new pending access request.  Returns its ID.
    pub fn create_pending(
        &mut self,
        secret_name: &str,
        pid: u32,
        pid_hash: Option<&str>,
        reason: &str,
    ) -> u64 {
        let id = self.next_pending_id;
        self.next_pending_id += 1;
        self.pending.push(PendingAccess {
            id,
            secret_name: secret_name.to_string(),
            pid,
            pid_hash: pid_hash.map(|s| s.to_string()),
            reason: reason.to_string(),
            expires_at: Instant::now() + self.pending_timeout,
            granted: false,
        });
        id
    }

    /// Mark a pending access as granted.  Returns `true` if the ID was found.
    pub fn grant_pending(&mut self, id: u64) -> bool {
        if let Some(p) = self.pending.iter_mut().find(|p| p.id == id) {
            if p.expires_at > Instant::now() {
                p.granted = true;
                return true;
            }
        }
        false
    }

    /// Remove (deny) a pending access by ID.  Returns `true` if found.
    pub fn deny_pending(&mut self, id: u64) -> bool {
        let before = self.pending.len();
        self.pending.retain(|p| p.id != id);
        self.pending.len() < before
    }

    /// Check whether a pending access has been granted and not expired.
    pub fn is_pending_granted(&self, id: u64) -> bool {
        self.pending
            .iter()
            .any(|p| p.id == id && p.granted && p.expires_at > Instant::now())
    }

    /// Remove a pending access by ID (cleanup after resolution).
    pub fn remove_pending(&mut self, id: u64) {
        self.pending.retain(|p| p.id != id);
    }

    /// Remove all expired pending accesses.
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.pending.retain(|p| p.expires_at > now);
    }

    /// Return info about all non-expired pending accesses.
    pub fn list_pending(&mut self) -> Vec<fuse_protocol::PendingAccessInfo> {
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
                    pid: p.pid,
                    pid_hash: p.pid_hash.clone(),
                    reason: p.reason.clone(),
                    expires_at: unix_now + remaining,
                }
            })
            .collect()
    }

    /// Force-grant a read: bypass hash/count checks, increment counter,
    /// set reading_pid, advance read_progress.  Used after manual approval.
    pub fn force_grant_read(
        &mut self,
        name: &str,
        pid: u32,
        offset: usize,
        size: usize,
    ) -> Option<Vec<u8>> {
        let rec = self.secrets.get_mut(name)?;
        rec.access_count += 1;
        rec.reading_pid = Some(pid);
        let end = offset.saturating_add(size).min(rec.content.len());
        rec.read_progress = rec.read_progress.max(end);
        Some(rec.content.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> ServerState {
        let mut s = ServerState::new();
        s.add("secrets.yaml", b"TOPSECRET".to_vec(), "abc123");
        s
    }

    #[test]
    fn first_read_with_correct_hash_grants() {
        let mut s = sample_state();
        let out = s.attempt_read("secrets.yaml", 100, Some("abc123"), 0, 1024);
        assert_eq!(out, ReadOutcome::Granted(b"TOPSECRET".to_vec()));
    }

    #[test]
    fn second_read_from_different_pid_denied() {
        let mut s = sample_state();
        s.attempt_read("secrets.yaml", 100, Some("abc123"), 0, 1024);
        let out = s.attempt_read("secrets.yaml", 200, Some("abc123"), 0, 1024);
        assert_eq!(out, ReadOutcome::AlreadyAccessed);
    }

    #[test]
    fn wrong_hash_denied() {
        let mut s = sample_state();
        let out = s.attempt_read("secrets.yaml", 100, Some("wrong"), 0, 1024);
        assert_eq!(
            out,
            ReadOutcome::HashMismatch {
                got: "wrong".into(),
                expected: "abc123".into(),
            }
        );
    }

    #[test]
    fn none_hash_denied() {
        let mut s = sample_state();
        let out = s.attempt_read("secrets.yaml", 100, None, 0, 1024);
        assert!(matches!(out, ReadOutcome::HashMismatch { .. }));
    }

    #[test]
    fn reset_allows_second_read() {
        let mut s = sample_state();
        s.attempt_read("secrets.yaml", 100, Some("abc123"), 0, 1024);
        s.reset(Some("secrets.yaml"));
        let out = s.attempt_read("secrets.yaml", 100, Some("abc123"), 0, 1024);
        assert_eq!(out, ReadOutcome::Granted(b"TOPSECRET".to_vec()));
    }

    #[test]
    fn reset_all_clears_everyone() {
        let mut s = sample_state();
        s.add("other", b"x".to_vec(), "h");
        s.attempt_read("secrets.yaml", 100, Some("abc123"), 0, 1024);
        assert_eq!(s.reset(None), 2);
    }

    #[test]
    fn rotate_hash_changes_access() {
        let mut s = sample_state();
        assert!(s.rotate_hash("secrets.yaml", "newhash"));
        let out = s.attempt_read("secrets.yaml", 100, Some("abc123"), 0, 1024);
        assert!(matches!(out, ReadOutcome::HashMismatch { .. }));
        let out = s.attempt_read("secrets.yaml", 100, Some("newhash"), 0, 1024);
        assert_eq!(out, ReadOutcome::Granted(b"TOPSECRET".to_vec()));
    }

    #[test]
    fn missing_secret_not_found() {
        let mut s = sample_state();
        assert_eq!(
            s.attempt_read("nope", 100, Some("abc123"), 0, 1024),
            ReadOutcome::NotFound
        );
    }

    // ── multi-chunk read tests ───────────────────────────────────

    #[test]
    fn multi_chunk_forward_reads_allowed() {
        let mut s = sample_state();
        // content = "TOPSECRET" (9 bytes)
        // Chunk 1: offset 0, size 4
        let out1 = s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 4);
        assert!(matches!(out1, ReadOutcome::Granted(_)));
        // Chunk 2: offset 4, size 4 — forward, must succeed
        let out2 = s.attempt_read("secrets.yaml", 42, Some("abc123"), 4, 4);
        assert!(matches!(out2, ReadOutcome::Granted(_)));
        // Chunk 3: offset 8, size 4 — forward, must succeed
        let out3 = s.attempt_read("secrets.yaml", 42, Some("abc123"), 8, 4);
        assert!(matches!(out3, ReadOutcome::Granted(_)));
        // Counter should still be 1
        assert_eq!(s.secrets.get("secrets.yaml").unwrap().access_count, 1);
        // Progress should cover the whole file
        assert_eq!(s.secrets.get("secrets.yaml").unwrap().read_progress, 9);
    }

    #[test]
    fn multi_chunk_backward_read_denied() {
        let mut s = sample_state();
        // Read first 4 bytes
        s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 4);
        // Re-read offset 0 — denied (already served)
        let out = s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 4);
        assert_eq!(out, ReadOutcome::AlreadyAccessed);
    }

    #[test]
    fn multi_chunk_overlap_denied() {
        let mut s = sample_state();
        // Read 0..6
        s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 6);
        // Read 3..9 — overlaps with 0..6 at bytes 3..6 — denied
        let out = s.attempt_read("secrets.yaml", 42, Some("abc123"), 3, 6);
        assert_eq!(out, ReadOutcome::AlreadyAccessed);
    }

    #[test]
    fn multi_chunk_read_beyond_eof_allowed() {
        let mut s = sample_state();
        // Read entire file
        s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 9);
        // Read at EOF — returns empty, but allowed (no overlap)
        let out = s.attempt_read("secrets.yaml", 42, Some("abc123"), 9, 4);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn multi_chunk_same_pid_no_hash_recheck() {
        let mut s = sample_state();
        s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 4);
        // Subsequent forward read with WRONG hash — still allowed
        let out = s.attempt_read("secrets.yaml", 42, Some("totally_wrong"), 4, 4);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn cross_pid_read_after_first_denied() {
        let mut s = sample_state();
        s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 1024);
        let out = s.attempt_read("secrets.yaml", 99, Some("abc123"), 0, 1024);
        assert_eq!(out, ReadOutcome::AlreadyAccessed);
    }

    #[test]
    fn reset_clears_read_progress() {
        let mut s = sample_state();
        s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 4);
        assert_eq!(
            s.secrets.get("secrets.yaml").unwrap().read_progress,
            4
        );
        s.reset(Some("secrets.yaml"));
        assert_eq!(
            s.secrets.get("secrets.yaml").unwrap().read_progress,
            0
        );
        // After reset, offset 0 is allowed again
        let out = s.attempt_read("secrets.yaml", 42, Some("abc123"), 0, 4);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn many_forward_reads_same_pid_still_one_count() {
        let mut s = sample_state();
        for i in 0..9 {
            let out = s.attempt_read("secrets.yaml", 7, Some("abc123"), i, 1);
            assert!(matches!(out, ReadOutcome::Granted(_)), "failed at offset {i}");
        }
        assert_eq!(
            s.secrets.get("secrets.yaml").unwrap().access_count,
            1
        );
    }

    // ── wildcard hash tests ──────────────────────────────────────

    #[test]
    fn wildcard_allows_known_hash() {
        let mut s = ServerState::new();
        s.add("s", b"DATA".to_vec(), "*");
        let out = s.attempt_read("s", 100, Some("any_hash_value"), 0, 1024);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn wildcard_allows_unknown_hash() {
        let mut s = ServerState::new();
        s.add("s", b"DATA".to_vec(), "*");
        // Simulates container process where /proc/{pid}/exe can't be read
        let out = s.attempt_read("s", 100, None, 0, 1024);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn wildcard_still_enforces_one_read() {
        let mut s = ServerState::new();
        s.add("s", b"DATA".to_vec(), "*");
        // First process reads
        let out = s.attempt_read("s", 100, None, 0, 1024);
        assert!(matches!(out, ReadOutcome::Granted(_)));
        // Different process denied
        let out = s.attempt_read("s", 200, None, 0, 1024);
        assert_eq!(out, ReadOutcome::AlreadyAccessed);
    }

    #[test]
    fn wildcard_still_enforces_forward_only() {
        let mut s = ServerState::new();
        s.add("s", b"0123456789".to_vec(), "*");
        s.attempt_read("s", 42, None, 0, 4);
        // Backward read denied even with wildcard
        let out = s.attempt_read("s", 42, None, 0, 4);
        assert_eq!(out, ReadOutcome::AlreadyAccessed);
        // Forward read allowed
        let out = s.attempt_read("s", 42, None, 4, 4);
        assert!(matches!(out, ReadOutcome::Granted(_)));
    }

    #[test]
    fn non_wildcard_denies_unknown_hash() {
        let mut s = sample_state(); // hash = "abc123"
        let out = s.attempt_read("secrets.yaml", 100, None, 0, 1024);
        assert!(matches!(out, ReadOutcome::HashMismatch { .. }));
    }
}

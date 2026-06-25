use std::collections::HashMap;

/// One secret file tracked by the gatekeeper.
#[derive(Debug, Clone)]
pub struct SecretRecord {
    pub content: Vec<u8>,
    pub allowed_hash: String,
    pub access_count: u64,
}

/// Result of a FUSE read attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum ReadOutcome {
    /// Content served successfully; counter was incremented.
    Granted(Vec<u8>),
    /// Process hash did not match.
    HashMismatch { got: String, expected: String },
    /// No such secret.
    NotFound,
}

/// Shared mutable state behind the FUSE filesystem and the socket server.
#[derive(Debug, Default)]
pub struct ServerState {
    pub secrets: HashMap<String, SecretRecord>,
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
            },
        );
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.secrets.remove(name).is_some()
    }

    /// Attempt to read a secret.  The caller supplies the *resolved* hash of
    /// the requesting process (or `None` if it could not be determined).
    ///
    /// This is the core gatekeeper logic, kept side-effect-free apart from
    /// mutating the counter so it is trivially unit-testable.
    pub fn attempt_read(&mut self, name: &str, pid_hash: Option<&str>) -> ReadOutcome {
        let Some(rec) = self.secrets.get_mut(name) else {
            return ReadOutcome::NotFound;
        };

        match pid_hash {
            Some(h) if h == rec.allowed_hash => {
                rec.access_count += 1;
                ReadOutcome::Granted(rec.content.clone())
            }
            Some(h) => ReadOutcome::HashMismatch {
                got: h.to_string(),
                expected: rec.allowed_hash.clone(),
            },
            None => ReadOutcome::HashMismatch {
                got: "<unknown>".to_string(),
                expected: rec.allowed_hash.clone(),
            },
        }
    }

    /// Reset the access counter for one secret (or all when `name` is `None`).
    /// Returns the number of counters that were reset.
    pub fn reset(&mut self, name: Option<&str>) -> usize {
        match name {
            Some(n) => {
                if let Some(rec) = self.secrets.get_mut(n) {
                    rec.access_count = 0;
                    1
                } else {
                    0
                }
            }
            None => {
                let count = self.secrets.len();
                for rec in self.secrets.values_mut() {
                    rec.access_count = 0;
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
        let out = s.attempt_read("secrets.yaml", Some("abc123"));
        assert_eq!(out, ReadOutcome::Granted(b"TOPSECRET".to_vec()));
    }

    #[test]
    fn second_read_also_grants() {
        let mut s = sample_state();
        s.attempt_read("secrets.yaml", Some("abc123"));
        let out = s.attempt_read("secrets.yaml", Some("abc123"));
        assert_eq!(out, ReadOutcome::Granted(b"TOPSECRET".to_vec()));
        assert_eq!(s.secrets.get("secrets.yaml").unwrap().access_count, 2);
    }

    #[test]
    fn wrong_hash_denied() {
        let mut s = sample_state();
        let out = s.attempt_read("secrets.yaml", Some("wrong"));
        assert_eq!(
            out,
            ReadOutcome::HashMismatch {
                got: "wrong".into(),
                expected: "abc123".into()
            }
        );
    }

    #[test]
    fn reset_zeroes_counter() {
        let mut s = sample_state();
        s.attempt_read("secrets.yaml", Some("abc123"));
        s.attempt_read("secrets.yaml", Some("abc123"));
        assert_eq!(s.secrets.get("secrets.yaml").unwrap().access_count, 2);
        s.reset(Some("secrets.yaml"));
        assert_eq!(s.secrets.get("secrets.yaml").unwrap().access_count, 0);
    }

    #[test]
    fn reset_all_clears_everyone() {
        let mut s = sample_state();
        s.add("other", b"x".to_vec(), "h");
        s.attempt_read("secrets.yaml", Some("abc123"));
        assert_eq!(s.reset(None), 2);
    }

    #[test]
    fn rotate_hash_changes_access() {
        let mut s = sample_state();
        assert!(s.rotate_hash("secrets.yaml", "newhash"));
        let out = s.attempt_read("secrets.yaml", Some("abc123"));
        assert!(matches!(out, ReadOutcome::HashMismatch { .. }));
        let out = s.attempt_read("secrets.yaml", Some("newhash"));
        assert_eq!(out, ReadOutcome::Granted(b"TOPSECRET".to_vec()));
    }

    #[test]
    fn missing_secret_not_found() {
        let mut s = sample_state();
        assert_eq!(s.attempt_read("nope", Some("abc123")), ReadOutcome::NotFound);
    }
}

use serde::{Deserialize, Serialize};

/// Read-only status snapshot for a secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretStatus {
    pub name: String,
    pub access_count: u64,
    /// One entry per permitted hash (issue #34 MR2/MR3): the hash and
    /// the process that obtained it, when known. Status renders one
    /// row per entry (review on #45) — so the wire carries the
    /// STRUCTURE, not a pre-joined display string. Breaking wire
    /// change: minor version bumped, mixed vintages fail the
    /// handshake instead of the parse.
    pub allowed_hashes: Vec<HashEntryStatus>,
    /// The container-view (anonymized) name for this secret (issue
    /// #47) — shown beside the clear name so bind-mounts and
    /// container configs can reference the stable inner form.
    pub inner: String,
    pub size: usize,
    /// Set by `grant-forever`: the allowed package may read without
    /// per-read approval.
    pub unlimited: bool,
}

/// One permitted hash with provenance, as reported by `status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashEntryStatus {
    pub hash: String,
    /// The process that obtained this hash (grant-forever fills it);
    /// None when permitted anonymously (add/rotate).
    pub by: Option<String>,
}

/// One entry in a `list-mounts` response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MountEntry {
    pub name: String,
    pub size: usize,
}

/// Information about a pending access request waiting for manual approval.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PendingAccessInfo {
    pub id: u64,
    pub secret_name: String,
    /// Name of the requesting process (from `/proc/<pid>`/comm), if known.
    #[serde(default)]
    pub process_name: Option<String>,
    pub pid: u32,
    pub pid_hash: Option<String>,
    /// Why `pid_hash` is absent, when the server knows: the package-hash
    /// inspection of the reading process failed with this error (e.g.
    /// process invisible from the server's PID namespace, or /proc maps
    /// unreadable due to ptrace/SELinux restrictions). Additive field:
    /// servers that predate it simply omit it.
    #[serde(default)]
    pub pid_hash_error: Option<String>,
    pub reason: String,
    /// The ask timed out and was auto-denied, but the process had a
    /// package hash: it stays listed for grant-forever/deny (issue
    /// #66) with grant disabled. Additive field: old servers omit it.
    #[serde(default)]
    pub expired: bool,
    /// Unix timestamp (seconds) when this request expires.
    pub expires_at: u64,
}

/// On-disk state file written by the orchestrator so that `fuse-client`
/// can restart the server with the same configuration when versions mismatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStateFile {
    pub version: String,
    pub server_pid: u32,
    pub server_binary: String,
    pub mount_point: String,
    pub socket: String,
    pub log_level: String,
    pub pending_timeout: u64,
    pub runtime_wrapper: Option<String>,
    /// The policy daemon's oracle rendezvous when the stack runs with
    /// an override (test isolation, #59): the restart path must
    /// respawn the server on the SAME rendezvous or the surviving
    /// data daemon never reconnects. `None` (and pre-field state
    /// files) means the server's global default.
    #[serde(default)]
    pub oracle_socket: Option<String>,
    pub secrets: Vec<StateSecretEntry>,
}

/// One secret entry in the state file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSecretEntry {
    pub fuse_name: String,
    pub host_path: String,
    pub hash: String,
}

// ── Commands (client → server) ─────────────────────────────────

/// Collapse a set of path-shaped secret names to their first points
/// of difference (issue #34) — implemented as a prefix tree: each
/// edge is exactly one path component, and the rendering follows
/// directly from the tree shape:
///
/// - a component whose parent node has MULTIPLE children is written
///   (it is one of the disambiguating alternatives — the "first
///   point of difference"),
/// - the final component (the file name) is always written,
/// - every maximal chain of remaining single-child nodes collapses
///   into one `...`.
///
///   [foo/bar/x/x1/bar.txt, foo/bar/y/y1/y2/bar.txt, foo/bar/baz.txt]
///   -> .../x/.../bar.txt, .../y/.../bar.txt, .../baz.txt
#[derive(Default)]
struct CollapseTrie {
    /// `terminal` marks a served name ending at this node (a name may
    /// also be a prefix of another name).
    terminal: bool,
    children: std::collections::BTreeMap<String, CollapseTrie>,
}

impl CollapseTrie {
    fn insert(&mut self, comps: &[&str]) {
        let mut node = self;
        for (i, c) in comps.iter().enumerate() {
            node = node.children.entry(c.to_string()).or_default();
            if i == comps.len() - 1 {
                node.terminal = true;
            }
        }
    }

    /// Render one component sequence against the tree.
    fn render(&self, comps: &[&str]) -> String {
        let mut node = self;
        let mut pieces: Vec<String> = Vec::new();
        let mut elided = false;
        for (i, c) in comps.iter().enumerate() {
            let parent_branches = node.children.len() > 1;
            node = node.children.get(*c).expect("inserted before render");
            let write = i == comps.len() - 1 || parent_branches;
            if write {
                if elided {
                    pieces.push("...".into());
                    elided = false;
                }
                pieces.push((*c).to_string());
            } else {
                elided = true;
            }
        }
        if elided {
            // The sequence ended on an elided chain — cannot happen
            // for rendered names (the last component is always
            // written), kept for completeness.
            pieces.push("...".into());
        }
        pieces.join("/")
    }
}

pub fn collapse_paths(paths: &[String]) -> Vec<String> {
    // Dedup, keep order.
    let mut set: Vec<String> = Vec::new();
    for p in paths {
        if !set.contains(p) {
            set.push(p.clone());
        }
    }
    let comps: Vec<Vec<&str>> = set.iter().map(|p| p.split('/').collect()).collect();

    let mut trie = CollapseTrie::default();
    for c in &comps {
        trie.insert(c);
    }
    comps.iter().map(|c| trie.render(c)).collect()
}

/// Deterministically anonymize one path component (issue #47):
/// first 12 hex of sha256(salt || component) — unguessable without
/// the per-install salt, stable across restarts because the salt is
/// persisted with the grant store. Twelve hex = 48 bits per
/// component; with the handful of components a real tree holds, the
/// collision probability is negligible (and detectable at serve
/// time — the server refuses a colliding anonymized name rather than
/// alias two secrets).
/// The per-install anonymization salt: NON-EMPTY by construction.
/// The only constructors are [`Salt::from_bytes`] (rejects empty) and
/// [`Salt::generate`] (OS entropy) — an unsalted, dictionary-reversible
/// anonymization (review on #58: "why do you just allow calling the
/// anonymize path function with an empty salt?") cannot be expressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Salt(Vec<u8>);

impl Salt {
    /// Adopt an existing salt; `None` when the bytes are empty (the
    /// caller decides what a missing salt means — mint or refuse).
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Salt> {
        if bytes.is_empty() {
            None
        } else {
            Some(Salt(bytes))
        }
    }

    /// A fresh 32-byte salt from the OS entropy source. A salt must
    /// come from the OS — hashing time/pid/addresses quietly degrades
    /// every anonymized name. Refuse rather than degrade.
    ///
    /// # Panics
    ///
    /// Panics if `/dev/urandom` cannot be opened or short-reads:
    /// anonymization must not quietly degrade.
    pub fn generate() -> Salt {
        let mut buf = [0u8; 32];
        let mut f = std::fs::File::open("/dev/urandom")
            .expect("/dev/urandom for the anonymization salt");
        use std::io::Read as _;
        f.read_exact(&mut buf)
            .expect("32 bytes from /dev/urandom");
        Salt(buf.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub fn anonymize(salt: &Salt, component: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(component.as_bytes());
    let d = h.finalize();
    d.iter().take(6).map(|b| format!("{b:02x}")).collect()
}


/// The container-view form of a full path: same components, each
/// anonymized under the salt.
/// The container-view name of a full path: ONE hash of the whole
/// path (review on #58), not per-component — short names, a flat
/// mount, and no depth/fan-out structure leaking into the
/// container. The hash input is the full path with separators, so
/// distinct paths are unambiguous.
pub fn anonymize_path(salt: &Salt, name: &str) -> String {
    anonymize(salt, name)
}

/// Whether a server version and a client version speak the same
/// protocol: major and minor must match; the patch component is
/// ignored by design (AGENTS.md) so patch releases never force a
/// server restart.  Malformed versions are incompatible — fail closed.
pub fn versions_compatible(server: &str, client: &str) -> bool {
    fn parts(v: &str) -> Option<(u32, u32)> {
        let mut it = v.split('.');
        let maj = it.next()?.parse().ok()?;
        let min = it.next()?.parse().ok()?;
        Some((maj, min))
    }
    match (parts(server), parts(client)) {
        (Some(s), Some(c)) => s == c,
        _ => false,
    }
}

/// Default permission bits for secrets whose sender does not carry the
/// mode field (conservative read-only).  Shared by the client-facing
/// `AddSecret` and the oracle `Upsert` wire formats.
pub fn default_secret_mode() -> u32 {
    0o400
}

/// Allowed-hash sentinel for secrets hosted without a binary hash
/// (issue #2): no real SHA-256 digest ever equals it, so every read
/// becomes a pending request for manual approval.  grant-forever can
/// still whitelist the observed package hash afterwards.
pub const PENDING_ONLY_HASH: &str = "!pending-only";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    /// Reset the access counter for one secret (or all when `name` is `None`).
    Reset { name: Option<String> },
    /// Return status of every secret.
    //
    // IMPORTANT: Do NOT change this variant's name, serde tag, or the
    // structure of SecretStatus in the response.  Older versions of
    // fuse-client call this command during the server-restart flow to
    // enumerate and restore secrets.  Changing it breaks cross-version
    // compatibility.
    Status,
    /// Add a new secret to the mount.  `mode` is the permission bits of
    /// the source file (masked read-only by the server); older clients
    /// that do not send it get the conservative 0400 default.
    /// MR4: the client sends the source PATH — bytes never cross the
    /// wire in either direction. The policy daemon stats the file
    /// (identity, size, mode) and registers it; content reaches
    /// readers only as fds passed to the data daemon at open time.
    AddSecret {
        name: String,
        path: String,
        hash: String,
        #[serde(default = "default_secret_mode")]
        mode: u32,
    },
    /// Remove a secret from the mount.
    RemoveSecret { name: String },
    /// The outer->inner (container-view) name map, on demand —
    /// status keeps its compact shape (review on #58: the inline
    /// anonymized-path column was far too long).
    ShowMap,
    /// Replace the allowed binary hash for a secret.
    RotateHash { name: String, new_hash: String },
    /// List all currently served secret filenames.
    ListMounts,
    /// List all pending access requests waiting for manual approval.
    ListPending,
    /// Grant a pending access request by ID.
    Grant { id: u64 },
    /// Grant a pending access request permanently: the observed package
    /// hash becomes the secret's allowed hash with unlimited reads.
    GrantForever { id: u64 },
    /// Deny a pending access request by ID (immediate rejection).
    Deny { id: u64 },
    /// Lock in the CURRENT authorizations and deny all future
    /// unauthorized access immediately (issue #66): whitelisted
    /// packages and live read budgets keep working; anything that
    /// would pend is refused on the spot. Persisted in the policy
    /// store — armed across restarts.
    LockDown,
    /// Request the server's protocol version.
    //
    // IMPORTANT: Do NOT change this variant's name or serde tag.
    // Older versions of fuse-client rely on this exact command to
    // detect version mismatches before restarting the server.
    GetVersion,
    /// Request the server's log file path.
    GetLogPath,
}

// ── Responses (server → client) ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// AddSecret succeeded; `inner` is the anonymized container-view
    /// name (issue #47) the mount serves the secret under.
    Added { inner: String },
    Ok,
    Error { message: String },
    #[serde(alias = "Status")]
    Status {
        secrets: Vec<SecretStatus>,
        /// Issue #66: the retro-active lockdown is armed — new
        /// unauthorized access is refused immediately. Additive
        /// (defaulted) so old clients still parse.
        #[serde(default)]
        lockdown: bool,
    },
    MountList { mounts: Vec<MountEntry> },
    PendingList { pending: Vec<PendingAccessInfo> },
    /// Server protocol version.
    Version { version: String },
    /// Server's log file path.
    LogPath { path: String },
    /// The outer->inner name map (issue #47), on demand.
    Map { entries: Vec<MapEntry> },
}

/// One row of the outer->inner name map.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MapEntry {
    /// Clear host-side name (the policy/display language).
    pub outer: String,
    /// Anonymized container-view path the mount serves it under.
    pub inner: String,
}

#[cfg(test)]
mod tests {
    use super::Salt;
    fn s4lt() -> Salt {
        Salt::from_bytes(b"salt".to_vec()).unwrap()
    }


#[test]
fn an_empty_salt_is_unrepresentable() {
        // Review on #58: "why do you just allow calling the anonymize
        // path function with an empty salt?" — you cannot anymore:
        // Salt::from_bytes rejects empty, anonymize* only accept &Salt,
        // and the only other constructor is OS entropy.
        assert!(Salt::from_bytes(Vec::new()).is_none());
        assert!(Salt::from_bytes(vec![1]).is_some());
        assert!(!Salt::generate().as_bytes().is_empty());
    }

    #[test]
    fn anonymize_is_deterministic_salt_sensitive_and_shaped() {
    let a = anonymize(&s4lt(), "git.netrc");
    let b = anonymize(&s4lt(), "git.netrc");
    assert_eq!(a, b, "same salt + component -> same name (stability)");
    assert_eq!(a.len(), 12, "12 hex chars");
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, anonymize(&Salt::from_bytes(b"other".to_vec()).unwrap(), "git.netrc"), "salt changes the name");
    assert_ne!(anonymize(&s4lt(), "a"), anonymize(&s4lt(), "b"));
    assert!(!anonymize_path(&s4lt(), "x/y/z.txt").contains('/'), "flat whole-path hash");
}


    #[test]
    fn collapse_to_first_points_of_difference_issue_example_1() {
        let got = collapse_paths(&[
            "foo/bar/x/x1/bar.txt".to_string(),
            "foo/bar/y/y1/y2/bar.txt".to_string(),
            "foo/bar/baz.txt".to_string(),
        ]);
        assert_eq!(
            got,
            vec![
                ".../x/.../bar.txt".to_string(),
                ".../y/.../bar.txt".to_string(),
                ".../baz.txt".to_string(),
            ]
        );
    }

    #[test]
    fn collapse_to_first_points_of_difference_issue_example_2() {
        let got = collapse_paths(&[
            "foo/bar/x/x1/bar.txt".to_string(),
            "foo/bar/y/y1/y2/bar.txt".to_string(),
            "foo/bar/x/x2/bar.txt".to_string(),
        ]);
        assert_eq!(
            got,
            vec![
                ".../x/x1/bar.txt".to_string(),
                ".../y/.../bar.txt".to_string(),
                ".../x/x2/bar.txt".to_string(),
            ]
        );
    }

    #[test]
    fn collapse_handles_names_nested_under_names() {
        // The trie marks terminals mid-tree: a served name that is
        // also a prefix of another renders both distinguishably.
        let got = collapse_paths(&["a/b".to_string(), "a/b/c.txt".to_string()]);
        assert_eq!(got, vec![".../b".to_string(), ".../c.txt".to_string()]);
    }

    #[test]
    fn collapse_degenerate_cases() {
        // single short path: itself
        assert_eq!(collapse_paths(&["a.txt".into()]), vec!["a.txt".to_string()]);
        // single long path: elided prefix + basename
        assert_eq!(
            collapse_paths(&["a/b/c/d.txt".into()]),
            vec![".../d.txt".to_string()]
        );
        // no common prefix: nothing elided at the front
        assert_eq!(
            collapse_paths(&["a/x.txt".into(), "b/y.txt".into()]),
            vec!["a/x.txt".to_string(), "b/y.txt".to_string()]
        );
    }

    use super::*;

    #[test]
    fn versions_compatible_ignores_patch_only() {
        assert!(versions_compatible("0.27.0", "0.27.9"));
        assert!(versions_compatible("1.2.3", "1.2.4"));
    }

    #[test]
    fn versions_compatible_rejects_major_minor_drift() {
        assert!(!versions_compatible("0.26.5", "0.27.0"));
        assert!(!versions_compatible("1.3.0", "1.2.9"));
        assert!(!versions_compatible("2.0.0", "1.99.0"));
    }

    #[test]
    fn versions_compatible_fails_closed_on_garbage() {
        assert!(!versions_compatible("", "0.27.0"));
        assert!(!versions_compatible("zero.27.0", "0.27.0"));
        // A missing patch component is still major.minor — compatible.
        assert!(versions_compatible("0.27", "0.27.0"));
    }


    use super::PendingAccessInfo;

    /// Wire compatibility: the `pid_hash_error` field is additive — a
    /// payload from a server that predates it (no field at all) must
    /// deserialize with the field defaulting to None.
    #[test]
    fn pending_info_deserializes_without_the_hash_error_field() {
        let old = r#"{
            "id": 5,
            "secret_name": "s",
            "process_name": "gh-curl",
            "pid": 42,
            "pid_hash": null,
            "reason": "read request",
            "expires_at": 99
        }"#;
        let info: PendingAccessInfo = serde_json::from_str(old).expect("old payload parses");
        assert_eq!(info.id, 5);
        assert_eq!(info.pid_hash_error, None, "absent field defaults to None");
    }

    #[test]
    fn pending_info_round_trips_the_hash_error() {
        let info = PendingAccessInfo {
            id: 6,
            secret_name: "s".into(),
            process_name: None,
            pid: 7,
            pid_hash: None,
            pid_hash_error: Some("read /proc/7/maps: Permission denied".into()),
            reason: "r".into(),
            expires_at: 1,
            expired: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: PendingAccessInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back, info);
        assert!(json.contains("pid_hash_error"));
    }
}

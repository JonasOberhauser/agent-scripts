use serde::{Deserialize, Serialize};

/// Read-only status snapshot for a secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretStatus {
    pub name: String,
    pub access_count: u64,
    pub allowed_hash: String,
    pub size: usize,
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
    pub pid: u32,
    pub pid_hash: Option<String>,
    pub reason: String,
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
    pub allow_other: bool,
    pub log_level: String,
    pub pending_timeout: u64,
    pub runtime_wrapper: Option<String>,
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
    /// Add a new secret to the mount.
    AddSecret {
        name: String,
        content: Vec<u8>,
        hash: String,
    },
    /// Remove a secret from the mount.
    RemoveSecret { name: String },
    /// Replace the allowed binary hash for a secret.
    RotateHash { name: String, new_hash: String },
    /// List all currently served secret filenames.
    ListMounts,
    /// List all pending access requests waiting for manual approval.
    ListPending,
    /// Grant a pending access request by ID.
    Grant { id: u64 },
    /// Deny a pending access request by ID (immediate rejection).
    Deny { id: u64 },
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
    Ok,
    Error { message: String },
    Status { secrets: Vec<SecretStatus> },
    MountList { mounts: Vec<MountEntry> },
    PendingList { pending: Vec<PendingAccessInfo> },
    /// Server protocol version.
    Version { version: String },
    /// Server's log file path.
    LogPath { path: String },
}

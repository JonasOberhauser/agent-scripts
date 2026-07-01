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

// ── Commands (client → server) ─────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    /// Reset the access counter for one secret (or all when `name` is `None`).
    Reset { name: Option<String> },
    /// Return status of every secret.
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
}

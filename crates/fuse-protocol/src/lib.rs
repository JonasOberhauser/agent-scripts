pub mod error;
pub mod io;
pub mod protocol;
pub mod real_io;

/// Semantic version of the fuse-server/fuse-client protocol.
/// Both client and server must share the same version.
/// Increment the minor version for every build that changes either.
//
// IMPORTANT: Do NOT change this constant's semantics or remove it.
// Older versions of fuse-client and fuse-server rely on this exact
// constant and the GetVersion command to detect version mismatches.
// Changing it without coordination breaks cross-version compatibility.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ── Well-known paths ───────────────────────────────────────────
// All hardcoded paths live here.  No other file should contain
// "/tmp/fuse-gatekeeper" as a literal string.

/// Unix socket for server-client communication.
pub const DEFAULT_SOCKET: &str = "/tmp/fuse-gatekeeper.sock";
/// FUSE mount point.
pub const DEFAULT_MOUNT_POINT: &str = "/tmp/fuse-gatekeeper-mnt";
/// Server log file.
pub const DEFAULT_LOG_PATH: &str = "/tmp/fuse-gatekeeper.log";
/// State file written by the orchestrator, read by fuse-client for restarts.
pub const STATE_FILE: &str = "/tmp/fuse-gatekeeper-state.json";

pub use error::IoError;
pub use io::{CommandOutput, IoProvider, SystemIo, Transport};
pub use protocol::{Command, MountEntry, PendingAccessInfo, Response, SecretStatus, ServerStateFile, StateSecretEntry};
pub use real_io::{MockSystemIo, RealSystemIo};

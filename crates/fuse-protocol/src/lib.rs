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

pub use error::IoError;
pub use io::{CommandOutput, IoProvider, SystemIo, Transport};
pub use protocol::{Command, MountEntry, PendingAccessInfo, Response, SecretStatus, ServerStateFile, StateSecretEntry};
pub use real_io::{MockSystemIo, RealSystemIo};

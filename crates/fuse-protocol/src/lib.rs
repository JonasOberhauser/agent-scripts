pub mod error;
pub mod io;
pub mod protocol;
pub mod real_io;

/// Semantic version of the fuse-server/fuse-client protocol.
/// Both client and server must share the same version.
/// Increment the minor version for every build that changes either.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use error::IoError;
pub use io::{CommandOutput, IoProvider, SystemIo, Transport};
pub use protocol::{Command, MountEntry, PendingAccessInfo, Response, SecretStatus, ServerStateFile, StateSecretEntry};
pub use real_io::{MockSystemIo, RealSystemIo};

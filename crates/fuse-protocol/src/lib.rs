pub mod error;
pub mod io;
pub mod protocol;
pub mod real_io;
pub mod servatui_protocols;

/// Semantic version of the fuse-server/fuse-client protocol.
/// Both client and server must share the same version.
/// Increment the minor version for every build that changes either.
//
// IMPORTANT: Do NOT change this constant's semantics or remove it.
// Older versions of fuse-client and fuse-server rely on this exact
// constant and the GetVersion command to detect version mismatches.
// Changing it without coordination breaks cross-version compatibility.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The client-server handshake compares only major and minor versions:
/// patch releases never change the wire protocol and must not force a
/// restart of the long-running shared server.  Unparseable versions
/// (e.g. an old server's placeholder) count as incompatible.
pub fn protocol_compatible(a: &str, b: &str) -> bool {
    fn major_minor(s: &str) -> Option<(&str, &str)> {
        let mut it = s.split('.');
        let maj = it.next()?;
        let min = it.next()?;
        let digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
        if digits(maj) && digits(min) {
            Some((maj, min))
        } else {
            None
        }
    }
    match (major_minor(a), major_minor(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

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

/// State file path, overridable via the `FUSE_GATEKEEPER_STATE` environment
/// variable (e.g. for E2E tests that must not clobber a live state file).
pub fn state_file() -> std::path::PathBuf {
    std::env::var_os("FUSE_GATEKEEPER_STATE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(STATE_FILE))
}

pub use error::IoError;
pub use io::{CommandOutput, IoProvider, SystemIo, Transport};
pub use protocol::{Command, MountEntry, PendingAccessInfo, Response, SecretStatus, ServerStateFile, StateSecretEntry};
pub use real_io::{MockSystemIo, RealSystemIo};
pub use servatui_protocols::{
    client_protocols, client_protocols_with_snapshots, pending_info, poll_pending_info,
    poll_pending_once, poll_secret_names, print_response, run_command_once, PendingIds,
    SecretNames,
};

#[cfg(test)]
mod tests {
    use super::protocol_compatible;

    #[test]
    fn same_version_is_compatible() {
        assert!(protocol_compatible("0.26.1", "0.26.1"));
    }

    #[test]
    fn patch_difference_is_compatible() {
        // Patch releases never change the protocol: a stale shared server
        // must not trigger restart prompts.
        assert!(protocol_compatible("0.26.1", "0.26.0"));
        assert!(protocol_compatible("0.26.0", "0.26.1"));
    }

    #[test]
    fn minor_difference_is_incompatible() {
        assert!(!protocol_compatible("0.26.1", "0.27.0"));
        assert!(!protocol_compatible("1.0.0", "0.26.1"));
    }

    #[test]
    fn unparseable_version_is_incompatible() {
        // e.g. an old server's "<unknown>" placeholder must be a mismatch.
        assert!(!protocol_compatible("0.26.1", "<unknown (old server)>"));
        assert!(!protocol_compatible("", "0.26.1"));
    }

    #[test]
    fn missing_patch_component_still_compares_major_minor() {
        assert!(protocol_compatible("0.26", "0.26.3"));
        assert!(!protocol_compatible("0.26", "0.27"));
    }
}

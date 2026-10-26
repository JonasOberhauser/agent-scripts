#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic, unused_results))]
pub mod error;

/// The message positions this crate uses (servyi/lints #7/#16
/// protocol): prose constructors whose string arguments are messages
/// by definition, not constants to name.
macro_rules! register_message {
    ($m:ident) => {
        #[allow(dead_code)]
        const _: &[(&str, &str)] = &[("servyi::message", stringify!($m))];
    };
}
register_message!(IoError);


pub mod hashd;
pub mod io;
pub mod oracle;
pub mod prefix_filter;
pub use oracle::{HostIdentity, KDev, Kino};
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

/// The ORACLE-dialect version (issue #109): the version axis of the
/// fused↔server wire (the control-channel Hello, the adoption gate,
/// the mixed-vintage warning).  It is INDEPENDENT of [`VERSION`]:
///
/// - `VERSION` (the workspace version) is the cmd-socket axis —
///   server↔client `GetVersion` compatibility.  A client-only change
///   bumps it and MUST NOT make an unchanged fused look incompatible
///   with an unchanged server.
/// - THIS constant bumps ONLY when the oracle dialect changes
///   (Hello/Ask/Serve/Remove shapes, SCM_RIGHTS usage) — additive
///   fields only, ever (freeze discipline).
///
/// Pinned to the workspace version at the split (#109) so every
/// deployed binary of the same vintage remains compatible across the
/// axis introduction; it evolves on its own from here.
pub const ORACLE_PROTOCOL_VERSION: &str = "0.34.0";

/// The client-server handshake compares only major and minor versions:
/// patch releases never change the wire protocol and must not force a
/// restart of the long-running shared server.  Unparseable versions
/// (e.g. an old server's placeholder) count as incompatible.
/// Version-component separator.
const SEP_VERSION: char = '.';

pub fn protocol_compatible(a: &str, b: &str) -> bool {
    fn major_minor(s: &str) -> Option<(&str, &str)> {
        let mut it = s.split(SEP_VERSION);
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
/// Where the policy daemon serves the data daemon (fused).
pub const DEFAULT_ORACLE_SOCKET: &str = "/tmp/fuse-gatekeeper-oracle.sock";
/// The flag every daemon/spawner uses to point at the oracle socket
/// (typed by fuse-server, fused, run-agent, and fuse-client's
/// respawn argv — one spelling).
pub const ORACLE_SOCKET_FLAG: &str = "--oracle-socket";
/// The policy daemon's binary name (clap name, orchestrator default).
pub const SERVER_BIN: &str = "fuse-server";
/// The data daemon's binary name (clap name, policy-daemon spawn).
pub const FUSED_BIN: &str = "fused";

// ── environment variables ───────────────────────────────────────
// ONE registry: env-var names are interface, and interface strings
// must not be duplicated per-call-site (the `FUSE_GATEKEEPER_STATE`
// name was read verbatim in two files before this existed; a rename
// would have needed a coordinated edit with nothing failing on a
// miss — the --allow-other lesson at the literal level).

/// Override for [`state_file`] (orchestrator-written, client-read).
pub const ENV_STATE_FILE: &str = "FUSE_GATEKEEPER_STATE";
/// Override for the policy daemon's persistent grant store (MR5).
pub const ENV_POLICY_FILE: &str = "FUSE_GATEKEEPER_POLICY";
/// clap env binding for the command-socket flag (fuse-client).
pub const ENV_CMD_SOCKET: &str = "FUSE_GATEKEEPER_SOCKET";
/// Default command socket (also fuse-server's `--socket` default).
pub const DEFAULT_CMD_SOCKET: &str = "/tmp/fuse-gatekeeper.sock";
/// Where `fuse-server` reaches the privileged hashd socket.
pub const ENV_HASHD_SOCK: &str = "FUSE_HASHD_SOCK";
/// bash's `complete -C` protocol: the completing line. Shared by the
/// client binary (reads it) and the e2e tests (sets it).
// Necessity: external identifiers (names restate their values —
// review on servyi/lints#16).
#[allow(unknown_lints)]
#[allow(inline_literal)]
pub const COMP_LINE: &str = "COMP_LINE";
/// bash's `complete -C` protocol: the cursor offset into COMP_LINE.
// Necessity: external identifiers (names restate their values —
// review on servyi/lints#16).
#[allow(unknown_lints)]
#[allow(inline_literal)]
pub const COMP_POINT: &str = "COMP_POINT";

/// State file path, overridable via [`ENV_STATE_FILE`] (e.g. for
/// E2E tests that must not clobber a live state file).
pub fn state_file() -> std::path::PathBuf {
    std::env::var_os(ENV_STATE_FILE)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(STATE_FILE))
}

pub use error::IoError;
pub use io::{CommandOutput, IoProvider, PathState, SystemIo, Transport};
pub use protocol::{Command, PENDING_ONLY_HASH, HashEntryStatus, MapEntry, MountEntry, PendingAccessInfo, Response, SecretStatus, ServerStateFile, StateSecretEntry, Salt, anonymize, anonymize_path, collapse_paths, versions_compatible};
pub use real_io::{MockSystemIo, RealSystemIo};
pub use servatui_protocols::{cmd, CommandSpec, Completer, COMMAND_TABLE,
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

#[cfg(test)]
mod oracle_axis_tests {
    use super::ORACLE_PROTOCOL_VERSION;

    /// Issue #109: the oracle axis is its own hand-versioned constant,
    /// not env-derived — dialect history, independent of the workspace
    /// (cmd-socket) version.  Pinned at the split to the then-current
    /// workspace version so same-vintage deploys stay compatible.
    #[test]
    fn oracle_axis_is_a_hand_versioned_constant() {
        assert_eq!(ORACLE_PROTOCOL_VERSION, "0.34.0");
    }

    /// The Hello wire shape carries the axis additively (freeze
    /// discipline): an old parser reading a NEW Hello must keep
    /// working — the field stays a bare optional string.
    #[test]
    fn hello_wire_shape_is_additive() {
        let wire = serde_json::to_string(&crate::oracle::OracleRequest::Hello {
            version: Some(ORACLE_PROTOCOL_VERSION.to_string()),
        })
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(v["type"].as_str().unwrap(), "hello");
        assert!(v["version"].is_string());
    }
}

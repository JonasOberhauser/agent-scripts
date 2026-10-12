//! The HANDOFF dialect (#93 F2, the seamless-restart design): a frozen,
//! versioned protocol between an OLD fuse-server lingering in handoff
//! mode and a NEW fuse-server resuming the stack — the ONLY cross-
//! version edge in the system (the old server↔fused and new
//! server↔fused pairs speak their own same-version oracle protocol;
//! review on #97: the new server must never talk to the old FUSED).
//!
//! Split into independent, idempotent commands on purpose (review on
//! #97): a new server that dies mid-operation leaves the old server's
//! state untouched (it keeps every fd copy until COMMIT), and the NEXT
//! attempt re-queries STATUS and re-runs whichever steps it needs.
//!
//! One JSON line per message, LF-terminated (the house framing). The
//! fd batch travels as SCM_RIGHTS ancillary data on the `Fd` reply.
//! Transport: a unix socket at a path recorded in the stack's state
//! file (derived from the oracle socket: `<oracle>.handoff`).
//!
//! FROZEN CONTRACT — additive changes only, ever: new optional fields
//! with defaults, new reply variants tolerated by old readers. Never
//! repurpose, never remove. `HANDOFF_PROTOCOL_VERSION` gates the
//! dialect; servers of different handoff versions simply do not
//! hand off (fresh-mount fallback — the status quo ante).

use serde::{Deserialize, Serialize};

/// The dialect version. Bump ONLY for an incompatible change (which
/// the freeze forbids in practice — prefer additive fields).
pub const HANDOFF_PROTOCOL_VERSION: u32 = 1;

/// How long the old server lingers in handoff mode with nobody
/// completing the takeover before it gives up (reaps its fused, exits)
/// — today's restart behavior as the degradation. Generous on purpose:
/// server startup under load is slow, and operator retry loops exist.
pub const HANDOFF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Derive the handoff rendezvous from the stack's oracle socket — one
/// path per stack, no new naming axis, recorded in the state file so
/// the new server finds it without guessing.
pub fn handoff_socket_path(oracle_socket: &std::path::Path) -> std::path::PathBuf {
    let mut s = oracle_socket.as_os_str().to_os_string();
    s.push(".handoff");
    s.into()
}

/// New server → old server. One command per connection, all safe to
/// repeat: the old server is stateless BETWEEN commands except for
/// `Commit`/`Abort`, and every `Get*` re-serves from copies it holds
/// until one of those two arrives.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HandoffRequest {
    /// Dialect probe + progress report: what the old server holds.
    Status,
    /// Take (or re-take) the custody batch: the mount-connection fd
    /// first, then any open host fds, as ONE SCM_RIGHTS control
    /// message on the `Fd` reply line. Repeatable BY THE SAME TAKER —
    /// the kernel dups per send and the old server keeps its copies
    /// until Commit/Abort. `requester_pid` arbitrates the takeover
    /// race: the FIRST live taker wins; a different requester gets
    /// `Error` while that one lives, and inherits the slot when it
    /// dies (the resumability contract — a crashed successor costs
    /// the next attempt nothing).
    GetFd { attempt: u64, requester_pid: u32 },
    /// Re-send the serialized session state (opaque JSON to the old
    /// server; schema-owned by the FUSED side, versioned by
    /// `session_schema`). Repeatable.
    GetState,
    /// The new pair is serving. The old server retires its fused,
    /// closes its fd copies LAST, and exits. Carries the committing
    /// server's pid for the log and for later Status replies.
    Commit { new_server_pid: u32 },
    /// Give up on the takeover: the old server degrades to today's
    /// behavior (reap fused, exit) so a fresh mount can proceed.
    Abort { reason: String },
}

/// Old server → new server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HandoffReply {
    /// Answer to Status.
    Status {
        handoff_protocol_version: u32,
        /// Whether the take-back from the old fused succeeded (else
        /// there is nothing to hand off — fresh-mount fallback).
        has_fd: bool,
        /// The session-state schema the (old) fused serialized; the
        /// new fused must understand it or decline.
        session_schema: u32,
        /// Set once a Commit arrived: the race arbiter — a second new
        /// server learns it lost and stands down.
        committed_to: Option<u32>,
        /// The old fused's pid (identity cross-check material).
        fused_pid: Option<u32>,
    },
    /// Answer to GetFd — the SCM_RIGHTS batch rides this line:
    /// fd\[0\] = the mount connection fd, fd\[1..\] = open host fds in
    /// table order (matching the state's `open_fds` entries).
    Fd { fd_count: u32 },
    /// Answer to GetState — opaque passthrough.
    State { state: serde_json::Value },
    /// Answer to Commit/Abort.
    Ok,
    /// Anything unparseable or inconsistent; the client should treat
    /// the handoff as unavailable (fresh-mount fallback).
    Error { message: String },
}

/// The session state a fused ships with its fd — written by the OLD
/// fused, read by the NEW fused (same schema gate), opaque to both
/// servers. The servers only carry the `session_schema` number.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandoffSession {
    /// Schema of `payload`; a resuming fused that does not understand
    /// it must DECLINE (never serve a half-understood session).
    pub session_schema: u32,
    pub payload: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_is_snake_cased_and_additive() {
        let s = serde_json::to_string(&HandoffRequest::GetFd {
            attempt: 3,
            requester_pid: 7,
        })
        .expect("internal enum: infallible");
        assert_eq!(s, r#"{"type":"get_fd","attempt":3,"requester_pid":7}"#);
        // additive tolerance: unknown OPTIONAL fields parse
        let with_future = r#"{"type":"status","future_field":true}"#;
        serde_json::from_str::<HandoffRequest>(with_future)
            .expect("future optional fields must not break old readers");
    }

    #[test]
    fn status_round_trips_with_defaults_for_absent_fields() {
        let s =
            r#"{"type":"status","handoff_protocol_version":1,"has_fd":true,"session_schema":1}"#;
        let r: HandoffReply = serde_json::from_str(s).expect("absent Option fields default");
        assert_eq!(
            r,
            HandoffReply::Status {
                handoff_protocol_version: 1,
                has_fd: true,
                session_schema: 1,
                committed_to: None,
                fused_pid: None,
            }
        );
    }

    #[test]
    fn handoff_socket_derives_from_the_oracle_path() {
        use std::path::Path;
        assert_eq!(
            handoff_socket_path(Path::new("/run/x/oracle.sock")),
            Path::new("/run/x/oracle.sock.handoff")
        );
    }
}

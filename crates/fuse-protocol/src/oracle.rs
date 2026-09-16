//! Wire protocol between the FUSE data daemon (`fused`) and the policy
//! daemon (`fuse-server`): fused holds the secret bytes and the mount;
//! every read asks the policy daemon, which owns the trust decisions
//! (one-read semantics, package hashes via hashd, pendings, grants) and
//! the servatui command socket.
//!
//! One JSON line per message, LF-terminated — the same framing as the
//! client-facing protocol.

use serde::{Deserialize, Serialize};

/// fused → policy daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OracleRequest {
    /// Live identity + attributes of a secret, by name, for
    /// LOOKUP/GETATTR (MR4 transparent reads): no adjudication —
    /// metadata visibility is unchanged. The observed (kdev, kino)
    /// lets fused detect host incarnation changes and allocate a new
    /// fuse inode; attrs are always live, never cached in the record.
    Stat { name: String },
    /// Open a secret for reading (adjudicated): `kdev`/`kino` are the
    /// pair fused recorded for the inode the kernel presented — the
    /// policy daemon opens the host file and verifies the descriptor's
    /// OWN identity against them (atomic open+verify). On Allow the
    /// reply carries the host fd as SCM_RIGHTS ancillary data on this
    /// socket; fused replies fh = that fd number and serves reads by
    /// pread. Policy denial → Deny; incarnation replaced → Stale
    /// (fused answers ESTALE, kernel re-resolves); gone/not regular →
    /// Gone (ENOENT).
    Open { name: String, pid: u32, kdev: u64, kino: u64 },
    /// A reader wants `size` bytes of `name` at `offset`. The policy
    /// daemon answers synchronously — including waiting out a pending
    /// until grant/expiry — then replies Allow or Deny.
    /// (Legacy path, pre-MR4; fused no longer sends it — reads are
    /// preads on adjudicated fds — but the semantics are the
    /// adjudication core Open reuses.)
    Ask { name: String, pid: u32, offset: u64, size: u32 },
    /// First message of a persistent CONTROL connection: the policy
    /// daemon pushes Serve/Remove commands to it as secrets change.
    /// `version` is the data daemon's protocol VERSION — wire-optional
    /// (older `fused` sends a bare `hello`), used only to LOG mixed
    /// vintages loudly instead of failing silently across them.
    Hello {
        #[serde(default)]
        version: Option<String>,
    },
}

/// Policy daemon → fused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OracleCommand {
    /// Serve this secret from now on (new or replaced content).
    ///
    /// `mode` is wire-OPTIONAL: policy daemons that predate mode
    /// passthrough do not send it, and a required field would make
    /// them silently invisible to a newer fused (the PR #37 field
    /// report: an alive mount listing only `.` and `..`).  Older
    /// senders therefore keep working; the conservative 0o400 default
    /// matches the client-facing AddSecret contract.
    /// Serve this secret in the mount from now on (MR4): the name
    /// enters the frozen tree with its CURRENT host identity — fused
    /// allocates its fuse inode from (kdev, kino) and refreshes it on
    /// every stat/open. No content: bytes live only in fds passed at
    /// Open. `mode` is wire-optional as before (older senders).
    Serve {
        name: String,
        kdev: u64,
        kino: u64,
        #[serde(default = "crate::protocol::default_secret_mode")]
        mode: u32,
    },
    /// Stop serving this secret (readers get ENOENT).
    Remove { name: String },
}

/// Replies, both directions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OracleReply {
    /// The open may proceed: an fd for the host file arrives as
    /// SCM_RIGHTS ancillary data attached to this reply line.
    Allow,
    /// Live identity + attrs by name (reply to Stat). `regular` is
    /// false when the path exists but is not a regular file.
    StatOk {
        kdev: u64,
        kino: u64,
        size: u64,
        mode: u32,
        regular: bool,
    },
    /// The name is not served (Stat) or its path no longer exists
    /// (Open) → ENOENT.
    Gone,
    /// The host incarnation changed since the caller's inode was
    /// recorded → ESTALE; the kernel re-resolves.
    Stale,
    /// The read must fail; the FUSE errno is the policy daemon's call
    /// (EACCES for denials, ENOENT when the policy no longer knows the
    /// secret).
    Deny { errno: i32, reason: String },
    Ok,
    Error { message: String },
}

#[cfg(test)]
mod tests {
    #[test]
    fn serve_without_mode_parses_with_conservative_default() {
        // Wire-optional mode (older senders keep working; the
        // conservative 0o400 default matches the client contract).
        let back: OracleCommand =
            serde_json::from_str(r#"{"type":"serve","name":"s.yaml","kdev":52,"kino":9}"#).unwrap();
        assert_eq!(
            back,
            OracleCommand::Serve { name: "s.yaml".into(), kdev: 52, kino: 9, mode: 0o400 }
        );
    }


    use super::*;

    #[test]
    fn round_trips_every_message() {
        let msgs: Vec<String> = vec![
            serde_json::to_string(&OracleRequest::Ask {
                name: "s.yaml".into(),
                pid: 42,
                offset: 3,
                size: 128,
            })
            .unwrap(),
            serde_json::to_string(&OracleCommand::Serve {
                name: "s.yaml".into(),
                kdev: 52,
                kino: 9,
                mode: 0o400,
            })
            .unwrap(),
            serde_json::to_string(&OracleCommand::Remove { name: "s.yaml".into() }).unwrap(),
            serde_json::to_string(&OracleReply::Allow).unwrap(),
            serde_json::to_string(&OracleReply::Deny {
                errno: 13,
                reason: "hash mismatch".into(),
            })
            .unwrap(),
            serde_json::to_string(&OracleReply::Ok).unwrap(),
            serde_json::to_string(&OracleReply::Error { message: "boom".into() }).unwrap(),
        ];
        // Each line parses back to an equal value of its own type.
        let m = &msgs[0];
        let back: OracleRequest = serde_json::from_str(m).unwrap();
        assert_eq!(
            back,
            OracleRequest::Ask { name: "s.yaml".into(), pid: 42, offset: 3, size: 128 }
        );
        let back: OracleCommand = serde_json::from_str(&msgs[1]).unwrap();
        assert_eq!(
            back,
            OracleCommand::Serve { name: "s.yaml".into(), kdev: 52, kino: 9, mode: 0o400 }
        );
        let back: OracleCommand = serde_json::from_str(&msgs[2]).unwrap();
        assert_eq!(back, OracleCommand::Remove { name: "s.yaml".into() });
        let back: OracleReply = serde_json::from_str(&msgs[3]).unwrap();
        assert_eq!(back, OracleReply::Allow);
        let back: OracleReply = serde_json::from_str(&msgs[4]).unwrap();
        assert_eq!(
            back,
            OracleReply::Deny { errno: 13, reason: "hash mismatch".into() }
        );
        let back: OracleReply = serde_json::from_str(&msgs[5]).unwrap();
        assert_eq!(back, OracleReply::Ok);
        let back: OracleReply = serde_json::from_str(&msgs[6]).unwrap();
        assert_eq!(back, OracleReply::Error { message: "boom".into() });
    }

    #[test]
    fn hello_carries_version_and_round_trips() {
        let wire = serde_json::to_string(&OracleRequest::Hello {
            version: Some("0.27.1".into()),
        })
        .unwrap();
        let back: OracleRequest = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, OracleRequest::Hello { version: Some("0.27.1".into()) });
    }

    #[test]
    fn bare_hello_from_an_old_data_daemon_still_parses() {
        // Pre-version daemons send {"type":"hello"} — the field is
        // wire-optional so they interoperate; the server just cannot
        // skew-check them.
        let back: OracleRequest = serde_json::from_str("{\"type\":\"hello\"}").unwrap();
        assert_eq!(back, OracleRequest::Hello { version: None });
    }
}

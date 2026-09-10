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
    /// A reader wants `size` bytes of `name` at `offset`. The policy
    /// daemon answers synchronously — including waiting out a pending
    /// until grant/expiry — then replies Allow or Deny.
    Ask { name: String, pid: u32, offset: u64, size: u32 },
    /// First message of a persistent CONTROL connection: the policy
    /// daemon pushes Upsert/Remove commands to it as secrets change.
    Hello,
}

/// Policy daemon → fused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OracleCommand {
    /// Serve this secret from now on (new or replaced content).
    Upsert { name: String, content: Vec<u8>, mode: u32 },
    /// Stop serving this secret (readers get ENOENT).
    Remove { name: String },
}

/// Replies, both directions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OracleReply {
    /// The read may be served.
    Allow,
    /// The read must fail; the FUSE errno is the policy daemon's call
    /// (EACCES for denials, ENOENT when the policy no longer knows the
    /// secret).
    Deny { errno: i32, reason: String },
    Ok,
    Error { message: String },
}

#[cfg(test)]
mod tests {
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
            serde_json::to_string(&OracleCommand::Upsert {
                name: "s.yaml".into(),
                content: b"BYTES".to_vec(),
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
            OracleCommand::Upsert { name: "s.yaml".into(), content: b"BYTES".to_vec(), mode: 0o400 }
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
}

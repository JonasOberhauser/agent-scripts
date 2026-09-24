#![allow(clippy::unwrap_used, clippy::panic, unused_results)]

#[cfg(test)]
mod tests {

    #[test]
    fn state_file_round_trips_the_oracle_rendezvous() {
        // #59 review finding: a stack running with an --oracle-socket
        // override must come back on the SAME rendezvous when
        // fuse-client restart respawns it — the surviving data daemon
        // retries that socket forever. The state file is the only
        // channel that carries it across the restart.
        let state = r#"{"version":"0.30.0","server_pid":7,"server_binary":"/x/fuse-server","mount_point":"/m","socket":"/s","log_level":"info","pending_timeout":300,"runtime_wrapper":null,"oracle_socket":"/tmp/.tmpABC/oracle.sock","secrets":[]}"#;
        let f: ServerStateFile = serde_json::from_str(state).unwrap();
        assert_eq!(f.oracle_socket.as_deref(), Some("/tmp/.tmpABC/oracle.sock"));
        // and it survives its own serialization
        let back: ServerStateFile =
            serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(back.oracle_socket, f.oracle_socket);
    }

    #[test]
    fn state_file_without_oracle_means_the_global_default() {
        // Pre-field state files (and the single-stack production
        // default) parse to None — exactly what they always meant.
        let old = r#"{"version":"0.28.0","server_pid":7,"server_binary":"/x/fuse-server","mount_point":"/m","socket":"/s","log_level":"info","pending_timeout":300,"runtime_wrapper":null,"secrets":[]}"#;
        let f: ServerStateFile = serde_json::from_str(old).unwrap();
        assert_eq!(f.oracle_socket, None);
    }


    use fuse_protocol::*;

    #[test]
    fn command_round_trip() {
        let cmd = Command::Reset {
            name: Some("secrets.yaml".into()),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let back: Command = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn add_secret_round_trip() {
        let cmd = Command::AddSecret {
            name: "token".into(),
            path: "/tmp/s.bin".into(),
            hash: "abc123".into(),
            mode: 0o600,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"add_secret\""));
        let back: Command = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn add_secret_without_mode_uses_conservative_default() {
        // Old clients do not send the mode field: it must deserialize to
        // the conservative 0400 rather than fail the whole command.
        let old = r#"{"type":"add_secret","name":"t","path":"/tmp/t.bin","hash":"h"}"#;
        let back: Command = serde_json::from_str(old).unwrap();
        match back {
            Command::AddSecret { mode, .. } => assert_eq!(mode, 0o400),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn grant_forever_round_trip() {
        let cmd = Command::GrantForever { id: 42 };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"grant_forever\""));
        let back: Command = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn response_status_round_trip() {
        let resp = Response::Status {
            secrets: vec![SecretStatus {
                inner: String::new(),
            name: "a".into(),
                access_count: 2,
                allowed_hashes: vec![HashEntryStatus { hash: "deadbeef".into(), by: None }],
                size: 42,
                unlimited: false,
            }],
        lockdown: false,
    };
        let json = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn reset_all_uses_none() {
        let cmd = Command::Reset { name: None };
        let json = serde_json::to_string(&cmd).unwrap();
        let back: Command = serde_json::from_str(&json).unwrap();
        assert_eq!(Command::Reset { name: None }, back);
    }
}

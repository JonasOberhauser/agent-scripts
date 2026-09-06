#[cfg(test)]
mod tests {
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
            content: vec![1, 2, 3],
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
        let old = r#"{"type":"add_secret","name":"t","content":[1],"hash":"h"}"#;
        let back: Command = serde_json::from_str(old).unwrap();
        match back {
            Command::AddSecret { mode, .. } => assert_eq!(mode, 0o400),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn response_status_round_trip() {
        let resp = Response::Status {
            secrets: vec![SecretStatus {
                name: "a".into(),
                access_count: 2,
                allowed_hash: "deadbeef".into(),
                size: 42,
            }],
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

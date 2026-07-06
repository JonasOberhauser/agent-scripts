use std::path::Path;

use fuse_protocol::{Command, Response};
use servyi_servatui::{SocketConnection, TypedConnection, RawConnection};

/// Check whether a fuse-server is listening at `socket_path`.
pub fn server_exists(socket_path: &Path) -> bool {
    SocketConnection::server_exists(socket_path)
}

/// Map a Command variant to its servatui protocol name.
pub fn command_name(cmd: &Command) -> &'static str {
    match cmd {
        Command::Status => "status",
        Command::Reset { name: None } => "reset-all",
        Command::Reset { name: Some(_) } => "reset",
        Command::AddSecret { .. } => "add",
        Command::RemoveSecret { .. } => "remove",
        Command::RotateHash { .. } => "rotate",
        Command::ListMounts => "mounts",
        Command::ListPending => "pending",
        Command::Grant { .. } => "grant",
        Command::Deny { .. } => "deny",
        Command::GetVersion => "version",
        Command::GetLogPath => "logpath",
    }
}

/// Connect to the fuse-server, send one Command, receive the Response.
/// Uses servatui's wire protocol (protocol name → request → response → sentinel).
pub fn send_command(socket_path: &Path, cmd: &Command) -> Result<Response, String> {
    let proto_name = command_name(cmd);
    let mut conn = SocketConnection::connect(socket_path)?;

    conn.send_typed(&proto_name.to_string())?;
    conn.send_typed(cmd)?;

    let data = conn.recv_bytes()?;

    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&data) {
        if let Some(err) = val.get("__error__").and_then(|v| v.as_str()) {
            return Err(err.to_string());
        }
    }

    let resp: Response = serde_json::from_slice(&data)
        .map_err(|e| format!("Failed to parse response: {e}"))?;

    conn.send_typed(&())?; // client step 2 output
    conn.send_typed(&())?; // sentinel

    Ok(resp)
}

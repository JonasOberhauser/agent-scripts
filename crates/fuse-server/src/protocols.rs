use std::sync::Mutex;

use servyi_servatui::{Plugin, Protocol, ShellAction};
use fuse_protocol::{Command, Response};

use crate::handler::handle_command;
use crate::state::ServerState;

fn server_protocol(name: &'static str, help: &'static str) -> Protocol {
    Plugin::new(name, help)
        .parse(|_| -> Result<Command, String> { unreachable!("parse is never called on server") })
        .client(|cmd: Command, _out, _input| Ok(cmd))
        .server_ctx(|cmd: Command, ctx: &Mutex<ServerState>| {
            let mut state = ctx.lock().unwrap_or_else(|e| e.into_inner());
            let resp = handle_command(cmd, &mut state);
            match resp {
                Response::Error { message } => Err(message),
                other => Ok(other),
            }
        })
        .client(|resp: Response, out, _input| {
            fuse_protocol::print_response(&resp, out);
            Ok(())
        })
        .finalize(|| Ok(ShellAction::Continue))
}

pub fn server_protocols() -> Vec<Protocol> {
    vec![
        server_protocol("status", "Show all secrets and access counts"),
        server_protocol("mounts", "List mounted secret files"),
        server_protocol("reset", "Reset access counter for one or all secrets"),
        server_protocol("reset-all", "Reset all access counters"),
        server_protocol("add", "Add a new secret from a file"),
        server_protocol("remove", "Remove a secret"),
        server_protocol("rotate", "Change the allowed binary hash"),
        server_protocol("pending", "Show pending access requests"),
        server_protocol("grant", "Grant a pending access request"),
        server_protocol("deny", "Deny a pending access request"),
        server_protocol("version", "Show server version"),
        server_protocol("logpath", "Show server log file path"),
    ]
}

use servyi_servatui::{Plugin, Protocol, ShellAction};
use fuse_protocol::{Command, CommandSpec, COMMAND_TABLE, Response};

use crate::handler::handle_command;
use crate::state::ServerState;

/// Derive the server-side Protocol for one table row.  All rows share
/// the same body: `handle_command` is the exhaustive typed dispatcher,
/// so a Command variant without server logic does not compile.  There
/// is deliberately no per-command list here to drift out of sync with
/// the client registry.
fn server_protocol(spec: &CommandSpec) -> Protocol {
    Plugin::new(spec.name, spec.help)
        .parse(|_| -> Result<Command, String> { unreachable!("parse is never called on server") })
        .client(|cmd: Command, _out, _input| Ok(cmd))
        .server_ctx(|cmd: Command, ctx: &ServerState| {
            let resp = handle_command(cmd, ctx);
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

/// The server registry, derived from the single command table.
pub fn server_protocols() -> Vec<Protocol> {
    COMMAND_TABLE.iter().map(server_protocol).collect()
}

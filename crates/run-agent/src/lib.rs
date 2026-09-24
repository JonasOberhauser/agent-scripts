#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic, unused_results))]
pub mod config;
pub mod orchestrator;
pub(crate) mod preflight;

pub use config::{
    build_create_args, build_exec_args, AgentConfig, Runtime, SecretMapping, DEFAULT_MOUNT_POINT,
    DEFAULT_SOCKET,
};
pub use orchestrator::{run_agent, RunResult};

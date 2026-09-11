//! `netrcd` — a host-side credential broker.
//!
//! Containers hold no long-lived credentials. Instead, clients send
//! typed requests over a unix socket ("perform this allowlisted
//! authenticated request against machine X"); the daemon joins the
//! request with a host-side netrc (the secret) and a two-layer policy
//! (shared site *profiles*: how to talk to a host; per-user *grants*:
//! what is permitted), performs the HTTPS call itself, and returns the
//! response. The credential's only journey is netrc → Authorization
//! header → pinned TLS, entirely on the host.
//!
//! Everything fails closed: unknown machine, missing grant, missing
//! credential, oversized or malformed input, TLS pin mismatch — typed
//! errors, never a guess, never a secret in an error message.

pub mod daemon;
pub mod engine;
pub mod exec;
pub mod loader;
pub mod netrc;
pub mod policy;
pub mod wire;

pub use daemon::{Daemon, DaemonConfig};
pub use engine::{adjudicate, RateState, Verdict};
pub use exec::{ExecError, Executor, OutboundRequest, RealExecutor, UpstreamResponse};
pub use loader::{load_runtime, Diagnostic, Runtime};
pub use wire::{ErrorCode, WireRequest, WireResponse};

/// One request over the wire, fully typed. Built by validating
/// [`WireRequest`]; a request that exists is well-formed.
#[derive(Debug, Clone)]
pub struct Request {
    pub machine: String,
    pub method: crate::policy::Method,
    /// `path?query`, normalized (leading '/', no `.`/`..` segments).
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

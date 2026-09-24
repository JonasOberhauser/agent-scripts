//! The `fused` data daemon crate.
//!
//! The bin target (`fused`) is the daemon; this lib target exposes the
//! pieces drivers, tests, and fuzz tiers link: the Store/FusedFs
//! (`fs`), the daemon side of the mock kernel (`mock_fuser`), and the
//! typed driver client (`mock_driver`).
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod fs;
pub mod mock_driver;
pub mod mock_fuser;

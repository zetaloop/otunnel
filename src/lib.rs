//! Secure MCP Tunnel transport for applications sharing a Tokio runtime.

pub mod config;
pub mod control;
pub mod harpoon;
mod net;
mod oauth;
mod process;
pub mod protocol;
pub mod runtime;
pub use runtime::{Report, Snapshot, Tunnel};
pub use tokio_util::sync::CancellationToken;
pub mod transport;

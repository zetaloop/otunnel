//! Secure MCP Tunnel transport for applications sharing a Tokio runtime.

pub mod config;
mod net;
mod process;
pub mod protocol;
pub mod transport;

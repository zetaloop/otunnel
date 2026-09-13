//! Secure MCP Tunnel transport for applications sharing a Tokio runtime.
//!
//! [`Tunnel`] owns configured services and forwards commands until its
//! [`CancellationToken`] is cancelled. [`transport::Transport`] allows a host
//! application to provide its own asynchronous MCP implementation.

pub mod admin;
mod cloudflare;
pub mod config;
pub mod control;
pub mod harpoon;
#[cfg(feature = "cli")]
pub mod health;
#[cfg(feature = "cli")]
pub mod management;
mod net;
mod oauth;
pub mod process;
pub mod protocol;
mod proxy;
pub mod runtime;
pub mod template;
pub use anyhow::{Error, Result};
pub use runtime::{Report, Snapshot, Tunnel};
pub use tokio_util::sync::CancellationToken;
pub mod transport;

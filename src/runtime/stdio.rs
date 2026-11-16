use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use http::HeaderMap;
use tokio::time::Instant;

use super::Tunnel;
use crate::{
    config,
    process::Process,
    protocol::{Reply, Request},
    transport::{Pipe, Sink, Transport},
};

struct Stdio(RwLock<Option<Arc<Pipe>>>);

impl Stdio {
    fn connection(&self) -> Result<Arc<Pipe>> {
        self.0
            .read()
            .expect("stdio mutex poisoned")
            .clone()
            .context("MCP command is restarting")
    }
}

#[async_trait]
impl Transport for Stdio {
    async fn forward(&self, request: Request, sink: &dyn Sink) -> Result<()> {
        self.connection()?.forward(request, sink).await
    }
    async fn terminate(&self, headers: HeaderMap, discovery: bool) -> Result<Reply> {
        self.connection()?.terminate(headers, discovery).await
    }
    fn kind(&self) -> Option<&'static str> {
        Some("stdio")
    }
    fn process_affinity(&self) -> bool {
        true
    }
    fn stateless(&self) -> bool {
        self.0
            .read()
            .expect("stdio mutex poisoned")
            .as_ref()
            .is_some_and(|pipe| pipe.stateless())
    }
    fn startup_probe(&self) -> bool {
        false
    }
}

async fn spawn(
    command: &str,
    enabled: bool,
    diagnostic: bool,
    initialized: bool,
) -> Result<(Process, Option<Arc<Pipe>>)> {
    let output = if enabled {
        std::process::Stdio::piped()
    } else if diagnostic {
        std::process::Stdio::from(std::io::stderr())
    } else {
        std::process::Stdio::inherit()
    };
    let mut process = Process::spawn(command, output)?;
    let pipe = if enabled {
        let (reader, writer) = process.pipes()?;
        Some(Arc::new(
            Pipe::new(reader, writer)
                .await?
                .send_initialized_notification(initialized),
        ))
    } else {
        None
    };
    Ok((process, pipe))
}

impl Tunnel {
    pub(super) async fn start_stdio(
        &mut self,
        command: config::Command,
        diagnostic: bool,
    ) -> Result<()> {
        let enabled = self.config.enabled(&command.channel);
        anyhow::ensure!(
            !enabled || !self.bindings.contains_key(&command.channel),
            "duplicate channel {}",
            command.channel
        );
        let initialized = self.config.mcp.stdio_send_initialized_notification;
        let restart = self.config.mcp.stdio_failure_policy == "restart";
        let (mut process, mut pipe) =
            spawn(&command.command, enabled, diagnostic, initialized).await?;
        let binding = Arc::new(Stdio(RwLock::new(pipe.clone())));
        if enabled {
            self.bindings
                .insert(command.channel.clone(), binding.clone());
        }
        let state = self.state.clone();
        let stop = self.stop.clone();
        self.children.spawn(async move {
            let mut delay = Duration::ZERO;
            loop {
                let started = Instant::now();
                let mut observation = pipe.as_ref().and_then(|pipe| pipe.observation());
                state.send_modify(|state| {
                    if let Some(pid) = process.id() {
                        state.process_ids.insert(command.channel.clone(), pid);
                    }
                    if let Some(observation) = &mut observation {
                        state.evidence.insert(command.channel.clone(), observation.borrow_and_update().clone());
                    }
                });
                let failure = loop {
                    tokio::select! {
                        biased;
                        () = stop.cancelled() => break None,
                        result = process.wait() => break Some(match result {
                            Ok(status) => anyhow::anyhow!("MCP child exited: {status}"),
                            Err(error) => error,
                        }),
                        result = async {
                            match &pipe {
                                Some(pipe) => pipe.closed().await,
                                None => std::future::pending().await,
                            }
                        } => break Some(result.err().unwrap_or_else(|| anyhow::anyhow!("MCP connection closed"))),
                        result = async {
                            match &mut observation {
                                Some(observation) => observation.changed().await,
                                None => std::future::pending().await,
                            }
                        } => {
                            if result.is_err() {
                                observation = None;
                            } else if let Some(observation) = &mut observation {
                                state.send_modify(|state| {
                                    state.evidence.insert(command.channel.clone(), observation.borrow_and_update().clone());
                                });
                            }
                        }
                    }
                };
                binding.0.write().expect("stdio mutex poisoned").take();
                if let Some(pipe) = pipe.take() {
                    pipe.close().await?;
                    if let Some(observation) = pipe.observation() {
                        state.send_modify(|state| {
                            state.evidence.insert(command.channel.clone(), observation.borrow().clone());
                        });
                    }
                }
                process.stop(Duration::from_secs(if failure.is_some() { 1 } else { 5 })).await?;
                state.send_modify(|state| { state.process_ids.remove(&command.channel); });
                if stop.is_cancelled() {
                    return Ok(());
                }
                let error = failure.context("MCP supervisor stopped")?;
                if !restart {
                    return Err(error.context(format!("channel {} closed", command.channel)));
                }
                delay = if delay.is_zero() || started.elapsed() >= Duration::from_secs(30) {
                    Duration::from_millis(100)
                } else {
                    (delay * 2).min(Duration::from_secs(5))
                };
                tracing::warn!(channel = %command.channel, %error, "MCP child failed; restarting");
                loop {
                    tokio::select! {
                        biased;
                        () = stop.cancelled() => return Ok(()),
                        () = tokio::time::sleep(delay) => {}
                    }
                    match spawn(&command.command, enabled, diagnostic, initialized).await {
                        Ok(child) => {
                            (process, pipe) = child;
                            *binding.0.write().expect("stdio mutex poisoned") = pipe.clone();
                            break;
                        }
                        Err(error) => {
                            tracing::warn!(channel = %command.channel, %error, "MCP child restart failed");
                            delay = (delay * 2).min(Duration::from_secs(5));
                        }
                    }
                }
            }
        });
        Ok(())
    }
}

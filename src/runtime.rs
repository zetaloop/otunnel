use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tokio::{
    sync::{Semaphore, watch},
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::Config,
    control::{Batch, Channel, Control, Delivery, StatusError},
    process::Process,
    protocol::{self, Command, Reply, Request},
    transport::{self, HttpTransport, Pipe, Probe, Sink, Transport},
};

#[derive(Clone, Default, Serialize)]
pub struct Snapshot {
    pub ready: bool,
    pub connected: bool,
    pub control: crate::control::Observation,
    pub lifecycle: &'static str,
    pub cloudflare_ready: Option<bool>,
    pub started_at: u64,
    pub channels: BTreeMap<String, Probe>,
    pub in_flight: usize,
    pub completed: u64,
    pub expired: u64,
    pub failed: u64,
    pub last_error: Option<String>,
}

#[derive(Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}
#[derive(Serialize)]
pub struct Report {
    pub checks: Vec<Check>,
    pub channels: BTreeMap<String, Probe>,
}
impl Report {
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|check| check.passed)
    }
}

/// A configured tunnel running on the caller's Tokio runtime.
/// Use `bind` to attach a transport already owned by the host application.
pub struct Tunnel {
    config: Config,
    control: Arc<Control>,
    harpoon: Arc<crate::harpoon::Harpoon>,
    bindings: BTreeMap<String, Arc<dyn Transport>>,
    children: JoinSet<Result<()>>,
    stop: CancellationToken,
    state: watch::Sender<Snapshot>,
}

impl Tunnel {
    pub fn new(mut config: Config) -> Result<Self> {
        for name in config
            .mcp
            .commands
            .iter_mut()
            .map(|command| &mut command.channel)
            .chain(
                config
                    .mcp
                    .server_urls
                    .iter_mut()
                    .map(|server| &mut server.channel),
            )
            .chain(config.control_plane.poll_channels.iter_mut())
        {
            *name = crate::config::channel(name)?;
        }
        let control = Arc::new(Control::new(&config)?);
        let harpoon = Arc::new(crate::harpoon::Harpoon::new(&config)?);
        let (state, _) = watch::channel(Snapshot {
            control: control.connection().borrow().clone(),
            lifecycle: "starting",
            started_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            ..Default::default()
        });
        Ok(Self {
            config,
            control,
            harpoon,
            bindings: BTreeMap::new(),
            children: JoinSet::new(),
            stop: CancellationToken::new(),
            state,
        })
    }

    pub fn bind(
        mut self,
        channel: impl Into<String>,
        transport: Arc<dyn Transport>,
    ) -> Result<Self> {
        let channel = crate::config::channel(&channel.into())?;
        anyhow::ensure!(
            !self.bindings.contains_key(&channel),
            "duplicate channel {channel}"
        );
        self.bindings.insert(channel, transport);
        Ok(self)
    }

    pub fn status(&self) -> watch::Receiver<Snapshot> {
        self.state.subscribe()
    }

    #[cfg(feature = "cli")]
    pub fn harpoon(&self) -> Arc<crate::harpoon::Harpoon> {
        self.harpoon.clone()
    }

    async fn prepare(&mut self, diagnostic: bool) -> Result<()> {
        if self.config.cloudflared.managed || self.config.cloudflared.token.is_some() {
            let companion =
                crate::cloudflare::Companion::new(&self.config.cloudflared, &self.control).await?;
            self.state
                .send_modify(|state| state.cloudflare_ready = Some(false));
            self.children
                .spawn(companion.supervise(self.stop.clone(), self.state.clone()));
        }
        let wait = self.config.mcp.startup_wait_timeout.0;
        let probe_timeout = if wait.is_zero() {
            Duration::from_secs(2)
        } else {
            wait
        };
        let mut pipes = Vec::new();
        for command in &self.config.mcp.commands {
            let enabled = self.config.enabled(&command.channel);
            let mut process = Process::spawn(&command.command, enabled)?;
            if enabled {
                pipes.push((command.channel.clone(), process.pipes()?));
            }
            self.children.spawn(process.supervise(self.stop.clone()));
        }
        for server in &self.config.mcp.server_urls {
            if self.config.enabled(&server.channel) {
                anyhow::ensure!(
                    !self.bindings.contains_key(&server.channel),
                    "duplicate channel {}",
                    server.channel
                );
                self.bindings.insert(
                    server.channel.clone(),
                    Arc::new(
                        HttpTransport::new(server, &self.config)?.harpoon(self.harpoon.clone()),
                    ),
                );
            }
        }
        for (channel, (reader, writer)) in pipes {
            anyhow::ensure!(
                !self.bindings.contains_key(&channel),
                "duplicate channel {channel}"
            );
            let pipe = Pipe::new(reader, writer)
                .await?
                .send_initialized_notification(self.config.mcp.stdio_send_initialized_notification);
            self.bindings.insert(channel, Arc::new(pipe));
        }
        for (name, transport) in &self.bindings {
            if !transport.available() {
                continue;
            }
            if !diagnostic && !transport.startup_probe() {
                self.state.send_modify(|state| {
                    state.channels.insert(
                        name.clone(),
                        transport::Probe {
                            status: 200,
                            authentication_required: false,
                            server: None,
                            tools: None,
                            oauth_status: None,
                            oauth_error: None,
                        },
                    );
                });
                continue;
            }
            let deadline = Instant::now() + probe_timeout;
            let probe = async {
                loop {
                    match transport::probe(transport.as_ref()).await {
                        Ok(probe) => return Ok(probe),
                        Err(error) if !wait.is_zero() && crate::net::connecting(&error) => {
                            tracing::debug!(channel = %name, %error, "MCP service is starting");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        Err(error) => return Err(error),
                    }
                }
            };
            let mut result = tokio::select! {
                result = timeout_at(deadline, probe) => result.with_context(|| format!("channel {name} startup timed out"))?,
                result = self.children.join_next(), if !self.children.is_empty() => {
                    result.context("child supervisor stopped")???;
                    bail!("MCP child stopped during startup");
                }
            }.with_context(|| format!("probe channel {name}"))?;
            let discovery = timeout_at(deadline, transport.discover())
                .await
                .context("OAuth discovery timed out")
                .and_then(|result| result);
            match discovery {
                Ok(reply) => {
                    result.oauth_status = Some(reply.status);
                    anyhow::ensure!(
                        !result.authentication_required || (200..300).contains(&reply.status),
                        "channel {name} requires authentication but OAuth discovery returned HTTP {}",
                        reply.status
                    );
                }
                Err(error) => {
                    if result.authentication_required {
                        return Err(error.context(format!("OAuth discovery for channel {name}")));
                    }
                    tracing::debug!(channel = %name, %error, "optional OAuth discovery unavailable");
                    result.oauth_error = Some(format!("{error:#}"));
                }
            }
            self.state.send_modify(|state| {
                state.channels.insert(name.clone(), result);
            });
        }
        if self.config.enabled("harpoon") && !self.bindings.contains_key("harpoon") {
            self.bindings.insert("harpoon".into(), self.harpoon.clone());
            if !self.harpoon.is_empty() {
                let probe = transport::probe(self.harpoon.as_ref()).await?;
                self.state.send_modify(|state| {
                    state.channels.insert("harpoon".into(), probe);
                });
            }
        }
        anyhow::ensure!(
            self.bindings.values().any(|binding| binding.available()),
            "no MCP channels configured"
        );
        for channel in &self.config.control_plane.poll_channels {
            anyhow::ensure!(
                self.bindings.contains_key(channel),
                "channel {channel} has no binding"
            );
        }
        self.control.set_channels(channels(&self.bindings))?;
        if self.state.borrow().cloudflare_ready == Some(false) {
            let mut status = self.state.subscribe();
            tokio::select! {
                result = status.wait_for(|state| state.cloudflare_ready == Some(true)) => { result?; }
                result = self.children.join_next() => { result.context("companion supervisor stopped")???; }
            }
        }
        Ok(())
    }

    pub async fn diagnose(mut self) -> Report {
        let mut checks = Vec::new();
        let configuration = self.config.validate();
        checks.push(Check {
            name: "configuration".into(),
            passed: configuration.is_ok(),
            detail: configuration.err().map_or_else(
                || "configuration loaded".into(),
                |error| format!("{error:#}"),
            ),
        });
        match self.prepare(true).await {
            Ok(()) => checks.push(Check {
                name: "mcp".into(),
                passed: true,
                detail: "MCP initialization and tool discovery completed".into(),
            }),
            Err(error) => checks.push(Check {
                name: "mcp".into(),
                passed: false,
                detail: format!("{error:#}"),
            }),
        }
        match self.control.metadata().await {
            Ok(_) => checks.push(Check {
                name: "control_plane".into(),
                passed: true,
                detail: "tunnel metadata received".into(),
            }),
            Err(error) => checks.push(Check {
                name: "control_plane".into(),
                passed: false,
                detail: format!("{error:#}"),
            }),
        }
        let channels = self.state.borrow().channels.clone();
        if let Err(error) = self.shutdown().await {
            checks.push(Check {
                name: "shutdown".into(),
                passed: false,
                detail: format!("{error:#}"),
            });
        }
        Report { checks, channels }
    }

    pub async fn run(mut self, shutdown: CancellationToken) -> Result<()> {
        let result = async {
            self.config.validate()?;
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = self.prepare(false) => result?,
            }
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = self.control.metadata() => { result?; }
            }
            self.state.send_modify(|state| {
                state.connected = true;
                state.control = self.control.connection().borrow().clone();
                state.lifecycle = "running";
                state.ready = state.cloudflare_ready.unwrap_or(true);
            });
            tracing::info!(channels = self.bindings.len(), "tunnel connected");
            self.dispatch(&shutdown).await
        }
        .await;
        self.state.send_modify(|state| {
            state.ready = false;
            state.connected = false;
            state.lifecycle = "draining";
            if let Err(error) = &result {
                state.last_error = Some(format!("{error:#}"));
            }
        });
        let closed = self.shutdown().await;
        result.and(closed)
    }

    async fn dispatch(&mut self, shutdown: &CancellationToken) -> Result<()> {
        let bindings = Arc::new(self.bindings.clone());
        let concurrency = self.config.control_plane.max_inflight_requests;
        let ttl = self
            .config
            .mcp
            .connection_max_ttl
            .map(|span| span.0)
            .filter(|duration| !duration.is_zero());
        let global = Arc::new(Semaphore::new(concurrency));
        let local: BTreeMap<_, _> = bindings
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    Arc::new(Semaphore::new(self.config.mcp.max_concurrent_requests)),
                )
            })
            .collect();
        let local = Arc::new(local);
        let mut requests: JoinSet<Result<bool>> = JoinSet::new();
        let mut connection = self.control.connection();
        let mut connections = JoinSet::new();
        for (name, binding) in bindings.iter() {
            let binding = binding.clone();
            let name = name.clone();
            connections.spawn(async move {
                binding
                    .closed()
                    .await
                    .with_context(|| format!("channel {name} closed"))
            });
        }
        let mut poll: Option<Pin<Box<dyn Future<Output = Result<Batch>> + Send>>> = None;
        let mut initial = true;
        let result = async {
            loop {
                if poll.is_none() && requests.len() < concurrency {
                    self.control.set_channels(channels(&bindings))?;
                    let control = self.control.clone();
                    let limit = concurrency - requests.len();
                    poll = Some(Box::pin(async move { control.poll(limit, initial).await }));
                    initial = false;
                }
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    changed = connection.changed() => {
                        changed?;
                        let observation = connection.borrow_and_update().clone();
                        self.state.send_modify(|state| {
                            state.connected = observation.connected;
                            state.control = observation;
                        });
                    }
                    child = self.children.join_next(), if !self.children.is_empty() => {
                        child.context("child supervisor stopped")???;
                        bail!("MCP child stopped");
                    }
                    connection = connections.join_next(), if !connections.is_empty() => {
                        connection.context("connection monitor stopped")???;
                        bail!("MCP connection stopped");
                    }
                    result = requests.join_next(), if !requests.is_empty() => {
                        let result = result.context("request worker stopped")?;
                        self.state.send_modify(|state| {
                            state.in_flight = requests.len();
                            match &result {
                                Ok(Ok(true)) => state.completed += 1,
                                Ok(Ok(false)) => state.expired += 1,
                                _ => state.failed += 1,
                            }
                        });
                        match result? {
                            Ok(_) => {}
                            Err(error) if error.downcast_ref::<StatusError>().is_some_and(|error| matches!(error.status, 401 | 403)) => return Err(error),
                            Err(error) => {
                                self.state.send_modify(|state| state.last_error = Some(format!("{error:#}")));
                                tracing::error!(%error, "tunnel request failed");
                            }
                        }
                    }
                    batch = async { match &mut poll { Some(poll) => poll.await, None => std::future::pending().await } } => {
                        let batch = batch?;
                        poll = None;
                        for command in batch.commands {
                            let control = self.control.clone();
                            let bindings = bindings.clone();
                            let global = global.clone();
                            let local = local.clone();
                            requests.spawn(async move {
                                let deadline = protocol::timeout(&command.response_timeout).and_then(|duration| batch.received.checked_add(duration));
                                if deadline.is_some_and(|deadline| deadline <= Instant::now()) { return Ok(false); }
                                let work = async {
                                    let _permit = global.acquire().await?;
                                    let permit = local.get(&command.channel).map(|limit| limit.acquire());
                                    let _local = match permit { Some(permit) => Some(permit.await?), None => None };
                                    execute(&control, &bindings, command, ttl).await
                                };
                                if let Some(deadline) = deadline {
                                    match timeout_at(deadline, work).await {
                                        Ok(result) => result.map(|()| true),
                                        Err(_) => Ok(false),
                                    }
                                } else { work.await.map(|()| true) }
                            });
                        }
                        self.state.send_modify(|state| state.in_flight = requests.len());
                    }
                }
            }
        }.await;
        requests.abort_all();
        while requests.join_next().await.is_some() {}
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        self.state.send_modify(|state| state.in_flight = 0);
        result
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.stop.cancel();
        let mut failure = None;
        for transport in self.bindings.values() {
            if let Err(error) = transport.close().await {
                failure.get_or_insert(error);
            }
        }
        while let Some(result) = self.children.join_next().await {
            if let Err(error) = result
                .map_err(anyhow::Error::from)
                .and_then(|result| result)
            {
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
impl Drop for Tunnel {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

async fn execute(
    control: &Arc<Control>,
    bindings: &BTreeMap<String, Arc<dyn Transport>>,
    command: Command,
    ttl: Option<Duration>,
) -> Result<()> {
    if !matches!(
        command.command_type.as_str(),
        "jsonrpc" | "session_termination" | "oauth_discovery"
    ) {
        tracing::warn!(request_id = %command.request_id, command_type = %command.command_type, "unsupported tunnel command");
        return Ok(());
    }
    let delivery = Delivery::new(control.clone(), &command);
    let headers = protocol::header_map(&command.headers)?;
    let binding = bindings.get(&command.channel);
    match command.command_type.as_str() {
        "jsonrpc" => {
            let request = Request {
                discovery: false,
                message: command.jsonrpc.context("JSON-RPC command has no payload")?,
                headers,
            };
            let outcome = match binding {
                Some(binding) => {
                    let forward = binding.forward(request.clone(), &delivery);
                    match ttl {
                        Some(ttl) => timeout(ttl, forward)
                            .await
                            .context("MCP connection lifetime exceeded")
                            .and_then(|result| result),
                        None => forward.await,
                    }
                }
                None => Err(anyhow::anyhow!(
                    "channel {} is unavailable",
                    command.channel
                )),
            };
            if let Err(error) = outcome {
                if error
                    .downcast_ref::<StatusError>()
                    .is_some_and(|error| error.status == 404)
                {
                    return Ok(());
                }
                if delivery.terminal_started()
                    || error
                        .downcast_ref::<StatusError>()
                        .is_some_and(|error| matches!(error.status, 401 | 403))
                {
                    return Err(error);
                }
                delivery
                    .send(Reply::error(&request, 502, -32603, format!("{error:#}"))?)
                    .await?;
            } else if !delivery.terminal_started() {
                delivery
                    .send(Reply::error(
                        &request,
                        502,
                        -32603,
                        "MCP stream ended without a terminal response",
                    )?)
                    .await?;
            }
        }
        "session_termination" | "oauth_discovery" => {
            let kind = if command.command_type == "session_termination" {
                "session_termination_response"
            } else {
                "oauth_discovery_response"
            };
            let outcome = match binding {
                Some(binding) if command.command_type == "session_termination" => {
                    binding.terminate(headers, false).await
                }
                Some(binding) => binding.discover().await,
                None => Ok(Reply::ack(404, kind)),
            };
            let reply = match outcome {
                Ok(reply) => reply,
                Err(error) => {
                    tracing::warn!(request_id = %command.request_id, %error, "MCP control request failed");
                    let mut reply = Reply::ack(502, kind);
                    reply.message = Some(serde_json::value::to_raw_value(
                        &serde_json::json!({"error":format!("{error:#}")}),
                    )?);
                    reply
                }
            };
            control.set_channels(channels(bindings))?;
            delivery.send(reply).await?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn channels(bindings: &BTreeMap<String, Arc<dyn Transport>>) -> Vec<Channel> {
    bindings
        .iter()
        .filter(|(_, transport)| transport.available())
        .map(|(name, transport)| Channel {
            name: name.clone(),
            stateless: transport.stateless(),
            proc_affinity: transport.process_affinity(),
        })
        .collect()
}

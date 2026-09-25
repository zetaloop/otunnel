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
    sync::watch,
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::Config,
    control::{Batch, Channel, Control, Delivery},
    process::Process,
    protocol::{self, Command, Reply, Request},
    transport::{self, HttpTransport, Pipe, Probe, Sink, Transport},
};

mod startup;
pub use startup::Startup;

#[derive(Clone, Default, Serialize)]
pub struct Snapshot {
    pub ready: bool,
    pub mcp_probe: Startup,
    pub oauth: Startup,
    pub metadata_error: Option<String>,
    pub connected: bool,
    pub control: crate::control::Observation,
    pub lifecycle: &'static str,
    pub cloudflare_ready: Option<bool>,
    pub cloudflare_observed_at: f64,
    pub proxy: crate::proxy_health::Snapshot,
    pub started_at: u64,
    pub channels: BTreeMap<String, Probe>,
    pub evidence: BTreeMap<String, serde_json::Value>,
    pub process_ids: BTreeMap<String, u32>,
    pub in_flight: usize,
    pub activity: Activity,
    pub completed: u64,
    pub expired: u64,
    pub failed: u64,
    pub last_error: Option<String>,
}

#[derive(Clone, Default, Serialize)]
pub struct Activity {
    pub queued: usize,
    #[serde(skip)]
    pub active: BTreeMap<String, f64>,
    pub enqueued: u64,
    pub dequeued: u64,
    pub last_enqueue: f64,
    pub last_dequeue: f64,
    pub last_start: f64,
    pub last_completion: f64,
    pub pressure_started: f64,
    pub pressure_seconds: f64,
    pub last_failed: bool,
}

pub use crate::diagnostic::{Check, Report};

/// A configured tunnel running on the caller's Tokio runtime.
/// Use `bind` to attach a transport already owned by the host application.
pub struct Tunnel {
    config: Config,
    control: Arc<Control>,
    harpoon: Arc<crate::harpoon::Harpoon>,
    proxy: Arc<crate::proxy_health::Checker>,
    bindings: BTreeMap<String, Arc<dyn Transport>>,
    children: JoinSet<Result<()>>,
    observers: JoinSet<()>,
    stop: CancellationToken,
    state: watch::Sender<Snapshot>,
}

impl Tunnel {
    pub fn new(mut config: Config) -> Result<Self> {
        config.normalize()?;
        let harpoon = Arc::new(crate::harpoon::Harpoon::new(&config)?);
        let mut control = Control::new(&config)?;
        control.suppress_raw = harpoon.rich_headers.clone();
        let control = Arc::new(control);
        let proxy = Arc::new(crate::proxy_health::Checker::new(&config)?);
        let probe = config
            .mcp
            .server_urls
            .iter()
            .any(|server| server.channel == "main" && config.enabled("main"));
        let (state, _) = watch::channel(Snapshot {
            mcp_probe: if probe {
                Startup::pending()
            } else {
                Startup::default()
            },
            oauth: if probe {
                Startup::pending()
            } else {
                Startup::default()
            },
            cloudflare_ready: (config.cloudflared.managed || config.cloudflared.token.is_some())
                .then_some(false),
            proxy: proxy.status().borrow().clone(),
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
            proxy,
            bindings: BTreeMap::new(),
            children: JoinSet::new(),
            observers: JoinSet::new(),
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
        if !diagnostic
            && (self.config.cloudflared.managed || self.config.cloudflared.token.is_some())
        {
            let companion =
                crate::cloudflare::Companion::new(&self.config.cloudflared, &self.control).await?;
            self.state
                .send_modify(|state| state.cloudflare_ready = Some(false));
            self.children
                .spawn(companion.supervise(self.stop.clone(), self.state.clone()));
        }
        let mut pipes = Vec::new();
        for command in &self.config.mcp.commands {
            let enabled = self.config.enabled(&command.channel);
            let output = if enabled {
                std::process::Stdio::piped()
            } else if diagnostic {
                std::process::Stdio::from(std::io::stderr())
            } else {
                std::process::Stdio::inherit()
            };
            let mut process = Process::spawn(&command.command, output)?;
            if let Some(pid) = process.id() {
                self.state.send_modify(|state| {
                    state.process_ids.insert(command.channel.clone(), pid);
                });
            }
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
        self.state.send_modify(|state| {
            state.evidence = self
                .bindings
                .iter()
                .filter_map(|(name, binding)| {
                    binding.observation().map(|value| (name.clone(), value))
                })
                .collect();
        });
        if self.config.enabled("harpoon") && !self.bindings.contains_key("harpoon") {
            self.bindings.insert("harpoon".into(), self.harpoon.clone());
            if !self.harpoon.is_empty() {
                let probe = transport::probe(self.harpoon.as_ref(), diagnostic).await?;
                self.state.send_modify(|state| {
                    state.channels.insert("harpoon".into(), probe);
                });
            }
        }
        anyhow::ensure!(
            self.bindings.values().any(|binding| binding.available()),
            "no MCP channels configured"
        );
        if self.config.control_plane.poll_channels.is_none() {
            anyhow::ensure!(
                self.bindings.contains_key("main"),
                "main channel is required; set --mcp.server-url or --mcp.command"
            );
        }
        if let Some(channels) = &self.config.control_plane.poll_channels {
            for channel in channels {
                anyhow::ensure!(
                    self.bindings.contains_key(channel),
                    "channel {channel} has no binding"
                );
            }
        }
        self.control.set_channels(channels(&self.bindings))?;
        Ok(())
    }

    pub async fn diagnose(mut self) -> Report {
        let mut checks = Vec::new();
        match self
            .config
            .validate_with_channels(self.bindings.keys().cloned())
        {
            Err(error) => checks.push(Check::fail("config_validation", format!("{error:#}"))),
            Ok(()) => {
                match self.prepare(true).await {
                    Err(error) => checks.push(Check::fail("mcp_target", format!("{error:#}"))),
                    Ok(()) => {
                        for (channel, transport) in &self.bindings {
                            if !transport.available() {
                                continue;
                            }
                            let id = |name: &str| {
                                if channel == "main" {
                                    name.to_owned()
                                } else {
                                    format!("{name}.{channel}")
                                }
                            };
                            let target = self
                                .config
                                .mcp
                                .server_urls
                                .iter()
                                .find(|server| &server.channel == channel)
                                .map(|server| server.url.clone())
                                .or_else(|| {
                                    self.config
                                        .mcp
                                        .commands
                                        .iter()
                                        .find(|command| &command.channel == channel)
                                        .map(|command| command.command.clone())
                                })
                                .unwrap_or_else(|| channel.clone());
                            checks.push(Check::pass(id("mcp_target"), target));
                            match startup::probe(
                                transport.as_ref(),
                                self.config.mcp.startup_wait_timeout.0,
                                true,
                            )
                            .await
                            {
                                Ok(probe) => {
                                    checks.push(Check::pass(
                                        id("mcp_server_reachable"),
                                        if probe.authentication_required {
                                            "MCP endpoint requires authentication"
                                        } else {
                                            "MCP initialization completed"
                                        },
                                    ));
                                    if let Some(count) = probe.tools {
                                        checks.push(Check::pass(
                                            id("mcp_tools"),
                                            format!("{count} tools discovered"),
                                        ));
                                    }
                                    self.state.send_modify(|state| {
                                        state.channels.insert(channel.clone(), probe);
                                    });
                                }
                                Err(error) => checks.push(Check::fail(
                                    id("mcp_server_reachable"),
                                    format!("{error:#}"),
                                )),
                            }
                            let result = timeout(Duration::from_secs(5), transport.discover())
                                .await
                                .context("OAuth discovery timed out")
                                .and_then(|result| result);
                            let check = match result {
                                Ok(reply) if reply.status == 404 && reply.message.is_none() => {
                                    Check::skip(
                                        id("oauth_metadata"),
                                        "transport does not expose OAuth metadata",
                                    )
                                }
                                Ok(reply) if (200..300).contains(&reply.status) => Check::pass(
                                    id("oauth_metadata"),
                                    "protected resource metadata discovered",
                                ),
                                Ok(reply) => Check::fail(
                                    id("oauth_metadata"),
                                    format!("OAuth discovery returned HTTP {}", reply.status),
                                ),
                                Err(error)
                                    if error
                                        .downcast_ref::<crate::oauth::DiscoveryError>()
                                        .is_some_and(|error| error.optional) =>
                                {
                                    Check::skip(
                                        id("oauth_metadata"),
                                        "server does not advertise OAuth metadata",
                                    )
                                }
                                Err(error) => {
                                    Check::fail(id("oauth_metadata"), format!("{error:#}"))
                                }
                            };
                            checks.push(check);
                        }
                    }
                }
                match self.control.metadata().await {
                    Ok(_) => checks.push(Check::pass(
                        "control_plane_connection",
                        "tunnel metadata received",
                    )),
                    Err(error) => checks.push(Check::fail(
                        "control_plane_connection",
                        format!("{error:#}"),
                    )),
                }
            }
        }
        let channels = self.state.borrow().channels.clone();
        if let Err(error) = self.shutdown().await {
            checks.push(Check::fail("shutdown", format!("{error:#}")));
        }
        Report::new(checks, channels, String::new())
    }

    pub async fn run(mut self, shutdown: CancellationToken) -> Result<()> {
        let result = async {
            self.config
                .validate_with_channels(self.bindings.keys().cloned())?;
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                result = self.prepare(false) => result?,
            }
            self.observe();
            if !self.config.mcp.startup_wait_timeout.0.is_zero()
                && self
                    .bindings
                    .get("main")
                    .is_some_and(|transport| transport.startup_probe())
            {
                let mut status = self.state.subscribe();
                tokio::select! {
                    result = status.wait_for(|state| state.mcp_probe.state != "pending") => {
                        result.context("MCP startup probe stopped")?;
                    }
                    () = shutdown.cancelled() => return Ok(()),
                }
            }
            self.state.send_modify(|state| {
                state.lifecycle = "running";
                state.refresh_readiness();
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
        let capacity = self.config.control_plane.max_inflight_requests;
        let concurrency = self.config.mcp.max_concurrent_requests;
        let ttl = self
            .config
            .mcp
            .connection_max_ttl
            .map(|span| span.0)
            .filter(|duration| !duration.is_zero());
        let mut queued = std::collections::VecDeque::new();
        let mut requests: JoinSet<(String, Result<bool>)> = JoinSet::new();
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
                while requests.len() < concurrency {
                    let Some((command, received)): Option<(Command, Instant)> = queued.pop_front() else { break; };
                    let control = self.control.clone();
                    let bindings = bindings.clone();
                    let id = command.request_id.clone();
                    self.state.send_modify(|state| {
                        let now = crate::control::now();
                        state.activity.queued = queued.len();
                        state.activity.dequeued += 1;
                        state.activity.last_dequeue = now;
                        state.activity.last_start = now;
                        state.activity.active.insert(id.clone(), now);
                    });
                    requests.spawn(async move {
                        let deadline = protocol::timeout(&command.response_timeout).and_then(|duration| received.checked_add(duration));
                        let result = if deadline.is_some_and(|deadline| deadline <= Instant::now()) { Ok(false) }
                            else if let Some(deadline) = deadline {
                                match timeout_at(deadline, execute(&control, &bindings, command, ttl)).await {
                                    Ok(result) => result.map(|()| true), Err(_) => Ok(false),
                                }
                            } else { execute(&control, &bindings, command, ttl).await.map(|()| true) };
                        (id, result)
                    });
                }
                let pressure = queued.len() >= capacity;
                self.state.send_if_modified(|state| {
                    if pressure == (state.activity.pressure_started > 0.0) { return false; }
                    let now = crate::control::now();
                    if pressure { state.activity.pressure_started = now; }
                    else { state.activity.pressure_seconds += now - state.activity.pressure_started; state.activity.pressure_started = 0.0; }
                    true
                });
                if poll.is_none() && !pressure {
                    self.control.set_channels(channels(&bindings))?;
                    let control = self.control.clone();
                    let limit = capacity - queued.len();
                    poll = Some(Box::pin(async move { control.poll(limit, initial).await }));
                    initial = false;
                }
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    changed = connection.changed() => {
                        changed?;
                        let observation = connection.borrow_and_update().clone();
                        self.state.send_modify(|state| { state.connected = observation.connected; state.control = observation; });
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
                        let (id, result) = result.context("request worker stopped")??;
                        self.state.send_modify(|state| {
                            state.evidence = bindings.iter().filter_map(|(name, binding)| binding.observation().map(|value| (name.clone(), value))).collect();
                            state.in_flight = requests.len() + queued.len();
                            state.activity.active.remove(&id);
                            state.activity.last_completion = crate::control::now();
                            state.activity.last_failed = !matches!(result, Ok(true));
                            match &result { Ok(true) => state.completed += 1, Ok(false) => state.expired += 1, Err(_) => state.failed += 1 }
                        });
                        match result {
                            Ok(_) => {},
                            Err(error) => {
                                self.state.send_modify(|state| state.last_error = Some(format!("{error:#}")));
                                tracing::error!(%error, "tunnel request failed");
                            }
                        }
                    }
                    batch = async { match &mut poll { Some(poll) => poll.await, None => std::future::pending().await } } => {
                        let batch = batch?;
                        poll = None;
                        let count = batch.commands.len();
                        queued.extend(batch.commands.into_iter().map(|command| (command, batch.received)));
                        self.state.send_modify(|state| {
                            state.in_flight = requests.len() + queued.len();
                            state.activity.queued = queued.len();
                            state.activity.enqueued += count as u64;
                            if count > 0 { state.activity.last_enqueue = crate::control::now(); }
                        });
                    }
                }
            }
        }.await;
        requests.abort_all();
        while requests.join_next().await.is_some() {}
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        self.state.send_modify(|state| {
            state.in_flight = 0;
            state.activity.queued = 0;
            state.activity.active.clear();
        });
        result
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.stop.cancel();
        let mut failure = None;
        while let Some(result) = self.observers.join_next().await {
            if let Err(error) = result {
                failure.get_or_insert(error.into());
            }
        }
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
    let Some(binding) = bindings.get(&command.channel).filter(|binding| {
        binding.available()
            && (command.command_type != "oauth_discovery" || command.channel == "main")
    }) else {
        let message = format!("unsupported channel {:?}", command.channel);
        let mut reply = match command.command_type.as_str() {
            "jsonrpc" => {
                let request = Request {
                    discovery: false,
                    message: command.jsonrpc.context("JSON-RPC command has no payload")?,
                    headers,
                };
                let id = protocol::view(&request.message)?.id;
                let mut reply = Reply::json(serde_json::value::to_raw_value(&serde_json::json!({
                    "jsonrpc":"2.0", "id":id,
                    "error":{"code":-32603,"message":format!("Bad Request: {message}")}
                }))?);
                reply.status = 400;
                reply
            }
            "oauth_discovery" => {
                let mut reply = Reply::ack(400, "oauth_discovery_response");
                reply.message = Some(serde_json::value::to_raw_value(&serde_json::json!({
                    "error":{"message":message,"type":"invalid_request_error","code":"unsupported_channel"}
                }))?);
                reply
            }
            _ => Reply::ack(400, "session_termination_response"),
        };
        reply.headers.clear();
        delivery.send(reply).await?;
        bail!(message);
    };
    match command.command_type.as_str() {
        "jsonrpc" => {
            let request = Request {
                discovery: false,
                message: command.jsonrpc.context("JSON-RPC command has no payload")?,
                headers,
            };
            let forward = binding.forward(request.clone(), &delivery);
            let outcome = match ttl {
                Some(ttl) => timeout(ttl, forward)
                    .await
                    .context("MCP connection lifetime exceeded")
                    .and_then(|result| result),
                None => forward.await,
            };
            if let Err(error) = outcome {
                if delivery.terminal_started() {
                    return Err(error);
                }
                tracing::warn!(%error, "MCP forwarding failed");
                delivery
                    .send(transport::Failure::from_error(&error).reply(&request)?)
                    .await?;
            } else if !delivery.terminal_started() {
                delivery
                    .send(
                        transport::Failure::protocol(0, "invalid_protocol_response")
                            .reply(&request)?,
                    )
                    .await?;
            }
        }
        "session_termination" | "oauth_discovery" => {
            let kind = if command.command_type == "session_termination" {
                "session_termination_response"
            } else {
                "oauth_discovery_response"
            };
            let outcome = if command.command_type == "session_termination" {
                binding.terminate(headers, false).await
            } else {
                binding.discover().await
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

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use http::HeaderMap;
use serde_json::{
    json,
    value::{RawValue, to_raw_value},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use super::{
    Sink, Transport,
    observation::{Observation, Token},
};
use crate::protocol::{self, Json, Reply, Request, field, replace, view};

enum Event {
    Response(Json),
    ToolsChanged,
    Cancelled(&'static str),
}

#[derive(Default)]
struct Receipt {
    token: Option<Token>,
    written: bool,
    events: Vec<Event>,
}

struct Pending {
    observation: Option<Arc<Mutex<Receipt>>>,
    scope: String,
    original: Json,
    progress: Option<Json>,
    responses: mpsc::UnboundedSender<Json>,
}
struct Frame {
    message: Json,
    observation: Option<Arc<Mutex<Receipt>>>,
    written: Option<oneshot::Sender<Result<Instant>>>,
}
#[derive(Default)]
struct Lifecycle {
    initialize_succeeded: bool,
    initialized_sent: bool,
    ready: bool,
}
struct State {
    observation: Mutex<Observation>,
    evidence: watch::Sender<serde_json::Value>,
    pending: Mutex<BTreeMap<u64, Pending>>,
    writing: Mutex<Option<Arc<Mutex<Receipt>>>>,
    writer: mpsc::UnboundedSender<Frame>,
    next: AtomicU64,
    error: Mutex<Option<String>>,
    stop: CancellationToken,
}

/// A multiplexed MCP connection over newline-delimited JSON.
pub struct Pipe {
    state: Arc<State>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    lifecycle: Mutex<Lifecycle>,
    send_initialized: bool,
    stateless: AtomicBool,
}

impl Pipe {
    pub async fn new<R, W>(reader: R, writer: W) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, mut receiver) = mpsc::unbounded_channel::<Frame>();
        let observation = Observation::new();
        let (evidence, _) = watch::channel(observation.snapshot());
        let state = Arc::new(State {
            observation: Mutex::new(observation),
            evidence,
            pending: Mutex::new(BTreeMap::new()),
            writing: Mutex::new(None),
            writer: sender,
            next: AtomicU64::new(1),
            error: Mutex::new(None),
            stop: CancellationToken::new(),
        });
        let output = state.clone();
        let writer = tokio::spawn(async move {
            let mut writer = BufWriter::new(writer);
            loop {
                let frame = tokio::select! {
                    frame = receiver.recv() => match frame { Some(frame) => frame, None => break },
                    () = output.stop.cancelled() => break,
                };
                if frame
                    .written
                    .as_ref()
                    .is_some_and(oneshot::Sender::is_closed)
                {
                    continue;
                }
                *output.writing.lock().expect("write mutex poisoned") = frame.observation.clone();
                let started = Instant::now();
                let written = async {
                    writer.write_all(frame.message.get().as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await
                };
                let result = tokio::select! {
                    result = written => result,
                    () = output.stop.cancelled() => break,
                };
                if let Err(error) = result {
                    output.fail(&error, "stdio_write_failed");
                    if let Some(ack) = frame.written {
                        let _ = ack.send(Err(error.into()));
                    }
                    break;
                }
                {
                    let mut writing = output.writing.lock().expect("write mutex poisoned");
                    if let Some(receipt) = writing.take() {
                        let mut receipt = receipt.lock().expect("receipt mutex poisoned");
                        receipt.token =
                            output.observe(|observation| observation.begin(&frame.message));
                        receipt.written = true;
                        for event in std::mem::take(&mut receipt.events) {
                            output.event(&mut receipt, event);
                        }
                    }
                }
                if let Some(ack) = frame.written {
                    let _ = ack.send(Ok(started));
                }
            }
        });
        let input = state.clone();
        let reader = tokio::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            let result: Result<()> = async {
                loop {
                    let line = tokio::select! {
                        line = lines.next_line() => line?.context("MCP stdout closed")?,
                        () = input.stop.cancelled() => return Ok(()),
                    };
                    if line.is_empty() {
                        continue;
                    }
                    input.receive(RawValue::from_string(line)?)?;
                }
            }
            .await;
            if let Err(error) = result {
                input.fail(&error, "stdio_read_failed");
            }
            input
                .pending
                .lock()
                .expect("routing mutex poisoned")
                .clear();
        });
        Ok(Self {
            state,
            tasks: Mutex::new(vec![reader, writer]),
            lifecycle: Mutex::new(Lifecycle::default()),
            send_initialized: false,
            stateless: AtomicBool::new(false),
        })
    }

    pub fn send_initialized_notification(mut self, enabled: bool) -> Self {
        self.send_initialized = enabled;
        self
    }

    fn reset_initialization(&self) {
        *self.lifecycle.lock().expect("lifecycle mutex poisoned") = Lifecycle::default();
    }

    fn initialization_required(&self, message: &RawValue) -> bool {
        let envelope = match view(message) {
            Ok(envelope) => envelope,
            Err(_) => return false,
        };
        let Some(method) = envelope.method.as_deref() else {
            return false;
        };
        envelope.id.is_some()
            && !matches!(method, "initialize" | "ping" | "server/discover")
            && !protocol::self_contained(message)
            && !self
                .lifecycle
                .lock()
                .expect("lifecycle mutex poisoned")
                .ready
    }

    fn initialization_error(&self, request: &Request) -> Result<Reply> {
        let id = view(&request.message)?.id;
        let mut reply = Reply::json(to_raw_value(&json!({
            "jsonrpc":"2.0",
            "id":id,
            "error":{
                "code":-32002,
                "message":"MCP server is not initialized; send initialize and notifications/initialized before operational requests",
                "data":{"origin":"tunnel-client","error_type":"mcp_initialization_required"}
            }
        }))?);
        reply.status = 409;
        Ok(reply)
    }

    async fn relay(&self, mut request: Request, sink: &dyn Sink) -> Result<()> {
        if let Some(id) = request.headers.get("x-request-id") {
            request.message = replace(
                &request.message,
                &["params", "_meta", "otunnel/requestId"],
                &to_raw_value(id.to_str()?)?,
            )?;
        }
        let self_contained = protocol::self_contained(&request.message);
        let method = view(&request.message)?
            .method
            .map(|method| method.into_owned());
        let id = view(&request.message)?.id.map(RawValue::to_owned);
        let Some(id) = id else {
            if view(&request.message)?.method.as_deref() == Some("notifications/cancelled") {
                let request_id = field(&request.message, "params")
                    .and_then(|v| field(&v, "requestId"))
                    .context("cancellation has no requestId")?;
                let scope = request.scope();
                let alias = self
                    .state
                    .pending
                    .lock()
                    .expect("routing mutex poisoned")
                    .iter()
                    .find(|(_, pending)| {
                        pending.scope == scope && protocol::same_id(&pending.original, &request_id)
                    })
                    .map(|(alias, _)| *alias);
                if let Some(alias) = alias {
                    request.message = replace(
                        &request.message,
                        &["params", "requestId"],
                        &to_raw_value(&alias)?,
                    )?;
                } else {
                    return sink.send(Reply::ack(202, "notify_ack")).await;
                }
            }
            self.state.write(request.message, None).await?;
            return sink.send(Reply::ack(202, "notify_ack")).await;
        };
        let alias = self.state.next.fetch_add(1, Ordering::Relaxed);
        let scope = request.scope();
        let progress = field(&request.message, "params")
            .and_then(|v| field(&v, "_meta"))
            .and_then(|v| field(&v, "progressToken"));
        request.message = replace(&request.message, &["id"], &to_raw_value(&alias)?)?;
        if progress.is_some() {
            request.message = replace(
                &request.message,
                &["params", "_meta", "progressToken"],
                &to_raw_value(&alias)?,
            )?;
        }
        let observation = matches!(
            method.as_deref(),
            Some("initialize" | "server/discover" | "tools/list")
        )
        .then(|| Arc::new(Mutex::new(Receipt::default())));
        let (sender, mut receiver) = mpsc::unbounded_channel();
        self.state
            .pending
            .lock()
            .expect("routing mutex poisoned")
            .insert(
                alias,
                Pending {
                    observation: observation.clone(),
                    scope,
                    original: id,
                    progress,
                    responses: sender,
                },
            );
        let _request = Lease {
            alias,
            state: self.state.clone(),
            deadline: request.deadline,
        };
        let started = self.state.write(request.message, observation).await?;
        while let Some(message) = receiver.recv().await {
            let response = view(&message)?;
            let terminal = response.method.is_none();
            if terminal && response.result.is_some() {
                if method.as_deref() == Some("initialize") && !self_contained {
                    let send_initialized = {
                        let mut lifecycle =
                            self.lifecycle.lock().expect("lifecycle mutex poisoned");
                        lifecycle.initialize_succeeded = true;
                        self.send_initialized && !lifecycle.initialized_sent
                    };
                    if send_initialized {
                        self.state
                            .write(
                                to_raw_value(
                                    &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                                )?,
                                None,
                            )
                            .await?;
                        let mut lifecycle =
                            self.lifecycle.lock().expect("lifecycle mutex poisoned");
                        lifecycle.initialized_sent = true;
                        lifecycle.ready = true;
                    }
                }
                if method.as_deref() == Some("server/discover") {
                    let versions = response
                        .result
                        .and_then(|result| field(result, "supportedVersions"))
                        .and_then(|value| serde_json::from_str::<Vec<String>>(value.get()).ok());
                    if versions.is_some_and(|versions| {
                        versions
                            .iter()
                            .any(|version| version == protocol::MCP_VERSION)
                    }) {
                        self.stateless.store(true, Ordering::Release);
                    }
                }
            }
            let completed = Instant::now();
            let mut reply = Reply::json(message);
            if terminal {
                reply = reply.timed("stdio", started, completed);
            } else {
                reply.kind = "jsonrpc_notify";
            }
            sink.send(reply).await?;
            if terminal {
                return Ok(());
            }
        }
        bail!("MCP connection closed before the request completed")
    }
}

impl State {
    async fn write(
        &self,
        message: Json,
        observation: Option<Arc<Mutex<Receipt>>>,
    ) -> Result<Instant> {
        let (sender, receiver) = oneshot::channel();
        self.writer
            .send(Frame {
                message,
                observation,
                written: Some(sender),
            })
            .map_err(|_| anyhow::anyhow!("MCP stdin closed"))?;
        receiver.await.context("MCP writer stopped")?
    }

    fn observe<T>(&self, update: impl FnOnce(&mut Observation) -> T) -> T {
        let mut observation = self.observation.lock().expect("observation mutex poisoned");
        let result = update(&mut observation);
        let snapshot = observation.snapshot();
        self.evidence.send_if_modified(|evidence| {
            if *evidence == snapshot {
                return false;
            }
            *evidence = snapshot;
            true
        });
        result
    }

    fn fail(&self, error: &dyn std::fmt::Display, reason: &str) {
        self.observe(|observation| observation.closed(reason));
        *self.error.lock().expect("error mutex poisoned") = Some(error.to_string());
        self.stop.cancel();
    }
    fn receive(&self, message: Json) -> Result<()> {
        let envelope = view(&message)?;
        if let Some(method) = envelope.method.as_deref() {
            if let Some(id) = envelope.id {
                let response = if method == "ping" {
                    to_raw_value(&json!({"jsonrpc":"2.0","id":id,"result":{}}))?
                } else {
                    to_raw_value(
                        &json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Client capability is unavailable"}}),
                    )?
                };
                self.writer
                    .send(Frame {
                        message: response,
                        observation: None,
                        written: None,
                    })
                    .map_err(|_| anyhow::anyhow!("MCP stdin closed"))?;
                return Ok(());
            }
            if method == "notifications/tools/list_changed" {
                let writing = self.writing.lock().expect("write mutex poisoned").clone();
                if let Some(receipt) = writing {
                    self.record(&receipt, Event::ToolsChanged);
                } else {
                    self.observe(Observation::list_changed);
                }
            }
            let pending = self.pending.lock().expect("routing mutex poisoned");
            let subscription = field(&message, "params")
                .and_then(|params| field(&params, "_meta"))
                .and_then(|meta| field(&meta, "io.modelcontextprotocol/subscriptionId"));
            if let Some(subscription) = subscription {
                if let Ok(alias) = serde_json::from_str::<u64>(subscription.get())
                    && let Some(call) = pending.get(&alias)
                {
                    let message = replace(
                        &message,
                        &["params", "_meta", "io.modelcontextprotocol/subscriptionId"],
                        &call.original,
                    )?;
                    let _ = call.responses.send(message);
                }
            } else if method == "notifications/progress" {
                let token = field(&message, "params").and_then(|v| field(&v, "progressToken"));
                if let Some(token) = token
                    && let Ok(alias) = serde_json::from_str::<u64>(token.get())
                    && let Some(call) = pending.get(&alias)
                    && let Some(original) = &call.progress
                {
                    let message = replace(&message, &["params", "progressToken"], original)?;
                    let _ = call.responses.send(message);
                }
            } else {
                let mut scopes = BTreeSet::new();
                for call in pending.values() {
                    if scopes.insert(&call.scope) {
                        let _ = call.responses.send(message.clone());
                    }
                }
            }
        } else if let Some(id) = envelope.id {
            let alias: u64 = serde_json::from_str(id.get())?;
            if let Some(call) = self
                .pending
                .lock()
                .expect("routing mutex poisoned")
                .remove(&alias)
            {
                if let Some(receipt) = call.observation {
                    self.record(&receipt, Event::Response(message.clone()));
                }
                let mut message = replace(&message, &["id"], &call.original)?;
                if field(&message, "result")
                    .and_then(|result| field(&result, "_meta"))
                    .and_then(|meta| field(&meta, "io.modelcontextprotocol/subscriptionId"))
                    .is_some()
                {
                    message = replace(
                        &message,
                        &["result", "_meta", "io.modelcontextprotocol/subscriptionId"],
                        &call.original,
                    )?;
                }
                let _ = call.responses.send(message);
            }
        } else {
            bail!("MCP response has no ID");
        }
        Ok(())
    }
    fn record(&self, receipt: &Mutex<Receipt>, event: Event) {
        let mut receipt = receipt.lock().expect("receipt mutex poisoned");
        if receipt.written {
            self.event(&mut receipt, event);
        } else {
            receipt.events.push(event);
        }
    }

    fn event(&self, receipt: &mut Receipt, event: Event) {
        match event {
            Event::Response(message) => {
                if let Some(token) = receipt.token.take() {
                    self.observe(|observation| observation.receive(token, &message));
                }
            }
            Event::ToolsChanged => self.observe(Observation::list_changed),
            Event::Cancelled(reason) => {
                if let Some(token) = receipt.token.take() {
                    self.observe(|observation| observation.failed(token, reason, false));
                }
            }
        }
    }

    fn cancel(&self, alias: u64, reason: &'static str) {
        if let Some(call) = self
            .pending
            .lock()
            .expect("routing mutex poisoned")
            .remove(&alias)
        {
            if let Some(receipt) = call.observation {
                self.record(&receipt, Event::Cancelled(reason));
            }
            let message = json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":alias,"reason":"Request ended"}});
            if let Ok(message) = to_raw_value(&message) {
                let _ = self.writer.send(Frame {
                    message,
                    observation: None,
                    written: None,
                });
            }
        }
    }
}

struct Lease {
    alias: u64,
    state: Arc<State>,
    deadline: Option<tokio::time::Instant>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.state.cancel(
            self.alias,
            if self
                .deadline
                .is_some_and(|deadline| deadline <= tokio::time::Instant::now())
            {
                "discovery_response_deadline"
            } else {
                "discovery_cancelled"
            },
        );
    }
}
impl Drop for Pipe {
    fn drop(&mut self) {
        self.state
            .observe(|observation| observation.closed("stdio_connection_closed"));
        self.state.stop.cancel();
    }
}

#[async_trait]
impl Transport for Pipe {
    async fn forward(&self, request: Request, sink: &dyn Sink) -> Result<()> {
        let envelope = view(&request.message)?;
        let self_contained = protocol::self_contained(&request.message);
        if envelope.method.as_deref() == Some("initialize") && !self_contained {
            self.reset_initialization();
        }
        if self.initialization_required(&request.message) {
            return sink.send(self.initialization_error(&request)?).await;
        }
        let initialized = envelope.method.as_deref() == Some("notifications/initialized")
            && envelope.id.is_none()
            && !self_contained;
        if initialized
            && self.send_initialized
            && self
                .lifecycle
                .lock()
                .expect("lifecycle mutex poisoned")
                .initialized_sent
        {
            return sink.send(Reply::ack(202, "notify_ack")).await;
        }
        let result = self.relay(request, sink).await;
        if result.is_ok() && initialized {
            let mut lifecycle = self.lifecycle.lock().expect("lifecycle mutex poisoned");
            lifecycle.ready = lifecycle.initialize_succeeded;
            if self.send_initialized && lifecycle.ready {
                lifecycle.initialized_sent = true;
            }
        }
        result
    }
    async fn terminate(&self, headers: HeaderMap, _discovery: bool) -> Result<Reply> {
        let scope = headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .context("session termination has no Mcp-Session-Id")?;
        let aliases: Vec<_> = self
            .state
            .pending
            .lock()
            .expect("routing mutex poisoned")
            .iter()
            .filter(|(_, call)| call.scope == scope)
            .map(|(alias, _)| *alias)
            .collect();
        for alias in aliases {
            self.state.cancel(alias, "discovery_cancelled");
        }
        Ok(Reply::ack(204, "session_termination_response"))
    }
    async fn close(&self) -> Result<()> {
        self.state
            .observe(|observation| observation.closed("stdio_connection_closed"));
        self.state.stop.cancel();
        let tasks = std::mem::take(&mut *self.tasks.lock().expect("task mutex poisoned"));
        for task in tasks {
            task.await?;
        }
        Ok(())
    }
    async fn closed(&self) -> Result<()> {
        self.state.stop.cancelled().await;
        let error = self
            .state
            .error
            .lock()
            .expect("error mutex poisoned")
            .clone()
            .unwrap_or_else(|| "MCP connection closed".into());
        bail!(error)
    }
    fn process_affinity(&self) -> bool {
        true
    }
    fn stateless(&self) -> bool {
        self.stateless.load(Ordering::Acquire)
    }
    fn observation(&self) -> Option<watch::Receiver<serde_json::Value>> {
        Some(self.state.evidence.subscribe())
    }
    fn startup_probe(&self) -> bool {
        false
    }
}

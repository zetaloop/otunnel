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
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use super::{Sink, Transport};
use crate::protocol::{self, Json, Reply, Request, field, replace, view};

struct Pending {
    scope: String,
    original: Json,
    progress: Option<Json>,
    responses: mpsc::UnboundedSender<Json>,
}
struct Frame {
    message: Json,
    written: Option<oneshot::Sender<Result<()>>>,
}
struct State {
    pending: Mutex<BTreeMap<u64, Pending>>,
    writer: mpsc::UnboundedSender<Frame>,
    next: AtomicU64,
    error: Mutex<Option<String>>,
    stop: CancellationToken,
}

/// A multiplexed MCP connection over newline-delimited JSON.
pub struct Pipe {
    state: Arc<State>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    send_initialized: bool,
    initialized: AtomicBool,
    stateless: AtomicBool,
}

impl Pipe {
    pub async fn new<R, W>(reader: R, writer: W) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, mut receiver) = mpsc::unbounded_channel::<Frame>();
        let state = Arc::new(State {
            pending: Mutex::new(BTreeMap::new()),
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
                    output.fail(&error);
                    if let Some(ack) = frame.written {
                        let _ = ack.send(Err(error.into()));
                    }
                    break;
                }
                if let Some(ack) = frame.written {
                    let _ = ack.send(Ok(()));
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
                input.fail(&error);
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
            send_initialized: false,
            initialized: AtomicBool::new(false),
            stateless: AtomicBool::new(false),
        })
    }

    pub fn send_initialized_notification(mut self, enabled: bool) -> Self {
        self.send_initialized = enabled;
        self
    }

    async fn relay(&self, mut request: Request, sink: &dyn Sink) -> Result<()> {
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
            self.state.write(request.message).await?;
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
        let (sender, mut receiver) = mpsc::unbounded_channel();
        self.state
            .pending
            .lock()
            .expect("routing mutex poisoned")
            .insert(
                alias,
                Pending {
                    scope,
                    original: id,
                    progress,
                    responses: sender,
                },
            );
        let _request = Lease {
            alias,
            state: self.state.clone(),
        };
        self.state.write(request.message).await?;
        while let Some(message) = receiver.recv().await {
            let response = view(&message)?;
            let terminal = response.method.is_none();
            if terminal && response.result.is_some() {
                if method.as_deref() == Some("initialize") && self.send_initialized {
                    self.state
                        .write(to_raw_value(
                            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                        )?)
                        .await?;
                    self.initialized.store(true, Ordering::Release);
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
            let mut reply = Reply::json(message);
            if !terminal {
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
    async fn write(&self, message: Json) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.writer
            .send(Frame {
                message,
                written: Some(sender),
            })
            .map_err(|_| anyhow::anyhow!("MCP stdin closed"))?;
        receiver.await.context("MCP writer stopped")?
    }
    fn fail(&self, error: &dyn std::fmt::Display) {
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
                        written: None,
                    })
                    .map_err(|_| anyhow::anyhow!("MCP stdin closed"))?;
                return Ok(());
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
    fn cancel(&self, alias: u64) {
        if self
            .pending
            .lock()
            .expect("routing mutex poisoned")
            .remove(&alias)
            .is_some()
        {
            let message = json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":alias,"reason":"Request ended"}});
            if let Ok(message) = to_raw_value(&message) {
                let _ = self.writer.send(Frame {
                    message,
                    written: None,
                });
            }
        }
    }
}

struct Lease {
    alias: u64,
    state: Arc<State>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.state.cancel(self.alias);
    }
}
impl Drop for Pipe {
    fn drop(&mut self) {
        self.state.stop.cancel();
    }
}

#[async_trait]
impl Transport for Pipe {
    async fn forward(&self, request: Request, sink: &dyn Sink) -> Result<()> {
        let envelope = view(&request.message)?;
        if self.send_initialized {
            match envelope.method.as_deref() {
                Some("initialize") => self.initialized.store(false, Ordering::Release),
                Some("notifications/initialized")
                    if envelope.id.is_none() && self.initialized.load(Ordering::Acquire) =>
                {
                    return sink.send(Reply::ack(202, "notify_ack")).await;
                }
                _ => {}
            }
        }
        self.relay(request, sink).await
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
            self.state.cancel(alias);
        }
        Ok(Reply::ack(204, "session_termination_response"))
    }
    async fn close(&self) -> Result<()> {
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
    fn startup_probe(&self) -> bool {
        false
    }
}

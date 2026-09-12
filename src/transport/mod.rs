use std::sync::Mutex;

use ::http::HeaderMap;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Serialize;
use serde_json::{Value, json};

use crate::protocol::{self, Reply, Request};

mod http;
mod pipe;

pub use http::HttpTransport;
pub use pipe::Pipe;

#[async_trait]
pub trait Sink: Send + Sync {
    async fn send(&self, reply: Reply) -> Result<()>;
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn forward(&self, request: Request, sink: &dyn Sink) -> Result<()>;
    async fn terminate(&self, _headers: HeaderMap) -> Result<Reply> {
        Ok(Reply::ack(405, "session_termination_response"))
    }
    async fn discover(&self) -> Result<Reply> {
        Ok(Reply::ack(404, "oauth_discovery_response"))
    }
    async fn close(&self) -> Result<()> {
        Ok(())
    }
    async fn closed(&self) -> Result<()> {
        std::future::pending().await
    }
    fn process_affinity(&self) -> bool {
        false
    }
    fn stateless(&self) -> bool {
        false
    }
    fn available(&self) -> bool {
        true
    }
}

#[derive(Default)]
struct Collector(Mutex<Option<Reply>>);
#[async_trait]
impl Sink for Collector {
    async fn send(&self, reply: Reply) -> Result<()> {
        if reply.terminal() {
            *self.0.lock().expect("response mutex poisoned") = Some(reply);
        }
        Ok(())
    }
}

pub async fn exchange(transport: &dyn Transport, request: Request) -> Result<Reply> {
    let collector = Collector::default();
    transport.forward(request, &collector).await?;
    collector
        .0
        .into_inner()
        .expect("response mutex poisoned")
        .context("MCP stream ended without a response")
}

#[derive(Clone, Serialize)]
pub struct Probe {
    pub status: u16,
    pub authentication_required: bool,
    pub server: Option<Value>,
    pub tools: Option<usize>,
    pub oauth_status: Option<u16>,
    pub oauth_error: Option<String>,
}

pub async fn probe(transport: &dyn Transport) -> Result<Probe> {
    let reply = exchange(transport, protocol::initialize()?).await?;
    let mut probe = Probe {
        status: reply.status,
        authentication_required: reply.status == 401,
        server: None,
        tools: None,
        oauth_status: None,
        oauth_error: None,
    };
    if probe.authentication_required {
        return Ok(probe);
    }
    anyhow::ensure!(
        reply.status < 400,
        "MCP initialization returned HTTP {}",
        reply.status
    );
    let message = reply
        .message
        .context("MCP initialization returned an empty response")?;
    let value = protocol::view(&message)?
        .result
        .context("MCP initialization returned an error")?;
    let value: Value = serde_json::from_str(value.get())?;
    probe.server = value.get("serverInfo").cloned();
    let mut headers = protocol::header_map(&reply.headers)?;
    headers.remove("content-type");
    if let Some(version) = value.get("protocolVersion").and_then(Value::as_str) {
        headers.insert("mcp-protocol-version", version.parse()?);
    }
    let result = async {
        let mut initialized =
            Request::new(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))?;
        initialized.headers = headers.clone();
        exchange(transport, initialized).await?;
        if value.pointer("/capabilities/tools").is_some() {
            let mut list = Request::new(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))?;
            list.headers = headers.clone();
            let reply = exchange(transport, list).await?;
            let message = reply
                .message
                .context("tools/list returned an empty response")?;
            let message: Value = serde_json::from_str(message.get())?;
            probe.tools = Some(
                message
                    .pointer("/result/tools")
                    .and_then(Value::as_array)
                    .context("tools/list returned an error")?
                    .len(),
            );
        }
        Ok(probe)
    }
    .await;
    if headers.contains_key("mcp-session-id") {
        transport.terminate(headers).await?;
    }
    result
}

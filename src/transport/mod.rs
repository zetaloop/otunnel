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
    async fn terminate(&self, _headers: HeaderMap, _discovery: bool) -> Result<Reply> {
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

pub(crate) async fn negotiate(transport: &dyn Transport) -> Result<(Reply, bool)> {
    let mut request = protocol::request("server/discover", json!({}), true)?;
    request.discovery = true;
    let reply = exchange(transport, request).await?;
    if reply.status == 401 || reply.status == 403 {
        return Ok((reply, false));
    }
    if let Some(message) = &reply.message {
        let envelope = protocol::view(message)?;
        if let Some(result) = envelope.result {
            let value: Value = serde_json::from_str(result.get())?;
            if value
                .get("supportedVersions")
                .and_then(Value::as_array)
                .is_some_and(|versions| {
                    versions
                        .iter()
                        .any(|version| version == protocol::MCP_VERSION)
                })
            {
                return Ok((reply, true));
            }
        }
    }
    let mut request = protocol::initialize()?;
    request.discovery = true;
    Ok((exchange(transport, request).await?, false))
}

pub async fn probe(transport: &dyn Transport) -> Result<Probe> {
    let (reply, stateless) = negotiate(transport).await?;
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
        "MCP discovery returned HTTP {}",
        reply.status
    );
    let message = reply
        .message
        .context("MCP discovery returned an empty response")?;
    let envelope = protocol::view(&message)?;
    let value = envelope.result.with_context(|| {
        format!(
            "MCP discovery failed: {}",
            envelope.error.map_or("missing result", |error| error.get())
        )
    })?;
    let value: Value = serde_json::from_str(value.get())?;
    probe.server = if stateless {
        value
            .get("_meta")
            .and_then(|meta| meta.get("io.modelcontextprotocol/serverInfo"))
            .cloned()
    } else {
        value.get("serverInfo").cloned()
    };
    let mut headers = HeaderMap::new();
    if stateless {
        headers.insert("mcp-protocol-version", protocol::MCP_VERSION.parse()?);
    } else {
        if let Some(session) = protocol::header_map(&reply.headers)?.get("mcp-session-id") {
            headers.insert("mcp-session-id", session.clone());
        }
        if let Some(version) = value.get("protocolVersion").and_then(Value::as_str) {
            headers.insert("mcp-protocol-version", version.parse()?);
        }
    }
    let result = async {
        if !stateless {
            let mut initialized =
                Request::new(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))?;
            initialized.headers = headers.clone();
            initialized.discovery = true;
            exchange(transport, initialized).await?;
        }
        if value.pointer("/capabilities/tools").is_some() {
            let mut cursor: Option<String> = None;
            let mut count = 0;
            loop {
                let mut params = json!({});
                if let Some(cursor) = &cursor {
                    params["cursor"] = Value::String(cursor.clone());
                }
                let mut list = protocol::request("tools/list", params, stateless)?;
                list.headers = headers.clone();
                list.discovery = true;
                let reply = exchange(transport, list).await?;
                anyhow::ensure!(
                    reply.status < 400,
                    "tools/list returned HTTP {}",
                    reply.status
                );
                let message = reply
                    .message
                    .context("tools/list returned an empty response")?;
                let message: Value = serde_json::from_str(message.get())?;
                count += message
                    .pointer("/result/tools")
                    .and_then(Value::as_array)
                    .context("tools/list returned an error")?
                    .len();
                match message
                    .pointer("/result/nextCursor")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                {
                    Some(next) => {
                        anyhow::ensure!(
                            cursor.as_deref() != Some(next),
                            "tools/list repeated its pagination cursor"
                        );
                        cursor = Some(next.to_owned());
                    }
                    None => break,
                }
            }
            probe.tools = Some(count);
        }
        Ok(probe)
    }
    .await;
    if headers.contains_key("mcp-session-id") {
        transport.terminate(headers, true).await?;
    }
    result
}

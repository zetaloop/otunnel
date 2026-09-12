use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bytes::Bytes;
use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use http::{HeaderMap, Method};
use serde_json::{json, value::RawValue};
use url::Url;

use super::{Sink, Transport};
use crate::{
    config,
    net::{Http, Options},
    protocol::{self, Reply, Request, view, wire_headers},
};

#[derive(Clone)]
pub struct HttpTransport {
    pub(crate) channel: String,
    pub(crate) client: Http,
    pub(crate) url: Url,
    headers: HeaderMap,
    pub(crate) discovery_headers: HeaderMap,
    pub(crate) harpoon: Option<Arc<crate::harpoon::Harpoon>>,
    pub(crate) challenge: Arc<RwLock<Option<HeaderMap>>>,
    stateless: Arc<AtomicBool>,
}
impl HttpTransport {
    pub fn new(server: &config::Server, config: &config::Config) -> Result<Self> {
        let url = Url::parse(&config::resolve(&server.url)?)?;
        let mcp = &config.mcp;
        let client = Http::new(
            url.clone(),
            Options {
                proxy: server
                    .http_proxy
                    .as_deref()
                    .or(mcp.http_proxy.as_deref())
                    .or(config.http_proxy.as_deref()),
                socket: server.unix_socket.as_deref(),
                ca_bundle: config.ca_bundle.as_deref(),
                client_cert: server.client_cert.as_deref().or(mcp.client_cert.as_deref()),
                client_key: server.client_key.as_deref().or(mcp.client_key.as_deref()),
            },
        )?;
        let mut discovery_headers = config::headers(&mcp.extra_headers)?;
        discovery_headers.extend(config::headers(&mcp.discovery_extra_headers)?);
        Ok(Self {
            channel: server.channel.clone(),
            client,
            url,
            headers: config::headers(&mcp.extra_headers)?,
            discovery_headers,
            harpoon: None,
            challenge: Arc::new(RwLock::new(None)),
            stateless: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn harpoon(mut self, registry: Arc<crate::harpoon::Harpoon>) -> Self {
        self.harpoon = Some(registry);
        self
    }

    fn observe(&self, request: &Request, response: &RawValue) -> Result<()> {
        if view(&request.message)?.method == Some("server/discover") {
            let value: serde_json::Value = serde_json::from_str(response.get())?;
            if let Some(versions) = value
                .pointer("/result/supportedVersions")
                .and_then(serde_json::Value::as_array)
            {
                self.stateless.store(
                    versions
                        .iter()
                        .any(|version| version == protocol::MCP_VERSION),
                    Ordering::Release,
                );
            }
        }
        Ok(())
    }

    fn headers(&self, incoming: HeaderMap) -> Result<HeaderMap> {
        let mut headers = self.headers.clone();
        headers.extend(incoming);
        let nominated: Vec<_> = headers
            .get_all("connection")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(|v| v.trim().to_owned())
            .collect();
        for name in nominated {
            headers.remove(name);
        }
        for name in [
            "connection",
            "content-length",
            "transfer-encoding",
            "keep-alive",
            "proxy-connection",
        ] {
            headers.remove(name);
        }
        headers
            .entry("accept")
            .or_insert("application/json, text/event-stream".parse()?);
        headers.insert("content-type", "application/json".parse()?);
        Ok(headers)
    }
}

#[async_trait]
impl Transport for HttpTransport {
    fn discovery_headers(&self) -> HeaderMap {
        self.discovery_headers.clone()
    }
    async fn discover(&self) -> Result<Reply> {
        crate::oauth::discover(self).await
    }
    async fn forward(&self, request: Request, sink: &dyn Sink) -> Result<()> {
        let id = view(&request.message)?.id.map(RawValue::to_owned);
        let mut headers = self.headers(request.headers.clone())?;
        let version = protocol::version(&request.message);
        let modern = version.as_deref() == Some(protocol::MCP_VERSION);
        if let Some(version) = &version {
            headers.insert("mcp-protocol-version", version.parse()?);
        }
        if let Some(method) = view(&request.message)?.method {
            headers.insert("mcp-method", method.parse()?);
        }
        if let Some(name) = protocol::field(&request.message, "params")
            .and_then(|params| protocol::field(&params, "name"))
        {
            let name: String = serde_json::from_str(name.get())?;
            headers.insert("mcp-name", name.parse()?);
        }
        let mut response = self
            .client
            .follow(
                Method::POST,
                self.url.clone(),
                headers.clone(),
                Bytes::copy_from_slice(request.message.get().as_bytes()),
                10,
            )
            .await?;
        if response.status == http::StatusCode::UNAUTHORIZED
            || matches!(
                view(&request.message)?.method,
                Some("initialize" | "server/discover")
            )
        {
            *self
                .challenge
                .write()
                .expect("authentication lock poisoned") = Some(response.headers.clone());
        }
        let Some(id) = id else {
            let mut reply = Reply::ack(response.status.as_u16(), "notify_ack");
            reply.headers = wire_headers(&response.headers, true);
            return sink.send(reply).await;
        };
        let mut last_event = None;
        let mut retry = Duration::from_secs(1);
        loop {
            let status = response.status;
            let response_headers = wire_headers(&response.headers, true);
            if let Some(session) = response.headers.get("mcp-session-id") {
                headers.insert("mcp-session-id", session.clone());
            }
            let sse = response
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.split(';')
                        .next()
                        .is_some_and(|v| v.trim().eq_ignore_ascii_case("text/event-stream"))
                });
            if !sse {
                let body = response.bytes().await?;
                let message = serde_json::from_slice::<Box<RawValue>>(&body).ok();
                let valid = message.as_ref().is_some_and(|message| {
                    view(message).is_ok_and(|v| {
                        v.method.is_none()
                            && v.id.is_some_and(|value| protocol::same_id(value, &id))
                            && (v.error.is_some() || v.result.is_some())
                    })
                });
                let mut reply = if valid {
                    self.observe(&request, message.as_ref().expect("validated response"))?;
                    Reply::json(message.expect("validated response"))
                } else {
                    Reply::error(
                        &request,
                        status.as_u16(),
                        -32603,
                        format!("MCP endpoint returned HTTP {status} without a JSON-RPC response"),
                    )?
                };
                reply.status = status.as_u16();
                reply.headers = response_headers;
                return sink.send(reply).await;
            }
            anyhow::ensure!(
                status.is_success(),
                "MCP event stream returned HTTP {status}"
            );
            let mut events = response.body.eventsource();
            while let Some(event) = events.next().await {
                let event = match event {
                    Ok(event) => event,
                    Err(error) if last_event.is_some() => {
                        tracing::debug!(%error, "MCP event stream interrupted");
                        break;
                    }
                    Err(error) => bail!("MCP event stream: {error}"),
                };
                if !modern && !event.id.is_empty() {
                    last_event = Some(event.id);
                }
                if let Some(delay) = event.retry {
                    retry = delay;
                }
                if event.data.is_empty() {
                    continue;
                }
                let message = RawValue::from_string(event.data)?;
                let envelope = view(&message)?;
                if envelope.method.is_some() && envelope.id.is_some() {
                    let response = Request::new(
                        json!({"jsonrpc":"2.0","id":envelope.id,"error":{"code":-32601,"message":"Client capability is unavailable"}}),
                    )?;
                    self.client
                        .send(
                            Method::POST,
                            &self.url,
                            headers.clone(),
                            Bytes::copy_from_slice(response.message.get().as_bytes()),
                        )
                        .await?;
                    continue;
                }
                let terminal = envelope.method.is_none();
                if terminal {
                    let response_id = envelope.id.context("MCP response has no ID")?;
                    anyhow::ensure!(
                        protocol::same_id(response_id, &id),
                        "MCP response ID does not match its request"
                    );
                    self.observe(&request, &message)?;
                }
                let mut reply = Reply::json(message);
                reply.status = status.as_u16();
                reply.headers = response_headers.clone();
                if let Some(last) = &last_event {
                    reply
                        .headers
                        .insert("Last-Event-ID".into(), vec![last.clone()]);
                }
                if !terminal {
                    reply.kind = "jsonrpc_notify";
                }
                sink.send(reply).await?;
                if terminal {
                    return Ok(());
                }
            }
            let last = last_event
                .as_ref()
                .context("MCP event stream closed before the response")?;
            headers.insert("last-event-id", last.parse()?);
            tokio::time::sleep(retry).await;
            response = self
                .client
                .follow(
                    Method::GET,
                    self.url.clone(),
                    headers.clone(),
                    Bytes::new(),
                    10,
                )
                .await?;
        }
    }
    async fn terminate(&self, headers: HeaderMap) -> Result<Reply> {
        let response = self
            .client
            .follow(
                Method::DELETE,
                self.url.clone(),
                self.headers(headers)?,
                Bytes::new(),
                10,
            )
            .await?;
        let mut reply = Reply::ack(response.status.as_u16(), "session_termination_response");
        reply.headers = wire_headers(&response.headers, true);
        Ok(reply)
    }
    fn stateless(&self) -> bool {
        self.stateless.load(Ordering::Acquire)
    }
}

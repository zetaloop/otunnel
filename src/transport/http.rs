use std::{
    sync::{
        Arc,
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

use super::{Failure, Sink, Transport};
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
    pub(crate) unix_socket: Option<String>,
    headers: HeaderMap,
    pub(crate) discovery_headers: HeaderMap,
    pub(crate) harpoon: Option<Arc<crate::harpoon::Harpoon>>,
    stateless: Arc<AtomicBool>,
}
impl HttpTransport {
    pub fn new(server: &config::Server, config: &config::Config) -> Result<Self> {
        let url = Url::parse(&server.url).context("invalid mcp.server-url")?;
        anyhow::ensure!(
            url.host_str().is_some(),
            "mcp.server-url must include scheme and host"
        );
        let mcp = &config.mcp;
        anyhow::ensure!(
            server.unix_socket.is_none() || server.http_proxy.is_none(),
            "mcp config: unix-socket cannot be combined with http-proxy for channel {:?}",
            server.channel
        );
        let proxy = if server.unix_socket.is_some() {
            None
        } else {
            server
                .http_proxy
                .as_deref()
                .or(mcp.http_proxy.as_deref())
                .or(config.http_proxy.as_deref())
        };
        let client = Http::new(
            url.clone(),
            Options {
                proxy,
                socket: server.unix_socket.as_deref(),
                ca_bundle: config.ca_bundle.as_deref(),
                client_cert: server.client_cert.as_deref().or(mcp.client_cert.as_deref()),
                client_key: server.client_key.as_deref().or(mcp.client_key.as_deref()),
            },
        )?;
        let client = client.logging(config.log.http_raw_unsafe.then_some("mcpclient"));
        let mut discovery_headers = config::headers(&mcp.extra_headers)?;
        discovery_headers.extend(config::headers(&mcp.discovery_extra_headers)?);
        Ok(Self {
            channel: server.channel.clone(),
            unix_socket: server.unix_socket.clone(),
            client,
            url,
            headers: config::headers(&mcp.extra_headers)?,
            discovery_headers,
            harpoon: None,
            stateless: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn harpoon(mut self, registry: Arc<crate::harpoon::Harpoon>) -> Self {
        self.harpoon = Some(registry);
        self
    }

    fn observe(&self, request: &Request, response: &RawValue) -> Result<()> {
        if view(&request.message)?.method.as_deref() == Some("server/discover") {
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

    fn headers(
        &self,
        url: &Url,
        base: &HeaderMap,
        incoming: &HeaderMap,
        discovery: bool,
    ) -> HeaderMap {
        let mut headers = base.clone();
        if url.origin() == self.url.origin() {
            if discovery
                || url.path().trim_end_matches('/') == self.url.path().trim_end_matches('/')
            {
                headers.extend(self.headers.clone());
                if discovery {
                    headers.extend(self.discovery_headers.clone());
                }
            }
            headers.extend(incoming.clone());
        }
        for name in ["host", "content-length", "transfer-encoding"] {
            headers.remove(name);
        }
        headers
    }

    pub(crate) async fn send(
        &self,
        mut method: Method,
        mut url: Url,
        mut headers: HeaderMap,
        mut body: Bytes,
        incoming: &HeaderMap,
        discovery: bool,
    ) -> Result<crate::net::Response> {
        let origin = url.origin();
        for hop in 0..10 {
            let response = self
                .client
                .send(
                    method.clone(),
                    &url,
                    self.headers(&url, &headers, incoming, discovery),
                    body.clone(),
                )
                .await?;
            if !matches!(response.status.as_u16(), 301 | 302 | 303 | 307 | 308) {
                return Ok(response);
            }
            let Some(location) = response.headers.get("location") else {
                return Ok(response);
            };
            let next = url.join(location.to_str()?)?;
            anyhow::ensure!(
                next.origin() == origin,
                "MCP redirect destination must use the configured origin"
            );
            anyhow::ensure!(hop < 9, "MCP request stopped after 10 redirects");
            if response.status.as_u16() == 303 && method != Method::HEAD
                || matches!(response.status.as_u16(), 301 | 302)
                    && !matches!(method, Method::GET | Method::HEAD)
            {
                method = Method::GET;
                body = Bytes::new();
            }
            let mut referer = url.clone();
            let _ = referer.set_username("");
            let _ = referer.set_password(None);
            headers.insert("referer", referer.as_str().parse()?);
            url = next;
        }
        unreachable!()
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn discover(&self) -> Result<Reply> {
        crate::oauth::discover(self).await
    }
    async fn forward(&self, request: Request, sink: &dyn Sink) -> Result<()> {
        let id = view(&request.message)?.id.map(RawValue::to_owned);
        let mut headers = HeaderMap::new();
        headers.insert("accept", "application/json, text/event-stream".parse()?);
        headers.insert("content-type", "application/json".parse()?);
        let version = protocol::version(&request.message);
        let modern = version.as_deref() == Some(protocol::MCP_VERSION);
        if let Some(version) = &version {
            headers.insert("mcp-protocol-version", version.parse()?);
        }
        if let Some(method) = view(&request.message)?.method.as_deref() {
            headers.insert("mcp-method", method.parse()?);
        }
        if let Some(name) = protocol::field(&request.message, "params")
            .and_then(|params| protocol::field(&params, "name"))
        {
            let name: String = serde_json::from_str(name.get())?;
            headers.insert("mcp-name", name.parse()?);
        }
        let mut response = self
            .send(
                Method::POST,
                self.url.clone(),
                headers.clone(),
                Bytes::copy_from_slice(request.message.get().as_bytes()),
                &request.headers,
                request.discovery,
            )
            .await?;
        if !response.status.is_success() {
            return sink
                .send(Failure::response(&request, response).await?)
                .await;
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
                            && protocol::field(message, "jsonrpc").is_some_and(|value| {
                                serde_json::from_str::<String>(value.get())
                                    .is_ok_and(|value| value == "2.0")
                            })
                            && (protocol::field(message, "error").is_some()
                                != protocol::field(message, "result").is_some())
                    })
                });
                let mut reply = if valid {
                    self.observe(&request, message.as_ref().expect("validated response"))?;
                    Reply::json(message.expect("validated response"))
                } else {
                    Failure::protocol(0, "invalid_protocol_response").reply(&request)?
                };
                if valid {
                    reply.status = status.as_u16();
                }
                reply.headers = response_headers;
                reply
                    .headers
                    .insert("Content-Type".into(), vec!["application/json".into()]);
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
                    self.send(
                        Method::POST,
                        self.url.clone(),
                        headers.clone(),
                        Bytes::copy_from_slice(response.message.get().as_bytes()),
                        &request.headers,
                        request.discovery,
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
                .send(
                    Method::GET,
                    self.url.clone(),
                    headers.clone(),
                    Bytes::new(),
                    &request.headers,
                    request.discovery,
                )
                .await?;
        }
    }
    async fn terminate(&self, headers: HeaderMap, discovery: bool) -> Result<Reply> {
        let response = self
            .send(
                Method::DELETE,
                self.url.clone(),
                HeaderMap::new(),
                Bytes::new(),
                &headers,
                discovery,
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

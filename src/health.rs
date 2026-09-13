use std::{
    collections::BTreeMap,
    convert::Infallible,
    io,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{
        ConnectInfo, DefaultBodyLimit, State, connect_info::Connected, rejection::BytesRejection,
    },
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response, Sse, sse::Event},
    routing::{MethodFilter, get},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt, stream};
use serde_json::value::RawValue;
use tokio::{net::TcpListener, sync::watch};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use crate::{
    config::Health,
    harpoon::Harpoon,
    net::{Http, Io, Options},
    protocol::{self, Reply, Request},
    runtime::Snapshot,
    transport,
};

/// The optional local status service. Binding it is independent of starting a tunnel.
pub struct Server {
    listener: Listener,
    status: watch::Receiver<Snapshot>,
    url: String,
    details: bool,
    harpoon: Option<Arc<Harpoon>>,
}
impl Server {
    pub async fn bind(
        config: &Health,
        status: watch::Receiver<Snapshot>,
        harpoon: Option<Arc<Harpoon>>,
    ) -> Result<Self> {
        let (listener, url) = if let Some(socket) = &config.unix_socket {
            let path = std::path::absolute(crate::config::resolve(socket)?)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let url = format!(
                "http+unix://{}",
                URL_SAFE_NO_PAD.encode(path.to_string_lossy().as_bytes())
            );
            let local = Local::bind(path)?;
            (Listener::Local(local), url)
        } else {
            let address = crate::config::resolve(&config.listen_addr)?;
            let address = if address.starts_with(':') {
                format!("0.0.0.0{address}")
            } else {
                address
            };
            let listener = TcpListener::bind(&address)
                .await
                .with_context(|| format!("bind health listener {address}"))?;
            let bound = listener.local_addr()?;
            let host = address
                .rsplit_once(':')
                .map(|(host, _)| host)
                .unwrap_or("")
                .trim_matches(['[', ']']);
            let host = if host.is_empty()
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_unspecified())
            {
                "localhost"
            } else {
                host
            };
            let mut url = Url::parse("http://localhost")?;
            url.set_host(Some(host))?;
            url.set_port(Some(bound.port()))
                .map_err(|_| anyhow::anyhow!("invalid health port"))?;
            (
                Listener::Tcp(listener),
                url.as_str().trim_end_matches('/').to_owned(),
            )
        };
        Ok(Self {
            listener,
            status,
            url,
            details: config.show_details,
            harpoon,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn serve(self, stop: CancellationToken) -> Result<()> {
        let state = Monitor {
            status: self.status,
            details: self.details,
            stop: stop.clone(),
            harpoon: self.harpoon.map(|harpoon| HarpoonHttp {
                harpoon,
                sessions: Arc::new(RwLock::new(BTreeMap::new())),
            }),
        };
        let mut router = Router::new()
            .route("/", get(|| async { Redirect::temporary("/ui") }))
            .route("/ui", get(|| async { Html(include_str!("ui.html")) }))
            .route("/healthz", get(|| async { "live" }))
            .route("/readyz", get(readiness))
            .route("/health", get(ready))
            .route("/health/mcp", get(status))
            .route("/api/status", get(status))
            .route("/api/events", get(events))
            .route("/metrics", get(metrics));
        if state.harpoon.is_some() {
            router = router.route(
                "/harpoon/mcp",
                get(harpoon_get)
                    .post(harpoon_post)
                    .delete(harpoon_delete)
                    .on(MethodFilter::HEAD, harpoon_method)
                    .fallback(harpoon_method)
                    .layer(DefaultBodyLimit::max(MCP_BODY_LIMIT))
                    .layer(middleware::from_fn_with_state(
                        state.clone(),
                        harpoon_access,
                    )),
            );
        }
        let router = router.with_state(state);
        axum::serve(
            self.listener,
            router.into_make_service_with_connect_info::<Peer>(),
        )
        .with_graceful_shutdown(stop.cancelled_owned())
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
struct HarpoonHttp {
    harpoon: Arc<Harpoon>,
    localhost: bool,
    sessions: Arc<RwLock<BTreeMap<String, CancellationToken>>>,
}

#[derive(Clone)]
struct Monitor {
    status: watch::Receiver<Snapshot>,
    details: bool,
    stop: CancellationToken,
    harpoon: Option<HarpoonHttp>,
}
const MCP_BODY_LIMIT: usize = 4 * 1024 * 1024;

fn mcp_error(status: StatusCode, message: &str) -> Response {
    (status, format!("{message}\n")).into_response()
}

fn mcp_session(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
}

#[derive(Clone)]
struct Peer(String);
impl Connected<axum::serve::IncomingStream<'_, Listener>> for Peer {
    fn connect_info(stream: axum::serve::IncomingStream<'_, Listener>) -> Self {
        Self(stream.remote_addr().clone())
    }
}

async fn harpoon_access(
    State(state): State<Monitor>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if peer.0 != "local"
        && !peer
            .0
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|address| address.ip().is_loopback())
    {
        return mcp_error(
            StatusCode::FORBIDDEN,
            "harpoon transport is restricted to loopback",
        );
    }
    if state
        .harpoon
        .as_ref()
        .is_some_and(|server| server.localhost)
    {
        let host = request
            .headers()
            .get("host")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let local = Url::parse(&format!("http://{host}"))
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            });
        if !local {
            return mcp_error(
                StatusCode::FORBIDDEN,
                &format!("Forbidden: invalid Host header {host:?}"),
            );
        }
    }
    next.run(request).await
}

async fn harpoon_method() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [("allow", "GET, POST, DELETE")],
        "Method Not Allowed\n",
    )
}

fn accepts(headers: &HeaderMap) -> (bool, bool) {
    let mut accepted = (false, false);
    for value in headers
        .get_all("accept")
        .iter()
        .filter_map(|value| value.to_str().ok())
    {
        for item in value.split(',') {
            match item
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str()
            {
                "application/json" | "application/*" => accepted.0 = true,
                "text/event-stream" | "text/*" => accepted.1 = true,
                "*/*" => accepted = (true, true),
                _ => {}
            }
        }
    }
    accepted
}

fn sse_messages(messages: &[Box<RawValue>]) -> String {
    messages
        .iter()
        .map(|message| format!("event: message\ndata: {}\n\n", message.get()))
        .collect()
}

async fn harpoon_post(
    State(state): State<Monitor>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(server) = state.harpoon else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let body = match body {
        Ok(body) => body,
        Err(error) => {
            return mcp_error(
                error.status(),
                if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    "request body too large"
                } else {
                    "failed to read body"
                },
            );
        }
    };
    if !headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        })
    {
        return mcp_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be 'application/json'",
        );
    }
    if accepts(&headers) != (true, true) {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            "Accept must contain both 'application/json' and 'text/event-stream'",
        );
    }
    if headers.contains_key("last-event-id") {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            "can't send Last-Event-ID for POST request",
        );
    }
    let trimmed = body
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map_or(&body[..], |start| &body[start..]);
    let is_batch = trimmed.first() == Some(&b'[');
    if is_batch
        && headers
            .get("mcp-protocol-version")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|version| version >= "2025-06-18")
    {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            &format!(
                "JSON-RPC batching is not supported in 2025-06-18 and later (request version: {})",
                headers["mcp-protocol-version"].to_str().unwrap_or_default()
            ),
        );
    }
    let messages: Vec<Box<RawValue>> = if is_batch {
        match serde_json::from_slice::<Vec<Box<RawValue>>>(trimmed) {
            Ok(messages) if !messages.is_empty() => messages,
            _ => return mcp_error(StatusCode::BAD_REQUEST, "invalid JSON-RPC batch"),
        }
    } else {
        match serde_json::from_slice(trimmed) {
            Ok(message) => vec![message],
            Err(_) => return mcp_error(StatusCode::BAD_REQUEST, "invalid JSON-RPC request"),
        }
    };
    if messages
        .iter()
        .any(|message| protocol::view(message).is_err())
    {
        return mcp_error(StatusCode::BAD_REQUEST, "invalid JSON-RPC request");
    }
    let methods: Vec<_> = messages
        .iter()
        .filter_map(|message| {
            protocol::view(message)
                .ok()?
                .method
                .map(|method| method.into_owned())
        })
        .collect();
    let supplied_session = mcp_session(&headers).map(str::to_owned);
    let legacy = supplied_session.is_some()
        || methods
            .iter()
            .any(|method| matches!(method.as_str(), "initialize" | "notifications/initialized"));
    if let Some(session) = &supplied_session {
        if methods.iter().any(|method| method == "initialize") {
            return mcp_error(
                StatusCode::BAD_REQUEST,
                "initialize cannot use an existing Mcp-Session-Id",
            );
        }
        if !server
            .sessions
            .read()
            .expect("Harpoon session lock poisoned")
            .contains_key(session)
        {
            return mcp_error(StatusCode::NOT_FOUND, "session not found");
        }
    } else if methods
        .iter()
        .any(|method| method == "notifications/initialized")
    {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            "notifications/initialized requires an Mcp-Session-Id",
        );
    }
    let created_session =
        if supplied_session.is_none() && methods.iter().any(|method| method == "initialize") {
            let id = Uuid::new_v4().to_string();
            server
                .sessions
                .write()
                .expect("Harpoon session lock poisoned")
                .insert(id.clone(), CancellationToken::new());
            Some(id)
        } else {
            None
        };
    let session_stop = supplied_session
        .as_ref()
        .or(created_session.as_ref())
        .and_then(|id| {
            server
                .sessions
                .read()
                .expect("Harpoon session lock poisoned")
                .get(id)
                .cloned()
        })
        .unwrap_or_else(|| state.stop.child_token());
    let exchange = futures_util::future::join_all(messages.into_iter().map(|message| {
        let harpoon = server.harpoon.clone();
        let headers = headers.clone();
        async move {
            let request = Request {
                message,
                headers,
                discovery: false,
            };
            match transport::exchange(harpoon.as_ref(), request.clone()).await {
                Ok(reply) => reply,
                Err(error) => Reply::error(&request, 200, -32603, format!("{error:#}"))
                    .unwrap_or_else(|_| Reply::ack(500, "jsonrpc_response")),
            }
        }
    }));
    let replies = tokio::select! {
        replies = exchange => replies,
        () = session_stop.cancelled() => return mcp_error(StatusCode::NOT_FOUND, "session is closing"),
        () = state.stop.cancelled() => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let messages: Vec<_> = replies
        .into_iter()
        .filter_map(|reply| reply.message)
        .collect();
    let mut response = if messages.is_empty() {
        StatusCode::ACCEPTED.into_response()
    } else if legacy {
        (
            StatusCode::OK,
            [
                ("content-type", "text/event-stream"),
                ("cache-control", "no-cache, no-transform"),
                ("connection", "keep-alive"),
            ],
            sse_messages(&messages),
        )
            .into_response()
    } else {
        let body = if messages.len() == 1 && !is_batch {
            messages[0].get().to_owned()
        } else {
            format!(
                "[{}]",
                messages
                    .iter()
                    .map(|message| message.get())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        (StatusCode::OK, [("content-type", "application/json")], body).into_response()
    };
    if let Some(session) = created_session
        && let Ok(value) = session.parse()
    {
        response.headers_mut().insert("mcp-session-id", value);
    }
    response
}

async fn harpoon_get(State(state): State<Monitor>, headers: HeaderMap) -> Response {
    if !accepts(&headers).1 {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            "Accept must contain 'text/event-stream' for GET requests",
        );
    }
    let Some(server) = state.harpoon else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(session) = mcp_session(&headers) else {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            "Bad Request: GET requires an Mcp-Session-Id header",
        );
    };
    let token = server
        .sessions
        .read()
        .expect("Harpoon session lock poisoned")
        .get(session)
        .cloned();
    let Some(token) = token else {
        return mcp_error(StatusCode::NOT_FOUND, "session not found");
    };
    if headers.contains_key("last-event-id") {
        return mcp_error(StatusCode::BAD_REQUEST, "stream replay unsupported");
    }
    let stop = state.stop;
    let stream = stream::unfold((token, stop), |(session, stop)| async move {
        tokio::select! {
            () = session.cancelled() => {}
            () = stop.cancelled() => {}
        }
        None::<(
            std::result::Result<Event, Infallible>,
            (CancellationToken, CancellationToken),
        )>
    });
    Sse::new(stream)
        .keep_alive(Default::default())
        .into_response()
}

async fn harpoon_delete(State(state): State<Monitor>, headers: HeaderMap) -> Response {
    let Some(server) = state.harpoon else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(session) = mcp_session(&headers) else {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            "Bad Request: DELETE requires an Mcp-Session-Id header",
        );
    };
    let token = server
        .sessions
        .write()
        .expect("Harpoon session lock poisoned")
        .remove(session);
    let Some(token) = token else {
        return mcp_error(StatusCode::NOT_FOUND, "session not found");
    };
    token.cancel();
    StatusCode::NO_CONTENT.into_response()
}

async fn readiness(State(state): State<Monitor>) -> impl IntoResponse {
    let snapshot = state.status.borrow();
    if snapshot.ready {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "mcp startup probe pending")
    }
}

async fn ready(State(state): State<Monitor>) -> Response {
    let snapshot = state.status.borrow().clone();
    let status = if snapshot.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    if state.details {
        (status, Json(snapshot)).into_response()
    } else {
        (status, Json(serde_json::json!({"ready":snapshot.ready}))).into_response()
    }
}
async fn status(State(state): State<Monitor>) -> Json<Snapshot> {
    Json(state.status.borrow().clone())
}
async fn events(
    State(state): State<Monitor>,
) -> Sse<impl Stream<Item = std::result::Result<Event, Infallible>>> {
    let stream = stream::unfold(
        (state.status, true, state.stop),
        |(mut status, first, stop)| async move {
            if !first {
                tokio::select! {
                    result = status.changed() => if result.is_err() { return None; },
                    () = stop.cancelled() => return None,
                }
            }
            let event = Event::default()
                .event("status")
                .json_data(status.borrow_and_update().clone())
                .expect("status is serializable");
            Some((Ok(event), (status, false, stop)))
        },
    );
    Sse::new(stream).keep_alive(Default::default())
}
async fn metrics(State(state): State<Monitor>) -> impl IntoResponse {
    let snapshot = state.status.borrow().clone();
    let uptime = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(snapshot.started_at);
    let body = format!(
        "# TYPE otunnel_ready gauge\notunnel_ready {}\n# TYPE otunnel_in_flight gauge\notunnel_in_flight {}\n# TYPE otunnel_requests_total counter\notunnel_requests_total{{outcome=\"completed\"}} {}\notunnel_requests_total{{outcome=\"expired\"}} {}\notunnel_requests_total{{outcome=\"failed\"}} {}\n# TYPE otunnel_uptime_seconds gauge\notunnel_uptime_seconds {}\n",
        u8::from(snapshot.ready),
        snapshot.in_flight,
        snapshot.completed,
        snapshot.expired,
        snapshot.failed,
        uptime
    );
    let body = format!(
        "# TYPE liveness gauge\nliveness 1\n# TYPE readiness gauge\nreadiness {}\n# TYPE commands_poll_last_successful_timestamp_seconds gauge\ncommands_poll_last_successful_timestamp_seconds {}\ncommands_poll_cycles_total {}\ncommands_poll_errors_total {}\ncommands_polled_total {}\n{body}",
        u8::from(snapshot.ready),
        snapshot.control.last_success,
        snapshot.control.cycles,
        snapshot.control.errors,
        snapshot.control.commands
    );
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

/// An HTTP or HTTP-over-Unix-socket health endpoint.
pub struct Target {
    pub base: String,
    url: String,
    client: Http,
}
impl Target {
    pub fn normalize(raw: &str) -> String {
        let raw = raw.trim();
        let raw = raw.strip_suffix("/healthz").unwrap_or(raw);
        raw.strip_suffix("/readyz")
            .unwrap_or(raw)
            .trim_end_matches('/')
            .to_owned()
    }
    pub fn new(raw: &str) -> Result<Self> {
        let base = Self::normalize(raw);
        anyhow::ensure!(!base.is_empty(), "health URL is empty");
        let (url, socket) = if let Some(encoded) = base.strip_prefix("http+unix://") {
            let socket = String::from_utf8(URL_SAFE_NO_PAD.decode(encoded)?)?;
            anyhow::ensure!(!socket.is_empty(), "health unix socket path is empty");
            ("http://localhost".to_owned(), Some(socket))
        } else {
            (base.clone(), None)
        };
        let client = Http::new(
            Url::parse(&url)?,
            Options {
                socket: socket.as_deref(),
                ..Default::default()
            },
        )?;
        Ok(Self { base, url, client })
    }
    pub async fn request(
        &self,
        path: &str,
        timeout: Duration,
        limit: Option<usize>,
    ) -> Result<(u16, Bytes)> {
        tokio::time::timeout(timeout, async {
            let mut url = Url::parse(&format!("{}{path}", self.url))?;
            for hop in 0..=10 {
                let mut response = self
                    .client
                    .send(http::Method::GET, &url, Default::default(), Bytes::new())
                    .await?;
                if response.status.is_redirection()
                    && let Some(location) = response.headers.get("location")
                {
                    anyhow::ensure!(hop < 10, "health request exceeded 10 redirects");
                    url = url.join(location.to_str()?)?;
                    continue;
                }
                let code = response.status.as_u16();
                let mut body = BytesMut::new();
                while let Some(chunk) = response.body.next().await {
                    let chunk = chunk?;
                    let count = limit.map_or(chunk.len(), |limit| {
                        chunk.len().min(limit.saturating_sub(body.len()))
                    });
                    body.extend_from_slice(&chunk[..count]);
                    if limit.is_some_and(|limit| body.len() >= limit) {
                        break;
                    }
                }
                return Ok((code, body.freeze()));
            }
            unreachable!()
        })
        .await
        .context("health request timed out")?
    }
}

enum Listener {
    Tcp(TcpListener),
    Local(Local),
}
impl axum::serve::Listener for Listener {
    type Io = Box<dyn Io>;
    type Addr = String;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let result: io::Result<(Self::Io, Self::Addr)> = match self {
                Self::Tcp(listener) => {
                    TcpListener::accept(listener)
                        .await
                        .map(|(stream, address)| {
                            (Box::new(stream) as Box<dyn Io>, address.to_string())
                        })
                }
                Self::Local(listener) => listener
                    .accept()
                    .await
                    .map(|stream| (stream, "local".into())),
            };
            match result {
                Ok(connection) => return connection,
                Err(error) => {
                    tracing::warn!(%error, "health listener could not accept a connection");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    fn local_addr(&self) -> io::Result<String> {
        match self {
            Self::Tcp(listener) => Ok(listener.local_addr()?.to_string()),
            Self::Local(listener) => Ok(listener.path.display().to_string()),
        }
    }
}

struct Local {
    path: PathBuf,
    #[cfg(unix)]
    listener: Option<tokio::net::UnixListener>,
    #[cfg(windows)]
    listener: Option<async_io::Async<socket2::Socket>>,
}
impl Local {
    #[cfg(unix)]
    fn bind(path: PathBuf) -> io::Result<Self> {
        let listener = tokio::net::UnixListener::bind(&path)?;
        Ok(Self {
            path,
            listener: Some(listener),
        })
    }
    #[cfg(windows)]
    fn bind(path: PathBuf) -> io::Result<Self> {
        let listener = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
        listener.bind(&socket2::SockAddr::unix(&path)?)?;
        listener.listen(128)?;
        Ok(Self {
            path,
            listener: Some(async_io::Async::new(listener)?),
        })
    }
    #[cfg(unix)]
    async fn accept(&self) -> io::Result<Box<dyn Io>> {
        Ok(Box::new(
            self.listener
                .as_ref()
                .expect("bound socket")
                .accept()
                .await?
                .0,
        ))
    }
    #[cfg(windows)]
    async fn accept(&self) -> io::Result<Box<dyn Io>> {
        let (socket, _) = self
            .listener
            .as_ref()
            .expect("bound socket")
            .read_with(|listener| listener.accept())
            .await?;
        Ok(Box::new(crate::net::Socket(async_io::Async::new(socket)?)))
    }
}
impl Drop for Local {
    fn drop(&mut self) {
        drop(self.listener.take());
        if let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(%error, "could not remove health socket");
        }
    }
}

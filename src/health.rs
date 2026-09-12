use std::{
    convert::Infallible,
    io,
    path::PathBuf,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response, Sse, sse::Event},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt, stream};
use tokio::{net::TcpListener, sync::watch};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    config::Health,
    net::{Http, Io, Options},
    runtime::Snapshot,
};

/// The optional local status service. Binding it is independent of starting a tunnel.
pub struct Server {
    listener: Listener,
    status: watch::Receiver<Snapshot>,
    url: String,
    details: bool,
}
impl Server {
    pub async fn bind(config: &Health, status: watch::Receiver<Snapshot>) -> Result<Self> {
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
        };
        let router = Router::new()
            .route("/", get(|| async { Redirect::temporary("/ui") }))
            .route("/ui", get(|| async { Html(include_str!("ui.html")) }))
            .route("/healthz", get(|| async { "live" }))
            .route("/readyz", get(readiness))
            .route("/health", get(ready))
            .route("/health/mcp", get(status))
            .route("/api/status", get(status))
            .route("/api/events", get(events))
            .route("/metrics", get(metrics))
            .with_state(state);
        axum::serve(self.listener, router)
            .with_graceful_shutdown(stop.cancelled_owned())
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
struct Monitor {
    status: watch::Receiver<Snapshot>,
    details: bool,
    stop: CancellationToken,
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

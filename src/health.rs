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
use bytes::Bytes;
use futures_util::{Stream, stream};
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
    url: Url,
    details: bool,
}
impl Server {
    pub async fn bind(config: &Health, status: watch::Receiver<Snapshot>) -> Result<Self> {
        let (listener, url) = if let Some(socket) = &config.unix_socket {
            let path = std::path::absolute(socket)?;
            let local = Local::bind(path)?;
            (Listener::Local(local), Url::parse("http://localhost")?)
        } else {
            let address = if config.listen_addr.starts_with(':') {
                format!("0.0.0.0{}", config.listen_addr)
            } else {
                config.listen_addr.clone()
            };
            let listener = TcpListener::bind(&address)
                .await
                .with_context(|| format!("bind health listener {address}"))?;
            let url = Url::parse(&format!("http://{}", listener.local_addr()?))?;
            (Listener::Tcp(listener), url)
        };
        Ok(Self {
            listener,
            status,
            url,
            details: config.show_details,
        })
    }

    pub fn url(&self) -> &Url {
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
            .route(
                "/healthz",
                get(|| async { Json(serde_json::json!({"status":"ok"})) }),
            )
            .route("/readyz", get(ready))
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
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

pub async fn probe(config: &Health, base: &str) -> Result<serde_json::Value> {
    let url = Url::parse(base)?;
    let client = Http::new(
        url.clone(),
        Options {
            socket: config.unix_socket.as_deref(),
            ..Default::default()
        },
    )?;
    tokio::time::timeout(Duration::from_secs(10), async {
        let response = client
            .send(
                http::Method::GET,
                &url.join("/api/status")?,
                Default::default(),
                Bytes::new(),
            )
            .await?;
        anyhow::ensure!(
            response.status.is_success(),
            "health endpoint returned HTTP {}",
            response.status
        );
        Ok(serde_json::from_slice(&response.bytes().await?)?)
    })
    .await
    .context("health request timed out")?
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
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        let (socket, _) = self
            .listener
            .as_ref()
            .expect("bound socket")
            .read_with(|listener| listener.accept())
            .await?;
        Ok(Box::new(async_io::Async::new(socket)?.compat()))
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

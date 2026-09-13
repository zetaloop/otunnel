use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    config::Health,
    harpoon::Harpoon,
    listener::{Listener, Peer},
    net::{Http, Options},
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
        let (listener, url) = Listener::bind(config).await?;
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
        };
        let router = Router::new()
            .route("/healthz", get(|| async { "live" }))
            .route("/readyz", get(readiness))
            .route("/health", get(ready))
            .route("/health/mcp", get(status))
            .route("/metrics", get(metrics));
        let mut router = router.with_state(state);
        if let Some(harpoon) = self.harpoon {
            let server = transport::Server::new(harpoon, stop.clone())
                .local_only("harpoon transport is restricted to loopback");
            router = router.route("/harpoon/mcp", server.route());
        }
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
struct Monitor {
    status: watch::Receiver<Snapshot>,
    details: bool,
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

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Router,
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
    config::Config,
    harpoon::Harpoon,
    listener::{Listener, Peer},
    net::{Http, Options},
    runtime::Snapshot,
    transport,
};

mod snapshot;

/// The optional local status service. Binding it is independent of starting a tunnel.
pub struct Server {
    listener: Listener,
    status: watch::Receiver<Snapshot>,
    url: String,
    config: Arc<Config>,
    address: String,
    trust: serde_json::Value,
    harpoon: Arc<Harpoon>,
}
impl Server {
    pub async fn bind(
        config: &Config,
        status: watch::Receiver<Snapshot>,
        harpoon: Arc<Harpoon>,
    ) -> Result<Self> {
        let (listener, url) = Listener::bind(&config.health).await?;
        let address = axum::serve::Listener::local_addr(&listener)?.local;
        let trust = snapshot::trust(config)?;
        Ok(Self {
            listener,
            status,
            url,
            config: Arc::new(config.clone()),
            address,
            trust,
            harpoon,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn serve(self, stop: CancellationToken) -> Result<()> {
        let enabled = !self.config.harpoon.additional_transports.is_empty();
        let state = Monitor {
            status: self.status,
            config: self.config,
            address: self.address,
            trust: self.trust,
            harpoon: self.harpoon.clone(),
        };
        let details = Router::new()
            .route("/health", axum::routing::any(snapshot::health))
            .route("/health/{*component}", axum::routing::any(snapshot::health))
            .route("/api/status", axum::routing::any(snapshot::status))
            .route("/api/system", axum::routing::any(snapshot::system))
            .layer(axum::middleware::from_fn(local));
        let mut router = Router::new()
            .route("/healthz", axum::routing::any(|| async { "live" }))
            .route("/readyz", axum::routing::any(readiness))
            .route("/metrics", get(metrics))
            .merge(details)
            .with_state(state);
        if enabled {
            let server = transport::Server::new(self.harpoon, stop.clone())
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
    config: Arc<Config>,
    address: String,
    trust: serde_json::Value,
    harpoon: Arc<Harpoon>,
}

async fn local(
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<Peer>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if peer.remote != "local" && !crate::listener::loopback_address(&peer.remote) {
        return (
            StatusCode::FORBIDDEN,
            "runtime details are restricted to loopback or a Unix socket\n",
        )
            .into_response();
    }
    next.run(request).await
}

async fn readiness(State(state): State<Monitor>) -> impl IntoResponse {
    let (ready, message) = state.status.borrow().readiness();
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        message,
    )
}

async fn metrics(State(state): State<Monitor>) -> impl IntoResponse {
    use std::fmt::Write;
    let snapshot = state.status.borrow();
    let mut body = String::new();
    for (name, kind, scope, value) in [
        ("liveness", "gauge", "health", 1.0),
        ("readiness", "gauge", "health", f64::from(snapshot.ready)),
        (
            "commands_poll_last_successful_timestamp_seconds",
            "gauge",
            "controlplane",
            snapshot.control.last_success.floor(),
        ),
        (
            "commands_poll_cycles_total",
            "counter",
            "controlplane",
            snapshot.control.cycles as f64,
        ),
        (
            "commands_polled_total",
            "counter",
            "controlplane",
            snapshot.control.commands as f64,
        ),
        (
            "commands_enqueued_total",
            "counter",
            "controlplane",
            snapshot.activity.enqueued as f64,
        ),
        (
            "commands_queue_capacity",
            "gauge",
            "controlplane",
            state.config.control_plane.max_inflight_requests as f64,
        ),
        (
            "commands_queue_length",
            "gauge",
            "controlplane",
            snapshot.activity.queued as f64,
        ),
    ] {
        writeln!(body, "# TYPE {name} {kind}\n{name}{{otel_scope_name={scope:?},otel_scope_schema_url=\"\",otel_scope_version=\"\"}} {value}").expect("metric output");
    }
    if !snapshot.control.error_kinds.is_empty() {
        body.push_str("# TYPE commands_poll_errors_total counter\n");
        for (kind, count) in &snapshot.control.error_kinds {
            writeln!(body, "commands_poll_errors_total{{error_kind={kind:?},otel_scope_name=\"controlplane\",otel_scope_schema_url=\"\",otel_scope_version=\"\"}} {count}").expect("metric output");
        }
    }
    body.push_str(&state.harpoon.metrics());
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
    follow_redirects: bool,
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
        Ok(Self {
            base,
            url,
            client,
            follow_redirects: true,
        })
    }
    pub fn follow_redirects(mut self, enabled: bool) -> Self {
        self.follow_redirects = enabled;
        self
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
                if self.follow_redirects
                    && response.status.is_redirection()
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

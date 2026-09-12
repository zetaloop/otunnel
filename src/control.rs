use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use serde::Serialize;
use serde_json::Value;
use tokio::{
    sync::watch,
    time::{Instant, timeout},
};
use url::Url;

use crate::{
    config::{self, Config},
    net::{Http, Options},
    protocol::{self, Command, Poll, Reply},
    transport::Sink,
};

#[derive(Clone, Serialize)]
pub struct Channel {
    pub name: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stateless: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub proc_affinity: bool,
}

pub struct Batch {
    pub received: Instant,
    pub commands: Vec<Command>,
}

#[derive(Debug)]
pub struct StatusError {
    pub status: u16,
    operation: &'static str,
}
impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tunnel {} returned HTTP {}", self.operation, self.status)
    }
}
impl std::error::Error for StatusError {}

pub struct Control {
    http: Http,
    url: Url,
    headers: HeaderMap,
    server_info: RwLock<Option<HeaderValue>>,
    subscriptions: Vec<String>,
    poll_timeout: Duration,
    initial_poll_timeout: Duration,
    guard: Duration,
    connected: watch::Sender<bool>,
}

impl Control {
    pub fn new(config: &Config) -> Result<Self> {
        let cp = &config.control_plane;
        let mut url = Url::parse(&config::resolve(&cp.base_url)?)?;
        if cp.client_cert.is_some() && url.host_str() == Some("api.openai.com") {
            url.set_host(Some("mtls.api.openai.com"))?;
        }
        url.set_path(&format!(
            "{}/v1/tunnels/",
            config::resolve(&cp.url_path)?.trim_end_matches('/')
        ));
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("control plane URL cannot contain path segments"))?
            .pop_if_empty()
            .push(&cp.tunnel_id);
        url.set_query(None);
        url.set_fragment(None);
        let http = Http::new(
            url.clone(),
            Options {
                proxy: cp.http_proxy.as_deref().or(config.http_proxy.as_deref()),
                ca_bundle: config.ca_bundle.as_deref(),
                client_cert: cp.client_cert.as_deref(),
                client_key: cp.client_key.as_deref(),
                ..Default::default()
            },
        )?;
        let mut headers = config::headers(&cp.extra_headers)?;
        let mut authorization =
            HeaderValue::try_from(format!("Bearer {}", config::resolve(&cp.api_key)?))?;
        authorization.set_sensitive(true);
        headers.insert("authorization", authorization);
        headers.insert("x-tunnel-client-name", HeaderValue::from_static("otunnel"));
        headers.insert(
            "x-tunnel-client-version",
            HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
        );
        headers.insert(
            "x-tunnel-client-wire-protocol-version",
            HeaderValue::from_static(protocol::WIRE_VERSION),
        );
        headers.insert(
            "x-tunnel-client-instance-id",
            uuid::Uuid::new_v4().to_string().parse()?,
        );
        if let Some(organization) = &cp.organization_id {
            headers.insert(
                "openai-organization",
                config::resolve(organization)?.parse()?,
            );
        }
        let mut subscriptions = cp
            .poll_channels
            .iter()
            .map(|name| config::channel(name))
            .collect::<Result<Vec<_>>>()?;
        subscriptions.sort();
        subscriptions.dedup();
        Ok(Self {
            http,
            url,
            headers,
            server_info: RwLock::new(None),
            subscriptions,
            poll_timeout: cp.poll_timeout.0,
            initial_poll_timeout: cp.initial_poll_timeout.0,
            guard: cp.poll_deadline_guardrail.0,
            connected: watch::channel(false).0,
        })
    }

    pub(crate) fn connection(&self) -> watch::Receiver<bool> {
        self.connected.subscribe()
    }

    pub fn set_channels(&self, mut channels: Vec<Channel>) -> Result<()> {
        channels.sort_by(|a, b| a.name.cmp(&b.name));
        anyhow::ensure!(
            channels.len() <= 32,
            "tunnel protocol permits at most 32 channels"
        );
        for (i, channel) in channels.iter().enumerate() {
            anyhow::ensure!(
                config::channel(&channel.name).is_ok_and(|name| name == channel.name),
                "invalid tunnel channel name: {}",
                channel.name
            );
            anyhow::ensure!(
                i == 0 || channels[i - 1].name != channel.name,
                "duplicate tunnel channel: {}",
                channel.name
            );
        }
        #[derive(Serialize)]
        struct Info {
            version: u8,
            channels: Vec<Channel>,
        }
        let version = if channels.iter().any(|channel| channel.stateless) {
            2
        } else {
            1
        };
        let value = serde_json::to_string(&Info { version, channels })?;
        anyhow::ensure!(
            value.len() <= 4096,
            "tunnel channel declaration exceeds 4096 bytes"
        );
        *self
            .server_info
            .write()
            .expect("channel metadata lock poisoned") = Some(value.parse()?);
        Ok(())
    }

    fn headers(&self) -> HeaderMap {
        let mut headers = self.headers.clone();
        if let Some(value) = &*self
            .server_info
            .read()
            .expect("channel metadata lock poisoned")
        {
            headers.insert("x-tunnel-mcp-server-info", value.clone());
        }
        headers
    }

    fn endpoint(&self, suffix: &str) -> Result<Url> {
        let mut url = self.url.clone();
        if !suffix.is_empty() {
            url.path_segments_mut()
                .map_err(|_| anyhow::anyhow!("invalid control plane URL"))?
                .extend(suffix.split('/'));
        }
        Ok(url)
    }

    pub async fn metadata(&self) -> Result<Value> {
        let metadata = self.fetch("").await?;
        self.connected.send_replace(true);
        Ok(metadata)
    }

    pub async fn cloudflare(&self) -> Result<Value> {
        self.fetch("cloudflare/runtime").await
    }

    async fn fetch(&self, suffix: &str) -> Result<Value> {
        let url = self.endpoint(suffix)?;
        timeout(Duration::from_secs(30), async {
            let response = self
                .http
                .send(Method::GET, &url, self.headers(), Bytes::new())
                .await?;
            if !response.status.is_success() {
                return Err(StatusError {
                    status: response.status.as_u16(),
                    operation: "metadata",
                }
                .into());
            }
            Ok(serde_json::from_slice(&response.bytes().await?)?)
        })
        .await
        .context("tunnel metadata request timed out")?
    }

    pub async fn poll(&self, limit: usize, initial: bool) -> Result<Batch> {
        let duration = if initial {
            self.initial_poll_timeout.min(self.poll_timeout)
        } else {
            self.poll_timeout
        };
        let mut url = self.endpoint("poll")?;
        {
            let mut query = url.query_pairs_mut();
            for channel in &self.subscriptions {
                query.append_pair("channel", channel);
            }
            query.append_pair("limit", &limit.clamp(1, 25).to_string());
            query.append_pair("timeout_ms", &duration.as_millis().to_string());
        }
        let mut attempt = 0;
        loop {
            let result = timeout(self.poll_timeout + self.guard, async {
                let response = self
                    .http
                    .send(Method::GET, &url, self.headers(), Bytes::new())
                    .await?;
                let received = Instant::now();
                let status = response.status.as_u16();
                let headers = response.headers.clone();
                let commands = if status == 204 {
                    Vec::new()
                } else if status == 200 {
                    serde_json::from_slice::<Poll>(&response.bytes().await?)?.commands()
                } else {
                    return Ok::<_, anyhow::Error>(Err((status, headers)));
                };
                Ok(Ok(Batch { received, commands }))
            })
            .await;
            let connected = matches!(&result, Ok(Ok(Ok(_))));
            self.connected.send_if_modified(|current| {
                if *current == connected {
                    return false;
                }
                *current = connected;
                true
            });
            let retry_headers = match result {
                Ok(Ok(Ok(batch))) => return Ok(batch),
                Ok(Ok(Err((status, headers)))) if status == 429 || status >= 500 => headers,
                Ok(Ok(Err((status, _)))) => {
                    return Err(StatusError {
                        status,
                        operation: "poll",
                    }
                    .into());
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "tunnel poll interrupted");
                    HeaderMap::new()
                }
                Err(_) => HeaderMap::new(),
            };
            tokio::time::sleep(retry_delay(attempt, &retry_headers)).await;
            attempt = attempt.saturating_add(1);
        }
    }

    async fn post(&self, command: &Correlation, reply: &Reply) -> Result<()> {
        #[derive(Serialize)]
        struct Payload<'a> {
            request_id: &'a str,
            channel: &'a str,
            #[serde(flatten)]
            reply: &'a Reply,
        }
        let body = Bytes::from(serde_json::to_vec(&Payload {
            request_id: &command.request_id,
            channel: &command.channel,
            reply,
        })?);
        let mut headers = self.headers();
        let mut shard = HeaderValue::try_from(&command.shard_token)?;
        shard.set_sensitive(true);
        headers.insert("x-tunnel-shard-token", shard);
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let url = self.endpoint("response")?;
        let mut attempt = 0;
        loop {
            let response = timeout(Duration::from_secs(30), async {
                let response = self
                    .http
                    .send(Method::POST, &url, headers.clone(), body.clone())
                    .await?;
                let status = response.status;
                let headers = response.headers.clone();
                if let Err(error) = timeout(Duration::from_secs(1), response.bytes())
                    .await
                    .context("response body drain timed out")
                    .and_then(|result| result)
                {
                    tracing::debug!(%error, "tunnel response acknowledgement body interrupted");
                }
                Ok::<_, anyhow::Error>((status, headers))
            })
            .await;
            let retry_headers = match response {
                Ok(Ok((status, headers))) => {
                    let code = status.as_u16();
                    if status.is_success() || code == 404 {
                        return Ok(());
                    }
                    if code == 429 || (reply.terminal() && matches!(code, 408 | 502 | 503 | 504)) {
                        headers
                    } else {
                        return Err(StatusError {
                            status: code,
                            operation: "response",
                        }
                        .into());
                    }
                }
                Ok(Err(error)) if reply.terminal() || crate::net::connecting(&error) => {
                    tracing::debug!(%error, "retrying tunnel response delivery");
                    HeaderMap::new()
                }
                Ok(Err(error)) => return Err(error),
                Err(_) if reply.terminal() => HeaderMap::new(),
                Err(_) => bail!("notification delivery timed out"),
            };
            tokio::time::sleep(retry_delay(attempt, &retry_headers)).await;
            attempt = attempt.saturating_add(1);
        }
    }
}

fn retry_delay(attempt: u32, headers: &HeaderMap) -> Duration {
    let local = Duration::from_secs_f64(
        (0.25 * 2_f64.powi(attempt.min(7) as i32) * (0.5 + rand::random::<f64>())).min(30.0),
    );
    let server = headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .parse::<u64>()
                .ok()
                .map(Duration::from_secs)
                .or_else(|| {
                    httpdate::parse_http_date(value)
                        .ok()?
                        .duration_since(SystemTime::now())
                        .ok()
                })
        })
        .unwrap_or_default()
        .min(Duration::from_secs(300));
    local.max(server)
}

struct Correlation {
    request_id: String,
    shard_token: String,
    channel: String,
}

pub struct Delivery {
    control: Arc<Control>,
    command: Correlation,
    notifications_failed: AtomicBool,
    terminal_started: AtomicBool,
}
impl Delivery {
    pub fn new(control: Arc<Control>, command: &Command) -> Self {
        Self {
            control,
            command: Correlation {
                request_id: command.request_id.clone(),
                shard_token: command.shard_token.clone(),
                channel: command.channel.clone(),
            },
            notifications_failed: AtomicBool::new(false),
            terminal_started: AtomicBool::new(false),
        }
    }
    pub fn terminal_started(&self) -> bool {
        self.terminal_started.load(Ordering::Acquire)
    }
}
#[async_trait]
impl Sink for Delivery {
    async fn send(&self, reply: Reply) -> Result<()> {
        if reply.terminal() {
            if self.terminal_started.swap(true, Ordering::AcqRel) {
                bail!("request already has a terminal response");
            }
            return self.control.post(&self.command, &reply).await;
        }
        if !self.notifications_failed.load(Ordering::Acquire)
            && let Err(error) = timeout(
                Duration::from_secs(30),
                self.control.post(&self.command, &reply),
            )
            .await
            .context("notification delivery timed out")
            .and_then(|result| result)
        {
            if error
                .downcast_ref::<StatusError>()
                .is_some_and(|e| matches!(e.status, 401 | 403))
            {
                return Err(error);
            }
            self.notifications_failed.store(true, Ordering::Release);
            tracing::warn!(request_id = %self.command.request_id, %error, "notification delivery interrupted");
        }
        Ok(())
    }
}

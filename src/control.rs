use std::{
    sync::{
        Arc, LazyLock, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
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

mod error;
mod observation;
mod routing;
pub use error::StatusError;
pub use observation::Upload;

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

#[derive(Clone, Default, Serialize)]
pub struct Observation {
    #[serde(skip)]
    pub(crate) metrics: Arc<crate::metrics::Metrics>,
    pub poll_state: &'static str,
    pub effective_wait: f64,
    pub deadline: f64,
    pub failure_category: &'static str,
    pub upload: Upload,
    pub connected: bool,
    pub instance_id: String,
    pub metadata: Option<Value>,
    pub last_attempt: f64,
    pub last_success: f64,
    pub last_error: f64,
    pub next_retry: f64,
    pub consecutive_failures: u64,
    pub cycles: u64,
    pub errors: u64,
    pub error_kinds: std::collections::BTreeMap<&'static str, u64>,
    pub commands: u64,
    pub http_status: u16,
}

impl Observation {
    pub fn metrics(&self) -> String {
        self.metrics.render()
    }
}

pub(crate) fn now() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub struct Control {
    http: Http,
    pub(crate) metrics: Arc<crate::metrics::Metrics>,
    pub(crate) suppress_raw: Arc<AtomicBool>,
    url: Url,
    headers: HeaderMap,
    server_info: RwLock<Option<HeaderValue>>,
    subscriptions: Vec<String>,
    poll_timeout: Duration,
    initial_poll_timeout: Duration,
    guard: Duration,
    learned_poll_ms: AtomicU64,
    routing: Mutex<routing::State>,
    uses_proxy: bool,
    observations: watch::Sender<Observation>,
}

impl Control {
    pub fn new(config: &Config) -> Result<Self> {
        let cp = &config.control_plane;
        let mut url = Url::parse(cp.base_url()).context("invalid control-plane.base-url")?;
        anyhow::ensure!(
            url.host_str().is_some(),
            "control-plane.base-url must include scheme and host"
        );
        url = config::endpoint(
            &url,
            cp.url_path.as_deref().unwrap_or_default(),
            "v1/tunnels",
        )?;
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
        let http = http.logging(config.log.http_raw_unsafe.then_some("controlplane"));
        let mut headers = config::headers(&cp.extra_headers)?;
        for name in [
            "authorization",
            "accept",
            "user-agent",
            "x-tunnel-client-name",
            "x-tunnel-client-version",
            "x-tunnel-client-wire-protocol-version",
            "x-tunnel-client-instance-id",
            "x-tunnel-client-capabilities",
            "x-tunnel-mcp-server-info",
            "x-tunnel-shard-token",
        ] {
            if headers.remove(name).is_some() {
                tracing::warn!(
                    header = name,
                    "control-plane extra header cannot override protected header"
                );
            }
        }
        headers.insert("accept", HeaderValue::from_static("application/json"));
        headers.insert(
            "x-tunnel-client-capabilities",
            HeaderValue::from_static("wrong-cluster-v1"),
        );
        let mut authorization =
            HeaderValue::try_from(format!("Bearer {}", config::resolve(&cp.api_key)?))?;
        authorization.set_sensitive(true);
        headers.insert("authorization", authorization);
        headers.insert(
            "user-agent",
            HeaderValue::from_static(crate::harpoon::headers::USER_AGENT),
        );
        headers.insert("x-tunnel-client-name", HeaderValue::from_static("otunnel"));
        headers.insert(
            "x-tunnel-client-version",
            HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
        );
        headers.insert(
            "x-tunnel-client-wire-protocol-version",
            HeaderValue::from_static(protocol::WIRE_VERSION),
        );
        static INSTANCE_ID: LazyLock<String> =
            LazyLock::new(|| format!("{:032x}", rand::random::<u128>()));
        let instance_id = INSTANCE_ID.clone();
        headers.insert("x-tunnel-client-instance-id", instance_id.parse()?);
        if let Some(organization) = &cp.organization_id {
            headers.insert("openai-organization", organization.trim().parse()?);
        }
        let subscriptions = cp.poll_channels.clone().unwrap_or_default();
        let uses_proxy = http.proxied(&url)?;
        let metrics = Arc::new(crate::metrics::Metrics::default());
        Ok(Self {
            http,
            metrics: metrics.clone(),
            suppress_raw: Arc::new(AtomicBool::new(config.harpoon.targets.iter().any(
                |target| {
                    target
                        .template
                        .as_ref()
                        .is_some_and(|template| template.rich())
                },
            ))),
            url,
            headers,
            server_info: RwLock::new(None),
            subscriptions,
            poll_timeout: cp.poll_timeout.0,
            initial_poll_timeout: cp.initial_poll_timeout.0,
            guard: cp.poll_deadline_guardrail.0,
            learned_poll_ms: AtomicU64::new(0),
            routing: Mutex::new(routing::State::default()),
            uses_proxy,
            observations: watch::channel(Observation {
                metrics,
                poll_state: "starting",
                effective_wait: cp.poll_timeout.0.as_secs_f64(),
                deadline: (cp.poll_timeout.0 + cp.poll_deadline_guardrail.0).as_secs_f64(),
                upload: Upload {
                    disposition: "not_observed",
                    ..Default::default()
                },
                instance_id,
                ..Default::default()
            })
            .0,
        })
    }

    pub(crate) fn tunnel_id(&self) -> &str {
        self.url
            .path_segments()
            .and_then(Iterator::last)
            .unwrap_or_default()
    }

    fn client(&self) -> Http {
        let client = self.http.clone();
        if self.suppress_raw.load(Ordering::Acquire) {
            client.logging(None)
        } else {
            client
        }
    }

    pub(crate) fn connection(&self) -> watch::Receiver<Observation> {
        self.observations.subscribe()
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
        let metadata = self.fetch().await?;
        self.observations.send_modify(|state| {
            state.metadata = Some(metadata.clone());
        });
        Ok(metadata)
    }

    pub async fn cloudflare(&self) -> Result<Value> {
        let url = self.endpoint("cloudflare/runtime")?;
        let client = self.http.clone().logging(None);
        for attempt in 0..3 {
            let deadline = Instant::now() + self.poll_timeout + self.guard;
            let response = tokio::time::timeout_at(
                deadline,
                client.send(Method::GET, &url, self.headers(), Bytes::new()),
            )
            .await;
            let headers = match response {
                Ok(Ok(response)) => {
                    let status = response.status.as_u16();
                    if response.status.is_success() {
                        let bytes = tokio::time::timeout_at(deadline, response.bytes())
                            .await
                            .map_err(|_| {
                                anyhow::anyhow!("managed Cloudflare runtime response timed out")
                            })?
                            .map_err(|_| {
                                anyhow::anyhow!("read managed Cloudflare runtime response")
                            })?;
                        let payload: Value = serde_json::from_slice(&bytes).map_err(|_| {
                            anyhow::anyhow!("decode managed Cloudflare runtime response")
                        })?;
                        anyhow::ensure!(
                            [
                                "/runtime_token",
                                "/cloudflare_tunnel/tunnel_id",
                                "/cloudflare_tunnel/name",
                                "/cloudflare_tunnel/account_id",
                            ]
                            .iter()
                            .all(|key| payload
                                .pointer(key)
                                .and_then(Value::as_str)
                                .is_some_and(|value| !value.trim().is_empty())),
                            "invalid managed Cloudflare runtime response"
                        );
                        return Ok(payload);
                    }
                    if attempt == 2 || !(status == 429 || (500..600).contains(&status)) {
                        return Err(StatusError::new(status, "Cloudflare runtime").into());
                    }
                    response.headers
                }
                _ if attempt == 2 => bail!("fetch managed Cloudflare runtime failed"),
                _ => HeaderMap::new(),
            };
            tokio::time::sleep(retry_delay(attempt, &headers)).await;
        }
        unreachable!()
    }

    async fn fetch(&self) -> Result<Value> {
        timeout(self.poll_timeout + self.guard, async {
            let response = self
                .client()
                .send(Method::GET, &self.url, self.headers(), Bytes::new())
                .await?;
            if !response.status.is_success() {
                return Err(StatusError::read(response, "metadata").await.into());
            }
            Ok(serde_json::from_slice(&response.bytes().await?)?)
        })
        .await
        .context("tunnel metadata request timed out")?
    }

    pub async fn poll(&self, limit: usize, mut initial: bool) -> Result<Batch> {
        if limit == 0 {
            return Ok(Batch {
                received: Instant::now(),
                commands: Vec::new(),
            });
        }
        let mut attempt = 0;
        let client = self.http.clone().logging(None);
        loop {
            let route = self
                .routing
                .lock()
                .expect("routing mutex poisoned")
                .snapshot();
            let learned = self.learned_poll_ms.load(Ordering::Relaxed);
            let duration = if learned == 0 {
                self.poll_timeout
            } else {
                self.poll_timeout.min(Duration::from_millis(learned))
            };
            let requested = if initial {
                self.initial_poll_timeout.min(duration)
            } else {
                duration
            };
            initial = false;
            let mut url = self.endpoint("poll")?;
            {
                let mut query = url.query_pairs_mut();
                for channel in &self.subscriptions {
                    query.append_pair("channel", channel);
                }
                query.append_pair("limit", &limit.min(25).to_string());
                query.append_pair("timeout_ms", &requested.as_millis().max(1).to_string());
            }
            let started = Instant::now();
            let mut received_headers = false;
            let mut response_status = 0;
            let mut correction = None;
            let mut failed_destination = false;
            self.observations.send_modify(|state| {
                state.poll_state = "polling";
                state.effective_wait = requested.as_secs_f64();
                state.deadline = (duration + self.guard).as_secs_f64();
                state.last_attempt = now();
                state.next_retry = 0.0;
                state.cycles += 1;
            });
            let result = timeout(duration + self.guard, async {
                let mut headers = self.headers();
                if let Some(token) = &route.token {
                    headers.insert("x-tunnel-shard-token", token.clone());
                }
                let response = client
                    .send(Method::GET, &url, headers, Bytes::new())
                    .await?;
                received_headers = true;
                let received = Instant::now();
                let status = response.status.as_u16();
                response_status = status;
                let headers = response.headers.clone();
                let mut status_error = StatusError::new(status, "poll");
                let mut commands = if status == 204 {
                    Vec::new()
                } else if status == 200 {
                    let poll = serde_json::from_slice::<Option<Poll>>(&response.bytes().await?)?
                        .unwrap_or_default();
                    poll.commands()
                } else {
                    failed_destination = matches!(status, 408 | 500..=599);
                    match response.limited(64 * 1024).await {
                        Ok(body) if body.len() <= 64 * 1024 => {
                            status_error.info = crate::net::ErrorInfo::parse(&body);
                            let parsed = if status == 409 {
                                routing::Correction::parse(&headers, &body)
                            } else {
                                Ok(None)
                            };
                            let malformed = parsed.is_err();
                            correction = parsed.ok().flatten();
                            if malformed
                                || status_error.code() == "wrong_cluster"
                                || headers.contains_key("x-tunnel-shard-token")
                            {
                                status_error.info = crate::net::ErrorInfo::default();
                                if correction.is_some() {
                                    status_error.info.code = "wrong_cluster".into();
                                    status_error.info.message =
                                        "polling placement rejected; retrying after backoff".into();
                                } else {
                                    status_error.info.message =
                                        "invalid polling routing correction".into();
                                }
                            }
                        }
                        Err(error) => {
                            failed_destination |= matches!(
                                observation::category(&error),
                                "network_error" | "timeout"
                            );
                            status_error.info.message = "invalid polling error response".into();
                        }
                        _ => status_error.info.message = "invalid polling error response".into(),
                    }
                    return Ok::<_, anyhow::Error>(Err((status_error, headers)));
                };
                for command in &mut commands {
                    command.polled_at = Some(received);
                    if let Some(created) = command.created_at.filter(|created| created.year() > 1) {
                        let age = now()
                            - received.elapsed().as_secs_f64()
                            - created.unix_timestamp_nanos() as f64 / 1e9;
                        if age >= 0.0 {
                            self.metrics
                                .observe("controlplane", "commands_age_seconds", &[], age);
                        }
                    }
                }
                Ok(Ok(Batch { received, commands }))
            })
            .await;
            if self.uses_proxy
                && !received_headers
                && let Ok(Err(error)) = &result
                && !crate::net::connecting(error)
                && error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof)
                        || cause
                            .downcast_ref::<hyper::Error>()
                            .is_some_and(hyper::Error::is_incomplete_message)
                })
            {
                let elapsed = started.elapsed();
                let minimum = Duration::from_secs(5);
                if requested > minimum && elapsed > minimum && elapsed < duration + self.guard {
                    let margin = self.guard.max(minimum).min(elapsed / 2);
                    let adjusted = (elapsed - margin).max(minimum).as_millis() as u64;
                    if Duration::from_millis(adjusted) < requested {
                        self.learned_poll_ms
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                                (current == 0 || adjusted < current).then_some(adjusted)
                            })
                            .ok();
                    }
                }
            }
            let connected = matches!(&result, Ok(Ok(Ok(_))));
            self.metrics.observe(
                "controlplane",
                "commands_poll_latency_seconds",
                &[("error", if connected { "false" } else { "true" })],
                started.elapsed().as_secs_f64(),
            );
            failed_destination |= match &result {
                Ok(Err(error)) => {
                    !received_headers
                        || matches!(observation::category(error), "network_error" | "timeout")
                }
                Err(_) => true,
                _ => false,
            };
            self.routing
                .lock()
                .expect("routing mutex poisoned")
                .complete(&route, correction, connected, failed_destination);
            self.observations.send_modify(|state| {
                state.connected = connected;
                match &result {
                    Ok(Ok(Ok(batch))) => {
                        state.poll_state = "idle";
                        state.failure_category = "";
                        state.last_success = now();
                        state.consecutive_failures = 0;
                        state.commands += batch.commands.len() as u64;
                        state.http_status = response_status;
                    }
                    _ => {
                        state.poll_state = "backoff";
                        state.failure_category = match &result {
                            Ok(Ok(Err(_))) => "http_error",
                            Ok(Err(error)) => observation::category(error),
                            _ => "timeout",
                        };
                        state.last_error = now();
                        state.consecutive_failures += 1;
                        state.errors += 1;
                        let kind = if state.failure_category == "timeout" {
                            "timeout"
                        } else {
                            "other"
                        };
                        *state.error_kinds.entry(kind).or_default() += 1;
                        state.http_status = match &result {
                            Ok(Ok(Err((error, _)))) => error.status,
                            _ => 0,
                        };
                    }
                }
            });
            let retry_headers = match result {
                Ok(Ok(Ok(batch))) => return Ok(batch),
                Ok(Ok(Err((error, headers)))) => {
                    tracing::warn!(%error, "tunnel poll failed");
                    headers
                }
                Ok(Err(error)) => {
                    tracing::warn!(
                        category = observation::category(&error),
                        "tunnel poll interrupted"
                    );
                    HeaderMap::new()
                }
                Err(_) => HeaderMap::new(),
            };
            let delay = retry_delay(attempt, &retry_headers);
            self.observations
                .send_modify(|state| state.next_retry = now() + delay.as_secs_f64());
            tokio::time::sleep(delay).await;
            attempt = attempt.saturating_add(1);
        }
    }

    async fn post(&self, command: &Correlation, reply: &Reply) -> Result<()> {
        let receipt = observation::Receipt::new(&self.observations);
        let result: Result<u16> = async {
            #[derive(Serialize)]
            struct Payload<'a> {
                request_id: &'a str,
                channel: &'a str,
                #[serde(flatten)]
                reply: &'a Reply,
            }
            let mut reply = reply.clone();
            if reply.kind != "oauth_discovery_response" {
                reply.headers = protocol::sanitize_headers(&reply.headers);
            }
            let body = Bytes::from(serde_json::to_vec(&Payload {
                request_id: &command.request_id,
                channel: &command.channel,
                reply: &reply,
            })?);
            let mut headers = self.headers();
            let mut shard = HeaderValue::try_from(&command.shard_token)?;
            shard.set_sensitive(true);
            headers.insert("x-tunnel-shard-token", shard);
            headers.entry("content-type").or_insert(HeaderValue::from_static("application/json"));
            if let Some(id) = &command.client_request_id {
                headers.entry("x-client-request-id").or_insert(HeaderValue::try_from(id)?);
            }
            let url = self.endpoint("response")?;
            for attempt in 0..3 {
                receipt.attempt(attempt != 0);
                let response = timeout(self.poll_timeout + self.guard, async {
                    let response = self
                        .client()
                        .send(Method::POST, &url, headers.clone(), body.clone())
                        .await?;
                    let status = response.status.as_u16();
                    let headers = response.headers.clone();
                    if let Some(id) = headers.get("x-request-id") {
                        tracing::debug!(tunnel_service_request_id = ?id, "control-plane response received");
                    }
                    let error = if matches!(status, 200 | 404) {
                        None
                    } else {
                        Some(StatusError::read(response, "response").await)
                    };
                    Ok::<_, anyhow::Error>((status, headers, error))
                })
                .await;
                match &response {
                    Ok(Ok((status, _, _))) if !matches!(*status, 200 | 404) => receipt.failure("http_error", *status),
                    Ok(Err(error)) => receipt.failure(observation::category(error), 0),
                    Err(_) => receipt.failure("timeout", 0),
                    _ => {}
                }
                let retry_headers = match response {
                    Ok(Ok((status, headers, error))) => {
                        let Some(error) = error else { return Ok(status); };
                        if attempt < 2
                            && (status == 429 || (reply.terminal() && matches!(status, 408 | 502 | 503 | 504)))
                        {
                            headers
                        } else {
                            return Err(error.into());
                        }
                    }
                    Ok(Err(error))
                        if attempt < 2 && (reply.terminal() || crate::net::connecting(&error)) =>
                    {
                        tracing::debug!(%error, "retrying tunnel response delivery");
                        HeaderMap::new()
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(_) if attempt < 2 && reply.terminal() => HeaderMap::new(),
                    Err(error) => return Err(error).context("tunnel response delivery timed out"),
                };
                tokio::time::sleep(retry_delay(attempt, &retry_headers)).await;
            }
            unreachable!()
        }
        .await;
        receipt.finish(&result);
        result.map(|_| ())
    }
}

fn retry_delay(attempt: u32, headers: &HeaderMap) -> Duration {
    let local = Duration::from_secs_f64(
        (0.2 + rand::random::<f64>() * (0.2 * 2_f64.powi(attempt.min(63) as i32) - 0.2)).min(10.0),
    );
    let server = headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let value = value.trim();
            if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
                Some(Duration::from_secs(
                    value.parse::<u64>().unwrap_or(60).min(60),
                ))
            } else {
                httpdate::parse_http_date(value)
                    .ok()?
                    .duration_since(SystemTime::now())
                    .ok()
            }
        })
        .unwrap_or_default()
        .min(Duration::from_secs(60));
    local.max(server)
}

struct Correlation {
    request_id: String,
    shard_token: String,
    channel: String,
    client_request_id: Option<String>,
    created_at: Option<time::OffsetDateTime>,
    polled_at: Instant,
    request_kind: String,
    request_method: Option<String>,
}

pub struct Delivery {
    control: Arc<Control>,
    command: Correlation,
    notifications_failed: AtomicBool,
    terminal_started: AtomicBool,
    delivered_status: AtomicU16,
}
impl Delivery {
    pub fn new(control: Arc<Control>, command: &Command) -> Self {
        Self {
            control,
            command: Correlation {
                request_id: command.request_id.clone(),
                shard_token: command.shard_token.clone(),
                channel: command.channel.clone(),
                created_at: command.created_at,
                polled_at: command.polled_at.unwrap_or_else(Instant::now),
                request_kind: match command.command_type.as_str() {
                    "jsonrpc" => {
                        if command.jsonrpc.as_ref().is_some_and(|message| {
                            protocol::view(message).is_ok_and(|message| message.id.is_some())
                        }) {
                            "call"
                        } else {
                            "notification"
                        }
                    }
                    kind => kind,
                }
                .into(),
                request_method: command.jsonrpc.as_ref().and_then(|message| {
                    protocol::view(message)
                        .ok()?
                        .method
                        .map(|method| method.into_owned())
                }),
                client_request_id: command
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("x-request-id"))
                    .and_then(|(_, values)| values.first())
                    .filter(|value| !value.is_empty())
                    .cloned(),
            },
            notifications_failed: AtomicBool::new(false),
            terminal_started: AtomicBool::new(false),
            delivered_status: AtomicU16::new(0),
        }
    }
    pub(crate) fn record_latency(&self) {
        let status = self.delivered_status.load(Ordering::Acquire);
        if status == 0 {
            return;
        }
        let status = status.to_string();
        let tunnel = self.control.tunnel_id();
        let mut attributes = vec![
            ("channel", self.command.channel.as_str()),
            ("tunnel_id", tunnel),
            ("tunnel_service_status", status.as_str()),
            ("request_kind", self.command.request_kind.as_str()),
        ];
        if let Some(method) = self
            .command
            .request_method
            .as_deref()
            .filter(|method| !method.is_empty())
        {
            attributes.push(("request_method", method));
        }
        if let Some(created) = self.command.created_at.filter(|created| created.year() > 1) {
            let elapsed = now() - created.unix_timestamp_nanos() as f64 / 1e9;
            if elapsed >= 0.0 {
                attributes.push(("latency_type", "enqueue_to_response"));
                self.control.metrics.observe(
                    "dispatcher",
                    "command_end_to_end_latency_milliseconds",
                    &attributes,
                    (elapsed * 1000.0).floor(),
                );
                attributes.pop();
            }
        }
        attributes.push(("latency_type", "poll_to_response"));
        self.control.metrics.observe(
            "dispatcher",
            "command_end_to_end_latency_milliseconds",
            &attributes,
            self.command.polled_at.elapsed().as_millis() as f64,
        );
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
            self.control.post(&self.command, &reply).await?;
            self.delivered_status.store(reply.status, Ordering::Release);
            return Ok(());
        }
        if !self.notifications_failed.load(Ordering::Acquire)
            && let Err(error) = self.control.post(&self.command, &reply).await
        {
            self.notifications_failed.store(true, Ordering::Release);
            tracing::warn!(request_id = %self.command.request_id, %error, "notification delivery interrupted");
        }
        Ok(())
    }
}

use std::{collections::BTreeMap, io, sync::Arc, time::Duration};

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::{ClientConfig, pki_types::ServerName};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::watch,
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{config, control, net::Io, proxy::Proxy};

#[derive(Clone, Default, Serialize)]
pub struct Snapshot {
    #[serde(skip)]
    metrics: Arc<crate::metrics::Metrics>,
    pub routes: Vec<Route>,
    pub observed_at: f64,
}

#[derive(Clone, Serialize)]
pub struct Route {
    pub kind: &'static str,
    pub summary: Value,
    pub history: Vec<Check>,
    pub state: &'static str,
    pub failure: &'static str,
    pub last_check: f64,
    pub last_success: f64,
}

#[derive(Clone, Default, Serialize)]
pub struct Check {
    pub timestamp: f64,
    pub success: bool,
    #[serde(skip_serializing_if = "zero")]
    pub tcp_duration_ms: u64,
    #[serde(skip_serializing_if = "zero")]
    pub connect_duration_ms: u64,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub error_phase: &'static str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub error_reason: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub http_status_category: String,
    #[serde(skip)]
    tls_failure: bool,
}

fn zero(value: &u64) -> bool {
    *value == 0
}

impl Snapshot {
    pub fn metrics(&self) -> String {
        use std::fmt::Write;
        let mut output = self.metrics.render();
        let proxies: BTreeMap<_, _> = self
            .routes
            .iter()
            .filter_map(|route| {
                let id = route.summary["proxy_id"].as_str()?;
                Some((id, route))
            })
            .collect();
        for name in [
            "proxy_health_state",
            "proxy_last_check_timestamp",
            "proxy_last_success_timestamp",
        ] {
            if !proxies.is_empty() {
                writeln!(output, "# TYPE {name} gauge").expect("metric output");
            }
            for (id, route) in &proxies {
                let value = match name {
                    "proxy_health_state" => u64::from(route.state == "healthy"),
                    "proxy_last_check_timestamp" => route.last_check as u64,
                    _ => route.last_success as u64,
                };
                if name == "proxy_health_state" || value != 0 {
                    writeln!(output, r#"{name}{{otel_scope_name="proxyhealth",otel_scope_schema_url="",otel_scope_version="",proxy_id="{id}"}} {value}"#).expect("metric output");
                }
            }
        }
        output
    }

    pub fn summaries(&self) -> Vec<Value> {
        self.routes.iter().map(|route| {
            let mut value = json!({"route":route.summary,"health_state":if route.state == "pending" {"unhealthy"} else {route.state}});
            if route.last_check > 0.0 { value["last_check"] = json!(route.last_check); }
            if route.last_success > 0.0 { value["last_success"] = json!(route.last_success); }
            if !route.history.is_empty() { value["history"] = json!(route.history); }
            value
        }).collect()
    }

    pub fn identities(&self) -> Vec<Value> {
        let mut identities = BTreeMap::new();
        for route in &self.routes {
            if let Some(id) = route.summary["proxy_id"].as_str() {
                identities.entry(id).or_insert_with(|| json!({"proxy_id":id,"proxy_url":route.summary["proxy_url"],"proxy_source":route.summary["proxy_source"]}));
            }
        }
        identities.into_values().collect()
    }
}

struct Target {
    kind: &'static str,
    name: String,
    proxy: Option<Url>,
    target: String,
    summary: Value,
}

pub struct Checker {
    targets: Vec<Target>,
    interval: Duration,
    tls: Arc<ClientConfig>,
    state: watch::Sender<Snapshot>,
}

impl Checker {
    pub fn new(config: &config::Config) -> Result<Self> {
        let mut targets = Vec::new();
        let source =
            |name: &'static str| config.proxy_sources.get(name).map_or(name, String::as_str);
        add(
            &mut targets,
            "control_plane",
            "control-plane",
            Some(Url::parse(config.control_plane.base_url())?),
            explicit([
                (
                    source("control-plane.http-proxy"),
                    config.control_plane.http_proxy.as_deref(),
                ),
                (source("http-proxy"), config.http_proxy.as_deref()),
            ]),
            false,
        )?;
        for server in &config.mcp.server_urls {
            add(
                &mut targets,
                "mcp_channel",
                &server.channel,
                Some(Url::parse(&server.url)?),
                explicit([
                    ("mcp.server-url", server.http_proxy.as_deref()),
                    (source("mcp.http-proxy"), config.mcp.http_proxy.as_deref()),
                    (source("http-proxy"), config.http_proxy.as_deref()),
                ]),
                server.unix_socket.is_some(),
            )?;
        }
        for command in &config.mcp.commands {
            add(
                &mut targets,
                "mcp_channel",
                &command.channel,
                None,
                None,
                true,
            )?;
        }
        for target in &config.harpoon.targets {
            let url = if !target.url.is_empty() {
                Some(Url::parse(&target.url)?)
            } else {
                target
                    .template
                    .as_ref()
                    .map(|template| Url::parse(&template.origin))
                    .transpose()?
            };
            add(
                &mut targets,
                "harpoon_target",
                &target.label,
                url,
                explicit([
                    (
                        source("harpoon.http-proxy"),
                        config.harpoon.http_proxy.as_deref(),
                    ),
                    (source("http-proxy"), config.http_proxy.as_deref()),
                ]),
                target.unix_socket.is_some(),
            )?;
        }
        targets.sort_by(|left, right| {
            (left.kind, left.name.as_str()).cmp(&(right.kind, right.name.as_str()))
        });
        let routes = targets
            .iter()
            .map(|target| Route {
                kind: target.kind,
                summary: target.summary.clone(),
                history: Vec::new(),
                state: if target.proxy.is_some() {
                    "pending"
                } else {
                    "direct"
                },
                failure: "",
                last_check: 0.0,
                last_success: 0.0,
            })
            .collect();
        let (state, _) = watch::channel(Snapshot {
            metrics: Arc::new(crate::metrics::Metrics::default()),
            routes,
            observed_at: 0.0,
        });
        Ok(Self {
            targets,
            interval: config.proxy.check_interval.0,
            tls: Arc::new(
                crate::net::tls::builder(config.ca_bundle.as_deref())?.with_no_client_auth(),
            ),
            state,
        })
    }

    pub fn status(&self) -> watch::Receiver<Snapshot> {
        self.state.subscribe()
    }

    pub async fn run(&self, stop: CancellationToken) {
        loop {
            self.check().await;
            tokio::select! {
                () = tokio::time::sleep(self.interval) => {}
                () = stop.cancelled() => return,
            }
        }
    }

    async fn check(&self) {
        for (index, target) in self.targets.iter().enumerate() {
            let Some(proxy) = &target.proxy else {
                continue;
            };
            let record = probe(proxy, &target.target, self.tls.clone()).await;
            self.state.send_modify(|state| {
                let route = &mut state.routes[index];
                route.last_check = record.timestamp;
                route.state = if record.success {
                    "healthy"
                } else {
                    "unhealthy"
                };
                route.failure = match (record.success, record.error_phase, record.tls_failure) {
                    (true, _, _) => "",
                    (_, "tcp", _) => "tcp_failed",
                    (_, _, true) => "tls_failed",
                    _ => "connect_failed",
                };
                if record.success {
                    route.last_success = record.timestamp;
                }
                let id = route.summary["proxy_id"]
                    .as_str()
                    .expect("proxy identifier");
                for (phase, duration) in [
                    ("tcp", record.tcp_duration_ms),
                    ("connect", record.connect_duration_ms),
                ] {
                    if duration > 0 {
                        state.metrics.observe(
                            "proxyhealth",
                            "proxy_check_phase_duration_seconds",
                            &[("proxy_id", id), ("phase", phase)],
                            duration as f64 / 1000.0,
                        );
                    }
                }
                if !record.success {
                    state.metrics.increment(
                        "proxyhealth",
                        "proxy_check_failures_total",
                        &[
                            ("proxy_id", id),
                            ("phase", record.error_phase),
                            ("reason", record.error_reason),
                        ],
                    );
                }
                state.observed_at = record.timestamp;
                route.history.push(record);
                if route.history.len() > 10 {
                    route.history.remove(0);
                }
            });
        }
    }
}

fn explicit<'a>(
    values: impl IntoIterator<Item = (&'a str, Option<&'a str>)>,
) -> Option<(&'a str, &'a str)> {
    values
        .into_iter()
        .find_map(|(name, value)| value.map(|value| (name, value)))
}

fn add(
    targets: &mut Vec<Target>,
    kind: &'static str,
    name: &str,
    target: Option<Url>,
    explicit: Option<(&str, &str)>,
    local: bool,
) -> Result<()> {
    let proxy = if local {
        None
    } else if let Some(target) = &target {
        Proxy::new(explicit.map(|(_, value)| value))?
            .select(target)?
            .cloned()
    } else {
        None
    };
    let scheme = target.as_ref().map(Url::scheme).unwrap_or_default();
    let target = target.as_ref().map(host_port).unwrap_or_default();
    let mut summary = json!({"kind":kind,"name":name,"route_mode":"direct","proxy_source":"none"});
    if !target.is_empty() {
        summary["target"] = json!(target);
    }
    if let Some(proxy) = &proxy {
        let source = match explicit {
            Some((name, value)) => value
                .strip_prefix("env:")
                .map_or_else(|| name.to_owned(), |name| format!("env:{}", name.trim())),
            None => {
                let names = if scheme == "https" {
                    ["HTTPS_PROXY", "https_proxy"]
                } else {
                    ["HTTP_PROXY", "http_proxy"]
                };
                names
                    .into_iter()
                    .find(|name| std::env::var(name).is_ok_and(|value| !value.trim().is_empty()))
                    .map_or_else(|| "environment".into(), |name| format!("env:{name}"))
            }
        };
        let redacted = format!(
            "{}://{}",
            proxy.scheme(),
            &proxy[url::Position::BeforeHost..url::Position::AfterPort]
        );
        let id = crate::template::hex(&Sha256::digest(redacted.as_bytes()));
        summary["route_mode"] = json!("proxy");
        summary["proxy_source"] = json!(source);
        summary["proxy_url"] = json!(redacted);
        summary["proxy_id"] = json!(id);
    }
    targets.push(Target {
        kind,
        name: name.into(),
        proxy,
        target,
        summary,
    });
    Ok(())
}

fn host_port(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.into()
    };
    match url.port_or_known_default() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

async fn probe(proxy: &Url, target: &str, tls: Arc<ClientConfig>) -> Check {
    let mut record = Check {
        timestamp: control::now(),
        ..Default::default()
    };
    let started = Instant::now();
    let result = timeout(
        Duration::from_secs(5),
        TcpStream::connect((
            proxy.host_str().unwrap_or_default(),
            proxy.port_or_known_default().unwrap_or_default(),
        )),
    )
    .await;
    record.tcp_duration_ms = started.elapsed().as_millis() as u64;
    let stream = match result {
        Ok(Ok(stream)) => stream,
        error => {
            record.error_phase = "tcp";
            record.error_reason = if error.is_err()
                || matches!(error, Ok(Err(ref error)) if error.kind() == io::ErrorKind::TimedOut)
            {
                "timeout"
            } else {
                "dial_error"
            };
            return record;
        }
    };
    let started = Instant::now();
    let mut handshake = proxy.scheme() == "https";
    let result = timeout(Duration::from_secs(5), async {
        let mut stream: Box<dyn Io> = Box::new(stream);
        if handshake {
            let name = ServerName::try_from(proxy.host_str().unwrap_or_default().to_owned())
                .map_err(io::Error::other)?;
            stream = Box::new(
                tokio_rustls::TlsConnector::from(tls)
                    .connect(name, stream)
                    .await?,
            );
            handshake = false;
        }
        let authorization = if proxy.username().is_empty() {
            String::new()
        } else {
            let user = percent_encoding::percent_decode_str(proxy.username()).decode_utf8_lossy();
            let password =
                percent_encoding::percent_decode_str(proxy.password().unwrap_or_default())
                    .decode_utf8_lossy();
            format!(
                "Proxy-Authorization: Basic {}\r\n",
                STANDARD.encode(format!("{user}:{password}"))
            )
        };
        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{authorization}\r\n");
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status).await?;
        let code = status
            .trim()
            .split(' ')
            .nth(1)
            .ok_or_else(|| io::Error::other("invalid proxy response"))?;
        record.http_status_category = code
            .chars()
            .next()
            .map_or_else(String::new, |first| format!("{first}xx"));
        if !code.starts_with('2') {
            return Err(io::Error::other("proxy connect failed"));
        }
        Ok::<_, io::Error>(())
    })
    .await;
    record.connect_duration_ms = started.elapsed().as_millis() as u64;
    record.success = matches!(result, Ok(Ok(())));
    if !record.success {
        record.error_phase = "connect";
        record.tls_failure = handshake;
        record.error_reason = if !record.http_status_category.is_empty() {
            "bad_status"
        } else if result.is_err()
            || matches!(result, Ok(Err(ref error)) if error.kind() == io::ErrorKind::TimedOut)
        {
            "timeout"
        } else {
            "connect_error"
        };
    }
    record
}

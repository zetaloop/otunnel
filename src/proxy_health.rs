use std::{io, sync::Arc, time::Duration};

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::{ClientConfig, pki_types::ServerName};
use serde::Serialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::watch,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{config, control, net::Io, proxy::Proxy};

#[derive(Clone, Default, Serialize)]
pub struct Snapshot {
    pub routes: Vec<Route>,
    pub observed_at: f64,
}

#[derive(Clone, Serialize)]
pub struct Route {
    pub kind: &'static str,
    pub state: &'static str,
    pub failure: &'static str,
    pub last_check: f64,
    pub last_success: f64,
}

struct Target {
    kind: &'static str,
    name: String,
    proxy: Option<Url>,
    target: String,
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
        add(
            &mut targets,
            "control_plane",
            "control-plane",
            Some(Url::parse(config.control_plane.base_url())?),
            config
                .control_plane
                .http_proxy
                .as_deref()
                .or(config.http_proxy.as_deref()),
            false,
        )?;
        for server in &config.mcp.server_urls {
            add(
                &mut targets,
                "mcp_channel",
                &server.channel,
                Some(Url::parse(&server.url)?),
                server
                    .http_proxy
                    .as_deref()
                    .or(config.mcp.http_proxy.as_deref())
                    .or(config.http_proxy.as_deref()),
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
                config
                    .harpoon
                    .http_proxy
                    .as_deref()
                    .or(config.http_proxy.as_deref()),
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
            let result = probe(proxy, &target.target, self.tls.clone()).await;
            let now = control::now();
            self.state.send_modify(|state| {
                let route = &mut state.routes[index];
                route.last_check = now;
                match result {
                    Ok(()) => {
                        route.state = "healthy";
                        route.failure = "";
                        route.last_success = now;
                    }
                    Err(failure) => {
                        route.state = "unhealthy";
                        route.failure = failure;
                    }
                }
                state.observed_at = now;
            });
        }
    }
}

fn add(
    targets: &mut Vec<Target>,
    kind: &'static str,
    name: &str,
    target: Option<Url>,
    explicit: Option<&str>,
    local: bool,
) -> Result<()> {
    let proxy = if local {
        None
    } else if let Some(target) = &target {
        Proxy::new(explicit)?.select(target)?.cloned()
    } else {
        None
    };
    let target = target.as_ref().map(host_port).unwrap_or_default();
    targets.push(Target {
        kind,
        name: name.into(),
        proxy,
        target,
    });
    Ok(())
}

fn host_port(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
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

async fn probe(
    proxy: &Url,
    target: &str,
    tls: Arc<ClientConfig>,
) -> std::result::Result<(), &'static str> {
    let host = proxy.host_str().ok_or("tcp_failed")?;
    let port = proxy.port_or_known_default().ok_or("tcp_failed")?;
    let stream = timeout(Duration::from_secs(5), TcpStream::connect((host, port)))
        .await
        .map_err(|_| "tcp_failed")?
        .map_err(|_| "tcp_failed")?;
    let mut stream: Box<dyn Io> = Box::new(stream);
    if proxy.scheme() == "https" {
        let name = ServerName::try_from(host.to_owned()).map_err(|_| "tls_failed")?;
        stream = Box::new(
            timeout(
                Duration::from_secs(5),
                tokio_rustls::TlsConnector::from(tls).connect(name, stream),
            )
            .await
            .map_err(|_| "tls_failed")?
            .map_err(|_| "tls_failed")?,
        );
    } else if proxy.scheme() != "http" {
        return Err("connect_failed");
    }
    let authorization = if proxy.username().is_empty() {
        String::new()
    } else {
        let username = percent_encoding::percent_decode_str(proxy.username()).decode_utf8_lossy();
        let password = percent_encoding::percent_decode_str(proxy.password().unwrap_or_default())
            .decode_utf8_lossy();
        format!(
            "Proxy-Authorization: Basic {}\r\n",
            STANDARD.encode(format!("{username}:{password}"))
        )
    };
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{authorization}\r\n");
    timeout(Duration::from_secs(5), async {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status).await?;
        Ok::<_, io::Error>(status)
    })
    .await
    .map_err(|_| "connect_failed")?
    .map_err(|_| "connect_failed")?
    .split_whitespace()
    .nth(1)
    .filter(|status| status.starts_with('2'))
    .map(|_| ())
    .ok_or("connect_failed")
}

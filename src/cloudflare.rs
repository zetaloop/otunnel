use std::{process::Stdio, time::Duration};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{ChildStderr, Command},
    sync::watch,
    time::{Instant, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    config::{Cloudflared, resolve},
    control::Control,
    net::{Http, Options},
    process::Process,
    runtime::Snapshot,
};

pub(crate) struct Companion {
    process: Process,
    output: ChildStderr,
    token: String,
    deadline: Instant,
}
impl Companion {
    pub async fn new(config: &Cloudflared, control: &Control) -> Result<Self> {
        anyhow::ensure!(
            !config.managed || config.token.is_none(),
            "cloudflared selects either a managed token or an explicit token"
        );
        let token = if config.managed {
            control
                .cloudflare()
                .await?
                .get("runtime_token")
                .and_then(Value::as_str)
                .context("Cloudflare runtime response has no token")?
                .to_owned()
        } else {
            resolve(
                config
                    .token
                    .as_deref()
                    .context("Cloudflare token is missing")?,
            )?
        };
        anyhow::ensure!(!token.is_empty(), "Cloudflare token is empty");
        let mut command = Command::new(&config.path);
        command
            .args([
                "tunnel",
                "--no-autoupdate",
                "--metrics",
                "127.0.0.1:0",
                "--output",
                "json",
                "run",
            ])
            .env("TUNNEL_TOKEN", &token)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::piped());
        let mut process = Process::launch(command)?;
        let output = process.stderr()?;
        Ok(Self {
            process,
            output,
            token,
            deadline: Instant::now() + config.ready_timeout.0,
        })
    }

    pub async fn supervise(
        self,
        stop: CancellationToken,
        state: watch::Sender<Snapshot>,
    ) -> Result<()> {
        let child_stop = stop.child_token();
        let process = self.process.supervise(child_stop.clone());
        tokio::pin!(process);
        let result = tokio::select! {
            result = &mut process => result.context("cloudflared exited"),
            result = monitor(self.output, &self.token, self.deadline, &stop, &state) => {
                child_stop.cancel();
                let closed = process.await;
                result.and(closed)
            }
        };
        state.send_modify(|state| {
            state.cloudflare_ready = Some(false);
            state.ready = false;
        });
        result
    }
}

async fn monitor(
    output: ChildStderr,
    token: &str,
    deadline: Instant,
    stop: &CancellationToken,
    state: &watch::Sender<Snapshot>,
) -> Result<()> {
    let mut output = BufReader::new(output).lines();
    let mut metrics: Option<(Http, Url)> = None;
    let mut ever_ready = false;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = stop.cancelled() => return Ok(()),
            () = tokio::time::sleep_until(deadline), if !ever_ready => bail!("cloudflared did not become ready before its startup deadline"),
            line = output.next_line() => {
                let line = line?.context("cloudflared closed its log stream")?;
                let line = line.replace(token, "[redacted]");
                let event = serde_json::from_str::<Value>(&line).ok();
                let message = event.as_ref().and_then(|event| event.get("message")).and_then(Value::as_str).unwrap_or(&line);
                if let Some(address) = message.strip_prefix("Starting metrics server on ").and_then(|value| value.strip_suffix("/metrics")) {
                    let url = Url::parse(&format!("http://{address}/ready"))?;
                    let client = Http::new(url.clone(), Options::default())?;
                    metrics = Some((client, url));
                    interval.reset_immediately();
                }
                match event.as_ref().and_then(|event| event.get("level")).and_then(Value::as_str) {
                    Some("error" | "fatal" | "panic") => tracing::error!(component = "cloudflared", %message),
                    Some("warn") => tracing::warn!(component = "cloudflared", %message),
                    Some("debug" | "trace") => tracing::debug!(component = "cloudflared", %message),
                    _ => tracing::info!(component = "cloudflared", %message),
                }
            }
            _ = interval.tick(), if metrics.is_some() => {
                let (client, url) = metrics.as_ref().expect("metrics endpoint discovered");
                let probe = tokio::time::timeout(Duration::from_secs(3), async {
                    let response = client.send(http::Method::GET, url, Default::default(), Bytes::new()).await?;
                    let ready = response.status.is_success();
                    response.bytes().await?;
                    Ok::<_, anyhow::Error>(ready)
                });
                let result = tokio::select! {
                    () = stop.cancelled() => return Ok(()),
                    result = probe => result.context("cloudflared health request timed out").and_then(|result| result),
                };
                let ready = match result {
                    Ok(ready) => ready,
                    Err(error) => { tracing::debug!(%error, "cloudflared health request failed"); false }
                };
                ever_ready |= ready;
                state.send_if_modified(|state| {
                    if state.cloudflare_ready == Some(ready) { return false; }
                    state.cloudflare_ready = Some(ready);
                    state.ready = state.connected && ready;
                    true
                });
            }
        }
    }
}

use std::{process::Stdio, time::Duration};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{ChildStderr, ChildStdout, Command},
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
    output: (ChildStdout, ChildStderr),
    token: String,
    deadline: Instant,
}
impl Companion {
    pub async fn new(config: &Cloudflared, control: &Control) -> Result<Self> {
        let token = if let Some(token) = &config.token {
            resolve(token)?
        } else if config.managed {
            control
                .cloudflare()
                .await?
                .get("runtime_token")
                .and_then(Value::as_str)
                .context("Cloudflare runtime response has no token")?
                .to_owned()
        } else {
            bail!("Cloudflare token is missing");
        };
        anyhow::ensure!(!token.is_empty(), "Cloudflare token is empty");
        let mut command = Command::new(&config.path);
        for (name, value) in std::env::vars_os() {
            let key = name.to_string_lossy();
            if key.eq_ignore_ascii_case("TUNNEL_TOKEN")
                || key.eq_ignore_ascii_case("TUNNEL_MANAGEMENT_DIAGNOSTICS")
                || value == std::ffi::OsStr::new(&token)
            {
                command.env_remove(name);
            }
        }
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
            .env("TUNNEL_MANAGEMENT_DIAGNOSTICS", "false")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut process = Process::launch(command)?;
        let output = process.output()?;
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
            state.cloudflare_observed_at = crate::control::now();
            state.ready = false;
        });
        result
    }
}

async fn monitor(
    output: (ChildStdout, ChildStderr),
    token: &str,
    deadline: Instant,
    stop: &CancellationToken,
    state: &watch::Sender<Snapshot>,
) -> Result<()> {
    let mut stdout = BufReader::new(output.0).lines();
    let mut stderr = BufReader::new(output.1).lines();
    let (mut stdout_open, mut stderr_open) = (true, true);
    let mut metrics: Option<(Http, Url)> = None;
    let mut ever_ready = false;
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = stop.cancelled() => return Ok(()),
            () = tokio::time::sleep_until(deadline), if !ever_ready => bail!("cloudflared did not become ready before its startup deadline"),
            line = async {
                tokio::select! {
                    line = stdout.next_line(), if stdout_open => ("stdout", line),
                    line = stderr.next_line(), if stderr_open => ("stderr", line),
                }
            }, if stdout_open || stderr_open => {
                let (stream, line) = line;
                let line = match line {
                    Ok(Some(line)) => line,
                    result => {
                        if stream == "stdout" { stdout_open = false; } else { stderr_open = false; }
                        if let Err(error) = result { tracing::warn!(component = "cloudflared", stream, %error, "read cloudflared output"); }
                        continue;
                    }
                };
                let line = line.replace(token, "[REDACTED]");
                let event = serde_json::from_str::<Value>(&line).ok();
                let message = event.as_ref().and_then(|event| event.get("message")).and_then(Value::as_str).unwrap_or(&line);
                if let Some(address) = message.strip_prefix("Starting metrics server on ").and_then(|value| value.strip_suffix("/metrics")) {
                    let url = Url::parse(&format!("http://{address}/ready"))?;
                    let client = Http::new(url.clone(), Options::default())?;
                    metrics = Some((client, url));
                    interval.reset_immediately();
                }
                match event.as_ref().and_then(|event| event.get("level")).and_then(Value::as_str) {
                    Some("error" | "fatal" | "panic") => tracing::error!(component = "cloudflared", stream, %message),
                    Some("warn") => tracing::warn!(component = "cloudflared", stream, %message),
                    Some("debug" | "trace") => tracing::debug!(component = "cloudflared", stream, %message),
                    _ => tracing::info!(component = "cloudflared", stream, %message),
                }
            }
            _ = interval.tick(), if metrics.is_some() => {
                let (client, url) = metrics.as_ref().expect("metrics endpoint discovered");
                let probe = tokio::time::timeout(Duration::from_millis(500), async {
                    let response = client.send(http::Method::GET, url, Default::default(), Bytes::new()).await?;
                    let ready = response.status == http::StatusCode::OK;
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
                if ready && !ever_ready {
                    ever_ready = true;
                    interval = tokio::time::interval(Duration::from_secs(1));
                    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
                }
                state.send_if_modified(|state| {
                    if state.cloudflare_ready == Some(ready) && state.cloudflare_observed_at > 0.0 { return false; }
                    state.cloudflare_ready = Some(ready);
                    state.cloudflare_observed_at = crate::control::now();
                    state.refresh_readiness();
                    true
                });
            }
        }
    }
}

use std::{fmt, time::Duration};

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::time::{Instant, timeout, timeout_at};

use super::{Snapshot, Tunnel};
use crate::{
    control,
    transport::{self, Probe, Transport},
};

#[derive(Clone, Serialize)]
pub struct Startup {
    pub state: &'static str,
    pub observed_at: Option<f64>,
    pub error: Option<String>,
}
impl Default for Startup {
    fn default() -> Self {
        Self {
            state: "disabled",
            observed_at: None,
            error: None,
        }
    }
}
impl Startup {
    pub(super) fn pending() -> Self {
        Self {
            state: "pending",
            ..Self::default()
        }
    }
    fn settled(state: &'static str, error: Option<String>) -> Self {
        Self {
            state,
            observed_at: Some(control::now()),
            error,
        }
    }
}

impl Snapshot {
    pub fn readiness(&self) -> (bool, String) {
        if self.lifecycle == "draining" {
            return (false, "runtime is draining".into());
        }
        if self.cloudflare_ready == Some(false) {
            return (false, "cloudflared not ready".into());
        }
        if self.oauth.state == "pending" {
            return (false, "oauth discovery pending".into());
        }
        if self.oauth.state == "failed" {
            return (
                false,
                format!(
                    "oauth discovery failed: {}",
                    self.oauth.error.as_deref().unwrap_or_default()
                ),
            );
        }
        if self.catalog.state == "pending" {
            return (false, "harpoon startup catalog pending".into());
        }
        if self.catalog.state == "failed" {
            return (
                false,
                format!(
                    "harpoon startup catalog failed: {}",
                    self.catalog.error.as_deref().unwrap_or_default()
                ),
            );
        }
        let message = self.mcp_probe.error.as_deref().unwrap_or_default();
        match self.mcp_probe.state {
            "pending" => (false, "mcp startup probe pending".into()),
            "auth-required" => (
                true,
                format!("ready (mcp initialize requires auth: {message})"),
            ),
            "timeout" => (
                true,
                format!("ready (mcp startup probe timed out: {message})"),
            ),
            "startup-timeout" => (false, format!("mcp startup wait failed: {message}")),
            "failed" => (false, format!("mcp probe failed: {message}")),
            _ => (true, "ready".into()),
        }
    }
    pub(crate) fn refresh_readiness(&mut self) {
        self.ready = self.readiness().0;
    }
    fn finish_catalog(&mut self, result: Result<()>) {
        self.catalog = match result {
            Ok(()) => Startup::settled("settled", None),
            Err(error) => Startup::settled("failed", Some(format!("{error:#}"))),
        };
        self.refresh_readiness();
    }
}

#[derive(Debug)]
struct StartupTimeout(Duration);
impl fmt::Display for StartupTimeout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "MCP startup wait exceeded {}",
            crate::config::Span(self.0)
        )
    }
}
impl std::error::Error for StartupTimeout {}

pub(super) async fn probe(transport: &dyn Transport, wait: Duration, tools: bool) -> Result<Probe> {
    let deadline = (!wait.is_zero()).then(|| Instant::now() + wait);
    let mut backoff = Duration::from_millis(50);
    loop {
        let attempt = Instant::now() + Duration::from_secs(2);
        let result = timeout_at(
            deadline.map_or(attempt, |end| end.min(attempt)),
            transport::probe(transport, tools),
        )
        .await;
        if deadline.is_some_and(|end| Instant::now() >= end) {
            return Err(StartupTimeout(wait).into());
        }
        let result = result.context("MCP startup probe timed out")?;
        let retry = result.as_ref().err().is_some_and(|error| {
            (!tools || deadline.is_some())
                && error
                    .downcast_ref::<control::StatusError>()
                    .is_some_and(|error| matches!(error.status, 429 | 500..=599))
                || deadline.is_some()
                    && error.chain().any(|cause| {
                        cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
                            matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionRefused
                                    | std::io::ErrorKind::NotFound
                            )
                        })
                    })
        });
        if !retry {
            return result;
        }
        let next = Instant::now() + backoff;
        tokio::time::sleep_until(deadline.map_or(next, |end| end.min(next))).await;
        backoff = (backoff * 2).min(Duration::from_secs(if deadline.is_some() { 1 } else { 30 }));
    }
}

impl Tunnel {
    pub(super) fn observe(&mut self) {
        let proxy = self.proxy.clone();
        let stop = self.stop.clone();
        self.observers.spawn(async move { proxy.run(stop).await });
        let mut proxy = self.proxy.status();
        let state = self.state.clone();
        let stop = self.stop.clone();
        self.observers.spawn(async move {
            loop {
                state.send_modify(|state| state.proxy = proxy.borrow_and_update().clone());
                tokio::select! {
                    result = proxy.changed() => if result.is_err() { return; },
                    () = stop.cancelled() => return,
                }
            }
        });
        let main = self
            .bindings
            .get("main")
            .filter(|transport| transport.startup_probe())
            .cloned();
        let wait = self.config.mcp.startup_wait_timeout.0;
        if let Some(main) = main.clone() {
            let state = self.state.clone();
            let stop = self.stop.clone();
            self.state.send_modify(|state| {
                state.mcp_probe = Startup::pending();
                state.refresh_readiness();
            });
            self.observers.spawn(async move {
                let result = tokio::select! {
                    result = probe(main.as_ref(), wait, false) => result,
                    () = stop.cancelled() => return,
                };
                state.send_modify(|state| {
                    state.mcp_probe = match result {
                        Ok(probe) => {
                            let status = if probe.authentication_required {
                                "auth-required"
                            } else {
                                "ok"
                            };
                            let error = probe
                                .authentication_required
                                .then(|| format!("MCP discovery returned HTTP {}", probe.status));
                            state.channels.insert("main".into(), probe);
                            Startup::settled(status, error)
                        }
                        Err(error) => {
                            tracing::warn!(%error, "MCP startup probe failed");
                            let status = if error.is::<StartupTimeout>() {
                                "startup-timeout"
                            } else if error.is::<tokio::time::error::Elapsed>() {
                                "timeout"
                            } else {
                                "failed"
                            };
                            Startup::settled(status, Some(format!("{error:#}")))
                        }
                    };
                    state.refresh_readiness();
                });
            });
        }
        if let Some(main) = main.filter(|_| self.config.mcp.oauth_discovery != "disabled") {
            let state = self.state.clone();
            let stop = self.stop.clone();
            let harpoon = self.harpoon.clone();
            let config = self.config.control_plane.clone();
            self.state.send_modify(|state| {
                state.oauth = Startup::pending();
            });
            self.observers.spawn(async move {
                if !wait.is_zero() {
                    let mut observation = state.subscribe();
                    tokio::select! {
                        _ = observation.wait_for(|state| state.mcp_probe.state != "pending") => {},
                        () = stop.cancelled() => return,
                    }
                }
                let mut backoff = Duration::from_secs(1);
                loop {
                    let discovery = tokio::select! {
                        result = timeout(Duration::from_secs(5), main.discover(Default::default(), true)) => result.context("OAuth discovery timed out").and_then(|result| result),
                        () = stop.cancelled() => return,
                    };
                    let retry = discovery.as_ref().err().is_some_and(|error| {
                        error.is::<tokio::time::error::Elapsed>() || error.downcast_ref::<crate::oauth::DiscoveryError>().is_some_and(|error| error.retry)
                    });
                    if retry {
                        tracing::warn!("OAuth discovery failed; retrying");
                        tokio::select! {
                            () = tokio::time::sleep(backoff.mul_f64(0.5 + rand::random::<f64>())) => {},
                            () = stop.cancelled() => return,
                        }
                        backoff = (backoff * 2).min(Duration::from_secs(30));
                        continue;
                    }
                    let (status, error) = match &discovery {
                        Ok(_) => ("complete", None),
                        Err(error) => {
                            let optional = error.downcast_ref::<crate::oauth::DiscoveryError>().is_some_and(|error| error.optional);
                            if optional {
                                tracing::info!("OAuth metadata not advertised; continuing without OAuth");
                            } else {
                                tracing::warn!(%error, "OAuth discovery failed");
                            }
                            (if optional { "not_advertised" } else { "failed" }, Some(format!("{error:#}")))
                        }
                    };
                    let catalog = if status == "failed" {
                        discovery.map(|_| ())
                    } else {
                        harpoon.log_catalog(&config)
                    };
                    state.send_modify(|state| {
                        if let Some(probe) = state.channels.get_mut("main") { probe.oauth_error = error.clone(); }
                        state.oauth = Startup::settled(status, error);
                        state.finish_catalog(catalog);
                    });
                    break;
                }
            });
        } else {
            let catalog = self.harpoon.log_catalog(&self.config.control_plane);
            self.state.send_modify(|state| {
                state.finish_catalog(catalog);
            });
        }
        let control = self.control.clone();
        let state = self.state.clone();
        let stop = self.stop.clone();
        self.observers.spawn(async move {
            let result = tokio::select! {
                result = control.metadata() => result,
                () = stop.cancelled() => return,
            };
            if let Err(error) = result {
                tracing::warn!(%error, "tunnel metadata unavailable");
                state.send_modify(|state| state.metadata_error = Some(format!("{error:#}")));
            }
        });
    }
}

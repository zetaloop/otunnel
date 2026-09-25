use std::collections::BTreeMap;

use anyhow::Result;
use axum::{
    Json,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::Monitor;
use crate::{config::Config, control, runtime::Snapshot};

pub(super) fn timestamp(seconds: f64) -> Option<String> {
    (seconds > 0.0)
        .then(|| {
            OffsetDateTime::from_unix_timestamp_nanos((seconds * 1e9) as i128)
                .ok()?
                .format(&Rfc3339)
                .ok()
        })
        .flatten()
}

fn dates(value: &mut Value) {
    if let Some(object) = value.as_object_mut() {
        for name in [
            "observed_at",
            "timestamp",
            "last_attempt",
            "last_success",
            "last_error",
            "next_retry",
            "last_accepted",
            "last_completed",
            "last_failure",
            "last_enqueue",
            "last_dequeue",
            "last_start",
            "last_completion",
        ] {
            if let Some(seconds) = object.get(name).and_then(Value::as_f64) {
                match timestamp(seconds) {
                    Some(value) => {
                        object.insert(name.into(), json!(value));
                    }
                    None => {
                        object.remove(name);
                    }
                }
            }
        }
        for child in object.values_mut() {
            dates(child);
        }
    } else if let Some(array) = value.as_array_mut() {
        for child in array {
            dates(child);
        }
    }
}

fn component(status: &str, state: &str, reason: &str, observed: f64, details: Value) -> Value {
    let mut value = json!({"status":status,"state":state,"limited":false,"details":details});
    if !reason.is_empty() {
        value["reason_code"] = json!(reason);
    }
    if let Some(time) = timestamp(observed) {
        value["observed_at"] = json!(time);
    }
    dates(&mut value);
    value
}

fn components(monitor: &Monitor, state: &Snapshot) -> BTreeMap<&'static str, Value> {
    let now = control::now();
    let config = &monitor.config;
    let polling = &state.control;
    let mut components = BTreeMap::new();
    components.insert("proxy", proxy(&state.proxy));
    let pressure = state.activity.pressure_started > 0.0;
    let poll_state = if state.lifecycle == "draining" {
        "stopped"
    } else if pressure {
        "backpressured"
    } else {
        polling.poll_state
    };
    let mut details = json!({
        "last_attempt":polling.last_attempt,"last_success":polling.last_success,"last_error":polling.last_error,
        "next_retry":polling.next_retry,"consecutive_failures":polling.consecutive_failures,
        "current_poll_age_seconds":if poll_state == "polling" {(now-polling.last_attempt).max(0.0)} else {0.0},
        "configured_wait_seconds":config.control_plane.poll_timeout.0.as_secs_f64(),
        "effective_wait_seconds":polling.effective_wait,"deadline_seconds":polling.deadline
    });
    if !polling.failure_category.is_empty() {
        details["failure_category"] = json!(polling.failure_category);
    }
    if polling.consecutive_failures > 0 && polling.http_status != 0 {
        details["http_status"] = json!(polling.http_status);
    }
    components.insert(
        "control-plane",
        component(
            if polling.consecutive_failures > 0 {
                "degraded"
            } else if polling.last_success > 0.0 {
                "ok"
            } else {
                "unknown"
            },
            poll_state,
            polling.failure_category,
            polling
                .last_attempt
                .max(polling.last_success)
                .max(polling.last_error),
            details,
        ),
    );
    let upload = &polling.upload;
    let mut details = json!(upload);
    if upload.failure_category.is_empty() {
        details
            .as_object_mut()
            .expect("upload")
            .remove("failure_category");
    }
    if upload.http_status == 0 {
        details
            .as_object_mut()
            .expect("upload")
            .remove("http_status");
    }
    components.insert(
        "response-delivery",
        component(
            if upload.disposition == "failed" || !matches!(upload.failure_category, "" | "canceled")
            {
                "degraded"
            } else if upload.completed > 0 {
                "ok"
            } else {
                "unknown"
            },
            if upload.in_progress > 0 {
                "uploading"
            } else {
                upload.disposition
            },
            upload.failure_category,
            upload.last_completed.max(upload.last_failure),
            details,
        ),
    );
    let activity = &state.activity;
    components.insert("queue", component("ok", if pressure {"backpressured"} else {"available"}, "",
        activity.last_enqueue.max(activity.last_dequeue), json!({
            "depth":activity.queued,"capacity":config.control_plane.max_inflight_requests,
            "utilization":activity.queued as f64 / config.control_plane.max_inflight_requests.max(1) as f64,
            "last_enqueue":activity.last_enqueue,"last_dequeue":activity.last_dequeue,
            "enqueued":activity.enqueued,"dequeued":activity.dequeued,
            "backpressure_seconds":activity.pressure_seconds + if pressure {(now-activity.pressure_started).max(0.0)} else {0.0}
        })));
    let oldest = activity
        .active
        .values()
        .copied()
        .min_by(f64::total_cmp)
        .map_or(0.0, |start| (now - start).max(0.0));
    components.insert("dispatcher", component(if activity.last_failed {"degraded"} else {"ok"},
        if state.lifecycle == "running" {"accepting"} else {state.lifecycle}, "", activity.last_start.max(activity.last_completion), json!({
            "active":activity.active.len(),"pool_limit":config.mcp.max_concurrent_requests,
            "last_start":activity.last_start,"last_completion":activity.last_completion,"oldest_active_age_seconds":oldest,
            "completed":state.completed+state.failed+state.expired,"failures":state.failed+state.expired,"timeouts":state.expired,
            "accepting":state.lifecycle == "running"
        })));
    let http = config
        .mcp
        .server_urls
        .iter()
        .any(|server| server.channel == "main" && config.enabled("main"));
    let stdio = config
        .mcp
        .commands
        .iter()
        .any(|command| command.channel == "main" && config.enabled("main"));
    let mut mcp = state.evidence.get("main").cloned().unwrap_or_else(|| {
        component(if http || stdio {"unknown"} else {"disabled"}, if http || stdio {"not_observed"} else {"disabled"},
            if http {"same_child_evidence_unavailable"} else {""}, 0.0,
            json!({"channel":"main","transport":if http {"http-streamable"} else if stdio {"stdio"} else {""},
                "initialize_epoch":0,"evidence":if http {"unsupported_transport"} else if stdio {"same_child"} else {"not_configured"},
                "initialize":{"ok":false,"identity_complete":false,"limited":false,"capability_names":[]},
                "tools_list":{"ok":false,"tool_names":[],"retained_count":0,"complete":false,"partial":false,"limited":false}
            }))
    });
    if http {
        let mut probe = json!({"state":match state.mcp_probe.state {
            "ok" => "succeeded", "auth-required" => "auth_required", "timeout" | "startup-timeout" => "timed_out", "failed" => "failed", _ => "pending"
        }});
        if let Some(time) = state.mcp_probe.observed_at.and_then(timestamp) {
            probe["observed_at"] = json!(time);
        }
        mcp["details"]["startup_probe"] = probe;
    }
    dates(&mut mcp);
    components.insert("mcp", mcp);
    let oauth = &state.oauth;
    components.insert(
        "oauth",
        component(
            match oauth.state {
                "disabled" => "disabled",
                "pending" => "unknown",
                "failed" => "degraded",
                _ => "ok",
            },
            oauth.state,
            match oauth.state {
                "not_advertised" => "metadata_not_advertised",
                "failed" => "discovery_failed",
                _ => "",
            },
            oauth.observed_at.unwrap_or_default(),
            json!({"discovery_complete":!matches!(oauth.state,"pending"|"disabled")}),
        ),
    );
    let catalog = match oauth.state {
        "pending" => "pending",
        "failed" => "failed",
        _ => "settled",
    };
    components.insert(
        "harpoon",
        component(
            match catalog {
                "pending" => "unknown",
                "failed" => "degraded",
                _ => "ok",
            },
            catalog,
            if catalog == "failed" {
                "catalog_failed"
            } else {
                ""
            },
            oauth.observed_at.unwrap_or_default(),
            json!({"target_count":monitor.harpoon.len(),"catalog_state":catalog}),
        ),
    );
    let (status, phase, reason) = match state.cloudflare_ready {
        None => ("disabled", "disabled", ""),
        Some(true) => ("ok", "ready", ""),
        Some(false) if state.cloudflare_observed_at == 0.0 => ("unknown", "pending", ""),
        Some(false) => ("degraded", "not_ready", "companion_not_ready"),
    };
    components.insert("cloudflared", component(status, phase, reason, state.cloudflare_observed_at,
        json!({"enabled":state.cloudflare_ready.is_some(),"ready":state.cloudflare_ready==Some(true)})));
    components
}

fn proxy(snapshot: &crate::proxy_health::Snapshot) -> Value {
    let proxied = snapshot.routes.iter().any(|route| route.state != "direct");
    let pending = snapshot.routes.iter().any(|route| route.state == "pending");
    let failed = snapshot
        .routes
        .iter()
        .any(|route| route.state == "unhealthy");
    let routes: Vec<_> = snapshot
        .routes
        .iter()
        .take(16)
        .enumerate()
        .map(|(index, route)| {
            let mut value = json!({
                "label":format!("route-{}", index + 1),
                "kind":route.kind,
                "state":route.state,
            });
            if !route.failure.is_empty() {
                value["failure_category"] = json!(route.failure);
            }
            if route.last_check > 0.0 {
                value["last_check"] = json!(route.last_check);
            }
            if route.last_success > 0.0 {
                value["last_success"] = json!(route.last_success);
            }
            value
        })
        .collect();
    let (status, state, reason) = if failed {
        ("degraded", "unhealthy", "route_check_failed")
    } else if pending {
        ("unknown", "pending", "")
    } else if proxied {
        ("ok", "healthy", "")
    } else {
        ("disabled", "direct", "")
    };
    let mut value = component(
        status,
        state,
        reason,
        snapshot.observed_at,
        json!({"route_count":snapshot.routes.len(),"routes":routes}),
    );
    value["limited"] = json!(snapshot.routes.len() > 16);
    value
}

pub(super) async fn health(State(monitor): State<Monitor>, request: Request) -> Response {
    let error = |status, reason| {
        (
            status,
            [("cache-control", "no-store")],
            Json(json!({"error":reason})),
        )
            .into_response()
    };
    if request.method() != Method::GET {
        let mut response = error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
        response
            .headers_mut()
            .insert("allow", "GET".parse().expect("method"));
        return response;
    }
    let state = monitor.status.borrow().clone();
    let query = request.uri().query();
    let path = request.uri().path();
    let now = control::now();
    let mut response = if path != "/health" {
        if query.is_some() {
            return error(StatusCode::BAD_REQUEST, "invalid_query");
        }
        let decoded =
            percent_encoding::percent_decode_str(path.strip_prefix("/health/").unwrap_or_default())
                .decode_utf8_lossy();
        let name = decoded.as_ref();
        let Some(mut value) = components(&monitor, &state).remove(name) else {
            return error(StatusCode::NOT_FOUND, "unknown_component");
        };
        value["schema_version"] = json!(1);
        value["snapshot_at"] = json!(timestamp(now));
        value["component"] = json!(name);
        value
    } else {
        let mut details = monitor.config.health.show_details;
        if let Some(query) = query {
            if query.is_empty() || query.len() > 128 || query.contains(';') {
                return error(StatusCode::BAD_REQUEST, "invalid_query");
            }
            let pairs: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
            if pairs.len() != 1
                || pairs[0].0 != "details"
                || !matches!(pairs[0].1.as_ref(), "true" | "false")
            {
                return error(StatusCode::BAD_REQUEST, "invalid_query");
            }
            details = pairs[0].1 == "true";
        }
        let mut value = json!({"schema_version":1,"live":true,"ready":state.ready,"snapshot_at":timestamp(now),"runtime":{
            "instance_id":state.control.instance_id,"version":env!("CARGO_PKG_VERSION"),"flavor":"runtime",
            "started_at":timestamp(state.started_at as f64),"uptime_seconds":(now-state.started_at as f64).max(0.0),"lifecycle":state.lifecycle
        }});
        if details {
            value["components"] = json!(components(&monitor, &state));
        }
        value
    };
    let limit = if path == "/health" {
        64 * 1024
    } else {
        24 * 1024
    };
    if let Some(components) = response
        .get_mut("components")
        .and_then(Value::as_object_mut)
    {
        for value in components.values_mut() {
            if serde_json::to_vec(value).expect("component JSON").len() > 24 * 1024 - 512 {
                value.as_object_mut().expect("component").remove("details");
                value["limited"] = json!(true);
            }
        }
    }
    if serde_json::to_vec(&response).expect("health JSON").len() > limit {
        if let Some(components) = response
            .get_mut("components")
            .and_then(Value::as_object_mut)
        {
            for value in components.values_mut() {
                value.as_object_mut().expect("component").remove("details");
                value["limited"] = json!(true);
            }
            response["truncated"] = json!(true);
        } else {
            response
                .as_object_mut()
                .expect("component")
                .remove("details");
            response["limited"] = json!(true);
        }
    }
    ([("cache-control", "no-store")], Json(response)).into_response()
}

pub(super) async fn status(State(monitor): State<Monitor>) -> Json<Value> {
    let state = monitor.status.borrow();
    let config = &monitor.config;
    let cp = &config.control_plane;
    let mut value = json!({
        "version":env!("CARGO_PKG_VERSION"),"client_instance_id":state.control.instance_id,
        "started_at":timestamp(state.started_at as f64),"uptime_seconds":(control::now()-state.started_at as f64).max(0.0) as u64,
        "health_listen_addr":monitor.address,"control_plane_base_url":cp.base_url(),"control_plane_tunnel_id":cp.tunnel_id,
        "control_plane_max_inflight":cp.max_inflight_requests,"control_plane_poll_timeout":cp.poll_timeout.to_string(),
        "control_plane_poll_deadline_guardrail":cp.poll_deadline_guardrail.to_string(),
        "raw_http_logging_enabled":config.log.http_raw_unsafe
    });
    let mut channels = BTreeMap::new();
    for server in &config.mcp.server_urls {
        let mut channel = json!({"name":server.channel,"enabled":true,"server_kind":"external","transport_kind":"http-streamable","details":[{"key":"address","value":server.url}]});
        if server.channel == "main" {
            channel["probe_status"] = json!(match state.mcp_probe.state {
                "startup-timeout" => "failed",
                "disabled" => "pending",
                status => status,
            });
            let reason = match state.mcp_probe.state {
                "failed" | "startup-timeout" => {
                    channel["enabled"] = json!(false);
                    "initial mcp probe failed"
                }
                "timeout" => "initial mcp probe timed out",
                "auth-required" => "mcp initialize requires auth",
                _ => "",
            };
            if !reason.is_empty() {
                channel["reason"] = json!(reason);
            }
            if let Some(error) = &state.mcp_probe.error {
                channel["probe_error"] = json!(error);
            }
            value["mcp_server_url"] = json!(server.url);
        }
        channels.insert(server.channel.clone(), channel);
    }
    for command in &config.mcp.commands {
        channels.insert(command.channel.clone(),json!({"name":command.channel,"enabled":true,"server_kind":"external","transport_kind":"stdio","details":[{"key":"pid","value":state.process_ids.get(&command.channel).map(u32::to_string).unwrap_or_else(|| "—".into())},{"key":"command","value":command.command}]}));
    }
    let mut channels: Vec<_> = channels.into_values().collect();
    channels.push(json!({"name":"harpoon","enabled":!monitor.harpoon.is_empty(),"server_kind":"builtin","transport_kind":"in-memory"}));
    if monitor.harpoon.is_empty() {
        channels.last_mut().expect("Harpoon channel")["reason"] =
            json!("no harpoon targets registered");
    }
    value["channels"] = json!(channels);
    if let Some(metadata) = &state.control.metadata {
        value["tunnel_metadata"] = json!({"ID":metadata["id"].as_str().unwrap_or_default(),"Name":metadata["name"].as_str().unwrap_or_default(),"Description":metadata["description"].as_str().unwrap_or_default()});
    }
    if let Some(error) = &state.metadata_error {
        value["tunnel_metadata_error"] = json!(error);
    }
    Json(value)
}

pub(super) async fn system(State(monitor): State<Monitor>) -> Json<Value> {
    let state = monitor.status.borrow();
    let mut value = json!({"tls":monitor.trust,"main_channel_probe_status":match state.mcp_probe.state { "disabled"=>"ok", "startup-timeout"=>"failed", status=>status }});
    if let Some(error) = &state.mcp_probe.error {
        value["main_channel_probe_error"] = json!(error);
    }
    let summaries = state.proxy.summaries();
    if !summaries.is_empty() {
        value["proxy_health"] = json!(summaries);
    }
    let identities = state.proxy.identities();
    if !identities.is_empty() {
        value["proxy_identity_map"] = json!(identities);
    }
    dates(&mut value);
    Json(value)
}

pub(super) fn trust(config: &Config) -> Result<Value> {
    let native = rustls_native_certs::load_native_certs();
    let mut result =
        json!({"system_trust":{"enabled":!native.certs.is_empty(),"source":"system cert pool"}});
    if let Some(path) = &config.ca_bundle {
        use sha2::{Digest, Sha256};
        let bytes = crate::config::pem(path)?;
        let mut roots = rustls::RootCertStore::empty();
        let mut certificates = Vec::new();
        let mut errors = 0;
        for certificate in rustls_pemfile::certs(&mut bytes.as_slice()) {
            let certificate = certificate?;
            let id = Sha256::digest(&certificate)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let status = match roots.add(certificate) {
                Ok(()) => "ok".to_owned(),
                Err(error) => {
                    errors += 1;
                    error.to_string()
                }
            };
            certificates.push(json!({"cert_id":id,"source":path,"parse_status":status}));
        }
        result["extra_bundle"] = json!({"path":path,"cert_count":certificates.len()-errors,"parse_errors":errors,"certificates":certificates});
    }
    Ok(result)
}

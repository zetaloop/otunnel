use std::{fs, path::Path, time::Duration};

use crate::{admin::Tunnel, health::Target};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};

use super::{
    files::{self, Files},
    session,
    state::{Alias, Process, Root},
};

pub fn string(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}
fn endpoint() -> Value {
    json!({"url":"","ok":false,"status":0,"body":"","error":""})
}

pub async fn probe(base: &str) -> Value {
    let mut probe = json!({"base_url":"","healthz":endpoint(),"readyz":endpoint()});
    let Ok(target) = Target::new(base) else {
        return probe;
    };
    probe["base_url"] = json!(target.base);
    for (key, path) in [("healthz", "/healthz"), ("readyz", "/readyz")] {
        let mut endpoint = endpoint();
        endpoint["url"] = json!(format!("{}{path}", target.base));
        match target
            .request(path, Duration::from_millis(500), Some(4096))
            .await
        {
            Ok((code, body)) => {
                endpoint["ok"] = json!((200..300).contains(&code));
                endpoint["status"] = json!(code);
                endpoint["body"] = json!(String::from_utf8_lossy(&body).trim());
            }
            Err(error) => endpoint["error"] = json!(format!("{error:#}")),
        }
        probe[key] = endpoint;
    }
    probe
}
pub async fn fetch(base: &str, path: &str) -> Result<Value> {
    let (code, body) = Target::new(base)?
        .request(path, Duration::from_millis(500), None)
        .await?;
    anyhow::ensure!(
        (200..300).contains(&code),
        "GET {base}{path} returned HTTP {code}"
    );
    Ok(serde_json::from_slice(&body)?)
}
async fn details(base: &str) -> Option<Value> {
    if !base.starts_with("http+unix://") {
        let url = url::Url::parse(base).ok()?;
        if !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.scheme(), "http" | "https")
        {
            return None;
        }
        let host = url.host_str()?;
        if host != "localhost"
            && !host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        {
            return None;
        }
    }
    let (code, body) = Target::new(base)
        .ok()?
        .request(
            "/health/mcp",
            Duration::from_millis(500),
            Some(24 * 1024 + 1),
        )
        .await
        .ok()?;
    if code != 200 || body.len() > 24 * 1024 {
        return None;
    }
    let value: Value = serde_json::from_slice(&body).ok()?;
    if value["schema_version"] != 1 || value["component"] != "mcp" {
        return None;
    }
    Some(
        json!({"health_details_url":format!("{base}/health?details=true"),"mcp_health_url":format!("{base}/health/mcp")}),
    )
}

pub fn path_details(path: &str) -> Value {
    let metadata = fs::metadata(path).ok();
    json!({"path":path,"exists":metadata.is_some(),"size_bytes":metadata.filter(|metadata| metadata.is_file()).map_or(0, |metadata| metadata.len())})
}
fn managed(root: &Root, directory: &str, path: &str) -> Value {
    let metadata = Files::open(root, directory, false)
        .and_then(|files| Ok(files.file(Path::new(path), false)?.metadata()?))
        .ok();
    json!({"path":path,"exists":metadata.is_some(),"size_bytes":metadata.map_or(0, |metadata| metadata.len())})
}
pub fn ui(base: &str) -> String {
    if base.is_empty() {
        String::new()
    } else {
        format!("{base}/ui")
    }
}

pub async fn local(root: &Root, alias: &str, record: &Alias, process: &Process) -> Result<Value> {
    let health_file = super::first(&[&process.health_url_file, &record.health_url_file]);
    let mut health = managed(root, "health", &health_file);
    let raw_url = files::health_url(root, &health_file);
    let probe = probe(&raw_url).await;
    let mut live = json!({"found":false});
    let tunnel_id = super::first(&[&record.tunnel_id, &process.tunnel_id]);
    if let Ok(files) = Files::open(root, "health", false)
        && let Ok(names) = files.names()
    {
        for path in names {
            if path.extension().is_none_or(|ext| ext != "url") {
                continue;
            }
            let raw = files::health_url(root, &path.to_string_lossy());
            let base = Target::normalize(&raw);
            if base.is_empty() || base == string(&probe["base_url"]) {
                continue;
            }
            let Ok(status) = fetch(&base, "/api/status").await else {
                continue;
            };
            if !tunnel_id.is_empty() && status["control_plane_tunnel_id"] != tunnel_id {
                continue;
            }
            let system = fetch(&base, "/api/system").await.unwrap_or(Value::Null);
            live = json!({"found":true,"base_url":base,"ui_url":ui(&base),"source_health_url_file":path,"match_reason":"control_plane_tunnel_id","status":status,"system":system});
            break;
        }
    }
    health["raw_url"] = json!(raw_url);
    health["base_url"] = probe["base_url"].clone();
    health["url"] = probe["healthz"]["url"].clone();
    health["ui"] = json!(ui(string(&probe["base_url"])));
    health["healthz"] = probe["healthz"].clone();
    health["readyz"] = probe["readyz"].clone();
    if probe["healthz"]["ok"] == true
        && let Some(links) = details(string(&probe["base_url"])).await
    {
        health
            .as_object_mut()
            .context("health object")?
            .extend(links.as_object().context("health links")?.clone());
    }
    let mut effective = json!({"base_url":health["base_url"],"url":health["url"],"ui":health["ui"],"healthz":health["healthz"],"readyz":health["readyz"]});
    for key in ["health_details_url", "mcp_health_url"] {
        if let Some(link) = health.get(key) {
            effective[key] = link.clone();
        }
    }
    if probe["healthz"]["ok"] != true
        && let Some(base) = live["base_url"].as_str()
    {
        let replacement = self::probe(base).await;
        effective = json!({"base_url":replacement["base_url"],"url":replacement["healthz"]["url"],"ui":ui(base),"healthz":replacement["healthz"],"readyz":replacement["readyz"]});
        if replacement["healthz"]["ok"] == true
            && let Some(links) = details(base).await
        {
            effective
                .as_object_mut()
                .context("effective health")?
                .extend(links.as_object().context("health links")?.clone());
        }
    }
    let profile_path = super::first(&[&process.profile_path, &record.profile_path]);
    let mut profile = path_details(&profile_path);
    profile["name"] = json!(super::first(&[&process.profile_name, &record.profile_name]));
    profile["dir"] = json!(super::first(&[&process.profile_dir, &record.profile_dir]));
    profile["config_path"] = json!(super::first(&[&process.config_path, &record.config_path]));
    let mut log = managed(root, "logs", &process.log_path);
    log["tail"] = json!(files::log_tail(root, &process.log_path));
    let tmux = process.mode == "tmux"
        && session::tmux(root, alias, process)
            .await
            .ok()
            .flatten()
            .is_some();
    let running = process.running();
    let runtime = if !(running || tmux || live["found"] == true) {
        "stopped"
    } else if effective["healthz"]["ok"] != true {
        "starting"
    } else if effective["readyz"]["ok"] != true {
        "healthy"
    } else {
        "ready"
    };
    let poll = poll_health(&live);
    let mut issues = Vec::new();
    if process.mode == "tmux" && !process.session_name.is_empty() && !tmux {
        issues.push("recorded tmux session is not running".into());
    }
    if process.mode == "process" && process.pid.is_some() && !running {
        issues.push("recorded process pid is not running".into());
    }
    if process.mode == "process"
        && process.pid.is_some()
        && (process.pid_start_time.is_empty() || process.pid_executable.is_empty())
    {
        issues.push(
            "recorded process identity is missing; refusing to reuse or signal a bare PID".into(),
        );
    }
    if !process.profile_path.is_empty() && profile["exists"] != true {
        issues.push("recorded runtime profile is missing".into());
    }
    if !process.health_url_file.is_empty() && raw_url.is_empty() {
        issues.push("health URL file has not been populated".into());
    }
    for (key, condition) in [("healthz", "healthy"), ("readyz", "ready")] {
        let endpoint = &health[key];
        if !process.alias.is_empty()
            && !string(&endpoint["url"]).is_empty()
            && endpoint["ok"] != true
        {
            let detail = if endpoint["status"].as_u64().unwrap_or_default() != 0 {
                format!("HTTP {}", endpoint["status"])
            } else {
                super::first(&[string(&endpoint["error"]), string(&endpoint["body"])])
            };
            issues.push(format!(
                "{} endpoint is not {condition} at {}{}",
                if key == "healthz" { "health" } else { "ready" },
                string(&endpoint["url"]),
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(" ({detail})")
                }
            ));
        }
    }
    if !process.log_path.is_empty() && !running && !tmux && log["exists"] == true {
        issues.push("runtime log exists but no active runtime is running".into());
    }
    if live["found"] == true && health["healthz"]["ok"] != true {
        issues.push(format!(
            "recorded health URL looks stale; live admin UI was found at {}",
            string(&live["base_url"])
        ));
    }
    if !matches!(
        string(&poll["state"]),
        "" | "unknown" | "healthy" | "direct"
    ) {
        issues.push(format!(
            "control-plane poll route health is {}",
            string(&poll["state"])
        ));
    }
    Ok(
        json!({"runtime_state":runtime,"issues":issues,"profile":profile,"health":health,"effective_health":effective,"live_admin_ui":live,"control_plane_poll_health":poll,"log":log,
        "tmux":{"session_name":super::first(&[&process.session_name, &session::session_name(root,alias)]),"running":tmux},"process_running":running || tmux}),
    )
}

fn poll_health(live: &Value) -> Value {
    let system = &live["system"];
    if system.is_null() {
        return json!({"state":"unknown","reason":"no live admin UI system snapshot"});
    }
    if let Some(routes) = system["proxy_health"].as_array() {
        for route in routes {
            if route["route"]["kind"] == "control_plane" {
                return json!({"state":super::first(&[string(&route["health_state"]),"unknown"]),"route":route["route"],"last_check":route["last_check"],"last_success":route["last_success"],"history":route["history"]});
            }
        }
    }
    if !live["status"]["control_plane_route"].is_null() {
        return json!({"state":"unknown","route":live["status"]["control_plane_route"],"reason":"route is present but proxy health snapshot did not report reachability"});
    }
    json!({"state":"unknown","reason":"control-plane route health is not available"})
}
fn nullable(items: &[String]) -> Value {
    if items.is_empty() {
        Value::Null
    } else {
        json!(items)
    }
}
pub fn tunnel(value: &Tunnel) -> Value {
    json!({"id":value.id,"name":value.name,"description":value.description,"organization_ids":nullable(&value.organization_ids),"workspace_ids":nullable(&value.workspace_ids),"tenant_ids":nullable(&value.tenant_ids)})
}
pub fn alias(value: &Alias) -> Value {
    json!({"alias":value.alias,"tunnel_id":value.tunnel_id,"name":value.name,"description":value.description,"admin_profile":value.admin_profile,"organization_ids":nullable(&value.organization_ids),"workspace_ids":nullable(&value.workspace_ids),"tenant_ids":nullable(&value.tenant_ids),"config_path":value.config_path,"profile_name":value.profile_name,"profile_dir":value.profile_dir,"profile_path":value.profile_path,"health_url_file":value.health_url_file,"updated_at":value.updated_at})
}
pub fn process(value: &Process) -> Value {
    let mut result = json!({"alias":value.alias,"tunnel_id":value.tunnel_id,"admin_profile":value.admin_profile,"mode":value.mode,"session_name":value.session_name,"config_path":value.config_path,"profile_name":value.profile_name,"profile_dir":value.profile_dir,"profile_path":value.profile_path,"health_url_file":value.health_url_file,"target_kind":value.target_kind,"target_value":value.target_value,"command":value.command,"log_path":value.log_path,"started_at":value.started_at});
    if let Some(pid) = value.pid {
        result["pid"] = json!(pid);
    }
    result
}

pub fn doctor(record: &Alias, process: &Process) -> String {
    let profile = super::first(&[&process.profile_name, &record.profile_name]);
    let directory = super::first(&[&process.profile_dir, &record.profile_dir]);
    let config = super::first(&[&process.config_path, &record.config_path]);
    let mut args = vec!["otunnel", "doctor"];
    if !profile.is_empty() {
        args.extend(["--profile", &profile]);
        if !directory.is_empty() {
            args.extend(["--profile-dir", &directory]);
        }
    } else if !config.is_empty() {
        args.extend(["--config", &config]);
    }
    args.push("--explain");
    shell_words::join(args)
}
pub fn repair(alias: &str, record: &Alias, process: &Process) -> String {
    let mut args = vec!["otunnel", "runtimes", "connect", "--alias", alias];
    if !record.admin_profile.is_empty() {
        args.extend(["--admin-profile", &record.admin_profile]);
    }
    if !record.profile_name.is_empty() {
        args.extend(["--profile", &record.profile_name]);
    }
    let directory = super::first(&[&process.profile_dir, &record.profile_dir]);
    if !directory.is_empty() {
        args.extend(["--profile-dir", &directory]);
    }
    for (name, values) in [
        ("--organization-id", &record.organization_ids),
        ("--workspace-id", &record.workspace_ids),
        ("--tenant-id", &record.tenant_ids),
    ] {
        if let Some(value) = values.first() {
            args.extend([name, value]);
            break;
        }
    }
    match process.target_kind.as_str() {
        "server_url" => args.extend(["--mcp-server-url", &process.target_value]),
        "command" => args.extend(["--mcp-command", &process.target_value]),
        _ => args.push("<add --mcp-server-url or --mcp-command>"),
    }
    shell_words::join(args)
}

#[derive(Serialize)]
pub struct Action {
    id: &'static str,
    command: String,
    reason: &'static str,
}
pub fn actions(
    alias: &str,
    record: &Alias,
    process: &Process,
    local: &Value,
    remote_error: &str,
) -> Vec<Action> {
    let mut actions = Vec::new();
    if local["profile"]["exists"] != true {
        actions.push(Action { id:"reconnect_missing_profile", command:repair(alias,record,process), reason:"the recorded runtime profile is missing, so reconnecting rewrites the profile and relaunches the managed runtime" });
    }
    if process.alias.is_empty() || local["runtime_state"] == "stopped" {
        actions.push(Action {
            id: "start_runtime",
            command: repair(alias, record, process),
            reason: "no managed runtime is currently running for this alias",
        });
    }
    if local["live_admin_ui"]["found"] == true && local["health"]["healthz"]["ok"] != true {
        actions.push(Action { id:"refresh_stale_health_url",command:format!("otunnel runtimes connect --alias {alias}"),reason:"the recorded health URL is stale but a live admin UI for the same tunnel was found" });
    }
    if !matches!(
        string(&local["control_plane_poll_health"]["state"]),
        "" | "unknown" | "healthy" | "direct"
    ) {
        actions.push(Action { id:"repair_control_plane_proxy",command:doctor(record,process),reason:"the local runtime is responding while its control-plane poll route is unhealthy" });
    }
    if !remote_error.trim().is_empty() {
        actions.push(Action { id:"check_remote_tunnel",command:format!("otunnel runtimes status {alias} --json"),reason:"the remote tunnel lookup returned an error and should be rechecked with the current runtime/admin credentials" });
    }
    if actions.is_empty() {
        actions.push(Action { id:"inspect",command:format!("otunnel runtimes status {alias} --json"),reason:"no immediate local repair was detected; rerun status for the freshest structured state" });
    }
    actions
}
pub fn next_steps(actions: &[Action], extras: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    for command in actions.iter().map(|action| &action.command).chain(extras) {
        if !result.contains(command) {
            result.push(command.clone());
        }
    }
    result
}

use std::collections::BTreeMap;

use anyhow::Result;
use clap::{ArgMatches, parser::ValueSource};
use otunnel::{
    Tunnel,
    diagnostic::{Check, Report, Status},
    health::Server,
};

const LINKS: &[(&str, &str)] = &[
    (
        "tunnels_management_url",
        "https://platform.openai.com/settings/organization/tunnels",
    ),
    (
        "runtime_api_keys_url",
        "https://platform.openai.com/settings/organization/api-keys",
    ),
    (
        "admin_api_keys_url",
        "https://platform.openai.com/settings/organization/admin-keys",
    ),
    (
        "chatgpt_connector_settings_url",
        "https://chatgpt.com/#settings/Connectors",
    ),
];

pub async fn execute(arguments: &ArgMatches) -> Result<u8> {
    let mut checks = Vec::new();
    let path = match super::source(arguments) {
        Ok(path) => path.map(|source| source.path),
        Err(error) => {
            checks.push(Check::fail("config_source", format!("{error:#}")));
            return output(arguments, checks, BTreeMap::new(), String::new());
        }
    };
    let selected = ["config", "profile", "profile-file"]
        .into_iter()
        .filter(|name| !super::value(arguments, name).trim().is_empty())
        .max_by_key(|name| match arguments.value_source(name) {
            Some(ValueSource::CommandLine) => 2,
            Some(ValueSource::EnvVariable) => 1,
            _ => 0,
        });
    let description = match selected {
        Some("profile") => format!("profile: {}", super::value(arguments, "profile").trim()),
        Some("profile-file") => format!(
            "profile file: {}",
            path.as_deref()
                .unwrap_or(std::path::Path::new(""))
                .display()
        ),
        _ => path.as_ref().map_or_else(
            || "flags/environment only".into(),
            |path| path.display().to_string(),
        ),
    };
    checks.push(Check::pass("config_source", description));
    if let Some(file) = &path {
        match std::fs::metadata(file) {
            Ok(_) => {
                checks.push(Check::pass("profile_load", file.display().to_string()));
            }
            Err(error) => {
                checks.push(Check::fail(
                    "profile_load",
                    format!("read {}: {error}", file.display()),
                ));
                return output(arguments, checks, BTreeMap::new(), String::new());
            }
        }
    } else {
        checks.push(Check::pass("profile_load", "flags/environment only"));
    }
    let config = match super::load(arguments).and_then(|config| {
        config.validate()?;
        Ok(config)
    }) {
        Ok(config) => config,
        Err(error) => {
            let message = format!("{error:#}");
            let id = if message.contains("tunnel ID") || message.contains("tunnel_id") {
                "tunnel_id"
            } else if message.contains("api_key")
                || message.contains("API key")
                || message.contains("CONTROL_PLANE_API_KEY")
                || message.contains("OPENAI_API_KEY")
            {
                "control_plane_api_key"
            } else if message.contains("control-plane.base-url") {
                "control_plane_base_url"
            } else {
                "config_validation"
            };
            checks.push(Check::fail(id, message));
            return output(arguments, checks, BTreeMap::new(), String::new());
        }
    };
    checks.push(Check::pass("tunnel_id", &config.control_plane.tunnel_id));
    checks.push(Check::pass("control_plane_api_key", "configured"));
    let next = match (selected, path.as_ref()) {
        (Some("profile"), _) => format!(
            "otunnel run --profile {}",
            super::value(arguments, "profile").trim()
        ),
        (Some("profile-file"), Some(path)) => {
            format!("otunnel run --profile-file {}", path.display())
        }
        (_, Some(path)) => format!("otunnel run --config {}", path.display()),
        _ => "otunnel run".into(),
    };
    let tunnel = match Tunnel::new(config.clone()) {
        Ok(tunnel) => tunnel,
        Err(error) => {
            checks.push(Check::fail("config_validation", format!("{error:#}")));
            return output(arguments, checks, BTreeMap::new(), next);
        }
    };
    let health = if config.health.unix_socket.is_some() || !config.health.listen_addr.is_empty() {
        Some(
            match Server::bind(&config, tunnel.status(), tunnel.harpoon()).await {
                Ok(server) => Check::pass(
                    "health_listener",
                    if let Some(socket) = &config.health.unix_socket {
                        format!("will bind unix socket {socket}")
                    } else if config.health.listen_addr.ends_with(":0") {
                        format!("ephemeral bind ok on {}", server.url())
                    } else {
                        format!("will bind {}", server.url())
                    },
                ),
                Err(error) => Check::fail("health_listener", format!("{error:#}")),
            },
        )
    } else {
        None
    };
    if config.cloudflared.managed || config.cloudflared.token.is_some() {
        match which::which(&config.cloudflared.path) {
            Ok(path) => checks.push(Check::pass("cloudflared_path", path.display().to_string())),
            Err(error) => checks.push(Check::fail(
                "cloudflared_path",
                format!("{}: {error}", config.cloudflared.path),
            )),
        }
    }
    let report = tunnel.diagnose().await;
    checks.extend(report.checks);
    checks.extend(health);
    output(arguments, checks, report.channels, next)
}

fn output(
    arguments: &ArgMatches,
    mut checks: Vec<Check>,
    channels: BTreeMap<String, otunnel::transport::Probe>,
    next: String,
) -> Result<u8> {
    let offset = checks
        .iter()
        .position(|check| check.id == "control_plane_api_key")
        .map_or(checks.len(), |index| index + 1);
    checks.splice(
        offset..offset,
        LINKS.iter().map(|(id, url)| Check::pass(*id, *url)),
    );
    for check in &mut checks {
        if check.status == Status::Pass {
            continue;
        }
        let (why, action) = match check.id.split('.').next().unwrap_or_default() {
            "config_source" | "profile_load" | "config_validation" => (
                "The selected configuration supplies the runtime connections and process commands.",
                "Check the reported configuration field or source path.",
            ),
            "tunnel_id" => (
                "The tunnel ID identifies the control-plane connection.",
                "Set --control-plane.tunnel-id to the ID of the configured tunnel.",
            ),
            "control_plane_api_key" => (
                "The runtime key is used to poll the tunnel and return results.",
                "Set control_plane.api_key or CONTROL_PLANE_API_KEY to the runtime credential or its reference.",
            ),
            "control_plane_connection" | "control_plane_base_url" => (
                "The configured control-plane transport must reach the tunnel API.",
                "Check the reported endpoint, credential, proxy and TLS configuration.",
            ),
            "mcp_target" | "mcp_server_reachable" | "mcp_tools" => (
                "The configured MCP transport is used for initialization and normal requests.",
                "Check the reported MCP command, URL, socket, proxy or certificate.",
            ),
            "oauth_metadata" => (
                "OAuth discovery describes the MCP resource and its authorization server.",
                "Check the advertised metadata URL and authentication headers.",
            ),
            "health_listener" => (
                "The runtime binds its health endpoint before starting the tunnel.",
                "Select an available health.listen_addr or health.unix_socket.",
            ),
            "cloudflared_path" => (
                "Cloudflare connections use the executable installed by the operator.",
                "Install cloudflared on PATH or set cloudflared.path to its executable.",
            ),
            "shutdown" => (
                "Processes started for diagnostics are closed when diagnostics finish.",
                "Inspect the reported process shutdown error.",
            ),
            _ => (
                "The diagnostic uses the same runtime transport as normal forwarding.",
                "Inspect the reported error.",
            ),
        };
        check.why = why.into();
        if check.status == Status::Fail {
            check.next.push(action.into());
        }
    }
    let report = Report::new(checks, channels, next);
    if arguments.get_flag("json") {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for check in &report.checks {
            println!(
                "CHECK {:<24} {:<4} {}",
                check.id,
                check.status.to_string(),
                check.summary
            );
        }
        println!("\nRESULT {}", report.result);
        if report.passed() {
            if !report.next.is_empty() {
                println!("NEXT   {}", report.next);
            }
        } else {
            println!(
                "FAILED_CHECKS {}\nEXIT_CODE 2",
                report.failed_checks.join(",")
            );
        }
        if arguments.get_flag("explain") {
            for check in report
                .checks
                .iter()
                .filter(|check| check.status != Status::Pass)
            {
                println!("\nCHECK {}   {}", check.id, check.status);
                if !check.why.is_empty() {
                    println!("Why this matters:\n  {}", check.why);
                }
                if !check.evidence.is_empty() {
                    println!("\nEvidence:");
                    for line in &check.evidence {
                        println!("  - {line}");
                    }
                }
                if !check.next.is_empty() {
                    println!("\nWhat to do next:");
                    for (index, line) in check.next.iter().enumerate() {
                        println!("  {}. {line}", index + 1);
                    }
                }
            }
        }
    }
    Ok(if report.passed() { 0 } else { 2 })
}

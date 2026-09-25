use std::{collections::BTreeMap, env, fs, path::PathBuf};

use anyhow::{Context, Result};
use http::HeaderName;
use serde_json::Value;

use super::Config;

pub(super) fn validate_profile(config: &Config, raw: &Value) -> Result<()> {
    for (name, pointer) in [
        ("control_plane.base_url", "/control_plane/base_url"),
        ("control_plane.url_path", "/control_plane/url_path"),
        ("control_plane.api_key", "/control_plane/api_key"),
        ("control_plane.client_cert", "/control_plane/client_cert"),
        ("control_plane.client_key", "/control_plane/client_key"),
        ("health.listen_addr", "/health/listen_addr"),
        ("health.unix_socket", "/health/unix_socket"),
    ] {
        if let Some(value) = raw.pointer(pointer).and_then(Value::as_str) {
            syntax(name, value)?;
        }
    }
    validate_headers(config, false)?;
    for server in &config.mcp.server_urls {
        syntax("mcp.server_urls.url", &server.url)?;
        if let Some(socket) = &server.unix_socket {
            syntax("mcp.server_urls.unix_socket", socket)?;
        }
    }
    for command in &config.mcp.commands {
        syntax("mcp.commands.command", &command.command)?;
    }
    for target in &config.harpoon.targets {
        anyhow::ensure!(
            !target.label.trim().is_empty(),
            "harpoon.targets entry requires label"
        );
        if let Some(template) = &target.template {
            anyhow::ensure!(
                target.url.is_empty() && target.unix_socket.is_none(),
                "harpoon.targets entry {:?}: template cannot be combined with url or unix_socket",
                target.label
            );
            header_syntax("harpoon.targets.template.headers", &template.headers, false)?;
        } else {
            anyhow::ensure!(
                !target.url.trim().is_empty(),
                "harpoon.targets entry {:?} requires url or template",
                target.label
            );
            syntax("harpoon.targets.url", &target.url)?;
            if let Some(socket) = &target.unix_socket {
                syntax("harpoon.targets.unix_socket", socket)?;
            }
        }
    }
    Ok(())
}

pub(super) fn validate_headers(config: &Config, runtime: bool) -> Result<()> {
    let control = if runtime {
        "control-plane.extra-headers"
    } else {
        "control_plane.extra_headers"
    };
    let mcp = if runtime {
        "mcp.extra-headers"
    } else {
        "mcp.extra_headers"
    };
    let discovery = if runtime {
        "mcp.discovery-extra-headers"
    } else {
        "mcp.discovery_extra_headers"
    };
    header_syntax(control, &config.control_plane.extra_headers, true)?;
    header_syntax(mcp, &config.mcp.extra_headers, false)?;
    header_syntax(discovery, &config.mcp.discovery_extra_headers, false)?;
    for target in &config.harpoon.targets {
        if let Some(template) = &target.template {
            header_syntax("harpoon.targets.template.headers", &template.headers, false)?;
        }
    }
    Ok(())
}

fn syntax(source: &str, value: &str) -> Result<()> {
    let value = value.trim();
    anyhow::ensure!(!value.is_empty(), "{source} cannot be empty");
    anyhow::ensure!(
        !value.contains(['\r', '\n']),
        "{source} cannot contain CR or LF"
    );
    let Some((kind, reference)) = value.split_once(':') else {
        return Ok(());
    };
    if kind == "env" {
        let name = reference.trim();
        anyhow::ensure!(
            name.as_bytes()
                .first()
                .is_some_and(|value| value.is_ascii_alphabetic() || *value == b'_')
                && name
                    .bytes()
                    .all(|value| value.is_ascii_alphanumeric() || value == b'_'),
            "invalid {source} reference {value:?}: environment variable name is invalid"
        );
    } else if kind == "file" {
        anyhow::ensure!(
            !reference.trim().is_empty(),
            "invalid {source} reference {value:?}: file path is required"
        );
    }
    Ok(())
}

fn header_syntax(source: &str, headers: &BTreeMap<String, String>, control: bool) -> Result<()> {
    let mut normalized = BTreeMap::new();
    for (name, value) in headers {
        let original = name;
        let normalized_name = HeaderName::try_from(name.trim())?.to_string();
        let canonical = crate::harpoon::headers::canonical(&normalized_name);
        if let Some(previous) = normalized.insert(canonical.clone(), value) {
            anyhow::ensure!(
                previous == value,
                "{source} contains conflicting values for case-insensitive HTTP header {canonical:?}"
            );
        }
        if control {
            anyhow::ensure!(
                !matches!(
                    normalized_name.as_str(),
                    "authorization"
                        | "accept"
                        | "user-agent"
                        | "x-tunnel-client-name"
                        | "x-tunnel-client-version"
                        | "x-tunnel-client-wire-protocol-version"
                        | "x-tunnel-mcp-server-info"
                ),
                "{source} {original:?} cannot override control-plane authentication or client metadata headers"
            );
        }
        if !value.trim().is_empty() {
            syntax(&format!("{source}.{canonical}"), value)?;
        }
    }
    Ok(())
}

pub fn resolve(value: &str) -> Result<String> {
    resolve_named("configuration value", value)
}

pub(super) fn resolve_named(source: &str, value: &str) -> Result<String> {
    let value = value.trim();
    anyhow::ensure!(!value.is_empty(), "{source} cannot be empty");
    let Some((kind, name)) = value.split_once(':') else {
        return Ok(value.into());
    };
    let resolved = if kind == "env" {
        let name = name.trim();
        anyhow::ensure!(
            !name.is_empty(),
            "invalid {source} reference {value:?}: environment variable name is required"
        );
        let resolved = env::var(name).with_context(|| {
            format!(
                "invalid {source} reference {value:?}: environment variable {name:?} is not set"
            )
        })?;
        anyhow::ensure!(
            !resolved.trim().is_empty(),
            "invalid {source} reference {value:?}: environment variable {name:?} is empty"
        );
        resolved
    } else if kind == "file" {
        let name = name.trim();
        anyhow::ensure!(
            !name.is_empty(),
            "invalid {source} reference {value:?}: file path is required"
        );
        let resolved = fs::read_to_string(name)
            .with_context(|| format!("invalid {source} reference {value:?}: read file"))?;
        anyhow::ensure!(
            !resolved.trim().is_empty(),
            "invalid {source} reference {value:?}: file is empty"
        );
        resolved
    } else {
        return Ok(value.into());
    };
    Ok(resolved.trim().to_owned())
}

pub fn path(value: &str) -> Result<PathBuf> {
    let value = value.trim();
    if let Some((kind, name)) = value.split_once(':') {
        if kind == "file" {
            anyhow::ensure!(!name.trim().is_empty(), "file path is required after file:");
            return Ok(PathBuf::from(name.trim()));
        }
        if kind == "env" {
            return resolve(value).map(PathBuf::from);
        }
    }
    Ok(PathBuf::from(value))
}

pub(super) fn read(config: &mut Config) -> Result<()> {
    for (name, value) in [
        ("control_plane.base_url", &mut config.control_plane.base_url),
        ("control_plane.url_path", &mut config.control_plane.url_path),
    ] {
        if let Some(value) = value {
            *value = resolve_named(name, value)?;
        }
    }
    if !config.control_plane.api_key.is_empty() {
        config.control_plane.api_key =
            resolve_named("control_plane.api_key", &config.control_plane.api_key)?;
    }

    config.health.listen_addr = resolve_named("health.listen_addr", &config.health.listen_addr)?;
    if let Some(socket) = &mut config.health.unix_socket {
        *socket = resolve_named("health.unix_socket", socket)?;
    }
    for server in &mut config.mcp.server_urls {
        server.url = resolve_named("mcp.server_urls.url", &server.url)?;
        if let Some(socket) = &mut server.unix_socket {
            *socket = path(socket)?.to_string_lossy().into_owned();
        }
    }
    for command in &mut config.mcp.commands {
        command.command = resolve_named("mcp.commands.command", &command.command)?;
    }
    config.normalize()
}

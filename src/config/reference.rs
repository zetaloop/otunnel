use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result};

use super::Config;

pub fn resolve(value: &str) -> Result<String> {
    let value = value.trim();
    let Some((kind, name)) = value.split_once(':') else {
        return Ok(value.into());
    };
    let resolved = if kind.eq_ignore_ascii_case("env") {
        let name = name.trim();
        anyhow::ensure!(
            !name.is_empty(),
            "environment variable name is required after env:"
        );
        env::var(name).with_context(|| format!("read environment variable {name}"))?
    } else if kind.eq_ignore_ascii_case("file") {
        let name = name.trim();
        anyhow::ensure!(!name.is_empty(), "file path is required after file:");
        fs::read_to_string(name).with_context(|| format!("read {name}"))?
    } else {
        return Ok(value.into());
    };
    anyhow::ensure!(
        !resolved.trim().is_empty(),
        "reference {value:?} resolved to an empty value"
    );
    Ok(resolved.trim().to_owned())
}

pub fn path(value: &str) -> Result<PathBuf> {
    let value = value.trim();
    if let Some((kind, name)) = value.split_once(':') {
        if kind.eq_ignore_ascii_case("file") {
            anyhow::ensure!(!name.trim().is_empty(), "file path is required after file:");
            return Ok(PathBuf::from(name.trim()));
        }
        if kind.eq_ignore_ascii_case("env") {
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
            *value = resolve(value).with_context(|| name.to_owned())?;
            anyhow::ensure!(!value.is_empty(), "{name} cannot be empty");
        }
    }
    config.health.listen_addr =
        resolve(&config.health.listen_addr).context("health.listen_addr")?;
    anyhow::ensure!(
        !config.health.listen_addr.is_empty(),
        "health.listen_addr cannot be empty"
    );
    if let Some(socket) = &mut config.health.unix_socket {
        *socket = resolve(socket).context("health.unix_socket")?;
        anyhow::ensure!(!socket.is_empty(), "health.unix_socket cannot be empty");
    }
    for server in &mut config.mcp.server_urls {
        server.url = resolve(&server.url).context("mcp.server_urls.url")?;
        anyhow::ensure!(!server.url.is_empty(), "mcp.server_urls entry requires url");
        if let Some(socket) = &mut server.unix_socket {
            *socket = path(socket)?.to_string_lossy().into_owned();
        }
    }
    for command in &mut config.mcp.commands {
        command.command = resolve(&command.command).context("mcp.commands.command")?;
        anyhow::ensure!(
            !command.command.is_empty(),
            "mcp.commands entry requires command"
        );
    }
    config.normalize()
}

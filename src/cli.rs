mod admin;
mod cloudflared;
mod doctor;
mod health;
mod management;
mod profiles;

use std::{
    env, fs,
    io::{self, IsTerminal, Write},
    path::PathBuf,
    sync::Mutex,
};

use anyhow::{Context, Result, bail};
use clap::{Arg, ArgAction, ArgMatches, Command};
use otunnel::{
    CancellationToken, Tunnel,
    config::{Config, Log},
    health::Server,
};
use serde_json::{Value, json};
use tracing_subscriber::{EnvFilter, fmt::writer::BoxMakeWriter};

#[derive(Clone, Copy)]
enum Kind {
    Text,
    Number,
    Boolean,
    List,
    Headers,
    Servers,
    Commands,
    Targets,
}
use Kind::*;

// CLI spellings and environment names are the public tunnel-client configuration interface.
const SETTINGS: &[(&str, &str, &str, Kind, &str)] = &[
    (
        "control-plane.tunnel-id",
        "CONTROL_PLANE_TUNNEL_ID",
        "/control_plane/tunnel_id",
        Text,
        "OpenAI tunnel identifier",
    ),
    (
        "control-plane.api-key",
        "CONTROL_PLANE_API_KEY",
        "/control_plane/api_key",
        Text,
        "Runtime key, env:NAME, or file:PATH",
    ),
    (
        "control-plane.base-url",
        "CONTROL_PLANE_BASE_URL",
        "/control_plane/base_url",
        Text,
        "Control-plane base URL",
    ),
    (
        "control-plane.url-path",
        "CONTROL_PLANE_URL_PATH",
        "/control_plane/url_path",
        Text,
        "Path prefix before /v1 routes",
    ),
    (
        "control-plane.organization-id",
        "CONTROL_PLANE_ORGANIZATION_ID",
        "/control_plane/organization_id",
        Text,
        "OpenAI organization identifier",
    ),
    (
        "control-plane.client-cert",
        "CONTROL_PLANE_CLIENT_CERT",
        "/control_plane/client_cert",
        Text,
        "Control-plane PEM client certificate",
    ),
    (
        "control-plane.client-key",
        "CONTROL_PLANE_CLIENT_KEY",
        "/control_plane/client_key",
        Text,
        "Control-plane PEM client private key",
    ),
    (
        "control-plane.http-proxy",
        "CONTROL_PLANE_HTTP_PROXY",
        "/control_plane/http_proxy",
        Text,
        "Control-plane outbound proxy",
    ),
    (
        "control-plane.extra-headers",
        "CONTROL_PLANE_EXTRA_HEADERS",
        "/control_plane/extra_headers",
        Headers,
        "Control-plane header: Name: Value",
    ),
    (
        "control-plane.max-inflight",
        "CONTROL_PLANE_MAX_INFLIGHT_REQUESTS",
        "/control_plane/max_inflight_requests",
        Number,
        "Maximum outstanding tunnel commands",
    ),
    (
        "control-plane.poll-channel",
        "CONTROL_PLANE_POLL_CHANNELS",
        "/control_plane/poll_channels",
        List,
        "Channels to receive requests for",
    ),
    (
        "control-plane.poll-timeout",
        "CONTROL_PLANE_POLL_TIMEOUT",
        "/control_plane/poll_timeout",
        Text,
        "Long-poll duration",
    ),
    (
        "control-plane.initial-poll-timeout",
        "CONTROL_PLANE_INITIAL_POLL_TIMEOUT",
        "/control_plane/initial_poll_timeout",
        Text,
        "First long-poll duration",
    ),
    (
        "control-plane.poll-deadline-guardrail",
        "CONTROL_PLANE_POLL_DEADLINE_GUARDRAIL",
        "/control_plane/poll_deadline_guardrail",
        Text,
        "Network allowance after the requested poll duration",
    ),
    (
        "mcp.server-url",
        "MCP_SERVER_URL",
        "/mcp/server_urls",
        Servers,
        "HTTP binding: channel=main,url=...,unix-socket=...",
    ),
    (
        "mcp.command",
        "MCP_COMMAND",
        "/mcp/commands",
        Commands,
        "Process binding: channel=main,command=...",
    ),
    (
        "mcp.extra-headers",
        "MCP_EXTRA_HEADERS",
        "/mcp/extra_headers",
        Headers,
        "MCP header: Name: Value",
    ),
    (
        "mcp.discovery-extra-headers",
        "MCP_DISCOVERY_EXTRA_HEADERS",
        "/mcp/discovery_extra_headers",
        Headers,
        "Discovery header: Name: Value",
    ),
    (
        "mcp.http-proxy",
        "MCP_HTTP_PROXY",
        "/mcp/http_proxy",
        Text,
        "MCP outbound proxy",
    ),
    (
        "mcp.client-cert",
        "MCP_CLIENT_CERT",
        "/mcp/client_cert",
        Text,
        "MCP PEM client certificate",
    ),
    (
        "mcp.client-key",
        "MCP_CLIENT_KEY",
        "/mcp/client_key",
        Text,
        "MCP PEM client private key",
    ),
    (
        "mcp.max-concurrent-requests",
        "MCP_MAX_CONCURRENT_REQUESTS",
        "/mcp/max_concurrent_requests",
        Number,
        "Maximum active requests per MCP channel",
    ),
    (
        "mcp.startup-wait-timeout",
        "MCP_STARTUP_WAIT_TIMEOUT",
        "/mcp/startup_wait_timeout",
        Text,
        "MCP startup and discovery duration",
    ),
    (
        "mcp.connection-max-ttl",
        "MCP_CONNECTION_MAX_TTL",
        "/mcp/connection_max_ttl",
        Text,
        "Maximum lifetime of an MCP transport connection",
    ),
    (
        "harpoon.target",
        "HARPOON_TARGETS",
        "/harpoon/targets",
        Targets,
        "HTTP target: label=...,url=...,desc=...",
    ),
    (
        "harpoon.http-proxy",
        "HARPOON_HTTP_PROXY",
        "/harpoon/http_proxy",
        Text,
        "Harpoon outbound proxy",
    ),
    (
        "harpoon.max-response-bytes",
        "HARPOON_MAX_RESPONSE_BYTES",
        "/harpoon/max_response_bytes",
        Number,
        "Harpoon response size limit",
    ),
    (
        "harpoon.max-redirects",
        "HARPOON_MAX_REDIRECTS",
        "/harpoon/max_redirects",
        Number,
        "Harpoon redirect limit",
    ),
    (
        "harpoon.hosts-include-loopback",
        "HARPOON_HOSTS_INCLUDE_LOOPBACK",
        "/harpoon/hosts_include_loopback",
        Boolean,
        "Register loopback OAuth hosts with Harpoon",
    ),
    (
        "harpoon.hosts-include-private",
        "HARPOON_HOSTS_INCLUDE_PRIVATE",
        "/harpoon/hosts_include_private",
        Boolean,
        "Register private OAuth hosts with Harpoon",
    ),
    (
        "harpoon.hosts-include-suffix",
        "HARPOON_HOSTS_INCLUDE_SUFFIX",
        "/harpoon/hosts_include_suffix",
        List,
        "Private OAuth host suffix",
    ),
    (
        "harpoon.hosts-include-regex",
        "HARPOON_HOSTS_INCLUDE_REGEX",
        "/harpoon/hosts_include_regex",
        List,
        "Private OAuth host expression",
    ),
    (
        "health.listen-addr",
        "HEALTH_LISTEN_ADDR",
        "/health/listen_addr",
        Text,
        "Health address; port 0 selects an ephemeral port; empty disables TCP",
    ),
    (
        "health.unix-socket",
        "HEALTH_UNIX_SOCKET",
        "/health/unix_socket",
        Text,
        "Health Unix socket instead of TCP",
    ),
    (
        "health.url-file",
        "HEALTH_URL_FILE",
        "/health/url_file",
        Text,
        "Write the bound health URL to a file",
    ),
    (
        "health.show-details",
        "HEALTH_SHOW_DETAILS",
        "/health/show_details",
        Boolean,
        "Include channel details in readiness responses",
    ),
    (
        "log.level",
        "LOG_LEVEL",
        "/log/level",
        Text,
        "Log filter, such as info or otunnel=debug",
    ),
    (
        "log.format",
        "LOG_FORMAT",
        "/log/format",
        Text,
        "Log format: text, struct-text, or json",
    ),
    (
        "log.file",
        "LOG_FILE",
        "/log/file",
        Text,
        "Append logs to a file, stdout, or stderr",
    ),
    (
        "pid.file",
        "PID_FILE",
        "/process/pid_file",
        Text,
        "Write this process ID to a file",
    ),
    (
        "cloudflared.managed",
        "CLOUDFLARED_MANAGED",
        "/cloudflared/managed",
        Boolean,
        "Fetch the Cloudflare runtime token from the control plane",
    ),
    (
        "cloudflared.token",
        "CLOUDFLARED_TUNNEL_TOKEN",
        "/cloudflared/token",
        Text,
        "Cloudflare token, env:NAME, or file:PATH",
    ),
    (
        "cloudflared.path",
        "CLOUDFLARED_PATH",
        "/cloudflared/path",
        Text,
        "Cloudflared executable",
    ),
    (
        "cloudflared.ready-timeout",
        "CLOUDFLARED_READY_TIMEOUT",
        "/cloudflared/ready_timeout",
        Text,
        "Cloudflared startup duration",
    ),
    (
        "ca-bundle",
        "CA_BUNDLE",
        "/ca_bundle",
        Text,
        "Additional PEM CA bundle",
    ),
    (
        "http-proxy",
        "TUNNEL_CLIENT_HTTP_PROXY",
        "/http_proxy",
        Text,
        "Global outbound HTTP proxy",
    ),
    (
        "allow-remote-ui",
        "ALLOW_REMOTE_UI",
        "/admin_ui/allow_remote",
        Boolean,
        "Allow remote access to the admin UI",
    ),
    (
        "open-web-ui",
        "OPEN_WEB_UI",
        "/admin_ui/open_browser",
        Boolean,
        "Open the admin UI after startup",
    ),
    (
        "admin-ui.log-buffer-events",
        "ADMIN_UI_LOG_BUFFER_EVENTS",
        "/admin_ui/log_buffer_events",
        Number,
        "Number of admin log events retained",
    ),
    (
        "proxy.check-interval",
        "PROXY_CHECK_INTERVAL",
        "/proxy/check_interval",
        Text,
        "Proxy health check interval",
    ),
    (
        "harpoon.capture-payloads",
        "HARPOON_CAPTURE_PAYLOADS",
        "/harpoon/capture_payloads",
        Boolean,
        "Retain Harpoon request and response payloads",
    ),
    (
        "harpoon.allow-plaintext-http",
        "HARPOON_ALLOW_PLAINTEXT_HTTP",
        "/harpoon/allow_plaintext_http",
        Boolean,
        "Allow HTTP Harpoon targets",
    ),
    (
        "harpoon.additional-transport",
        "HARPOON_ADDITIONAL_TRANSPORTS",
        "/harpoon/additional_transports",
        List,
        "Additional Harpoon transport URL",
    ),
    (
        "log.http-raw-unsafe",
        "LOG_HTTP_RAW_UNSAFE",
        "/log/http_raw_unsafe",
        Boolean,
        "Log raw HTTP requests and responses",
    ),
    (
        "mcp.stdio-send-initialized-notification",
        "MCP_STDIO_SEND_INITIALIZED_NOTIFICATION",
        "/mcp/stdio_send_initialized_notification",
        Boolean,
        "Complete downstream stdio initialization",
    ),
];

const ALIASES: &[(&str, &str)] = &[
    ("control-plane.base-url", "control-plane-base-url"),
    ("control-plane.url-path", "control-plane-url-path"),
    ("control-plane.tunnel-id", "control-plane-tunnel-id"),
    (
        "control-plane.organization-id",
        "control-plane-organization-id",
    ),
    ("control-plane.api-key", "control-plane-api-key"),
    ("control-plane.client-cert", "control-plane-client-cert"),
    ("control-plane.client-key", "control-plane-client-key"),
    ("mcp.server-url", "mcp-server-url"),
    ("mcp.command", "mcp-command"),
    ("mcp.extra-headers", "mcp-extra-headers"),
    ("mcp.discovery-extra-headers", "mcp-discovery-extra-headers"),
    ("health.listen-addr", "health-listen-addr"),
    ("health.unix-socket", "health-unix-socket"),
    ("health.url-file", "health-url-file"),
    ("health.show-details", "health-show-details"),
];

fn argument(name: &'static str, kind: Kind) -> Arg {
    let argument = Arg::new(name).long(name);
    match kind {
        Boolean => argument
            .num_args(0..=1)
            .require_equals(true)
            .default_missing_value("true")
            .value_parser([
                "1", "t", "T", "TRUE", "true", "True", "0", "f", "F", "FALSE", "false", "False",
            ]),
        List | Headers | Servers | Commands | Targets => argument.action(ArgAction::Append),
        _ => argument,
    }
}

pub fn command() -> Command {
    let source = || {
        [
            Arg::new("config")
                .long("config")
                .env("TUNNEL_CLIENT_CONFIG")
                .help("YAML configuration file"),
            Arg::new("profile")
                .long("profile")
                .env("TUNNEL_CLIENT_PROFILE")
                .help("Named YAML profile"),
            Arg::new("profile-dir")
                .long("profile-dir")
                .env("TUNNEL_CLIENT_PROFILE_DIR")
                .help("Profile directory; defaults to $XDG_CONFIG_HOME/tunnel-client"),
            Arg::new("profile-file")
                .long("profile-file")
                .env("TUNNEL_CLIENT_PROFILE_FILE")
                .help("Explicit profile YAML file"),
        ]
    };
    let configured = |command: Command| {
        command.args(source()).args(SETTINGS.iter().flat_map(
            |(name, environment, _, kind, help)| {
                let mut options = vec![
                    argument(name, *kind)
                        .env(*environment)
                        .hide_env_values(true)
                        .help(*help),
                ];
                options.extend(
                    ALIASES
                        .iter()
                        .filter(|(canonical, _)| canonical == name)
                        .map(|(_, alias)| argument(alias, *kind).hide(true)),
                );
                options
            },
        ))
    };
    Command::new("otunnel")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Connect local MCP services to OpenAI tunnels")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(configured(
            Command::new("run").about("Run the configured tunnel and MCP processes"),
        ))
        .subcommand(
            configured(
                Command::new("doctor")
                    .about("Diagnose the configured transports, services, and control plane"),
            )
            .arg(flag("json").help("Emit a JSON report"))
            .arg(flag("explain").help("Explain failed checks and their evidence")),
        )
        .subcommand(health::command())
        .subcommand(cloudflared::command())
        .subcommand(admin::command())
        .subcommand(management::profiles_command())
        .subcommand(management::runtimes_command())
        .subcommand(profiles::command())
        .subcommand(profiles::init_command())
        .subcommand(
            Command::new("completion")
                .about("Generate shell completions")
                .arg(
                    Arg::new("shell")
                        .required(true)
                        .value_parser(clap::value_parser!(clap_complete::Shell)),
                ),
        )
}

fn source(matches: &ArgMatches) -> Result<Option<PathBuf>> {
    use clap::parser::ValueSource;

    for layer in [ValueSource::CommandLine, ValueSource::EnvVariable] {
        let selected: Vec<_> = ["config", "profile", "profile-file"]
            .into_iter()
            .filter(|name| matches.value_source(name) == Some(layer))
            .filter_map(|name| {
                matches
                    .get_one::<String>(name)
                    .map(|value| (name, value.trim().to_owned()))
            })
            .filter(|(_, value)| layer == ValueSource::CommandLine || !value.is_empty())
            .collect();
        anyhow::ensure!(
            selected.len() <= 1,
            "config, profile, and profile-file select alternative configuration sources"
        );
        let Some((name, value)) = selected.into_iter().next() else {
            continue;
        };
        anyhow::ensure!(!value.is_empty(), "--{name} requires a value");
        return match name {
            "profile" => Ok(Some(otunnel::config::profile_path(
                &value,
                matches.get_one::<String>("profile-dir").map(String::as_str),
            )?)),
            "profile-file" => {
                let file = otunnel::config::expand_home(&value)?;
                anyhow::ensure!(
                    file.extension()
                        .is_some_and(|extension| extension == "yaml"),
                    "profile file must end with .yaml"
                );
                otunnel::config::profile_name(
                    file.file_stem()
                        .and_then(|name| name.to_str())
                        .context("invalid profile filename")?,
                )?;
                Ok(Some(file))
            }
            _ => Ok(Some(PathBuf::from(value))),
        };
    }
    Ok(None)
}

fn value<'a>(arguments: &'a ArgMatches, name: &str) -> &'a str {
    arguments
        .try_get_one::<String>(name)
        .ok()
        .flatten()
        .map_or("", String::as_str)
}

fn boolean(value: &str) -> std::result::Result<bool, String> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!("invalid boolean {value:?}")),
    }
}

fn flag(name: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .num_args(0..=1)
        .require_equals(true)
        .default_missing_value("true")
        .default_value("false")
        .value_parser(boolean)
}

fn load(matches: &ArgMatches) -> Result<Config> {
    if matches.value_source("profile-dir") == Some(clap::parser::ValueSource::CommandLine) {
        anyhow::ensure!(
            matches
                .get_one::<String>("profile-dir")
                .is_some_and(|directory| !directory.trim().is_empty()),
            "profile directory is required when --profile-dir is set"
        );
    }
    let source = source(matches)?;
    let config = source.map(Config::read).transpose()?.unwrap_or_default();
    let mut initial_poll_timeout = config.control_plane.initial_poll_timeout;
    let mut value = serde_json::to_value(config)?;
    for (name, _, pointer, kind, _) in SETTINGS {
        let selected = if matches.value_source(name) == Some(clap::parser::ValueSource::CommandLine)
        {
            name
        } else {
            ALIASES
                .iter()
                .find(|(canonical, alias)| {
                    canonical == name
                        && matches.value_source(alias)
                            == Some(clap::parser::ValueSource::CommandLine)
                })
                .map_or(name, |(_, alias)| alias)
        };
        let Some(arguments) = matches.get_many::<String>(selected) else {
            continue;
        };
        let mut arguments = arguments.cloned().collect::<Vec<_>>();
        if matches!(kind, List | Headers | Servers | Commands | Targets)
            && arguments.len() == 1
            && arguments[0].trim_start().starts_with('[')
        {
            arguments =
                serde_json::from_str(&arguments[0]).with_context(|| format!("parse --{name}"))?;
        }
        if matches.value_source(selected) == Some(clap::parser::ValueSource::EnvVariable) {
            match kind {
                Servers | Commands | Targets => {
                    arguments = arguments
                        .iter()
                        .flat_map(|value| value.lines())
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .collect()
                }
                List if *name != "control-plane.poll-channel" => {
                    arguments = arguments
                        .iter()
                        .flat_map(|value| value.split(';'))
                        .map(str::to_owned)
                        .collect()
                }
                Headers if arguments.len() == 1 && arguments[0].trim_start().starts_with('{') => {
                    let headers: std::collections::BTreeMap<String, String> =
                        serde_json::from_str(&arguments[0])?;
                    arguments = headers
                        .into_iter()
                        .map(|(name, value)| format!("{name}: {value}"))
                        .collect();
                }
                Headers => {
                    arguments = arguments
                        .iter()
                        .flat_map(|value| value.split([',', ';']))
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
                _ => {}
            }
        }
        let parsed = match kind {
            Text => json!(arguments[0]),
            Number => json!(
                arguments[0]
                    .parse::<u64>()
                    .with_context(|| format!("--{name} requires an unsigned integer"))?
            ),
            Boolean => json!(boolean(&arguments[0]).map_err(anyhow::Error::msg)?),
            List if *name == "control-plane.poll-channel" => json!(
                arguments
                    .iter()
                    .flat_map(|value| value.split(','))
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>()
            ),
            List => json!(
                arguments
                    .iter()
                    .map(|value| value.trim())
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>()
            ),
            Headers => {
                let mut headers = serde_json::Map::new();
                for argument in arguments {
                    let (name, value) = argument
                        .split_once(':')
                        .context("HTTP headers use Name: Value")?;
                    http::HeaderName::try_from(name.trim())?;
                    headers.insert(name.trim().to_owned(), json!(value.trim()));
                }
                Value::Object(headers)
            }
            Servers | Commands | Targets => Value::Array(
                arguments
                    .iter()
                    .map(|value| mapping(value, *kind))
                    .collect::<Result<_>>()?,
            ),
        };
        if *name == "control-plane.initial-poll-timeout" {
            initial_poll_timeout = serde_json::from_value(parsed)?;
            continue;
        }
        *value
            .pointer_mut(pointer)
            .context("configuration field is missing")? = parsed;
    }
    let mut config: Config = serde_json::from_value(value)?;
    config.control_plane.initial_poll_timeout = initial_poll_timeout;
    if config.control_plane.api_key.is_empty()
        && let Ok(key) = env::var("OPENAI_API_KEY")
    {
        config.control_plane.api_key = key;
    }
    Ok(config)
}

fn mapping(value: &str, kind: Kind) -> Result<Value> {
    let entry = value.trim();
    let qualified = [
        "url=",
        "command=",
        "channel=",
        "unix-socket=",
        "http-proxy=",
        "client-cert=",
        "client-key=",
    ]
    .iter()
    .any(|prefix| entry.to_ascii_lowercase().starts_with(prefix));
    if matches!(kind, Commands) {
        let (channel, command) = if !qualified {
            ("main", value)
        } else if let Some(entry) = entry.strip_prefix("channel=") {
            let (channel, rest) = entry
                .split_once(',')
                .context("command entry is missing command")?;
            (
                channel.trim(),
                rest.trim()
                    .strip_prefix("command=")
                    .context("command entry requires command=...")?
                    .trim(),
            )
        } else {
            let command = entry
                .strip_prefix("command=")
                .context("command entry requires command=...")?
                .trim();
            command
                .rsplit_once(",channel=")
                .map_or(("main", command), |(command, channel)| {
                    (channel.trim(), command.trim())
                })
        };
        if qualified {
            for key in [
                "http-proxy",
                "url",
                "unix-socket",
                "client-cert",
                "client-key",
            ] {
                anyhow::ensure!(
                    !command.to_ascii_lowercase().contains(&format!(",{key}=")),
                    "unsupported stdio field {key}"
                );
            }
        }
        otunnel::config::command_args(command)?;
        return Ok(json!({"channel":otunnel::config::channel(channel)?, "command":command}));
    }
    if matches!(kind, Servers) && !qualified {
        return Ok(json!({"url":value}));
    }
    let mut result = serde_json::Map::new();
    for field in entry
        .split(',')
        .map(str::trim)
        .filter(|field| !field.is_empty())
    {
        let (key, value) = field
            .split_once('=')
            .context("channel fields use name=value")?;
        let mut key = key.trim().replace('-', "_");
        let mut value = value.trim();
        if matches!(kind, Targets) {
            key.make_ascii_lowercase();
            value = value.trim_matches(['\"', '\'']);
            if key == "desc" {
                key = "description".into();
            } else if !["label", "url", "unix_socket"].contains(&key.as_str()) {
                continue;
            }
        } else {
            anyhow::ensure!(
                !key.is_empty() && !value.is_empty(),
                "channel fields must not be empty"
            );
        }
        result.insert(key, json!(value));
    }
    anyhow::ensure!(
        result
            .get("url")
            .and_then(Value::as_str)
            .is_some_and(|url| !url.is_empty()),
        "target URL is required"
    );
    if matches!(kind, Targets) {
        anyhow::ensure!(
            result
                .get("label")
                .and_then(Value::as_str)
                .is_some_and(|label| !label.is_empty()),
            "target label is required"
        );
    }
    Ok(Value::Object(result))
}

pub async fn execute(matches: &ArgMatches) -> Result<u8> {
    let (name, matches) = matches.subcommand().context("missing command")?;
    if name == "completion" {
        let shell = *matches
            .get_one::<clap_complete::Shell>("shell")
            .context("missing shell")?;
        clap_complete::generate(shell, &mut command(), "otunnel", &mut io::stdout());
        return Ok(0);
    }
    match name {
        "health" => return health::execute(matches).await,
        "doctor" => return doctor::execute(matches).await,
        "cloudflared" => return cloudflared::execute(matches),
        "admin" => return admin::execute(matches).await,
        "admin-profiles" => return management::profiles(matches),
        "runtimes" => return management::runtimes(matches).await,
        "profiles" => return profiles::execute(matches),
        "init" => return profiles::init(matches),
        _ => {}
    }
    let config = load(matches)?;
    logger(&config.log)?;
    match name {
        "run" => {
            config.validate()?;
            let tunnel = Tunnel::new(config.clone())?;
            let stop = CancellationToken::new();
            let _pid = config
                .process
                .pid_file
                .as_ref()
                .map(|path| Record::write(path, std::process::id().to_string()))
                .transpose()?;
            let mut url_file = None;
            let health = if config.health.unix_socket.is_some()
                || !config.health.listen_addr.is_empty()
            {
                let server = Server::bind(&config, tunnel.status(), tunnel.harpoon()).await?;
                tracing::info!(url = %server.url(), socket = ?config.health.unix_socket, "health service available");
                url_file = config
                    .health
                    .url_file
                    .as_ref()
                    .map(|path| Record::write(path, server.url().to_string()))
                    .transpose()?;
                let stop = stop.clone();
                Some(tokio::spawn(async move {
                    let result = server.serve(stop.clone()).await;
                    stop.cancel();
                    result
                }))
            } else {
                None
            };
            let running = tunnel.run(stop.clone());
            tokio::pin!(running);
            let result = tokio::select! {
                result = &mut running => result,
                signal = signal() => { stop.cancel(); signal.and(running.await) }
            };
            stop.cancel();
            let health = match health {
                Some(task) => task.await.context("health service task failed")?,
                None => Ok(()),
            };
            drop(url_file);
            result.and(health)?;
            Ok(0)
        }
        _ => unreachable!(),
    }
}

fn logger(config: &Log) -> Result<()> {
    let file = config.file.as_deref().filter(|value| !value.is_empty());
    let format = if config.format.is_empty() && file.is_some() {
        "struct-text"
    } else {
        &config.format
    };
    let (writer, terminal): (Box<dyn Write + Send>, bool) = if let Some(path) = file {
        (
            Box::new(
                fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .with_context(|| format!("open log {path}"))?,
            ),
            false,
        )
    } else if format.is_empty() {
        (Box::new(io::stderr()), io::stderr().is_terminal())
    } else {
        (Box::new(io::stdout()), io::stdout().is_terminal())
    };
    let writer = BoxMakeWriter::new(Mutex::new(writer));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(&config.level)?)
        .with_writer(writer)
        .with_ansi(terminal);
    match format {
        "json" => subscriber
            .json()
            .try_init()
            .map_err(|error| anyhow::anyhow!(error))?,
        "text" | "struct-text" | "" => subscriber
            .try_init()
            .map_err(|error| anyhow::anyhow!(error))?,
        format => bail!("unknown log format {format}"),
    }
    Ok(())
}

async fn signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = terminate.recv() => {} }
    }
    #[cfg(windows)]
    {
        let mut interrupt = tokio::signal::windows::ctrl_break()?;
        let mut close = tokio::signal::windows::ctrl_close()?;
        let mut shutdown = tokio::signal::windows::ctrl_shutdown()?;
        tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = interrupt.recv() => {}, _ = close.recv() => {}, _ = shutdown.recv() => {} }
    }
    Ok(())
}

struct Record {
    path: PathBuf,
    content: String,
}
impl Record {
    fn write(path: &str, content: String) -> Result<Self> {
        let parent = std::path::Path::new(path)
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        fs::create_dir_all(parent)?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(content.as_bytes())?;
        file.persist(path)
            .with_context(|| format!("write {path}"))?;
        Ok(Self {
            path: PathBuf::from(path),
            content,
        })
    }
}
impl Drop for Record {
    fn drop(&mut self) {
        if fs::read_to_string(&self.path).is_ok_and(|content| content == self.content)
            && let Err(error) = fs::remove_file(&self.path)
        {
            tracing::warn!(%error, path = %self.path.display(), "could not remove runtime file");
        }
    }
}

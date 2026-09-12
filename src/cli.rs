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
    health,
    runtime::Check,
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
        "OTUNNEL_HTTP_PROXY",
        "/http_proxy",
        Text,
        "Global outbound HTTP proxy",
    ),
];

pub fn command() -> Command {
    let source = || {
        [
            Arg::new("config")
                .long("config")
                .env("OTUNNEL_CONFIG")
                .help("YAML configuration file"),
            Arg::new("profile")
                .long("profile")
                .env("TUNNEL_CLIENT_PROFILE")
                .help("Named YAML profile"),
            Arg::new("profile-dir")
                .long("profile-dir")
                .env("TUNNEL_CLIENT_PROFILE_DIR")
                .help("Profile directory; defaults to $XDG_CONFIG_HOME/otunnel"),
            Arg::new("profile-file")
                .long("profile-file")
                .env("TUNNEL_CLIENT_PROFILE_FILE")
                .help("Explicit profile YAML file"),
        ]
    };
    let configured = |command: Command| {
        command
            .args(source())
            .args(SETTINGS.iter().map(|(name, environment, _, kind, help)| {
                let mut argument = Arg::new(*name)
                    .long(*name)
                    .env(*environment)
                    .hide_env_values(true)
                    .help(*help);
                match kind {
                    Boolean => {
                        argument = argument
                            .num_args(0..=1)
                            .default_missing_value("true")
                            .value_parser(["true", "false"])
                    }
                    List | Headers | Servers | Commands | Targets => {
                        argument = argument.action(ArgAction::Append)
                    }
                    _ => {}
                }
                argument
            }))
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
            .arg(
                Arg::new("json")
                    .long("json")
                    .action(ArgAction::SetTrue)
                    .help("Emit a JSON report"),
            ),
        )
        .subcommand(
            configured(Command::new("health").about("Read a running tunnel's health status"))
                .arg(Arg::new("url").long("url").help("Health base URL"))
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Emit a JSON report"),
                ),
        )
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

fn load(matches: &ArgMatches) -> Result<Config> {
    let source = matches
        .get_one::<String>("config")
        .cloned()
        .or_else(|| env::var("TUNNEL_CLIENT_CONFIG").ok())
        .or_else(|| matches.get_one::<String>("profile-file").cloned())
        .map(PathBuf::from);
    let source = match source {
        Some(source) => Some(source),
        None => match matches.get_one::<String>("profile") {
            Some(profile) => {
                let directory = matches
                    .get_one::<String>("profile-dir")
                    .map(PathBuf::from)
                    .or_else(|| {
                        env::var_os("XDG_CONFIG_HOME")
                            .map(|path| PathBuf::from(path).join("otunnel"))
                    })
                    .or_else(|| {
                        env::var_os("HOME")
                            .or_else(|| env::var_os("USERPROFILE"))
                            .map(|home| PathBuf::from(home).join(".config/otunnel"))
                    })
                    .context("profile directory is unavailable; use --profile-dir")?;
                Some(directory.join(format!("{profile}.yaml")))
            }
            None => None,
        },
    };
    let config = source.map(Config::read).transpose()?.unwrap_or_default();
    let mut value = serde_json::to_value(config)?;
    for (name, _, pointer, kind, _) in SETTINGS {
        let Some(arguments) = matches.get_many::<String>(name) else {
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
        let parsed = match kind {
            Text => json!(arguments[0]),
            Number => json!(
                arguments[0]
                    .parse::<u64>()
                    .with_context(|| format!("--{name} requires an unsigned integer"))?
            ),
            Boolean => json!(arguments[0].parse::<bool>()?),
            List => json!(
                arguments
                    .iter()
                    .flat_map(|value| value.split(','))
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>()
            ),
            Headers => {
                let mut headers = value
                    .pointer(pointer)
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                for argument in arguments {
                    let (name, value) = argument
                        .split_once(':')
                        .context("HTTP headers use Name: Value")?;
                    let name = http::HeaderName::try_from(name.trim())?.to_string();
                    headers.retain(|key, _| !key.eq_ignore_ascii_case(&name));
                    headers.insert(name, json!(value.trim()));
                }
                Value::Object(headers)
            }
            Servers | Commands | Targets => Value::Array(
                arguments
                    .iter()
                    .map(|value| {
                        mapping(
                            value,
                            if matches!(kind, Commands) {
                                "command"
                            } else {
                                "url"
                            },
                        )
                    })
                    .collect::<Result<_>>()?,
            ),
        };
        *value
            .pointer_mut(pointer)
            .context("configuration field is missing")? = parsed;
    }
    let mut config: Config = serde_json::from_value(value)?;
    if config.control_plane.api_key.is_empty()
        && let Ok(key) = env::var("OPENAI_API_KEY")
    {
        config.control_plane.api_key = key;
    }
    Ok(config)
}

fn mapping(value: &str, primary: &str) -> Result<Value> {
    if value.trim_start().starts_with('{') {
        return Ok(serde_json::from_str(value)?);
    }
    if !value.starts_with("channel=")
        && !value.starts_with("label=")
        && !value.starts_with(&format!("{primary}="))
        && !value.starts_with('"')
    {
        return Ok(json!({primary:value}));
    }
    let mut result = serde_json::Map::new();
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(value.as_bytes());
    let record = csv.records().next().context("empty channel definition")??;
    for field in &record {
        let (key, value) = field
            .split_once('=')
            .context("channel fields use name=value")?;
        result.insert(key.trim().replace('-', "_"), json!(value.trim()));
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
                let server = health::Server::bind(&config.health, tunnel.status()).await?;
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
        "doctor" => {
            let tunnel = Tunnel::new(config.clone())?;
            let health =
                if config.health.unix_socket.is_some() || !config.health.listen_addr.is_empty() {
                    match health::Server::bind(&config.health, tunnel.status()).await {
                        Ok(server) => Some(Ok(server)),
                        Err(error) => Some(Err(error)),
                    }
                } else {
                    None
                };
            let mut report = tunnel.diagnose().await;
            if let Some(health) = health {
                let (passed, detail) = match health {
                    Ok(server) => (true, format!("bound {}", server.url())),
                    Err(error) => (false, format!("{error:#}")),
                };
                report.checks.push(Check {
                    name: "health_listener".into(),
                    passed,
                    detail,
                });
            }
            if matches.get_flag("json") {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for check in &report.checks {
                    println!(
                        "CHECK {:<24} {} {}",
                        check.name,
                        if check.passed { "PASS" } else { "FAIL" },
                        check.detail
                    );
                }
                for (name, channel) in &report.channels {
                    println!(
                        "CHANNEL {name} HTTP {} tools={} oauth={}",
                        channel.status,
                        channel
                            .tools
                            .map_or_else(|| "-".into(), |count| count.to_string()),
                        channel.authentication_required
                    );
                }
                println!("RESULT {}", if report.passed() { "pass" } else { "fail" });
            }
            Ok(if report.passed() { 0 } else { 2 })
        }
        "health" => {
            let base = if let Some(url) = matches.get_one::<String>("url") {
                url.clone()
            } else if let Some(file) = &config.health.url_file {
                fs::read_to_string(file)?.trim().to_owned()
            } else if config.health.unix_socket.is_some() {
                "http://localhost".into()
            } else {
                anyhow::ensure!(
                    !config.health.listen_addr.ends_with(":0"),
                    "ephemeral health addresses require --url or health.url_file"
                );
                format!("http://{}", config.health.listen_addr)
            };
            let status = health::probe(&config.health, &base).await?;
            let ready = status
                .get("ready")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if matches.get_flag("json") {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("{} {base}", if ready { "READY" } else { "NOT_READY" });
            }
            Ok(if ready { 0 } else { 2 })
        }
        _ => unreachable!(),
    }
}

fn logger(config: &Log) -> Result<()> {
    let (writer, terminal): (Box<dyn Write + Send>, bool) =
        match config.file.as_deref().filter(|value| !value.is_empty()) {
            None | Some("stderr") => (Box::new(io::stderr()), io::stderr().is_terminal()),
            Some("stdout") => (Box::new(io::stdout()), io::stdout().is_terminal()),
            Some(path) => (
                Box::new(
                    fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .with_context(|| format!("open log {path}"))?,
                ),
                false,
            ),
        };
    let writer = BoxMakeWriter::new(Mutex::new(writer));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(&config.level)?)
        .with_writer(writer)
        .with_ansi(terminal);
    match config.format.as_str() {
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
        let mut close = tokio::signal::windows::ctrl_close()?;
        let mut shutdown = tokio::signal::windows::ctrl_shutdown()?;
        tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = close.recv() => {}, _ = shutdown.recv() => {} }
    }
    Ok(())
}

struct Record {
    path: PathBuf,
    content: String,
}
impl Record {
    fn write(path: &str, content: String) -> Result<Self> {
        fs::write(path, &content).with_context(|| format!("write {path}"))?;
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

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use http::{HeaderMap, HeaderName, HeaderValue};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

// YAML null has the same effect as an omitted setting.
macro_rules! settings {
    ($name:ident { $($(#[$attribute:meta])* $field:ident: $kind:ty = $default:expr),* $(,)? }) => {
        #[derive(Clone, Serialize)]
        pub struct $name { $($(#[$attribute])* pub $field: $kind),* }
        impl Default for $name {
            fn default() -> Self { Self { $($field: $default),* } }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Fields { $($(#[$attribute])* $field: Option<$kind>),* }
                let fields = Option::<Fields>::deserialize(deserializer)?;
                Ok(match fields {
                    Some(fields) => Self { $($field: fields.$field.unwrap_or_else(|| $default)),* },
                    None => Self::default(),
                })
            }
        }
    };
}

mod duration;
mod reference;
pub use duration::Span;
pub use reference::{path, resolve};

settings!(Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    config_version: Option<u8> = None,
    control_plane: ControlPlane = ControlPlane::default(),
    mcp: Mcp = Mcp::default(),
    harpoon: Harpoon = Harpoon::default(),
    health: Health = Health::default(),
    admin_ui: AdminUi = AdminUi::default(),
    log: Log = Log::default(),
    process: Process = Process::default(),
    cloudflared: Cloudflared = Cloudflared::default(),
    proxy: Proxy = Proxy::default(),
    ca_bundle: Option<String> = None,
    http_proxy: Option<String> = None,
});

impl Config {
    pub fn validate_profile(text: &str) -> Result<()> {
        Self::parse(text)?.validate_source(text)
    }

    fn validate_source(&self, text: &str) -> Result<()> {
        self.scope()?;
        let mut input = text.as_bytes();
        let raw = serde_saphyr::read::<_, Value>(&mut input)
            .next()
            .transpose()?
            .context("configuration is empty")?;
        reference::validate_profile(self, &raw)?;
        self.mcp.oauth_origins()?;
        for target in &self.harpoon.targets {
            if let Some(definition) = &target.template {
                definition
                    .validate()
                    .with_context(|| format!("harpoon target {:?} template", target.label))?;
            }
        }
        Ok(())
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::load(&text, |_| {}).with_context(|| format!("parse config file {}", path.display()))
    }

    /// Apply configuration overrides before resolving references and validating values.
    pub fn load(text: &str, configure: impl FnOnce(&mut Self)) -> Result<Self> {
        let mut config = Self::parse(text)?;
        configure(&mut config);
        config.validate_source(text)?;
        reference::read(&mut config)?;
        Ok(config)
    }
    pub fn parse(text: &str) -> Result<Self> {
        let mut input = text.as_bytes();
        let mut documents = serde_saphyr::read::<_, Self>(&mut input);
        let config = documents
            .next()
            .transpose()?
            .context("configuration is empty")?;
        anyhow::ensure!(
            config
                .config_version
                .is_none_or(|version| matches!(version, 1 | 2)),
            "unsupported config_version"
        );
        anyhow::ensure!(
            config.config_version == Some(2)
                || config
                    .harpoon
                    .targets
                    .iter()
                    .all(|target| target.template.is_none()),
            "Harpoon templates require config_version: 2"
        );
        for target in &config.harpoon.targets {
            anyhow::ensure!(
                !target.label.trim().is_empty(),
                "harpoon.targets entry requires label"
            );
            if let Some(template) = &target.template {
                template.rules()?;
                anyhow::ensure!(
                    target.url.is_empty() && target.unix_socket.is_none(),
                    "harpoon.targets entry {:?}: template cannot be combined with url or unix_socket",
                    target.label
                );
                anyhow::ensure!(
                    template.version == 1,
                    "harpoon.targets entry {:?}: template version must be 1",
                    target.label
                );
            } else {
                anyhow::ensure!(
                    !target.url.trim().is_empty(),
                    "harpoon.targets entry {:?} requires url or template",
                    target.label
                );
            }
        }
        if config.config_version == Some(2) {
            // A version-two profile is a single YAML document, including empty trailing documents.
            serde_saphyr::from_str::<Self>(text)?;
        }
        Ok(config)
    }
    fn scope(&self) -> Result<()> {
        let defaults = AdminUi::default();
        for (name, enabled) in [
            ("admin_ui.allow_remote", self.admin_ui.allow_remote),
            ("admin_ui.open_browser", self.admin_ui.open_browser),
            (
                "admin_ui.log_buffer_events",
                self.admin_ui.log_buffer_events != defaults.log_buffer_events,
            ),
            ("harpoon.capture_payloads", self.harpoon.capture_payloads),
        ] {
            anyhow::ensure!(!enabled, "{name} must retain its default in otunnel");
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_with_channels(std::iter::empty::<String>())
    }

    pub(crate) fn validate_with_channels(
        &self,
        additional: impl IntoIterator<Item = String>,
    ) -> Result<()> {
        self.scope()?;
        reference::validate_headers(self, true)?;
        self.mcp.oauth_origins()?;
        if let Some(organization) = &self.control_plane.organization_id {
            anyhow::ensure!(
                !organization.contains(['\r', '\n']),
                "control-plane.organization-id cannot contain header line breaks"
            );
        }
        let level = self.log.level.trim().to_ascii_lowercase();
        anyhow::ensure!(
            matches!(level.as_str(), "debug" | "info" | "warn" | "error"),
            "parse log level {:?}: expected debug, info, warn, or error",
            self.log.level
        );
        let format = self.log.format.trim().to_ascii_lowercase();
        anyhow::ensure!(
            matches!(format.as_str(), "" | "struct-text" | "json"),
            "unsupported log format {:?}: supported formats are \"struct-text\" or \"json\"",
            self.log.format
        );
        anyhow::ensure!(
            level == "info" || !format.is_empty(),
            "log level requires 'struct-text' or 'json' log format"
        );
        anyhow::ensure!(
            self.config_version
                .is_none_or(|version| matches!(version, 1 | 2)),
            "unsupported config_version"
        );
        anyhow::ensure!(
            self.control_plane
                .tunnel_id
                .strip_prefix("tunnel_")
                .is_some_and(|id| {
                    id.len() == 32
                        && id
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                }),
            "invalid tunnel ID: expected tunnel_<32 lowercase letters or digits>"
        );
        let api_key =
            reference::resolve_named("control_plane.api_key", &self.control_plane.api_key)?;
        anyhow::ensure!(
            api_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
            "control plane API key is malformed"
        );
        if self.control_plane.max_inflight_requests == 0 || self.mcp.max_concurrent_requests == 0 {
            bail!("request concurrency must be positive");
        }
        anyhow::ensure!(
            self.control_plane.max_inflight_requests <= 10000,
            "control-plane.max-inflight must be less than or equal to 10000"
        );
        for (name, duration) in [
            (
                "control-plane.poll-timeout",
                self.control_plane.poll_timeout.0,
            ),
            (
                "control-plane.initial-poll-timeout",
                self.control_plane.initial_poll_timeout.0,
            ),
            (
                "control-plane.poll-deadline-guardrail",
                self.control_plane.poll_deadline_guardrail.0,
            ),
            (
                "cloudflared.ready-timeout",
                self.cloudflared.ready_timeout.0,
            ),
            (
                "mcp.connection-max-ttl",
                self.mcp
                    .connection_max_ttl
                    .map_or(Duration::ZERO, |span| span.0),
            ),
        ] {
            anyhow::ensure!(!duration.is_zero(), "{name} must be positive");
        }
        anyhow::ensure!(
            self.control_plane.poll_deadline_guardrail.0 < Duration::from_secs(60),
            "control-plane.poll-deadline-guardrail must be less than 1m0s"
        );
        anyhow::ensure!(
            self.control_plane.poll_timeout.0
                <= Duration::from_secs(600) - self.control_plane.poll_deadline_guardrail.0,
            "control-plane.poll-timeout plus control-plane.poll-deadline-guardrail must be less than or equal to 10m0s"
        );
        anyhow::ensure!(
            !self.proxy.check_interval.0.is_zero(),
            "proxy.check-interval must be positive"
        );
        if let Some(limit) = self.harpoon.max_response_bytes {
            anyhow::ensure!(limit > 0, "harpoon.max-response-bytes must be positive");
            anyhow::ensure!(
                limit <= 100 * 1024,
                "harpoon.max-response-bytes must be less than or equal to 102400"
            );
        }
        anyhow::ensure!(
            self.harpoon.max_redirects <= 5,
            "harpoon.max-redirects must be less than or equal to 5"
        );
        for transport in &self.harpoon.additional_transports {
            anyhow::ensure!(
                transport.trim().eq_ignore_ascii_case("http-streamable"),
                "unsupported harpoon transport {:?}",
                transport.trim()
            );
        }
        for pattern in &self.harpoon.hosts_include_regex {
            Regex::new(&format!("(?i:{})", pattern.trim()))
                .with_context(|| format!("invalid harpoon host regex {pattern:?}"))?;
        }
        let mut channels = BTreeSet::new();
        for name in self
            .mcp
            .server_urls
            .iter()
            .map(|server| server.channel.clone())
            .chain(
                self.mcp
                    .commands
                    .iter()
                    .map(|command| command.channel.clone()),
            )
            .chain(additional)
        {
            let name = channel(&name)?;
            anyhow::ensure!(
                channels.insert(name.clone()),
                "channel {name} has multiple bindings"
            );
        }
        match &self.control_plane.poll_channels {
            None => anyhow::ensure!(
                channels.contains("main"),
                if channels.is_empty() {
                    "main channel is required; set --mcp.server-url or --mcp.command, or MCP_SERVER_URL or MCP_COMMAND"
                } else {
                    "main channel is required; add channel=main to one --mcp.server-url or --mcp.command entry"
                }
            ),
            Some(poll_channels) => {
                for name in poll_channels {
                    match name.as_str() {
                        "harpoon" => anyhow::ensure!(
                            channels.contains("harpoon")
                                || !self.harpoon.targets.is_empty()
                                || poll_channels.iter().any(|channel| channel == "main"),
                            "control-plane.poll-channel harpoon has no routable target"
                        ),
                        _ => anyhow::ensure!(
                            channels.contains(name),
                            "control-plane.poll-channel {name:?} has no local handler"
                        ),
                    }
                }
            }
        }
        Ok(())
    }
    pub fn normalize(&mut self) -> Result<()> {
        for name in self
            .mcp
            .commands
            .iter_mut()
            .map(|command| &mut command.channel)
            .chain(
                self.mcp
                    .server_urls
                    .iter_mut()
                    .map(|server| &mut server.channel),
            )
        {
            *name = channel(name)?;
        }
        if let Some(channels) = &mut self.control_plane.poll_channels {
            anyhow::ensure!(
                !channels.is_empty(),
                "control-plane.poll-channel contains an empty channel"
            );
            let mut poll_channels = BTreeSet::new();
            for name in channels.iter_mut() {
                let original = name.clone();
                anyhow::ensure!(
                    !original.trim().is_empty(),
                    "control-plane.poll-channel contains an empty channel"
                );
                let normalized = channel(&original)?;
                anyhow::ensure!(
                    original == normalized,
                    "control-plane.poll-channel {original:?} is not canonical; use {normalized:?}"
                );
                anyhow::ensure!(
                    poll_channels.insert(normalized.clone()),
                    "duplicate control-plane.poll-channel {normalized:?}"
                );
                *name = normalized;
            }
            channels.sort();
        }
        let optional = |value: &mut Option<String>| {
            if let Some(text) = value {
                *text = text.trim().to_owned();
                if text.is_empty() {
                    *value = None;
                }
            }
        };
        for value in [
            &mut self.ca_bundle,
            &mut self.http_proxy,
            &mut self.mcp.http_proxy,
            &mut self.mcp.client_cert,
            &mut self.mcp.client_key,
            &mut self.harpoon.http_proxy,
            &mut self.control_plane.client_cert,
            &mut self.control_plane.client_key,
            &mut self.control_plane.http_proxy,
            &mut self.control_plane.organization_id,
            &mut self.health.unix_socket,
            &mut self.health.url_file,
            &mut self.process.pid_file,
            &mut self.log.file,
        ] {
            optional(value);
        }
        for server in &mut self.mcp.server_urls {
            for value in [
                &mut server.unix_socket,
                &mut server.http_proxy,
                &mut server.client_cert,
                &mut server.client_key,
            ] {
                optional(value);
            }
        }
        for target in &mut self.harpoon.targets {
            optional(&mut target.unix_socket);
        }
        if self.health.listen_addr.is_empty() {
            self.health.listen_addr = Health::default().listen_addr;
        }
        self.cloudflared.path = self.cloudflared.path.trim().to_owned();
        if self.cloudflared.path.is_empty() {
            self.cloudflared.path = "cloudflared".into();
        }
        self.log.level = self.log.level.trim().to_ascii_lowercase();
        self.log.format = self.log.format.trim().to_ascii_lowercase();
        Ok(())
    }
    pub fn enabled(&self, channel: &str) -> bool {
        self.control_plane
            .poll_channels
            .as_ref()
            .is_none_or(|channels| channels.iter().any(|name| name == channel))
    }
}

settings!(ControlPlane {
    base_url: Option<String> = None,
    url_path: Option<String> = None,
    tunnel_id: String = String::new(),
    api_key: String = String::new(),
    organization_id: Option<String> = None,
    max_inflight_requests: usize = 20,
    poll_timeout: Span = Span(Duration::from_secs(30)),
    #[serde(skip)]
    initial_poll_timeout: Span = Span(Duration::from_secs(30)),
    poll_deadline_guardrail: Span = Span(Duration::from_secs(5)),
    poll_channels: Option<Vec<String>> = None,
    extra_headers: BTreeMap<String, String> = BTreeMap::new(),
    http_proxy: Option<String> = None,
    client_cert: Option<String> = None,
    client_key: Option<String> = None,
});
impl ControlPlane {
    pub fn base_url(&self) -> &str {
        let url = self
            .base_url
            .as_deref()
            .filter(|url| !url.is_empty())
            .unwrap_or("https://api.openai.com");
        if self.client_cert.is_some()
            && url.trim().trim_end_matches('/') == "https://api.openai.com"
        {
            "https://mtls.api.openai.com"
        } else {
            url
        }
    }
}
settings!(Mcp {
    server_urls: Vec<Server> = Vec::new(),
    commands: Vec<Command> = Vec::new(),
    extra_headers: BTreeMap<String, String> = BTreeMap::new(),
    discovery_extra_headers: BTreeMap<String, String> = BTreeMap::new(),
    oauth_trusted_origins: Vec<String> = Vec::new(),
    startup_wait_timeout: Span = Span(Duration::ZERO),
    stdio_send_initialized_notification: bool = false,
    connection_max_ttl: Option<Span> = Some(Span(Duration::from_secs(600))),
    max_concurrent_requests: usize = 10,
    http_proxy: Option<String> = None,
    client_cert: Option<String> = None,
    client_key: Option<String> = None,
});
impl Mcp {
    pub(crate) fn oauth_origins(&self) -> Result<Vec<url::Url>> {
        self.oauth_trusted_origins.iter().map(|value| {
            let url = url::Url::parse(value).context("invalid OAuth origin")?;
            let authority = value.split_once("://").map(|(_, rest)| rest.trim_end_matches('/'));
            anyhow::ensure!(
                matches!(url.scheme(), "http" | "https")
                    && url.host_str().is_some()
                    && url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && authority.is_some_and(|authority| !authority.is_empty()
                        && !authority.contains(['@', '/', '?', '#', '\\', '%'])
                        && !authority.ends_with(':'))
                    && !value.chars().any(char::is_whitespace)
                    && !value.ends_with("//")
                    && url.port() != Some(0),
                "mcp.oauth_trusted_origins: expected an HTTP(S) origin without credentials, path, query, or fragment"
            );
            Ok(url)
        }).collect()
    }
}
settings!(Server {
    channel: String = main_channel(),
    url: String = String::new(),
    unix_socket: Option<String> = None,
    http_proxy: Option<String> = None,
    client_cert: Option<String> = None,
    client_key: Option<String> = None,
});
settings!(Command {
    channel: String = main_channel(),
    command: String = String::new(),
});

pub fn command_args(value: &str) -> Result<Vec<String>> {
    let mut args = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.trim().chars() {
        if escaped {
            word.push(character);
            escaped = false;
        } else if quote == Some('\'') {
            if character == '\'' {
                quote = None;
            } else {
                word.push(character);
            }
        } else {
            match character {
                '\\' => escaped = true,
                '"' => quote = if quote.is_some() { None } else { Some('"') },
                '\'' if quote.is_none() => quote = Some('\''),
                ' ' | '\t' | '\n' | '\r' if quote.is_none() => {
                    if !word.is_empty() {
                        args.push(std::mem::take(&mut word));
                    }
                }
                _ => word.push(character),
            }
        }
    }
    anyhow::ensure!(!escaped, "unterminated escape sequence");
    anyhow::ensure!(quote.is_none(), "unterminated quoted string");
    if !word.is_empty() {
        args.push(word);
    }
    anyhow::ensure!(!args.is_empty(), "command is empty");
    Ok(args)
}

settings!(Harpoon {
    targets: Vec<Target> = Vec::new(),
    http_proxy: Option<String> = None,
    max_response_bytes: Option<usize> = Some(100 * 1024),
    max_redirects: usize = 5,
    allow_plaintext_http: bool = false,
    additional_transports: Vec<String> = Vec::new(),
    capture_payloads: bool = false,
    hosts_include_loopback: bool = true,
    hosts_include_private: bool = true,
    hosts_include_suffix: Vec<String> = Vec::new(),
    hosts_include_regex: Vec<String> = Vec::new(),
});
settings!(Target {
    label: String = String::new(),
    url: String = String::new(),
    description: String = String::new(),
    unix_socket: Option<String> = None,
    template: Option<crate::template::Definition> = None,
});
settings!(Health {
    listen_addr: String = "127.0.0.1:8080".into(),
    unix_socket: Option<String> = None,
    url_file: Option<String> = None,
    show_details: bool = false,
});
settings!(AdminUi {
    allow_remote: bool = false,
    open_browser: bool = false,
    log_buffer_events: usize = 2000,
});
settings!(Log {
    level: String = "info".into(),
    format: String = String::new(),
    file: Option<String> = None,
    http_raw_unsafe: bool = false,
});
settings!(Process { pid_file: Option<String> = None });
settings!(Cloudflared {
    managed: bool = false,
    token: Option<String> = None,
    path: String = "cloudflared".into(),
    ready_timeout: Span = Span(Duration::from_secs(30)),
});
settings!(Proxy {
    check_interval: Span = Span(Duration::from_secs(60))
});

pub(crate) fn endpoint(base: &url::Url, prefix: &str, route: &str) -> Result<url::Url> {
    let prefix = prefix.trim();
    let mut result = base.clone();
    result.set_path("/");
    result.set_query(None);
    result.set_fragment(None);
    let prefix = if prefix.is_empty() {
        String::new()
    } else {
        anyhow::ensure!(
            prefix.starts_with('/') && !prefix.starts_with("//"),
            "control-plane.url-path must start with '/' and contain only a path"
        );
        let parsed = result.join(prefix)?;
        anyhow::ensure!(
            parsed.query().is_none_or(str::is_empty) && parsed.fragment().is_none_or(str::is_empty),
            "control-plane.url-path cannot contain a query or fragment"
        );
        percent_encoding::percent_decode_str(parsed.path())
            .decode_utf8()?
            .into_owned()
    };
    let mut segments = Vec::new();
    for segment in prefix.split('/').chain(route.split('/')) {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }
    result
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("control-plane URL cannot contain path segments"))?
        .clear()
        .extend(segments);
    Ok(result)
}

pub fn main_channel() -> String {
    "main".into()
}
pub fn channel(name: &str) -> Result<String> {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() {
        return Ok(main_channel());
    }
    anyhow::ensure!(
        name.len() <= 64
            && name.bytes().all(|value| value.is_ascii_lowercase()
                || value.is_ascii_digit()
                || matches!(value, b'_' | b'-')),
        "invalid channel name {name}"
    );
    Ok(name)
}

pub fn profile_dir(explicit: Option<&str>) -> Result<PathBuf> {
    let variable = |name| env::var(name).ok().filter(|value| !value.trim().is_empty());
    if let Some(directory) = explicit
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| variable("TUNNEL_CLIENT_PROFILE_DIR"))
    {
        return expand_home(&directory);
    }
    if let Some(directory) = variable("XDG_CONFIG_HOME") {
        return Ok(expand_home(&directory)?.join("tunnel-client"));
    }
    if let Some(directory) = variable("HOME") {
        return Ok(expand_home(&directory)?.join(".config/tunnel-client"));
    }
    #[cfg(windows)]
    let directory = env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let directory = env::home_dir().map(|home| home.join("Library/Application Support"));
    #[cfg(all(unix, not(target_os = "macos")))]
    let directory = env::home_dir().map(|home| home.join(".config"));
    Ok(directory
        .context("profile directory is unavailable; use --profile-dir")?
        .join("tunnel-client"))
}
pub fn profile_name(name: &str) -> Result<&str> {
    let name = name.trim();
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b'-')),
        "invalid profile name {name:?}: use letters, numbers, '.', '_' or '-'"
    );
    Ok(name)
}
pub fn profile_path(name: &str, directory: Option<&str>) -> Result<PathBuf> {
    Ok(profile_dir(directory)?.join(format!("{}.yaml", profile_name(name)?)))
}
pub fn expand_home(value: &str) -> Result<PathBuf> {
    let value = value.trim();
    if value == "~" || value.starts_with("~/") {
        let home = env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .map(PathBuf::from)
            .context("cannot expand home path without HOME")?;
        Ok(home.join(value.strip_prefix("~/").unwrap_or("")))
    } else {
        Ok(PathBuf::from(value))
    }
}

pub fn pem(value: &str) -> Result<Vec<u8>> {
    let file = path(value)?;
    fs::read(&file).with_context(|| format!("read {}", file.display()))
}
pub fn headers(values: &BTreeMap<String, String>) -> Result<HeaderMap> {
    let mut normalized = BTreeMap::new();
    for (name, value) in values {
        let name = HeaderName::try_from(name)?.to_string();
        if let Some(previous) = normalized.insert(name.clone(), value.as_str()) {
            anyhow::ensure!(
                previous == value,
                "conflicting values for case-insensitive HTTP header {name}"
            );
        }
    }
    let mut headers = HeaderMap::new();
    for (name, raw) in normalized {
        let raw = raw.trim();
        let value = match raw.split_once(':') {
            Some((kind, variable)) if kind.eq_ignore_ascii_case("env") => env::var(variable.trim())
                .with_context(|| format!("read header environment variable {variable}"))?
                .trim()
                .as_bytes()
                .to_vec(),
            Some((kind, path)) if kind.eq_ignore_ascii_case("file") => {
                let mut bytes =
                    fs::read(path.trim()).with_context(|| format!("read header file {path}"))?;
                let ending = if bytes.ends_with(b"\r\n") {
                    2
                } else if bytes.ends_with(b"\r") || bytes.ends_with(b"\n") {
                    1
                } else {
                    0
                };
                bytes.truncate(bytes.len() - ending);
                bytes
            }
            _ => raw.as_bytes().to_vec(),
        };
        anyhow::ensure!(
            !value.iter().all(u8::is_ascii_whitespace),
            "resolved HTTP header {name} is empty"
        );
        headers.insert(
            HeaderName::try_from(name)?,
            HeaderValue::from_bytes(&value)?,
        );
    }
    Ok(headers)
}

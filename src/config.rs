use std::{collections::BTreeMap, env, fs, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug)]
pub struct Span(pub Duration);

impl Serialize for Span {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&humantime::format_duration(self.0))
    }
}

impl<'de> Deserialize<'de> for Span {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        humantime::parse_duration(&value)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub control_plane: ControlPlane,
    pub mcp: Mcp,
    pub harpoon: Harpoon,
    pub health: Health,
    pub log: Log,
    pub process: Process,
    pub cloudflared: Cloudflared,
    pub ca_bundle: Option<String>,
    pub http_proxy: Option<String>,
}

impl Config {
    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        serde_saphyr::from_str(
            &fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?,
        )
        .with_context(|| format!("parse {}", path.display()))
    }

    pub fn validate(&self) -> Result<()> {
        if self.control_plane.tunnel_id.is_empty() {
            bail!("control_plane.tunnel_id is required");
        }
        if resolve(&self.control_plane.api_key)?.is_empty() {
            bail!("control_plane.api_key is required");
        }
        if self.control_plane.max_inflight_requests == 0 || self.mcp.max_concurrent_requests == 0 {
            bail!("request concurrency must be positive");
        }
        let mut channels = std::collections::BTreeSet::new();
        for name in self
            .mcp
            .server_urls
            .iter()
            .map(|s| &s.channel)
            .chain(self.mcp.commands.iter().map(|s| &s.channel))
        {
            if !channels.insert(name) {
                bail!("channel {name} has multiple bindings");
            }
        }
        Ok(())
    }

    pub fn enabled(&self, channel: &str) -> bool {
        self.control_plane.poll_channels.is_empty()
            || self
                .control_plane
                .poll_channels
                .iter()
                .any(|name| name == channel)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlPlane {
    pub base_url: String,
    pub url_path: String,
    pub tunnel_id: String,
    pub api_key: String,
    pub organization_id: Option<String>,
    pub max_inflight_requests: usize,
    pub poll_timeout: Span,
    pub initial_poll_timeout: Span,
    pub poll_deadline_guardrail: Span,
    pub poll_channels: Vec<String>,
    pub extra_headers: BTreeMap<String, String>,
    pub http_proxy: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
}

impl Default for ControlPlane {
    fn default() -> Self {
        Self {
            base_url: "https://api.openai.com".into(),
            url_path: String::new(),
            tunnel_id: String::new(),
            api_key: String::new(),
            organization_id: None,
            max_inflight_requests: 20,
            poll_timeout: Span(Duration::from_secs(30)),
            initial_poll_timeout: Span(Duration::from_secs(30)),
            poll_deadline_guardrail: Span(Duration::from_secs(5)),
            poll_channels: Vec::new(),
            extra_headers: BTreeMap::new(),
            http_proxy: None,
            client_cert: None,
            client_key: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Mcp {
    pub server_urls: Vec<Server>,
    pub commands: Vec<Command>,
    pub extra_headers: BTreeMap<String, String>,
    pub discovery_extra_headers: BTreeMap<String, String>,
    pub startup_wait_timeout: Span,
    pub connection_max_ttl: Option<Span>,
    pub max_concurrent_requests: usize,
    pub http_proxy: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
}

impl Default for Mcp {
    fn default() -> Self {
        Self {
            server_urls: Vec::new(),
            commands: Vec::new(),
            extra_headers: BTreeMap::new(),
            discovery_extra_headers: BTreeMap::new(),
            startup_wait_timeout: Span(Duration::from_secs(30)),
            connection_max_ttl: None,
            max_concurrent_requests: 32,
            http_proxy: None,
            client_cert: None,
            client_key: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Server {
    #[serde(default = "main_channel")]
    pub channel: String,
    pub url: String,
    #[serde(default)]
    pub unix_socket: Option<String>,
    #[serde(default)]
    pub http_proxy: Option<String>,
    #[serde(default)]
    pub client_cert: Option<String>,
    #[serde(default)]
    pub client_key: Option<String>,
    #[serde(default)]
    pub command: Option<Invocation>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Command {
    #[serde(default = "main_channel")]
    pub channel: String,
    pub command: Invocation,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Invocation {
    Text(String),
    Args(Vec<String>),
}

impl Invocation {
    pub fn args(&self) -> Result<Vec<String>> {
        let args = match self {
            Self::Text(value) => shell_words::split(value)?,
            Self::Args(args) => args.clone(),
        };
        if args.is_empty() {
            bail!("command is empty");
        }
        Ok(args)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Harpoon {
    pub targets: Vec<Target>,
    pub http_proxy: Option<String>,
    pub max_response_bytes: Option<usize>,
    pub max_redirects: usize,
    pub hosts_include_loopback: bool,
    pub hosts_include_private: bool,
    pub hosts_include_suffix: Vec<String>,
    pub hosts_include_regex: Vec<String>,
}

impl Default for Harpoon {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            http_proxy: None,
            max_response_bytes: None,
            max_redirects: 10,
            hosts_include_loopback: true,
            hosts_include_private: true,
            hosts_include_suffix: Vec::new(),
            hosts_include_regex: Vec::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Target {
    pub label: String,
    #[serde(default)]
    pub url: String,
    #[serde(default, alias = "desc")]
    pub description: String,
    #[serde(default)]
    pub unix_socket: Option<String>,
    #[serde(default)]
    pub template: Option<crate::template::Definition>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Health {
    pub listen_addr: String,
    pub unix_socket: Option<String>,
    pub url_file: Option<String>,
    pub show_details: bool,
}
impl Default for Health {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:0".into(),
            unix_socket: None,
            url_file: None,
            show_details: false,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Log {
    pub level: String,
    pub format: String,
    pub file: Option<String>,
}
impl Default for Log {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: "text".into(),
            file: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Process {
    pub pid_file: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Cloudflared {
    pub managed: bool,
    pub token: Option<String>,
    pub path: String,
    pub ready_timeout: Span,
}
impl Default for Cloudflared {
    fn default() -> Self {
        Self {
            managed: false,
            token: None,
            path: "cloudflared".into(),
            ready_timeout: Span(Duration::from_secs(30)),
        }
    }
}

pub fn main_channel() -> String {
    "main".into()
}

pub fn resolve(value: &str) -> Result<String> {
    if let Some(name) = value.strip_prefix("env:") {
        env::var(name).with_context(|| format!("read environment variable {name}"))
    } else if let Some(path) = value.strip_prefix("file:") {
        Ok(fs::read_to_string(path)
            .with_context(|| format!("read {path}"))?
            .trim()
            .into())
    } else {
        Ok(value.into())
    }
}

pub fn pem(value: &str) -> Result<Vec<u8>> {
    if let Some(path) = value.strip_prefix("file:") {
        fs::read(path).with_context(|| format!("read {path}"))
    } else {
        let path = resolve(value)?;
        fs::read(&path).with_context(|| format!("read {path}"))
    }
}

pub fn headers(values: &BTreeMap<String, String>) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        headers.insert(
            HeaderName::try_from(name)?,
            HeaderValue::try_from(resolve(value)?)?,
        );
    }
    Ok(headers)
}

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
        if value == "0" {
            return Ok(Self(Duration::ZERO));
        }
        humantime::parse_duration(&value)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

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
    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        Self::parse(&fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?)
            .with_context(|| format!("parse {}", path.display()))
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
        if config.config_version == Some(2) {
            // A version-two profile is a single YAML document, including empty trailing documents.
            serde_saphyr::from_str::<Self>(text)?;
        }
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.config_version
                .is_none_or(|version| matches!(version, 1 | 2)),
            "unsupported config_version"
        );
        if self.control_plane.tunnel_id.is_empty() {
            bail!("control_plane.tunnel_id is required");
        }
        if resolve(&self.control_plane.api_key)?.is_empty() {
            bail!("control_plane.api_key is required");
        }
        if self.control_plane.max_inflight_requests == 0 || self.mcp.max_concurrent_requests == 0 {
            bail!("request concurrency must be positive");
        }
        let mut channels = BTreeSet::new();
        for name in self
            .mcp
            .server_urls
            .iter()
            .map(|server| &server.channel)
            .chain(self.mcp.commands.iter().map(|command| &command.channel))
        {
            let name = channel(name)?;
            anyhow::ensure!(
                channels.insert(name.clone()),
                "channel {name} has multiple bindings"
            );
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

settings!(ControlPlane {
    base_url: String = "https://api.openai.com".into(),
    url_path: String = String::new(),
    tunnel_id: String = String::new(),
    api_key: String = String::new(),
    organization_id: Option<String> = None,
    max_inflight_requests: usize = 20,
    poll_timeout: Span = Span(Duration::from_secs(30)),
    initial_poll_timeout: Span = Span(Duration::from_secs(30)),
    poll_deadline_guardrail: Span = Span(Duration::from_secs(5)),
    poll_channels: Vec<String> = Vec::new(),
    extra_headers: BTreeMap<String, String> = BTreeMap::new(),
    http_proxy: Option<String> = None,
    client_cert: Option<String> = None,
    client_key: Option<String> = None,
});
settings!(Mcp {
    server_urls: Vec<Server> = Vec::new(),
    commands: Vec<Command> = Vec::new(),
    extra_headers: BTreeMap<String, String> = BTreeMap::new(),
    discovery_extra_headers: BTreeMap<String, String> = BTreeMap::new(),
    startup_wait_timeout: Span = Span(Duration::ZERO),
    stdio_send_initialized_notification: bool = false,
    connection_max_ttl: Option<Span> = Some(Span(Duration::from_secs(600))),
    max_concurrent_requests: usize = 10,
    http_proxy: Option<String> = None,
    client_cert: Option<String> = None,
    client_key: Option<String> = None,
});
settings!(Server {
    channel: String = main_channel(),
    url: String = String::new(),
    unix_socket: Option<String> = None,
    http_proxy: Option<String> = None,
    client_cert: Option<String> = None,
    client_key: Option<String> = None,
    command: Option<Invocation> = None,
    cwd: Option<String> = None,
    env: BTreeMap<String, String> = BTreeMap::new(),
});
settings!(Command {
    channel: String = main_channel(),
    command: Invocation = Invocation::Text(String::new()),
    cwd: Option<String> = None,
    env: BTreeMap<String, String> = BTreeMap::new(),
});

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Invocation {
    Text(String),
    Args(Vec<String>),
}
impl Invocation {
    pub fn args(&self) -> Result<Vec<String>> {
        let args = match self {
            Self::Text(value) => shell_words::split(&resolve(value)?)?,
            Self::Args(args) => args.clone(),
        };
        anyhow::ensure!(!args.is_empty(), "command is empty");
        Ok(args)
    }
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
    #[serde(alias = "desc")]
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

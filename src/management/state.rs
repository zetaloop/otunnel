use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Alias {
    pub alias: String,
    pub tunnel_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub admin_profile: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub organization_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub workspace_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tenant_ids: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub config_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub profile_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub profile_dir: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub profile_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub health_url_file: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Process {
    pub alias: String,
    pub tunnel_id: String,
    pub config_path: String,
    pub health_url_file: String,
    pub target_kind: String,
    pub target_value: String,
    pub command: String,
    pub started_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub admin_profile: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub profile_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub profile_dir: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub profile_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tmux_socket: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pid_start_time: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pid_executable: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub log_path: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AdminProfile {
    pub name: String,
    pub control_plane_base_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub control_plane_url_path: String,
    pub admin_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AdminProfiles {
    pub active_profile: String,
    pub profiles: BTreeMap<String, AdminProfile>,
}

#[derive(Clone)]
pub struct Root {
    pub path: PathBuf,
}
impl Default for Root {
    fn default() -> Self {
        if let Some(root) = variable("TUNNEL_CLIENT_STATE_DIR") {
            return Self { path: root.into() };
        }
        let mut candidates = Vec::new();
        if let Some(root) = variable("CODEX_HOME") {
            candidates.push(PathBuf::from(root).join("tunnel-mcp"));
        }
        let home = variable("HOME").map(PathBuf::from);
        if let Some(home) = &home {
            candidates.extend([home.join(".codex/tunnel-mcp"), home.join(".tunnel-client")]);
        }
        if let Some(path) = candidates.into_iter().find(|candidate| candidate.is_dir()) {
            return Self { path };
        }
        if let Some(root) = variable("XDG_STATE_HOME") {
            return Self {
                path: PathBuf::from(root).join("tunnel-client"),
            };
        }
        let path = if let Some(home) = home.or_else(env::home_dir) {
            home.join(if cfg!(target_os = "macos") {
                "Library/Application Support/tunnel-client"
            } else {
                ".local/state/tunnel-client"
            })
        } else {
            PathBuf::from(".tunnel-client")
        };
        Self { path }
    }
}
impl Root {
    pub fn initialize(&self) -> Result<()> {
        for name in ["", "configs", "health", "logs"] {
            fs::create_dir_all(self.path.join(name))?;
        }
        Ok(())
    }
    pub fn lock(&self) -> Result<File> {
        let directory = self.path.join("locks");
        fs::create_dir_all(&directory)?;
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(directory.join("state.lock"))?;
        file.lock()?;
        Ok(file)
    }
    pub fn read<T: DeserializeOwned + Default>(&self, name: &str) -> Result<T> {
        let path = self.path.join(name);
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "state file {} is not valid JSON-compatible YAML",
                    path.display()
                )
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
            Err(error) => Err(error).with_context(|| format!("read state file {}", path.display())),
        }
    }
    pub fn save(&self, name: &str, value: &impl Serialize) -> Result<()> {
        fs::create_dir_all(&self.path)?;
        let mut file = tempfile::NamedTempFile::new_in(&self.path)?;
        serde_json::to_writer_pretty(file.as_file_mut(), value)?;
        file.write_all(b"\n")?;
        file.persist(self.path.join(name))
            .with_context(|| format!("replace state file {name}"))?;
        Ok(())
    }
    pub fn profiles(&self) -> Result<AdminProfiles> {
        let mut value: BTreeMap<String, Value> = self.read("admin_profiles.yaml")?;
        let active_profile = value
            .remove("active_profile")
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default();
        let profiles = if let Some(value) = value.remove("profiles") {
            serde_json::from_value(value)?
        } else {
            value
                .into_iter()
                .map(|(key, value)| Ok((key, serde_json::from_value(value)?)))
                .collect::<Result<_>>()?
        };
        Ok(AdminProfiles {
            active_profile,
            profiles,
        })
    }
    pub fn aliases(&self) -> Result<BTreeMap<String, Alias>> {
        self.read("aliases.yaml")
    }
    pub fn processes(&self) -> Result<BTreeMap<String, Process>> {
        self.read("processes.yaml")
    }
    pub fn history(&self, action: &str, alias: &str, tunnel: &str, detail: &str) -> Result<()> {
        self.initialize()?;
        let mut options = fs::OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(self.path.join("history.md"))?;
        let tunnel = if tunnel.trim().is_empty() {
            "-"
        } else {
            tunnel
        };
        let detail = detail.replace('\n', " ");
        write!(
            file,
            "- {} action={action} alias={alias} tunnel_id={tunnel}",
            timestamp()
        )?;
        if !detail.trim().is_empty() {
            write!(file, " detail={}", detail.trim())?;
        }
        writeln!(file)?;
        Ok(())
    }
}

pub fn timestamp() -> String {
    humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string()
}
pub fn variable(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}
pub fn alias(value: &str) -> Result<String> {
    let result = value
        .to_ascii_lowercase()
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    anyhow::ensure!(
        !result.is_empty(),
        "alias must contain at least one ASCII letter or number"
    );
    Ok(result)
}
pub fn reference(value: &str) -> Result<()> {
    anyhow::ensure!(
        value.starts_with("env:") || value.starts_with("file:"),
        "credential must be an env:NAME or file:/path reference"
    );
    Ok(())
}

pub fn target(value: &str) -> Result<()> {
    use regex::Regex;
    use std::sync::LazyLock;
    static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        [
        r"sk-[A-Za-z0-9_-]{12,}",
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}",
        r"(?i)\bAuthorization\s*:",
        r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|password|secret)=\S+",
        r"(?i)\b(OPENAI_ADMIN_KEY|OPENAI_API_KEY|CONTROL_PLANE_API_KEY)=",
        r"://[^/\s:@]+:[^/\s:@]+@",
    ].into_iter().map(|pattern| Regex::new(pattern).expect("valid credential pattern")).collect()
    });
    static FLAG: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)^-{1,2}[a-z0-9_-]*(api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|password|secret)[a-z0-9_-]*$").expect("valid credential flag pattern")
    });
    static REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(env:[A-Za-z_][A-Za-z0-9_]*|file:.+|\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})$").expect("valid credential reference pattern")
    });
    anyhow::ensure!(
        !PATTERNS.iter().any(|pattern| pattern.is_match(value)),
        "MCP target contains inline credential material; use env or file references"
    );
    let words: Vec<_> = value.split_whitespace().collect();
    for pair in words.windows(2) {
        anyhow::ensure!(
            !FLAG.is_match(pair[0]) || pair[1].starts_with('-') || REFERENCE.is_match(pair[1]),
            "MCP command contains inline credential material; use env or file references"
        );
    }
    Ok(())
}

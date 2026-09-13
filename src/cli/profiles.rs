use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command as Process, Stdio},
};

use anyhow::{Context, Result};
use clap::{Arg, ArgMatches, Command};
use otunnel::config::{self, Config};
use serde_json::json;

const SAMPLES: &[(&str, &str)] = &[
    (
        "sample_mcp_enterprise_proxy",
        "HTTP or stdio MCP target for outbound proxies or private PKI environments",
    ),
    (
        "sample_mcp_remote_no_auth",
        "Remote HTTP MCP server that does not advertise OAuth/PRMD metadata",
    ),
    (
        "sample_mcp_stdio_local",
        "Local stdio MCP server with the shortest first-use tunnel-client path",
    ),
    (
        "sample_mcp_with_dcr",
        "HTTP or stdio MCP target with DCR-friendly tunnel-client defaults",
    ),
];

fn text(arguments: &ArgMatches, name: &str) -> String {
    arguments
        .try_get_one::<String>(name)
        .ok()
        .flatten()
        .map_or_else(String::new, |value| value.trim().to_owned())
}
fn strings(command: Command, names: &[&'static str]) -> Command {
    command.args(names.iter().map(|name| Arg::new(*name).long(*name)))
}
fn named(command: Command) -> Command {
    command.arg(Arg::new("name").required(true))
}

pub fn command() -> Command {
    Command::new("profiles")
        .about("Manage tunnel-client YAML profiles")
        .subcommand_required(true)
        .arg(Arg::new("profile-dir").long("profile-dir").global(true))
        .subcommand(
            Command::new("list")
                .about("List configured profiles")
                .arg(super::flag("json")),
        )
        .subcommand(
            strings(
                named(Command::new("add").about("Add a profile from a file or sample")),
                &[
                    "from-file",
                    "sample",
                    "tunnel-id",
                    "mcp-server-url",
                    "mcp-command",
                ],
            )
            .arg(super::flag("force")),
        )
        .subcommand(named(
            Command::new("edit").about("Edit a profile and validate it before saving"),
        ))
        .subcommand(
            Command::new("samples")
                .about("Inspect built-in profile samples")
                .subcommand_required(true)
                .subcommand(Command::new("list"))
                .subcommand(named(Command::new("show"))),
        )
}
pub fn init_command() -> Command {
    strings(
        Command::new("init").about("Create a runnable tunnel-client profile"),
        &[
            "sample",
            "profile-dir",
            "tunnel-id",
            "control-plane-url-path",
            "mcp-server-url",
            "mcp-command",
        ],
    )
    .arg(
        Arg::new("profile")
            .long("profile")
            .default_value("sample_mcp_with_dcr"),
    )
    .arg(
        Arg::new("control-plane-base-url")
            .long("control-plane-base-url")
            .default_value("https://api.openai.com"),
    )
    .arg(
        Arg::new("control-plane-api-key-ref")
            .long("control-plane-api-key-ref")
            .default_value("env:CONTROL_PLANE_API_KEY"),
    )
    .arg(
        Arg::new("health-listen-addr")
            .long("health-listen-addr")
            .default_value("127.0.0.1:8080"),
    )
    .arg(super::flag("force"))
    .arg(super::flag("open-web-ui"))
}

pub fn execute(arguments: &ArgMatches) -> Result<u8> {
    let (action, arguments) = arguments.subcommand().context("missing profiles command")?;
    let directory = config::profile_dir(Some(&text(arguments, "profile-dir")))?;
    let name = text(arguments, "name");
    match action {
        "list" => {
            let mut profiles = Vec::new();
            match fs::read_dir(&directory) {
                Ok(entries) => {
                    for entry in entries {
                        let entry = entry?;
                        let filename = entry.file_name();
                        if !entry.file_type()?.is_dir()
                            && let Some(name) = filename
                                .to_str()
                                .and_then(|name| name.strip_suffix(".yaml"))
                            && config::profile_name(name).is_ok()
                        {
                            profiles.push(json!({"name":name,"path":entry.path()}));
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("read profile directory {}", directory.display())
                    });
                }
            }
            profiles.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
            if arguments.get_flag("json") {
                println!("{}", serde_json::to_string_pretty(&profiles)?);
            } else if profiles.is_empty() {
                println!("No profiles found in {}", directory.display());
            } else {
                for profile in profiles {
                    println!(
                        "{}\t{}",
                        profile["name"].as_str().unwrap_or_default(),
                        profile["path"].as_str().unwrap_or_default()
                    );
                }
            }
        }
        "samples" => {
            let (action, arguments) = arguments.subcommand().context("missing samples command")?;
            if action == "list" {
                for (name, description) in SAMPLES {
                    println!("{name}\t{description}");
                }
            } else {
                let name = text(arguments, "name");
                let (_, description) = sample(&name)?;
                println!("Sample: {name}\nSummary: {description}");
                let mut values = Values {
                    tunnel: "tunnel_0123456789abcdef0123456789abcdef".into(),
                    ..Default::default()
                };
                match name.as_str() {
                    "sample_mcp_stdio_local" => values.command = "python /path/to/server.py".into(),
                    "sample_mcp_remote_no_auth" => {
                        values.url = "https://mcp.example.com/mcp".into()
                    }
                    "sample_mcp_enterprise_proxy" => {
                        values.url = "https://mcp.internal.example.com/mcp".into()
                    }
                    _ => values.url = "http://127.0.0.1:3001/mcp".into(),
                }
                println!("\n{}", generate(&name, values)?);
            }
        }
        "add" => {
            let path = directory.join(format!("{}.yaml", config::profile_name(&name)?));
            let from = text(arguments, "from-file");
            let sample = text(arguments, "sample");
            anyhow::ensure!(
                from.is_empty() != sample.is_empty(),
                "set exactly one of --from-file or --sample"
            );
            let contents = if !from.is_empty() {
                fs::read_to_string(&from).with_context(|| format!("read source profile {from}"))?
            } else {
                generate(&sample, Values::from(arguments))?
            };
            validate(&contents)?;
            write(&path, contents.as_bytes(), arguments.get_flag("force"))?;
            println!("Added profile {name} at {}", path.display());
        }
        "edit" => {
            let path = directory.join(format!("{}.yaml", config::profile_name(&name)?));
            create_directory(&directory)?;
            let contents = match fs::read_to_string(&path) {
                Ok(contents) => contents,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => generate(
                    "sample_mcp_with_dcr",
                    Values {
                        tunnel: "tunnel_00000000000000000000000000000000".into(),
                        url: "http://127.0.0.1:3001/mcp".into(),
                        ..Default::default()
                    },
                )?,
                Err(error) => {
                    return Err(error).with_context(|| format!("read profile {}", path.display()));
                }
            };
            let temporary = tempfile::Builder::new()
                .prefix(&format!(".{name}."))
                .suffix(".yaml")
                .tempfile_in(&directory)?;
            fs::write(temporary.path(), contents)?;
            let editor = env::var("VISUAL")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| env::var("EDITOR").ok())
                .context("set VISUAL or EDITOR to edit profiles")?;
            let mut words = editor.split_whitespace();
            let executable = words
                .next()
                .context("set VISUAL or EDITOR to edit profiles")?;
            let result = Process::new(executable)
                .args(words)
                .arg(temporary.path())
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()?;
            anyhow::ensure!(result.success(), "editor exited with {result}");
            let edited = fs::read_to_string(temporary.path())?;
            validate(&edited).with_context(|| {
                format!("profile did not validate; not saving {}", path.display())
            })?;
            temporary
                .persist(&path)
                .with_context(|| format!("save profile {}", path.display()))?;
            println!("Saved profile {name} at {}", path.display());
        }
        _ => unreachable!(),
    }
    Ok(0)
}

pub fn init(arguments: &ArgMatches) -> Result<u8> {
    let name = text(arguments, "profile");
    let name = if name.is_empty() {
        "sample_mcp_with_dcr"
    } else {
        &name
    };
    let values = Values::from(arguments);
    let sample_name = text(arguments, "sample");
    let sample_name = if sample_name.is_empty() {
        if !values.command.is_empty() && values.url.is_empty() {
            "sample_mcp_stdio_local"
        } else {
            "sample_mcp_with_dcr"
        }
    } else {
        &sample_name
    };
    let data = generate(sample_name, values)?;
    validate(&data)?;
    let command = text(arguments, "mcp-command");
    if !command.is_empty() {
        preflight(&config::command_args(&command)?, 0)?;
    }
    let path = config::profile_path(name, Some(&text(arguments, "profile-dir")))?;
    write(&path, data.as_bytes(), arguments.get_flag("force"))?;
    println!(
        "Created profile {name} at {}\nSample: {sample_name}\nNext:\n  otunnel doctor --profile {name}\n  otunnel run --profile {name}",
        path.display()
    );
    Ok(0)
}

fn sample(name: &str) -> Result<&'static (&'static str, &'static str)> {
    SAMPLES
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .with_context(|| format!("unknown sample {name:?}; run `otunnel profiles samples list`"))
}

struct Values {
    tunnel: String,
    base: String,
    prefix: String,
    key: String,
    health: String,
    browser: bool,
    url: String,
    command: String,
}
impl Default for Values {
    fn default() -> Self {
        Self {
            tunnel: String::new(),
            base: "https://api.openai.com".into(),
            prefix: String::new(),
            key: "env:CONTROL_PLANE_API_KEY".into(),
            health: "127.0.0.1:8080".into(),
            browser: false,
            url: String::new(),
            command: String::new(),
        }
    }
}
impl From<&ArgMatches> for Values {
    fn from(arguments: &ArgMatches) -> Self {
        let mut result = Self::default();
        for (name, field) in [
            ("tunnel-id", &mut result.tunnel),
            ("control-plane-base-url", &mut result.base),
            ("control-plane-url-path", &mut result.prefix),
            ("control-plane-api-key-ref", &mut result.key),
            ("health-listen-addr", &mut result.health),
            ("mcp-server-url", &mut result.url),
            ("mcp-command", &mut result.command),
        ] {
            let value = text(arguments, name);
            if !value.is_empty() {
                *field = value;
            }
        }
        result.browser = arguments
            .try_get_one::<bool>("open-web-ui")
            .ok()
            .flatten()
            .copied()
            .unwrap_or_default();
        result
    }
}
fn generate(name: &str, mut values: Values) -> Result<String> {
    sample(name)?;
    anyhow::ensure!(
        !values.browser,
        "admin_ui.open_browser must retain its default in otunnel"
    );
    anyhow::ensure!(
        values
            .tunnel
            .strip_prefix("tunnel_")
            .is_some_and(|id| id.len() == 32
                && id
                    .bytes()
                    .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit())),
        "tunnel ID must match tunnel_<32 lowercase letters or digits>"
    );
    url::Url::parse(&values.base)?;
    anyhow::ensure!(
        values
            .key
            .split_once(':')
            .is_some_and(|(kind, value)| matches!(kind, "env" | "file") && !value.is_empty()),
        "use env:VARNAME or file:/path/to/key"
    );
    match name {
        "sample_mcp_stdio_local" => {
            anyhow::ensure!(
                !values.command.is_empty(),
                "sample_mcp_stdio_local requires --mcp-command"
            );
            values.url.clear();
        }
        "sample_mcp_remote_no_auth" => {
            anyhow::ensure!(
                !values.url.is_empty(),
                "sample_mcp_remote_no_auth requires --mcp-server-url"
            );
            values.command.clear();
        }
        _ => anyhow::ensure!(
            values.url.is_empty() != values.command.is_empty(),
            "{name} requires exactly one of --mcp-server-url or --mcp-command"
        ),
    }
    let mut profile = json!({"control_plane":{"base_url":values.base,"tunnel_id":values.tunnel,"api_key":values.key},
        "health":{"listen_addr":values.health},"admin_ui":{"open_browser":values.browser},"log":{"level":"info","format":"json"}});
    if !values.prefix.is_empty() {
        profile["control_plane"]["url_path"] = json!(values.prefix);
    }
    if !values.command.is_empty() {
        profile["mcp"] = json!({"commands":[{"channel":"main","command":values.command}]});
    } else {
        url::Url::parse(&values.url)?;
        profile["mcp"] = json!({"server_urls":[{"channel":"main","url":values.url}]});
    }
    if name == "sample_mcp_enterprise_proxy" {
        profile["ca_bundle"] = json!("env:ENTERPRISE_CA_BUNDLE");
        profile["http_proxy"] = json!("env:HTTPS_PROXY");
    }
    #[derive(serde::Serialize)]
    struct Sample {
        config_version: u8,
        #[serde(flatten)]
        fields: serde_json::Value,
    }
    Ok(serde_saphyr::to_string(&Sample {
        config_version: 1,
        fields: profile,
    })?)
}

fn validate(contents: &str) -> Result<()> {
    let config = Config::parse(contents)?;
    for target in config.harpoon.targets {
        if let Some(definition) = target.template {
            anyhow::ensure!(
                config.config_version == Some(2),
                "Harpoon templates require config_version: 2"
            );
            definition.validate()?;
        }
    }
    Ok(())
}
fn create_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("create profile directory {}", path.display()))
}
fn write(path: &Path, contents: &[u8], force: bool) -> Result<()> {
    let directory = path.parent().context("profile directory is missing")?;
    create_directory(directory)?;
    if force && let Ok(metadata) = fs::metadata(path) {
        anyhow::ensure!(
            metadata.is_file(),
            "profile {} must be a regular file",
            path.display()
        );
    }
    #[cfg(windows)]
    if force {
        let mut file = fs::OpenOptions::new().create(true).write(true).open(path)?;
        anyhow::ensure!(file.metadata()?.is_file(), "profile must be a regular file");
        file.set_len(0)?;
        file.write_all(contents)?;
        return Ok(());
    }
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(contents)?;
    let result = if force {
        file.persist(path)
    } else {
        file.persist_noclobber(path)
    };
    result.with_context(|| {
        format!(
            "write profile {}; use --force to replace an existing profile",
            path.display()
        )
    })?;
    Ok(())
}

fn preflight(arguments: &[String], depth: usize) -> Result<PathBuf> {
    let name = arguments.first().context("command is empty")?;
    let executable = which::which(name)
        .with_context(|| format!("stdio MCP executable {name:?} was not found"))?;
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut prefix = [0; 4096];
        let count = fs::File::open(&executable)?.read(&mut prefix)?;
        if prefix[..count].starts_with(b"#!") {
            let source = String::from_utf8_lossy(&prefix[2..count]);
            let line = source.lines().next().unwrap_or_default();
            let interpreter = shell_words::split(line)?;
            if let Some(interpreter) = interpreter.first() {
                which::which(interpreter).with_context(|| {
                    format!("script interpreter {interpreter:?} is unavailable")
                })?;
            }
        }
    }
    if depth >= 4 {
        return Ok(executable);
    }
    let base = Path::new(name)
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or(name)
        .to_ascii_lowercase();
    let mut index = 1;
    while let Some(value) = arguments.get(index) {
        if base == "env" {
            if matches!(value.as_str(), "-u" | "--unset" | "-C" | "--chdir") {
                index += 2;
                continue;
            }
            if matches!(value.as_str(), "-S" | "--split-string") {
                let nested = arguments
                    .get(index + 1)
                    .context("env split-string requires a command")?;
                if arguments.len() == index + 2 {
                    preflight(&shell_words::split(nested)?, depth + 1)?;
                } else {
                    preflight(&arguments[index + 1..], depth + 1)?;
                }
                break;
            }
            if value == "--" {
                preflight(&arguments[index + 1..], depth + 1)?;
                break;
            }
            if value.starts_with('-') || value.contains('=') {
                index += 1;
                continue;
            }
            preflight(&arguments[index..], depth + 1)?;
            break;
        }
        if matches!(base.as_str(), "sh" | "bash" | "zsh" | "dash" | "ksh")
            && value.starts_with('-')
            && value.contains('c')
        {
            let command = arguments
                .get(index + 1)
                .context("shell -c requires a command string")?;
            let words = shell_words::split(command)?;
            let start = words
                .iter()
                .position(|word| {
                    !matches!(word.as_str(), "exec" | "command") && !word.contains('=')
                })
                .unwrap_or(words.len());
            if start < words.len() {
                preflight(&words[start..], depth + 1)?;
            }
            break;
        }
        if !matches!(
            base.as_str(),
            "sh" | "bash"
                | "zsh"
                | "dash"
                | "ksh"
                | "python"
                | "python3"
                | "node"
                | "ruby"
                | "perl"
                | "php"
                | "deno"
        ) {
            break;
        }
        if matches!(
            (base.as_str(), value.as_str()),
            ("python" | "python3", "-m" | "-c")
                | ("node", "-e" | "--eval")
                | ("ruby" | "perl" | "php", "-e" | "-E")
                | ("deno", "eval")
        ) || value.starts_with("--eval=")
        {
            break;
        }
        if matches!(
            (base.as_str(), value.as_str()),
            ("node", "-r" | "--require" | "--loader" | "--import")
                | ("ruby", "-I" | "-r")
                | ("perl", "-I" | "-M")
                | ("php", "-c" | "-d")
                | ("deno", "--config" | "--import-map" | "--cert")
        ) {
            index += 2;
            continue;
        }
        if value.starts_with('-') {
            index += 1;
            continue;
        }
        anyhow::ensure!(
            fs::metadata(value)
                .with_context(|| format!("stdio MCP script {value:?} was not found"))?
                .is_file(),
            "stdio MCP script {value:?} is a directory"
        );
        fs::File::open(value)?;
        break;
    }
    Ok(executable)
}

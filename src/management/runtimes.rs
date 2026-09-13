use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde_json::{Value, json};

use super::{
    Manager,
    files::Files,
    first, inspect, session,
    state::{self, AdminProfile, Alias, Process},
};
use crate::{
    admin::{Client, Tunnel},
    config::Config,
};

#[derive(Default)]
pub struct Remote {
    pub profile: String,
    pub key: String,
    pub base_url: String,
    pub url_path: String,
}
#[derive(Default)]
pub struct Scope {
    pub organizations: Vec<String>,
    pub workspaces: Vec<String>,
    pub tenant: String,
}
impl Scope {
    fn validate(&self, list: bool) -> Result<()> {
        anyhow::ensure!(
            usize::from(!self.organizations.is_empty())
                + usize::from(!self.workspaces.is_empty())
                + usize::from(!self.tenant.is_empty())
                <= 1,
            "runtimes accepts exactly one remote scope family: --organization-id, --workspace-id, or --tenant-id"
        );
        if list {
            anyhow::ensure!(
                self.organizations.len() <= 1,
                "runtimes list accepts at most one --organization-id for remote listing"
            );
            anyhow::ensure!(
                self.workspaces.len() <= 1,
                "runtimes list accepts at most one --workspace-id for remote listing"
            );
        }
        Ok(())
    }
    fn present(&self) -> bool {
        !self.organizations.is_empty() || !self.workspaces.is_empty() || !self.tenant.is_empty()
    }
}
#[derive(Default)]
pub struct Create {
    pub alias: String,
    pub name: String,
    pub description: String,
    pub remote: Remote,
    pub scope: Scope,
}
#[derive(Default)]
pub struct Connect {
    pub create: Create,
    pub tunnel_id: String,
    pub profile: String,
    pub profile_dir: String,
    pub server_url: String,
    pub command: String,
    pub key: String,
    pub binary: String,
}
pub struct Outcome {
    pub payload: Value,
    pub code: u8,
}

impl Manager {
    fn remote(&self, requested: &Remote, fallback: &str) -> Result<AdminProfile> {
        let name = state::alias(&first(&[
            &requested.profile,
            fallback,
            &state::variable("TUNNEL_MCP_ADMIN_PROFILE").unwrap_or_default(),
            "default",
        ]))?;
        let mut file = self.root.profiles()?;
        let previous = file.profiles.get(&name).cloned().unwrap_or_default();
        let base = first(&[
            &requested.base_url,
            &previous.control_plane_base_url,
            &state::variable("CONTROL_PLANE_BASE_URL").unwrap_or_default(),
            "https://api.openai.com",
        ]);
        let prefix = first(&[
            &requested.url_path,
            &previous.control_plane_url_path,
            &state::variable("CONTROL_PLANE_URL_PATH").unwrap_or_default(),
        ]);
        let key = first(&[&requested.key, &previous.admin_key, "env:OPENAI_ADMIN_KEY"]);
        state::reference(&key)?;
        if previous.name.is_empty()
            || previous.control_plane_base_url != base
            || previous.control_plane_url_path != prefix
            || previous.admin_key != key
        {
            let profile = AdminProfile {
                name: name.clone(),
                control_plane_base_url: base,
                control_plane_url_path: prefix,
                admin_key: key,
                updated_at: state::timestamp(),
            };
            file.profiles.insert(name.clone(), profile.clone());
            file.active_profile = name;
            self.root.save("admin_profiles.yaml", &file)?;
            return Ok(profile);
        }
        Ok(previous)
    }
    async fn resolve_tunnel(
        &self,
        alias: &str,
        options: &Create,
        profile: &AdminProfile,
        aliases: &mut BTreeMap<String, Alias>,
    ) -> Result<Tunnel> {
        if let Some(previous) = aliases.get(alias)
            && !previous.tunnel_id.is_empty()
        {
            let previous_profile = self.remote(&Remote::default(), &previous.admin_profile)?;
            match client(&previous_profile, "")?
                .get(&previous.tunnel_id)
                .await
            {
                Ok(tunnel) => return Ok(tunnel),
                Err(error) if not_found(&error) => {
                    self.root.history(
                        "stale-alias",
                        alias,
                        &previous.tunnel_id,
                        &error.to_string(),
                    )?;
                    aliases.remove(alias);
                    self.root.save("aliases.yaml", aliases)?;
                }
                Err(error) => return Err(error),
            }
        }
        let client = client(profile, "")?;
        if options.scope.present() {
            options.scope.validate(true)?;
            match client
                .list(
                    options
                        .scope
                        .organizations
                        .first()
                        .map_or("", String::as_str),
                    options.scope.workspaces.first().map_or("", String::as_str),
                    &options.scope.tenant,
                )
                .await
            {
                Ok(list) => {
                    if let Some(tunnel) = list
                        .tunnels
                        .unwrap_or_default()
                        .into_iter()
                        .find(|tunnel| tunnel.name == first(&[&options.name, alias]))
                    {
                        return Ok(tunnel);
                    }
                }
                Err(error) if not_found(&error) => {}
                Err(error) => return Err(error),
            }
        }
        anyhow::ensure!(
            !options.scope.organizations.is_empty() || !options.scope.workspaces.is_empty(),
            "creating a tunnel requires --organization-id or --workspace-id"
        );
        let mut body = json!({"name":first(&[&options.name,alias]),"description":first(&[&options.description,&format!("MCP tunnel for {alias}")])});
        if !options.scope.organizations.is_empty() {
            body["organization_ids"] = json!(options.scope.organizations);
        }
        if !options.scope.workspaces.is_empty() {
            body["workspace_ids"] = json!(options.scope.workspaces);
        }
        client.create(body).await
    }
    pub async fn create(&self, options: Create) -> Result<Value> {
        let alias = state::alias(&options.alias)?;
        options.scope.validate(false)?;
        self.root.initialize()?;
        let _lock = self.root.lock()?;
        let mut aliases = self.root.aliases()?;
        let fallback = aliases
            .get(&alias)
            .map_or("", |record| record.admin_profile.as_str());
        let profile = self.remote(&options.remote, fallback)?;
        let tunnel = self
            .resolve_tunnel(&alias, &options, &profile, &mut aliases)
            .await?;
        aliases.insert(alias.clone(), record(&alias, &tunnel, &profile.name));
        self.root.save("aliases.yaml", &aliases)?;
        self.root.history(
            "create",
            &alias,
            &tunnel.id,
            &format!("name={} admin_profile={}", tunnel.name, profile.name),
        )?;
        Ok(
            json!({"alias":alias,"tunnel":inspect::tunnel(&tunnel),"admin_profile":profile.name,"admin_profile_path":self.root.path.join("admin_profiles.yaml"),"state_root":self.root.path}),
        )
    }
    pub async fn connect(&self, options: Connect) -> Result<Outcome> {
        session::executable(&options.binary)?;
        let alias = state::alias(&options.create.alias)?;
        options.create.scope.validate(false)?;
        self.root.initialize()?;
        let profile_name = first(&[&options.profile, &alias]);
        crate::config::profile_name(&profile_name)?;
        let profile_dir = if options.profile_dir.trim().is_empty() {
            crate::config::profile_dir(None)?
        } else {
            PathBuf::from(options.profile_dir.trim())
        };
        let (target_kind, target_value) = if !options.server_url.trim().is_empty() {
            let url = url::Url::parse(options.server_url.trim())?;
            anyhow::ensure!(
                matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
                "--mcp-server-url must be an http or https URL"
            );
            ("server_url", options.server_url.trim().to_owned())
        } else {
            anyhow::ensure!(
                !options.command.trim().is_empty(),
                "connect requires --mcp-server-url or --mcp-command"
            );
            ("command", options.command.clone())
        };
        state::target(&target_value)?;
        let key = first(&[&options.key, "env:CONTROL_PLANE_API_KEY"]);
        state::reference(&key)?;
        let _lock = self.root.lock()?;
        let mut aliases = self.root.aliases()?;
        let previous = aliases.get(&alias).cloned().unwrap_or_default();
        let profile = self.remote(&options.create.remote, &previous.admin_profile)?;
        let mut remote_error = String::new();
        let tunnel = if !options.tunnel_id.trim().is_empty() {
            let id = options.tunnel_id.trim();
            anyhow::ensure!(
                id.strip_prefix("tunnel_").is_some_and(|id| id.len() == 32
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())),
                "tunnel ID must match tunnel_<32 lowercase letters or digits>"
            );
            match async { client(&profile, &key)?.get(id).await }.await {
                Ok(tunnel) => tunnel,
                Err(error) => {
                    remote_error = format!("{error:#}");
                    Tunnel {
                        id: id.into(),
                        name: first(&[&options.create.name, &alias]),
                        description: first(&[
                            &options.create.description,
                            &format!("MCP tunnel for {alias}"),
                        ]),
                        organization_ids: options.create.scope.organizations.clone(),
                        workspace_ids: options.create.scope.workspaces.clone(),
                        ..Default::default()
                    }
                }
            }
        } else {
            match self
                .resolve_tunnel(&alias, &options.create, &profile, &mut aliases)
                .await
            {
                Ok(tunnel) => tunnel,
                Err(error)
                    if !previous.tunnel_id.is_empty()
                        && error.downcast_ref::<crate::admin::RequestError>().is_some()
                        && not_found(&error) =>
                {
                    remote_error = format!("{error:#}");
                    Tunnel {
                        id: previous.tunnel_id.clone(),
                        name: first(&[&previous.name, &alias]),
                        description: first(&[
                            &previous.description,
                            &format!("MCP tunnel for {alias}"),
                        ]),
                        organization_ids: previous.organization_ids.clone(),
                        workspace_ids: previous.workspace_ids.clone(),
                        tenant_ids: previous.tenant_ids.clone(),
                        ..Default::default()
                    }
                }
                Err(error) => return Err(error),
            }
        };
        let health_file = self.root.path.join("health").join(format!("{alias}.url"));
        let log_file = self.root.path.join("logs").join(format!("{alias}.log"));
        let mut configuration = json!({"config_version":1,"control_plane":{"base_url":profile.control_plane_base_url,"tunnel_id":tunnel.id,"api_key":key},
            "health":{"listen_addr":"127.0.0.1:0","url_file":health_file},"admin_ui":{"open_browser":false},"log":{"level":"info","format":"json","file":log_file}});
        if !profile.control_plane_url_path.is_empty() {
            configuration["control_plane"]["url_path"] = json!(profile.control_plane_url_path);
        }
        configuration["mcp"] = if target_kind == "server_url" {
            json!({"server_urls":[{"channel":"main","url":target_value}]})
        } else {
            json!({"commands":[{"channel":"main","command":target_value}]})
        };
        let profile_path = profile_dir.join(format!("{profile_name}.yaml"));
        write_profile(&profile_path, &configuration)?;
        let mut record = record(&alias, &tunnel, &profile.name);
        record.profile_name = profile_name;
        record.profile_dir = profile_dir.to_string_lossy().into_owned();
        record.profile_path = profile_path.to_string_lossy().into_owned();
        record.config_path = record.profile_path.clone();
        record.health_url_file = health_file.to_string_lossy().into_owned();
        aliases.insert(alias.clone(), record.clone());
        self.root.save("aliases.yaml", &aliases)?;
        let mut processes = self.root.processes()?;
        let existing = processes.get(&alias).cloned().unwrap_or_default();
        let replace = !previous.tunnel_id.is_empty() && previous.tunnel_id != tunnel.id;
        if replace && !existing.alias.is_empty() {
            self.root.history(
                "stale-process",
                &alias,
                &existing.tunnel_id,
                &format!("replacing with tunnel_id={}", tunnel.id),
            )?;
        }
        let mut launch = session::start(&self.root, &record, &existing, replace, &key).await?;
        let process = Process {
            alias: alias.clone(),
            tunnel_id: tunnel.id.clone(),
            admin_profile: profile.name.clone(),
            config_path: record.config_path.clone(),
            profile_name: record.profile_name.clone(),
            profile_dir: record.profile_dir.clone(),
            profile_path: record.profile_path.clone(),
            health_url_file: record.health_url_file.clone(),
            target_kind: target_kind.into(),
            target_value,
            command: launch.command.clone(),
            started_at: state::timestamp(),
            mode: launch.mode.into(),
            session_name: launch.session_name.clone(),
            pid: launch.pid,
            pid_start_time: launch.identity.start.clone(),
            pid_executable: launch.identity.executable.clone(),
            log_path: launch.log_path.clone(),
            ..Default::default()
        };
        processes.insert(alias.clone(), process.clone());
        self.root.save("processes.yaml", &processes)?;
        launch.release();
        self.root.history(
            "connect",
            &alias,
            &tunnel.id,
            &format!(
                "mode={} session=- pid={} started={} healthy={} ready={}",
                launch.mode,
                launch.pid.unwrap_or_default(),
                launch.started,
                launch.healthy,
                launch.ready
            ),
        )?;
        let local = inspect::local(&self.root, &alias, &record, &process).await?;
        let mut payload = self.status_payload(&alias, &record, &process, &profile, &local)?;
        for field in [
            "tunnel_id",
            "remote",
            "stale",
            "error",
            "repair_command",
            "control_plane_poll_health",
            "remote_lookup_attempted",
            "remote_lookup_auth_kind",
            "remote_lookup_auth_ref",
            "remote_skipped_reason",
        ] {
            payload
                .as_object_mut()
                .context("runtime payload")?
                .remove(field);
        }
        payload["tunnel"] = inspect::tunnel(&tunnel);
        payload["remote_error"] = json!(remote_error);
        payload["repair_actions"] = json!(inspect::actions(
            &alias,
            &record,
            &process,
            &local,
            &remote_error
        ));
        payload["next_steps"] = json!([inspect::doctor(&record, &process)]);
        payload["process"] = inspect::process(&process);
        for (name, value) in serde_json::to_value(&launch)?
            .as_object()
            .context("launch object")?
        {
            if !matches!(
                name.as_str(),
                "healthy" | "ready" | "health_url" | "log_tail"
            ) {
                payload[name] = value.clone();
            }
        }
        let mut diagnostics = json!({});
        if !launch.log_path.is_empty() {
            diagnostics["log_path"] = json!(launch.log_path);
        }
        if !launch.log_tail.is_empty() {
            diagnostics["log_tail"] = json!(launch.log_tail);
        }
        if let Some(code) = launch.exit_code {
            diagnostics["exit_code"] = json!(code);
        }
        payload["launch_diagnostics"] = if diagnostics
            .as_object()
            .is_some_and(|value| value.is_empty())
        {
            Value::Null
        } else {
            diagnostics
        };
        Ok(Outcome {
            payload,
            code: if launch.healthy { 0 } else { 2 },
        })
    }
    pub async fn list(&self, remote: Remote, scope: Scope) -> Result<Value> {
        scope.validate(true)?;
        self.root.initialize()?;
        let profile = self.remote(&remote, "")?;
        let aliases = self.root.aliases()?;
        let mut payload = json!({"aliases":aliases.values().map(inspect::alias).collect::<Vec<_>>(),"admin_profile":profile.name,"admin_profile_path":self.root.path.join("admin_profiles.yaml"),"state_root":self.root.path});
        if scope.present() {
            let remote = client(&profile, "")?
                .list(
                    scope.organizations.first().map_or("", String::as_str),
                    scope.workspaces.first().map_or("", String::as_str),
                    &scope.tenant,
                )
                .await?;
            payload["remote_tunnels"] = json!(
                remote
                    .tunnels
                    .unwrap_or_default()
                    .iter()
                    .map(|tunnel| {
                        let mut value = inspect::tunnel(tunnel);
                        let record = aliases
                            .values()
                            .rev()
                            .find(|record| record.tunnel_id == tunnel.id);
                        value["local_alias"] =
                            json!(record.map_or("", |record| record.alias.as_str()));
                        value["local_admin_profile"] =
                            json!(record.map_or("", |record| record.admin_profile.as_str()));
                        value
                    })
                    .collect::<Vec<_>>()
            );
        }
        Ok(payload)
    }
    pub async fn status(&self, alias: &str, remote: Remote) -> Result<Outcome> {
        let alias = state::alias(alias)?;
        let aliases = self.root.aliases()?;
        let processes = self.root.processes()?;
        let record = aliases
            .get(&alias)
            .with_context(|| format!("alias {alias} is not known; run create or connect first"))?;
        let process = processes.get(&alias).cloned().unwrap_or_default();
        let profile = self.remote(&remote, &record.admin_profile)?;
        let local = inspect::local(&self.root, &alias, record, &process).await?;
        let mut payload = self.status_payload(&alias, record, &process, &profile, &local)?;
        let mut references = Vec::new();
        for path in [
            &process.profile_path,
            &record.profile_path,
            &process.config_path,
            &record.config_path,
        ] {
            if let Ok(bytes) = fs::read(path)
                && let Ok(config) = serde_json::from_slice::<Value>(&bytes)
                && let Some(key) = config
                    .pointer("/control_plane/api_key")
                    .and_then(Value::as_str)
                && state::reference(key).is_ok()
            {
                references.push((key.to_owned(), "runtime"));
            }
        }
        references.extend([
            ("env:CONTROL_PLANE_API_KEY".into(), "runtime"),
            ("env:OPENAI_API_KEY".into(), "runtime"),
            (profile.admin_key.clone(), "admin"),
        ]);
        for (reference, kind) in &references {
            if let Err(reason) = available(reference) {
                payload["remote_skipped_reason"] = json!(reason.to_string());
                continue;
            }
            payload["remote_lookup_attempted"] = json!(true);
            payload["remote_lookup_auth_kind"] = json!(kind);
            payload["remote_lookup_auth_ref"] = json!(reference);
            payload["remote_skipped_reason"] = json!("");
            match async { client(&profile, reference)?.get(&record.tunnel_id).await }.await {
                Ok(tunnel) => payload["remote"] = inspect::tunnel(&tunnel),
                Err(error) => {
                    payload["stale"] = json!(not_found(&error));
                    payload["error"] = json!(format!("{error:#}"));
                    payload["remote_error"] = payload["error"].clone();
                }
            }
            break;
        }
        let actions = inspect::actions(
            &alias,
            record,
            &process,
            &local,
            inspect::string(&payload["error"]),
        );
        payload["next_steps"] = json!(inspect::next_steps(
            &actions,
            &[
                inspect::doctor(record, &process),
                format!("otunnel runtimes status {alias}")
            ]
        ));
        payload["repair_actions"] = json!(actions);
        let code = if payload["stale"] == true && process.alias.is_empty() {
            2
        } else {
            0
        };
        Ok(Outcome { payload, code })
    }
    fn status_payload(
        &self,
        alias: &str,
        record: &Alias,
        process: &Process,
        profile: &AdminProfile,
        local: &Value,
    ) -> Result<Value> {
        let actions = inspect::actions(alias, record, process, local, "");
        let mut payload = json!({"alias":alias,"tunnel_id":record.tunnel_id,"admin_profile":profile.name,"admin_profile_path":self.root.path.join("admin_profiles.yaml"),
            "remote":null,"stale":false,"error":"","remote_error":"","repair_command":inspect::repair(alias,record,process),"repair_actions":actions,
            "config_path":record.config_path,"profile_name":record.profile_name,"profile_dir":record.profile_dir,"profile_path":record.profile_path,"profile_exists":local["profile"]["exists"],
            "health_url_file":record.health_url_file,"health_url":local["health"]["url"],"ui_url":local["health"]["ui"],"runtime_state":local["runtime_state"],
            "healthy":local["effective_health"]["healthz"]["ok"],"ready":local["effective_health"]["readyz"]["ok"],"control_plane_poll_health":local["control_plane_poll_health"],
            "remote_lookup_attempted":false,"remote_lookup_auth_kind":"","remote_lookup_auth_ref":"","remote_skipped_reason":"",
            "tmux":local["tmux"],"process_running":local["process_running"],"process":if process.alias.is_empty() { Value::Null } else { inspect::process(process) },"local":local,
            "next_steps":inspect::next_steps(&actions,&[inspect::doctor(record,process),format!("otunnel runtimes status {alias}")])});
        for key in ["health_details_url", "mcp_health_url"] {
            if let Some(value) = local["effective_health"].get(key) {
                payload[key] = value.clone();
            }
        }
        Ok(payload)
    }
    pub async fn stop(&self, alias: &str, remote: Remote) -> Result<Outcome> {
        let alias = state::alias(alias)?;
        let _lock = self.root.lock()?;
        let aliases = self.root.aliases()?;
        let mut processes = self.root.processes()?;
        let record = aliases
            .get(&alias)
            .with_context(|| format!("alias {alias} is not known; run create or connect first"))?;
        let profile = self.remote(&remote, &record.admin_profile)?;
        let mut process = processes.get(&alias).cloned().unwrap_or_default();
        let previous_mode = process.mode.clone();
        let result: Result<bool> = async {
            if process.alias.is_empty() || process.mode == "stopped" {
                return Ok(true);
            }
            match process.mode.as_str() {
                "tmux" => match session::tmux(&self.root, &alias, &process).await? {
                    Some(socket) => {
                        session::tmux_stop(&self.root, &alias, &process, &socket).await?;
                        Ok(false)
                    }
                    None => Ok(true),
                },
                "process" => match process.pid {
                    Some(pid) => Ok(!process.identity().stop(pid).await?),
                    None => Ok(true),
                },
                _ => Ok(true),
            }
        }
        .await;
        let (already_stopped, stop_error) = match result {
            Ok(already) => (already, String::new()),
            Err(error) => (false, format!("{error:#}")),
        };
        if stop_error.is_empty() {
            if let Ok(files) = Files::open(&self.root, "health", false) {
                files.remove(&self.root.path.join("health").join(format!("{alias}.url")))?;
            }
            if !process.alias.is_empty() {
                process.mode = "stopped".into();
                process.session_name.clear();
                process.tmux_socket.clear();
                process.pid = None;
                process.pid_start_time.clear();
                process.pid_executable.clear();
                processes.insert(alias.clone(), process.clone());
                self.root.save("processes.yaml", &processes)?;
            }
        }
        self.root.history(
            "stop",
            &alias,
            &record.tunnel_id,
            &format!(
                "previous_mode={previous_mode} already_stopped={already_stopped}{}",
                if stop_error.is_empty() {
                    String::new()
                } else {
                    format!(" error={stop_error}")
                }
            ),
        )?;
        let local = inspect::local(&self.root, &alias, record, &process).await?;
        let mut payload = self.status_payload(&alias, record, &process, &profile, &local)?;
        payload["error"] = json!(stop_error);
        payload["remote_error"] = json!(stop_error);
        payload["remote_skipped_reason"] = json!("stop is a local-only operation");
        let actions = inspect::actions(&alias, record, &process, &local, &stop_error);
        payload["next_steps"] = json!(inspect::next_steps(
            &actions,
            &[
                inspect::doctor(record, &process),
                format!("otunnel runtimes status {alias}")
            ]
        ));
        payload["repair_actions"] = json!(actions);
        payload["already_stopped"] = json!(already_stopped);
        payload["stopped"] = json!(stop_error.is_empty());
        payload["stop_error"] = json!(stop_error);
        Ok(Outcome {
            payload,
            code: if stop_error.is_empty() { 0 } else { 2 },
        })
    }
    pub fn remove(&self, alias: &str) -> Result<Value> {
        let alias = state::alias(alias)?;
        let _lock = self.root.lock()?;
        let mut aliases = self.root.aliases()?;
        let mut processes = self.root.processes()?;
        anyhow::ensure!(
            aliases.contains_key(&alias)
                || processes
                    .get(&alias)
                    .is_some_and(|process| !process.alias.is_empty()),
            "alias {alias} is not known"
        );
        let record = aliases.get(&alias).cloned().unwrap_or_default();
        let process = processes.get(&alias).cloned().unwrap_or_default();
        anyhow::ensure!(
            process.alias.is_empty() || matches!(process.mode.as_str(), "" | "stopped"),
            "alias {alias} still has a managed runtime; run `otunnel runtimes stop {alias}` first"
        );
        let mut removed = Vec::new();
        for path in [
            &record.config_path,
            &record.profile_path,
            &record.health_url_file,
            &process.config_path,
            &process.profile_path,
            &process.health_url_file,
            &process.log_path,
        ] {
            if path.trim().is_empty() || removed.contains(path) {
                continue;
            }
            let directory = if path == &process.log_path {
                Some("logs")
            } else if path == &record.health_url_file || path == &process.health_url_file {
                Some("health")
            } else {
                None
            };
            let result = if let Some(directory) = directory {
                Files::open(&self.root, directory, false)
                    .and_then(|files| files.remove(Path::new(path)))
            } else {
                fs::remove_file(path).map_err(anyhow::Error::from)
            };
            if let Err(error) = result
                && !error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            {
                return Err(error).with_context(|| format!("remove local state path {path}"));
            }
            removed.push(path.clone());
        }
        aliases.remove(&alias);
        processes.remove(&alias);
        self.root.save("aliases.yaml", &aliases)?;
        self.root.save("processes.yaml", &processes)?;
        let tunnel = first(&[&record.tunnel_id, &process.tunnel_id]);
        self.root.history(
            "rm",
            &alias,
            &tunnel,
            &format!("removed_paths={}", removed.len()),
        )?;
        Ok(
            json!({"alias":alias,"removed":true,"removed_paths":removed,"state_root":self.root.path,"tunnel_id":tunnel}),
        )
    }
    pub async fn cleanup(&self, apply: bool) -> Result<Value> {
        self.root.initialize()?;
        let _lock = self.root.lock()?;
        let mut aliases = self.root.aliases()?;
        let mut processes = self.root.processes()?;
        let names: BTreeSet<_> = aliases.keys().chain(processes.keys()).cloned().collect();
        let mut entries = Vec::new();
        let mut removed = Vec::new();
        for name in names {
            let record = aliases.get(&name).cloned().unwrap_or_default();
            let process = processes.get(&name).cloned().unwrap_or_default();
            let local = inspect::local(&self.root, &name, &record, &process).await?;
            let classification =
                if local["live_admin_ui"]["found"] == true || local["process_running"] == true {
                    "live_runtime"
                } else if local["profile"]["exists"] == true {
                    "valid_profile"
                } else if !inspect::string(&local["profile"]["path"]).is_empty()
                    || !inspect::string(&local["profile"]["name"]).is_empty()
                {
                    "missing_profile"
                } else {
                    "stale_alias"
                };
            entries.push(json!({"alias":name,"tunnel_id":first(&[&record.tunnel_id,&process.tunnel_id]),"classification":classification,"profile":local["profile"],"runtime_state":local["runtime_state"],"live_runtime":local["live_admin_ui"],"cleanup_safe":classification == "stale_alias","cleanup_command":"otunnel runtimes cleanup --apply"}));
            if apply && classification == "stale_alias" {
                aliases.remove(&name);
                processes.remove(&name);
                removed.push(name.clone());
                self.root.history(
                    "cleanup",
                    &name,
                    &first(&[&record.tunnel_id, &process.tunnel_id]),
                    "removed stale local alias/process metadata",
                )?;
            }
        }
        if apply {
            self.root.save("aliases.yaml", &aliases)?;
            self.root.save("processes.yaml", &processes)?;
        }
        Ok(
            json!({"state_root":self.root.path,"apply":apply,"entries":entries,"removed":removed,"next_steps":["Review entries with classification=stale_alias, then run `otunnel runtimes cleanup --apply` to remove only stale local alias/process metadata."]}),
        )
    }
}

fn client(profile: &AdminProfile, reference: &str) -> Result<Client> {
    let reference = first(&[reference, &profile.admin_key]);
    state::reference(&reference)?;
    let key = crate::config::resolve(&reference)?;
    Client::new(
        &profile.control_plane_base_url,
        &profile.control_plane_url_path,
        key.trim(),
        None,
    )
}
fn not_found(error: &anyhow::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("404") || message.contains("not found")
}
fn available(reference: &str) -> Result<()> {
    if let Some(name) = reference.strip_prefix("env:") {
        anyhow::ensure!(
            state::variable(name).is_some(),
            "environment variable {name} is not set"
        );
    } else {
        let path = reference.strip_prefix("file:").unwrap_or(reference);
        let metadata =
            fs::metadata(path).with_context(|| format!("secret file {path} does not exist"))?;
        anyhow::ensure!(metadata.len() > 0, "secret file {path} is empty");
    }
    Ok(())
}
fn record(alias: &str, tunnel: &Tunnel, profile: &str) -> Alias {
    Alias {
        alias: alias.into(),
        tunnel_id: tunnel.id.clone(),
        name: tunnel.name.clone(),
        description: tunnel.description.clone(),
        organization_ids: tunnel.organization_ids.clone(),
        workspace_ids: tunnel.workspace_ids.clone(),
        tenant_ids: tunnel.tenant_ids.clone(),
        admin_profile: profile.into(),
        updated_at: state::timestamp(),
        ..Default::default()
    }
}
fn write_profile(path: &Path, value: &Value) -> Result<()> {
    let directory = path.parent().context("profile directory is missing")?;
    fs::create_dir_all(directory)?;
    let root = cap_std::fs::Dir::open_ambient_dir(directory, cap_std::ambient_authority())?;
    let name = path.file_name().context("profile filename is missing")?;
    if let Ok(metadata) = root.metadata(name) {
        anyhow::ensure!(metadata.is_file(), "profile must be a regular file");
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Config::parse(std::str::from_utf8(&bytes)?)?;
    #[cfg(windows)]
    {
        let file = root.open_with(
            name,
            cap_std::fs::OpenOptions::new().create(true).write(true),
        )?;
        anyhow::ensure!(file.metadata()?.is_file(), "profile must be a regular file");
        file.set_len(0)?;
        file.into_std().write_all(&bytes)?;
    }
    #[cfg(unix)]
    {
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        file.write_all(&bytes)?;
        file.persist(path)?;
    }
    Ok(())
}

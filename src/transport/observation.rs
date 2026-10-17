use std::collections::BTreeSet;

use serde_json::{Value, json, value::RawValue};

use crate::{control, protocol};

pub(super) struct Observation {
    snapshot: Value,
    epoch: u64,
    discover_epoch: u64,
    revision: u64,
    epoch_limited: bool,
    discover_limited: bool,
    catalog_limited: bool,
    active: bool,
    version: Option<String>,
    cursor: Option<String>,
    pages: usize,
    cursors: BTreeSet<String>,
}

pub(super) struct Token {
    method: String,
    epoch: u64,
    discover_epoch: u64,
    revision: u64,
    version: Option<String>,
    page: Option<usize>,
}

impl Observation {
    pub fn new() -> Self {
        Self {
            snapshot: json!({"state":"not_observed","details":{
                "channel":"main","transport":"stdio","child_state":"running",
                "child_generation":format!("{:032x}", rand::random::<u128>()),
                "initialize_epoch":0,"evidence":"same_child",
                "initialize":identity(),"tools_list":catalog()
            }}),
            epoch: 0,
            discover_epoch: 0,
            revision: 0,
            epoch_limited: false,
            discover_limited: false,
            catalog_limited: false,
            active: false,
            version: None,
            cursor: None,
            pages: 0,
            cursors: BTreeSet::new(),
        }
    }

    pub fn snapshot(&self) -> Value {
        let mut snapshot = self.snapshot.clone();
        snapshot["status"] = json!(match snapshot["state"].as_str() {
            Some("initialized" | "server_discovered" | "discovered") => "ok",
            Some("failed" | "closed") => "degraded",
            _ => "unknown",
        });
        snapshot["limited"] = json!(
            self.epoch_limited
                || self.discover_limited
                || self.catalog_limited
                || snapshot["details"]["initialize"]["limited"] == true
                || snapshot["details"]["server_discover"]["limited"] == true
                || snapshot["details"]["tools_list"]["limited"] == true
        );
        snapshot
    }

    fn state(&mut self, state: &str, reason: &str, observed: Option<f64>) {
        self.snapshot["state"] = json!(state);
        let snapshot = self.snapshot.as_object_mut().expect("observation object");
        if reason.is_empty() {
            snapshot.remove("reason_code");
        } else {
            snapshot.insert("reason_code".into(), json!(reason));
        }
        if let Some(observed) = observed {
            snapshot.insert("observed_at".into(), json!(observed));
        } else {
            snapshot.remove("observed_at");
        }
    }

    fn restore(&mut self) {
        let details = &self.snapshot["details"];
        let (state, observed) = if details["server_discover"]["ok"] == true {
            (
                "server_discovered",
                details["server_discover"]["observed_at"].as_f64(),
            )
        } else if details["initialize"]["ok"] == true {
            ("initialized", details["initialize"]["observed_at"].as_f64())
        } else {
            ("not_observed", None)
        };
        self.state(state, "", observed);
    }

    fn reset(&mut self) {
        self.snapshot["details"]["tools_list"] = catalog();
        self.active = false;
        self.version = None;
        self.cursor = None;
        self.pages = 0;
        self.cursors.clear();
    }

    fn advance(&mut self) -> bool {
        if !self.catalog_limited
            && let Some(revision) = self.revision.checked_add(1)
        {
            self.revision = revision;
            return true;
        }
        self.catalog_limited = true;
        self.invalidate("catalog_revision_limit", true);
        false
    }

    fn invalidate(&mut self, reason: &str, limited: bool) {
        self.active = false;
        self.cursor = None;
        let data = &mut self.snapshot["details"]["tools_list"];
        data["complete"] = json!(false);
        data["partial"] = json!(true);
        data["limited"] = json!(data["limited"] == true || limited);
        self.snapshot["reason_code"] = json!(reason);
    }

    pub fn begin(&mut self, message: &RawValue) -> Option<Token> {
        let view = protocol::view(message).ok()?;
        view.id?;
        let method = view.method?.into_owned();
        if self.snapshot["details"]["child_state"] != "running" || self.epoch_limited {
            return None;
        }
        let version = protocol::self_contained_version(message);
        let mut page = None;
        match method.as_str() {
            "initialize" => {
                let Some(epoch) = self.epoch.checked_add(1) else {
                    self.epoch_limited = true;
                    self.snapshot["details"]["initialize"] = identity();
                    self.snapshot["details"]["initialize"]["limited"] = json!(true);
                    self.reset();
                    self.state("not_observed", "initialize_epoch_limit", None);
                    return None;
                };
                self.epoch = epoch;
                self.snapshot["details"]["initialize_epoch"] = json!(epoch);
                self.snapshot["details"]["initialize"] = identity();
                self.snapshot["details"]
                    .as_object_mut()?
                    .remove("server_discover");
                self.reset();
                self.state("not_observed", "", None);
            }
            "server/discover" => {
                if version.is_none() || self.discover_limited {
                    return None;
                }
                let Some(epoch) = self.discover_epoch.checked_add(1) else {
                    self.discover_limited = true;
                    self.snapshot["details"]["server_discover"] = discovery();
                    self.snapshot["details"]["server_discover"]["limited"] = json!(true);
                    self.reset();
                    self.restore();
                    self.snapshot["reason_code"] = json!("server_discover_epoch_limit");
                    self.snapshot["observed_at"] = json!(control::now());
                    return None;
                };
                self.discover_epoch = epoch;
                self.snapshot["details"]["server_discover_epoch"] = json!(epoch);
                self.snapshot["details"]
                    .as_object_mut()?
                    .remove("server_discover");
                if !self.advance() {
                    return None;
                }
                self.reset();
                self.restore();
                if protocol::field(message, "params")
                    .is_some_and(|params| params.get().len() > 8192)
                {
                    self.snapshot["details"]["server_discover"] = discovery();
                    self.snapshot["details"]["server_discover"]["limited"] = json!(true);
                    self.snapshot["reason_code"] = json!("observation_params_limit");
                    self.snapshot["observed_at"] = json!(control::now());
                    return None;
                }
            }
            "tools/list" => {
                if self.snapshot["details"]["initialize"]["ok"] != true && version.is_none() {
                    return None;
                }
                let params = protocol::field(message, "params");
                let cursor = match params.as_deref() {
                    None => Ok(None),
                    Some(params) if params.get().len() > 8192 => Err(true),
                    Some(params) => match serde_json::from_str::<Value>(params.get()) {
                        Ok(Value::Null) => Ok(None),
                        Ok(Value::Object(params)) => cursor(params.get("cursor")),
                        _ => Err(false),
                    },
                };
                if matches!(cursor, Ok(None)) {
                    if !self.advance() {
                        return None;
                    }
                    self.reset();
                    self.version = version.clone();
                    self.restore();
                }
                let failure = match &cursor {
                    Err(limited) => Some(("invalid_tools_cursor", *limited)),
                    Ok(Some(_)) if version != self.version => {
                        Some(("tools_protocol_mismatch", false))
                    }
                    Ok(Some(cursor)) if !self.active || self.cursor.as_ref() != Some(cursor) => {
                        Some(("tools_cursor_mismatch", false))
                    }
                    _ if self.pages >= 32 => Some(("tools_page_limit", true)),
                    _ => None,
                };
                if let Some((reason, limited)) = failure {
                    self.invalidate(reason, limited);
                    self.advance();
                    return None;
                }
                if self.catalog_limited {
                    return None;
                }
                self.active = true;
                page = Some(self.pages);
            }
            _ => return None,
        }
        Some(Token {
            method,
            epoch: self.epoch,
            discover_epoch: self.discover_epoch,
            revision: self.revision,
            version,
            page,
        })
    }

    fn matches(&self, token: &Token) -> bool {
        self.snapshot["details"]["child_state"] == "running"
            && token.epoch == self.epoch
            && !self.epoch_limited
            && (token.method == "initialize"
                || (token.discover_epoch == self.discover_epoch
                    && !self.discover_limited
                    && token.revision == self.revision
                    && !self.catalog_limited
                    && (token.method != "tools/list" || token.page == Some(self.pages))))
    }

    pub fn receive(&mut self, token: Token, message: &RawValue) {
        if !self.matches(&token) {
            return;
        }
        let Ok(response) = protocol::view(message) else {
            return;
        };
        if response.error.is_some() {
            self.failed(token, "mcp_discovery_error", false);
            return;
        }
        if response
            .result
            .is_some_and(|result| result.get().len() > 1024 * 1024)
        {
            self.failed(token, "observation_result_limit", true);
            return;
        }
        let result = response
            .result
            .and_then(|result| serde_json::from_str::<Value>(result.get()).ok());
        let invalid = match token.method.as_str() {
            "initialize" => "invalid_initialize_result",
            "server/discover" => "invalid_server_discover_result",
            _ => "invalid_tools_result",
        };
        let Some(result) = result else {
            self.failed(token, invalid, false);
            return;
        };
        let now = control::now();
        match token.method.as_str() {
            "initialize" | "server/discover" => {
                let (field, state, observed) = if token.method == "initialize" {
                    ("initialize", "initialized", initialize(&result))
                } else {
                    (
                        "server_discover",
                        "server_discovered",
                        discover(&result, token.version.as_deref()),
                    )
                };
                let Some(mut observed) = observed else {
                    self.failed(token, invalid, false);
                    return;
                };
                observed["observed_at"] = json!(now);
                self.snapshot["details"][field] = observed;
                self.state(state, "", Some(now));
            }
            "tools/list" if self.active => {
                let Some(tools) = result.get("tools").and_then(Value::as_array) else {
                    self.failed(token, invalid, false);
                    return;
                };
                let next = match cursor(result.get("nextCursor")) {
                    Ok(cursor) => cursor,
                    Err(limited) => {
                        self.failed(token, invalid, limited);
                        return;
                    }
                };
                let mut names = Vec::new();
                let mut limited = false;
                for tool in tools {
                    let Some(name) = tool
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|name| !name.is_empty())
                    else {
                        self.failed(token, invalid, false);
                        return;
                    };
                    if name.len() > 128 {
                        limited = true;
                    } else {
                        names.push(name.to_owned());
                    }
                }
                let (mut names, page_limited) = bounded(names);
                names.extend(
                    self.snapshot["details"]["tools_list"]["tool_names"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_owned),
                );
                let (names, names_limited) = bounded(names);
                let data = &mut self.snapshot["details"]["tools_list"];
                data["ok"] = json!(true);
                data["observed_at"] = json!(now);
                data["retained_count"] = json!(names.len());
                data["tool_names"] = json!(names);
                data["limited"] =
                    json!(data["limited"] == true || limited || page_limited || names_limited);
                data["complete"] = json!(next.is_none() && data["limited"] == false);
                data["partial"] = json!(data["complete"] != true);
                self.pages += 1;
                self.cursor = next;
                self.state("discovered", "", Some(now));
                if let Some(cursor) = &self.cursor {
                    if !self.cursors.insert(cursor.clone()) {
                        self.invalidate("tools_cursor_cycle", false);
                    }
                } else {
                    self.active = false;
                }
            }
            _ => {}
        }
    }

    pub fn failed(&mut self, token: Token, reason: &str, limited: bool) {
        if !self.matches(&token) {
            return;
        }
        match token.method.as_str() {
            "tools/list" => {
                self.invalidate(reason, limited);
                if !self.advance() {
                    return;
                }
            }
            "server/discover" => {
                self.snapshot["details"]["server_discover"] = discovery();
                self.snapshot["details"]["server_discover"]["limited"] = json!(limited);
                self.reset();
                if !self.advance() {
                    return;
                }
            }
            _ => {
                self.snapshot["details"]["initialize"] = identity();
                self.snapshot["details"]["initialize"]["limited"] = json!(limited);
            }
        }
        if limited {
            self.restore();
            self.snapshot["reason_code"] = json!(reason);
            self.snapshot["observed_at"] = json!(control::now());
        } else {
            self.state("failed", reason, Some(control::now()));
        }
    }

    pub fn list_changed(&mut self) {
        let details = &self.snapshot["details"];
        if details["child_state"] != "running"
            || (details["initialize"]["ok"] != true
                && details["server_discover"]["ok"] != true
                && details["tools_list"]["ok"] != true
                && !self.active)
        {
            return;
        }
        if self.advance() {
            self.reset();
            self.snapshot["details"]["tools_list"]["partial"] = json!(true);
            self.restore();
            self.snapshot["reason_code"] = json!("tools_list_changed");
            self.snapshot["observed_at"] = json!(control::now());
        }
    }

    pub fn closed(&mut self, reason: &str) {
        if self.snapshot["details"]["child_state"] == "closed" {
            return;
        }
        self.snapshot["details"]["child_state"] = json!("closed");
        self.snapshot["details"]["initialize"] = identity();
        self.snapshot["details"]
            .as_object_mut()
            .expect("details object")
            .remove("server_discover");
        self.reset();
        self.state("closed", reason, Some(control::now()));
    }
}

fn identity() -> Value {
    json!({"ok":false,"identity_complete":false,"limited":false,"capability_names":[]})
}

fn discovery() -> Value {
    json!({"ok":false,"limited":false,"supported_versions":[],"capability_names":[]})
}

fn catalog() -> Value {
    json!({"ok":false,"tool_names":[],"retained_count":0,"complete":false,"partial":false,"limited":false})
}

fn capabilities(result: &Value) -> Option<Vec<&'static str>> {
    let capabilities = result.get("capabilities")?.as_object()?;
    let mut names = Vec::new();
    for name in [
        "completions",
        "logging",
        "prompts",
        "resources",
        "tasks",
        "tools",
    ] {
        if let Some(value) = capabilities.get(name) {
            value.as_object()?;
            names.push(name);
        }
    }
    Some(names)
}

fn initialize(result: &Value) -> Option<Value> {
    let version = result
        .get("protocolVersion")?
        .as_str()
        .filter(|version| !version.is_empty())?;
    let info = result.get("serverInfo")?;
    let name = info.get("name")?.as_str().filter(|name| !name.is_empty())?;
    let server_version = info.get("version")?.as_str()?;
    let mut observed = identity();
    observed["ok"] = json!(true);
    observed["identity_complete"] = json!(true);
    observed["capability_names"] = json!(capabilities(result)?);
    for (name, value) in [
        ("protocol_version", version),
        ("server_name", name),
        ("server_version", server_version),
    ] {
        if value.len() > 256 {
            observed["limited"] = json!(true);
            observed["identity_complete"] = json!(false);
        } else if !value.is_empty() {
            observed[name] = json!(value);
        }
    }
    Some(observed)
}

fn discover(result: &Value, requested: Option<&str>) -> Option<Value> {
    if result
        .get("resultType")
        .is_some_and(|kind| kind.as_str() != Some("complete"))
    {
        return None;
    }
    let versions = result.get("supportedVersions")?.as_array()?;
    if versions.is_empty() {
        return None;
    }
    let mut versions = versions
        .iter()
        .map(|version| {
            version
                .as_str()
                .filter(|version| protocol::valid_date(version))
                .map(str::to_owned)
        })
        .collect::<Option<Vec<_>>>()?;
    versions.sort();
    versions.dedup();
    let requested =
        requested.filter(|requested| versions.iter().any(|version| version == requested));
    let limited = versions.len() > 32;
    versions.truncate(32);
    if let Some(requested) = requested
        && !versions.iter().any(|version| version == requested)
    {
        *versions.last_mut()? = requested.to_owned();
        versions.sort();
    }
    Some(json!({
        "ok":true,"limited":limited,"supported_versions":versions,
        "capability_names":capabilities(result)?
    }))
}

fn cursor(value: Option<&Value>) -> Result<Option<String>, bool> {
    let Some(value) = value else {
        return Ok(None);
    };
    let cursor = value.as_str().ok_or(false)?;
    if cursor.len() > 4096 {
        return Err(true);
    }
    Ok(Some(cursor.to_owned()))
}

fn bounded(mut names: Vec<String>) -> (Vec<String>, bool) {
    names.sort();
    names.dedup();
    let mut limited = names.len() > 256;
    names.truncate(256);
    let mut bytes = 2;
    for (index, name) in names.iter().enumerate() {
        let encoded = serde_json::to_string(name).expect("tool name JSON");
        let size = encoded.len()
            + name
                .bytes()
                .filter(|byte| matches!(byte, b'<' | b'>' | b'&'))
                .count()
                * 5
            + name
                .chars()
                .filter(|character| matches!(character, '\u{2028}' | '\u{2029}'))
                .count()
                * 3
            + usize::from(index > 0);
        if bytes + size > 16 * 1024 {
            names.truncate(index);
            limited = true;
            break;
        }
        bytes += size;
    }
    (names, limited)
}

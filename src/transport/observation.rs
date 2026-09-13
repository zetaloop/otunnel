use std::collections::BTreeSet;

use serde_json::{Value, json, value::RawValue};

use crate::{control, protocol};

pub(super) struct Observation {
    snapshot: Value,
    epoch: u64,
    revision: u64,
    cursor: Option<String>,
    pages: usize,
    cursors: BTreeSet<String>,
}

pub(super) struct Token {
    method: String,
    epoch: u64,
    revision: u64,
    page: bool,
}

impl Observation {
    pub fn new() -> Self {
        Self {
            snapshot: json!({"status":"unknown","state":"not_observed","limited":false,"details":{
                "channel":"main","transport":"stdio","child_state":"running",
                "child_generation":format!("{:032x}", rand::random::<u128>()),
                "initialize_epoch":0,"evidence":"same_child",
                "initialize":identity(),"tools_list":catalog()
            }}),
            epoch: 0,
            revision: 0,
            cursor: None,
            pages: 0,
            cursors: BTreeSet::new(),
        }
    }

    pub fn snapshot(&self) -> Value {
        self.snapshot.clone()
    }

    pub fn begin(&mut self, message: &RawValue) -> Option<Token> {
        let view = protocol::view(message).ok()?;
        let method = view.method?.into_owned();
        let mut page = false;
        match method.as_str() {
            "initialize" | "server/discover" => {
                self.epoch = self.epoch.saturating_add(1);
                self.snapshot["details"]["initialize_epoch"] = json!(self.epoch);
                self.snapshot["details"]["initialize"] = identity();
                self.snapshot["details"]["tools_list"] = catalog();
                self.snapshot["state"] = json!("not_observed");
                self.snapshot["status"] = json!("unknown");
                self.snapshot.as_object_mut()?.remove("reason_code");
                self.cursor = None;
            }
            "tools/list" => {
                let cursor = protocol::field(message, "params")
                    .and_then(|params| protocol::field(&params, "cursor"))
                    .and_then(|cursor| serde_json::from_str::<String>(cursor.get()).ok())
                    .filter(|cursor| !cursor.is_empty());
                if cursor.is_none() {
                    self.revision = self.revision.saturating_add(1);
                    self.snapshot["details"]["tools_list"] = catalog();
                    self.cursor = None;
                    self.pages = 0;
                    self.cursors.clear();
                }
                page = cursor == self.cursor;
            }
            _ => return None,
        }
        Some(Token {
            method,
            epoch: self.epoch,
            revision: self.revision,
            page,
        })
    }

    pub fn receive(&mut self, token: Token, message: &RawValue) {
        if token.epoch != self.epoch {
            return;
        }
        let now = control::now();
        let Some(result) = protocol::field(message, "result") else {
            if matches!(token.method.as_str(), "initialize" | "server/discover") {
                self.snapshot["status"] = json!("degraded");
                self.snapshot["state"] = json!("failed");
                self.snapshot["reason_code"] = json!("initialize_failed");
                self.snapshot["observed_at"] = json!(now);
            }
            return;
        };
        if result.get().len() > 1024 * 1024 {
            self.snapshot["limited"] = json!(true);
            return;
        }
        let Ok(result) = serde_json::from_str::<Value>(result.get()) else {
            return;
        };
        if matches!(token.method.as_str(), "initialize" | "server/discover") {
            let info = result
                .get("serverInfo")
                .or_else(|| result.pointer("/_meta/io.modelcontextprotocol~1serverInfo"));
            let mut observed = identity();
            observed["ok"] = json!(true);
            observed["observed_at"] = json!(now);
            let mut complete = true;
            for (source, name) in [("name", "server_name"), ("version", "server_version")] {
                match info
                    .and_then(|info| info.get(source))
                    .and_then(Value::as_str)
                {
                    Some(value) if !value.is_empty() && value.len() <= 256 => {
                        observed[name] = json!(value)
                    }
                    _ => complete = false,
                }
            }
            observed["identity_complete"] = json!(complete);
            observed["limited"] = json!(!complete);
            if let Some(version) = result
                .get("protocolVersion")
                .and_then(Value::as_str)
                .filter(|version| version.len() <= 256)
            {
                observed["protocol_version"] = json!(version);
            }
            let mut names: Vec<_> = result
                .get("capabilities")
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|capabilities| capabilities.keys())
                .filter(|name| {
                    [
                        "tools",
                        "prompts",
                        "resources",
                        "logging",
                        "completions",
                        "sampling",
                        "roots",
                        "elicitation",
                        "tasks",
                    ]
                    .contains(&name.as_str())
                })
                .cloned()
                .collect();
            names.sort();
            observed["capability_names"] = json!(names);
            self.snapshot["details"]["initialize"] = observed;
            self.snapshot["limited"] = json!(!complete);
            self.snapshot["state"] = json!("initialized");
            self.snapshot["status"] = json!("ok");
            self.snapshot["observed_at"] = json!(now);
        } else if token.revision == self.revision {
            let data = &mut self.snapshot["details"]["tools_list"];
            let Some(tools) = result.get("tools").and_then(Value::as_array) else {
                data["partial"] = json!(true);
                return;
            };
            self.pages += 1;
            if !token.page || self.pages > 32 {
                data["partial"] = json!(true);
                data["limited"] = json!(true);
                return;
            }
            let mut names: BTreeSet<String> = data["tool_names"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            let mut total: usize = names.iter().map(String::len).sum();
            for tool in tools {
                let Some(name) = tool
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty())
                else {
                    data["partial"] = json!(true);
                    continue;
                };
                if name.len() > 128 || names.len() >= 256 || total + name.len() > 16 * 1024 {
                    data["limited"] = json!(true);
                    data["partial"] = json!(true);
                    continue;
                }
                if names.insert(name.to_owned()) {
                    total += name.len();
                }
            }
            self.cursor = result
                .get("nextCursor")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            if let Some(cursor) = &self.cursor
                && (cursor.len() > 4096 || !self.cursors.insert(cursor.clone()))
            {
                data["partial"] = json!(true);
                data["limited"] = json!(true);
            }
            data["ok"] = json!(true);
            data["observed_at"] = json!(now);
            data["retained_count"] = json!(names.len());
            data["tool_names"] = json!(names);
            data["complete"] = json!(self.cursor.is_none() && data["partial"] == false);
            let limited = data["limited"] == true;
            self.snapshot["limited"] = json!(self.snapshot["limited"] == true || limited);
            self.snapshot["state"] = json!("discovered");
            self.snapshot["status"] = json!("ok");
            self.snapshot["observed_at"] = json!(now);
        }
    }

    pub fn closed(&mut self) {
        self.snapshot["status"] = json!("degraded");
        self.snapshot["state"] = json!("closed");
        self.snapshot["reason_code"] = json!("child_closed");
        self.snapshot["details"]["child_state"] = json!("closed");
        self.snapshot["observed_at"] = json!(control::now());
    }
}

fn identity() -> Value {
    json!({"ok":false,"identity_complete":false,"limited":false,"capability_names":[]})
}
fn catalog() -> Value {
    json!({"ok":false,"tool_names":[],"retained_count":0,"complete":false,"partial":false,"limited":false})
}

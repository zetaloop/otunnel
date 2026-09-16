use std::{borrow::Cow, collections::BTreeMap, time::Duration};

use anyhow::{Context, Result, bail};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{
    Value,
    value::{RawValue, to_raw_value},
};

pub type Json = Box<RawValue>;
pub type Headers = BTreeMap<String, Vec<String>>;
pub const MCP_VERSION: &str = "2026-07-28";
pub const WIRE_VERSION: &str = "2026-08-25";

pub(crate) const SUPPORTED_VERSIONS: [&str; 5] = [
    MCP_VERSION,
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];

pub(crate) fn validate_meta(message: &RawValue) -> std::result::Result<(), String> {
    let Some(version) = version(message) else {
        return Ok(());
    };
    if version.as_str() < MCP_VERSION {
        return Ok(());
    }
    let meta = field(message, "params").and_then(|params| field(&params, "_meta"));
    let capabilities = meta
        .as_deref()
        .and_then(|meta| field(meta, "io.modelcontextprotocol/clientCapabilities"))
        .and_then(|value| serde_json::from_str::<Value>(value.get()).ok());
    if !capabilities.is_some_and(|value| value.is_object()) {
        return Err(
            "missing or invalid _meta field \"io.modelcontextprotocol/clientCapabilities\"".into(),
        );
    }
    if let Some(info) = meta
        .as_deref()
        .and_then(|meta| field(meta, "io.modelcontextprotocol/clientInfo"))
    {
        let valid = serde_json::from_str::<Value>(info.get())
            .ok()
            .and_then(|value| value.as_object().cloned())
            .is_some_and(|value| {
                value.get("name").is_none_or(Value::is_string)
                    && value.get("version").is_none_or(Value::is_string)
            });
        if !valid {
            return Err("invalid _meta field \"io.modelcontextprotocol/clientInfo\"".into());
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct Command {
    pub request_id: String,
    pub shard_token: String,
    pub command_type: String,
    #[serde(default = "crate::config::main_channel")]
    pub channel: String,
    #[serde(default)]
    pub headers: Headers,
    #[serde(default)]
    pub response_timeout: Value,
    #[serde(default)]
    pub jsonrpc: Option<Json>,
}

#[derive(Deserialize)]
pub struct Poll {
    pub commands: Vec<Json>,
}

impl Poll {
    pub fn commands(self) -> Vec<Command> {
        self.commands
            .into_iter()
            .filter_map(|raw| {
                let parsed = (|| -> Result<Command> {
                    let mut command: Command = serde_json::from_str(raw.get())?;
                    anyhow::ensure!(
                        !command.request_id.is_empty() && !command.shard_token.is_empty(),
                        "command is missing its request ID or shard token"
                    );
                    command.channel = crate::config::channel(&command.channel)?;
                    match command.command_type.as_str() {
                        "jsonrpc" => {
                            let message = command
                                .jsonrpc
                                .as_deref()
                                .context("JSON-RPC command has no payload")?;
                            let version = field(message, "jsonrpc")
                                .and_then(|value| serde_json::from_str::<String>(value.get()).ok());
                            anyhow::ensure!(
                                version.as_deref() == Some("2.0"),
                                "invalid JSON-RPC payload"
                            );
                            view(message)?;
                        }
                        "oauth_discovery" => {}
                        "session_termination" => {
                            anyhow::ensure!(
                                command.headers.iter().any(|(name, values)| {
                                    name.eq_ignore_ascii_case("mcp-session-id")
                                        && values.iter().any(|value| !value.is_empty())
                                }),
                                "session termination has no Mcp-Session-Id header"
                            );
                        }
                        _ => bail!("unknown command type"),
                    }
                    Ok(command)
                })();
                match parsed {
                    Ok(command) => Some(command),
                    Err(error) => {
                        tracing::warn!(%error, "invalid tunnel command skipped");
                        None
                    }
                }
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub message: Json,
    pub headers: HeaderMap,
    pub discovery: bool,
}
impl Request {
    pub fn new(value: Value) -> Result<Self> {
        Ok(Self {
            message: to_raw_value(&value)?,
            headers: HeaderMap::new(),
            discovery: false,
        })
    }
    pub fn scope(&self) -> String {
        self.headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| {
                field(&self.message, "params")
                    .and_then(|v| field(&v, "_meta"))
                    .and_then(|v| field(&v, "openai/session"))
                    .map(|v| v.get().to_owned())
                    .unwrap_or_default()
            })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Reply {
    #[serde(rename = "resp_json", skip_serializing_if = "Option::is_none")]
    pub message: Option<Json>,
    #[serde(rename = "resp_headers", skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: Headers,
    #[serde(rename = "resp_code")]
    pub status: u16,
    #[serde(rename = "resp_type")]
    pub kind: &'static str,
}
impl Reply {
    pub fn json(message: Json) -> Self {
        Self {
            message: Some(message),
            headers: BTreeMap::from([("Content-Type".into(), vec!["application/json".into()])]),
            status: 200,
            kind: "jsonrpc_response",
        }
    }
    pub fn ack(status: u16, kind: &'static str) -> Self {
        Self {
            message: None,
            headers: BTreeMap::new(),
            status,
            kind,
        }
    }
    pub fn terminal(&self) -> bool {
        self.kind != "jsonrpc_notify"
    }
    pub fn error(
        request: &Request,
        status: u16,
        code: i32,
        message: impl AsRef<str>,
    ) -> Result<Self> {
        let id = view(&request.message)?.id;
        if id.is_none() {
            return Ok(Self::ack(status, "notify_ack"));
        }
        let mut result = Self::json(to_raw_value(
            &serde_json::json!({"jsonrpc":"2.0", "id":id, "error":{"code":code,"message":message.as_ref()}}),
        )?);
        result.status = status;
        Ok(result)
    }
}

#[derive(Deserialize)]
pub struct View<'a> {
    #[serde(borrow)]
    pub id: Option<&'a RawValue>,
    #[serde(borrow)]
    pub method: Option<Cow<'a, str>>,
    #[serde(borrow)]
    pub result: Option<&'a RawValue>,
    #[serde(borrow)]
    pub error: Option<&'a RawValue>,
}
pub fn view(value: &RawValue) -> Result<View<'_>> {
    Ok(serde_json::from_str(value.get())?)
}

pub fn field(value: &RawValue, key: &str) -> Option<Json> {
    let object: BTreeMap<String, &RawValue> = serde_json::from_str(value.get()).ok()?;
    object.get(key).map(|value| (*value).to_owned())
}

pub fn replace(value: &RawValue, keys: &[&str], replacement: &RawValue) -> Result<Json> {
    let Some((key, rest)) = keys.split_first() else {
        return Ok(replacement.to_owned());
    };
    let mut object: BTreeMap<String, Json> = serde_json::from_str(value.get())?;
    let child = object.get(*key).map_or("{}", |v| v.get());
    let child = RawValue::from_string(child.to_owned())?;
    object.insert((*key).into(), replace(&child, rest, replacement)?);
    Ok(to_raw_value(&object)?)
}

pub fn header_map(headers: &Headers) -> Result<HeaderMap> {
    let mut result = HeaderMap::new();
    for (name, values) in headers {
        let name = HeaderName::try_from(name)?;
        for value in values {
            result.append(name.clone(), HeaderValue::try_from(value)?);
        }
    }
    Ok(result)
}

pub fn wire_headers(headers: &HeaderMap, filtered: bool) -> Headers {
    let excluded: Vec<_> = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .collect();
    let mut result = Headers::new();
    for name in headers.keys() {
        if name == "connection" || excluded.iter().any(|value| value == name.as_str()) {
            continue;
        }
        let canonical = if filtered {
            match name.as_str() {
                "access-control-expose-headers" => "Access-Control-Expose-Headers".into(),
                "content-type" => "Content-Type".into(),
                "last-event-id" => "Last-Event-Id".into(),
                "mcp-protocol-version" => "Mcp-Protocol-Version".into(),
                "mcp-session-id" => "Mcp-Session-Id".into(),
                "www-authenticate" => "Www-Authenticate".into(),
                _ => continue,
            }
        } else {
            crate::harpoon::headers::canonical(name.as_str())
        };
        let values: Vec<_> = headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
        if !values.is_empty() {
            result.insert(canonical, values);
        }
    }
    result
}

pub fn timeout(value: &Value) -> Option<Duration> {
    let text = value.as_str()?;
    let split = text.find(|c: char| !c.is_ascii_digit())?;
    let number: u64 = text[..split].parse().ok()?;
    let factor = match &text[split..] {
        "ns" => 1,
        "us" => 1_000,
        "ms" => 1_000_000,
        "s" => 1_000_000_000,
        "m" => 60_000_000_000,
        "h" => 3_600_000_000_000,
        _ => return None,
    };
    let nanos = number.checked_mul(factor)?;
    (nanos <= i64::MAX as u64).then(|| Duration::from_nanos(nanos))
}

pub fn initialize() -> Result<Request> {
    Request::new(
        serde_json::json!({"jsonrpc":"2.0", "id":0, "method":"initialize", "params":{
            "protocolVersion":"2025-11-25", "capabilities":{}, "clientInfo":{"name":"otunnel","version":env!("CARGO_PKG_VERSION")}
        }}),
    )
}

pub fn request(method: &str, mut params: Value, stateless: bool) -> Result<Request> {
    if stateless {
        params["_meta"] = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": MCP_VERSION,
            "io.modelcontextprotocol/clientInfo": {"name":"otunnel","version":env!("CARGO_PKG_VERSION")},
            "io.modelcontextprotocol/clientCapabilities": {}
        });
    }
    Request::new(serde_json::json!({"jsonrpc":"2.0","id":0,"method":method,"params":params}))
}

pub fn version(message: &RawValue) -> Option<String> {
    let value = field(message, "params")
        .and_then(|params| field(&params, "_meta"))
        .and_then(|meta| field(&meta, "io.modelcontextprotocol/protocolVersion"))?;
    serde_json::from_str(value.get()).ok()
}

pub fn self_contained(message: &RawValue) -> bool {
    let Some(version) = version(message) else {
        return false;
    };
    valid_date(&version) && version.as_str() >= MCP_VERSION && validate_meta(message).is_ok()
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let number = |range: std::ops::Range<usize>| {
        bytes[range].iter().try_fold(0u16, |value, byte| {
            byte.is_ascii_digit()
                .then_some(value * 10 + u16::from(byte - b'0'))
        })
    };
    let Some(year) = number(0..4) else {
        return false;
    };
    let Some(month) = number(5..7) else {
        return false;
    };
    let Some(day) = number(8..10) else {
        return false;
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    month > 0
        && day > 0
        && days
            .get(usize::from(month - 1))
            .is_some_and(|limit| day <= *limit)
}

pub fn result(request: &Request, value: &RawValue) -> Result<Reply> {
    let id = view(&request.message)?.id;
    if id.is_none() {
        bail!("request has no response ID");
    }
    Ok(Reply::json(to_raw_value(
        &serde_json::json!({"jsonrpc":"2.0", "id":id, "result":value}),
    )?))
}

pub fn same_id(left: &RawValue, right: &RawValue) -> bool {
    serde_json::from_str::<Value>(left.get()).ok()
        == serde_json::from_str::<Value>(right.get()).ok()
}

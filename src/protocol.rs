use std::{collections::BTreeMap, time::Duration};

use anyhow::{Result, bail};
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
    pub commands: Vec<Command>,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub message: Json,
    pub headers: HeaderMap,
}
impl Request {
    pub fn new(value: Value) -> Result<Self> {
        Ok(Self {
            message: to_raw_value(&value)?,
            headers: HeaderMap::new(),
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
    pub method: Option<&'a str>,
    #[serde(borrow)]
    pub result: Option<&'a RawValue>,
    #[serde(borrow)]
    pub error: Option<&'a RawValue>,
}
pub fn view(value: &RawValue) -> Result<View<'_>> {
    Ok(serde_json::from_str(value.get())?)
}

pub fn field(value: &RawValue, key: &str) -> Option<Json> {
    let object: BTreeMap<&str, &RawValue> = serde_json::from_str(value.get()).ok()?;
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
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().to_ascii_lowercase())
        .collect();
    let allowed = [
        "content-type",
        "mcp-session-id",
        "mcp-protocol-version",
        "last-event-id",
        "access-control-expose-headers",
        "www-authenticate",
    ];
    headers
        .keys()
        .filter(|name| {
            name.as_str() != "connection"
                && !excluded.iter().any(|v| v == name.as_str())
                && (!filtered || allowed.contains(&name.as_str()))
        })
        .filter_map(|name| {
            let values: Vec<_> = headers
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect();
            (!values.is_empty()).then(|| (name.to_string(), values))
        })
        .collect()
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
            "protocolVersion":MCP_VERSION, "capabilities":{}, "clientInfo":{"name":"otunnel","version":env!("CARGO_PKG_VERSION")}
        }}),
    )
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

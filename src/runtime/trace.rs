use std::{collections::BTreeMap, fmt, sync::LazyLock};

use regex::Regex;
use serde::de::{self, MapAccess, Visitor};
use serde_json::value::{RawValue, to_raw_value};

use crate::protocol::{self, Command, Json};

pub(super) fn owns_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("traceparent") || name.eq_ignore_ascii_case("tracestate")
}

pub(super) fn forward(command: &Command) -> Option<Json> {
    if command.headers.keys().any(|name| owns_header(name)) {
        return None;
    }
    let (parent, state) = carrier(command.trace_context.as_deref()?)?;
    static PARENT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^00-[0-9a-f]{32}-[0-9a-f]{16}-0[0-3]$").expect("traceparent regex")
    });
    if parent.len() != 55
        || !PARENT.is_match(&parent)
        || parent[3..35].bytes().all(|byte| byte == b'0')
        || parent[36..52].bytes().all(|byte| byte == b'0')
    {
        return None;
    }
    let state = tracestate(&state)?;
    let message = command.jsonrpc.as_deref()?;
    protocol::view(message).ok()?.method?;
    let mut message = object(message)?;
    let mut params = match message.get("params") {
        Some(raw) => object(raw)?,
        None => BTreeMap::new(),
    };
    let mut meta = match params.get("_meta") {
        Some(raw) => object(raw)?,
        None => BTreeMap::new(),
    };
    if meta.contains_key("traceparent") || meta.contains_key("tracestate") {
        return None;
    }
    meta.insert("traceparent".into(), to_raw_value(&parent).ok()?);
    if !state.is_empty() {
        meta.insert("tracestate".into(), to_raw_value(&state).ok()?);
    }
    params.insert("_meta".into(), to_raw_value(&meta).ok()?);
    message.insert("params".into(), to_raw_value(&params).ok()?);
    to_raw_value(&message).ok()
}

fn carrier(raw: &RawValue) -> Option<(String, String)> {
    struct Carrier;
    impl<'de> Visitor<'de> for Carrier {
        type Value = (String, String);

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a trace carrier")
        }

        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut result = (String::new(), String::new());
            while let Some(name) = map.next_key::<String>()? {
                let field = if name.eq_ignore_ascii_case("traceparent") {
                    Some(&mut result.0)
                } else if name.eq_ignore_ascii_case("tracestate") {
                    Some(&mut result.1)
                } else {
                    None
                };
                if let Some(field) = field {
                    if let Some(value) = map.next_value::<Option<String>>()? {
                        *field = value;
                    }
                } else {
                    map.next_value::<de::IgnoredAny>()?;
                }
            }
            Ok(result)
        }
    }
    serde::Deserializer::deserialize_map(
        &mut serde_json::Deserializer::from_str(raw.get()),
        Carrier,
    )
    .ok()
}

fn tracestate(raw: &str) -> Option<String> {
    if raw.len() > 512 {
        return None;
    }
    static KEY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^(?:[a-z][a-z0-9_*/-]{0,255}|[a-z0-9][a-z0-9_*/-]{0,240}@[a-z][a-z0-9_*/-]{0,13})$",
        )
        .expect("tracestate key regex")
    });
    let mut members = Vec::new();
    for member in raw.split(',').filter(|member| !member.is_empty()) {
        let (key, value) = member.split_once('=')?;
        let key = key.trim_start_matches([' ', '\t']);
        let value = value.trim_end_matches([' ', '\t']);
        if members.len() == 32
            || !KEY.is_match(key)
            || value.is_empty()
            || value.len() > 256
            || !value
                .bytes()
                .all(|byte| (b' '..=b'~').contains(&byte) && byte != b'=')
            || members.iter().any(|(existing, _)| *existing == key)
        {
            return None;
        }
        members.push((key, value));
    }
    Some(
        members
            .into_iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(","),
    )
}

// Rewriting only these containers keeps nested values raw. Duplicate keys are ambiguous.
fn object(raw: &RawValue) -> Option<BTreeMap<String, Json>> {
    struct Object;
    impl<'de> Visitor<'de> for Object {
        type Value = BTreeMap<String, Json>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an object without duplicate keys")
        }

        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some((name, value)) = map.next_entry::<String, Json>()? {
                if result.insert(name, value).is_some() {
                    return Err(de::Error::custom("duplicate key"));
                }
            }
            Ok(result)
        }
    }
    serde::Deserializer::deserialize_map(&mut serde_json::Deserializer::from_str(raw.get()), Object)
        .ok()
}

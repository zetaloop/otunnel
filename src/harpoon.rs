use std::{
    net::IpAddr,
    sync::{Arc, LazyLock, RwLock},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use indexmap::IndexMap;
use percent_encoding::percent_decode_str;
use regex::Regex;
use serde::Serialize;
use serde_json::{
    Value, json,
    value::{RawValue, to_raw_value},
};
use url::Url;

use crate::{
    config,
    net::{Http, Options},
    protocol::{self, Reply, Request},
    transport::{Sink, Transport},
};

mod call;
pub(crate) mod headers;

const INSTRUCTIONS: &str = "Harpoon provides a constrained outbound HTTP client. Use list_targets to see allowlisted targets and call_target to make GET/POST/PUT requests with strict size, timeout, and redirect limits. get_oauth_target_audience is a narrow opt-in lookup for OAuth token-endpoint private_key_jwt audiences. Harpoon cannot reach arbitrary hosts or paths outside the configured allowlist.";
const TEMPLATE_INSTRUCTIONS: &str = "Harpoon provides a constrained outbound HTTP client. Use list_targets to see allowlisted targets. For exact targets, use call_target to make GET/POST/PUT requests with strict size, timeout, and redirect limits. For entries with template_version and parameters_schema, use call_target_template with the label and all parameters declared by parameters_schema; each value must satisfy that schema. Templates make GET requests to a fixed destination and do not follow redirects. get_oauth_target_audience is a narrow opt-in lookup for OAuth token-endpoint private_key_jwt audiences. Harpoon cannot reach arbitrary hosts or paths outside the configured allowlist.";

#[derive(Clone, Serialize)]
pub struct TargetInfo {
    pub label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub category: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub allowed_methods: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_version: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters_schema: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation: Option<Value>,
}

#[derive(Clone)]
pub(crate) struct Target {
    pub info: TargetInfo,
    pub url: Url,
    pub original_url: String,
    pub unix_socket: Option<String>,
    pub client: Http,
    pub template: Option<Arc<crate::template::Template>>,
}

pub struct Harpoon {
    config: config::Harpoon,
    ca_bundle: Option<String>,
    proxy: Option<String>,
    patterns: Vec<Regex>,
    targets: RwLock<IndexMap<String, Target>>,
}

impl Harpoon {
    pub fn new(config: &config::Config) -> Result<Self> {
        let harpoon = Self {
            config: config.harpoon.clone(),
            ca_bundle: config.ca_bundle.clone(),
            proxy: config
                .harpoon
                .http_proxy
                .clone()
                .or(config.http_proxy.clone()),
            patterns: config
                .harpoon
                .hosts_include_regex
                .iter()
                .map(|pattern| pattern.trim())
                .filter(|pattern| !pattern.is_empty())
                .map(|pattern| Regex::new(&format!("(?i:{pattern})")))
                .collect::<std::result::Result<_, _>>()?,
            targets: RwLock::new(IndexMap::new()),
        };
        for target in &config.harpoon.targets {
            harpoon.register(target)?;
        }
        Ok(harpoon)
    }

    pub fn register(&self, target: &config::Target) -> Result<()> {
        let template = target
            .template
            .as_ref()
            .map(crate::template::Template::new)
            .transpose()?
            .map(Arc::new);
        anyhow::ensure!(
            template.is_none()
                || target.url.is_empty()
                    && target.unix_socket.as_deref().unwrap_or_default().is_empty(),
            "Harpoon target cannot combine a template with an exact URL or socket"
        );
        let original_url = match &template {
            Some(template) => template.origin().to_string(),
            None => config::resolve(&target.url)?,
        };
        let url = Url::parse(&original_url)?;
        let client = self.client(&url, target.unix_socket.as_deref())?;
        self.insert(Target {
            info: TargetInfo {
                label: target.label.trim().into(),
                description: target.description.trim().into(),
                category: "config".into(),
                source: "config".into(),
                tags: Vec::new(),
                allowed_methods: if template.is_some() {
                    vec!["GET".into()]
                } else {
                    vec!["GET".into(), "POST".into(), "PUT".into()]
                },
                template_version: template.as_ref().map(|_| 1),
                parameters_schema: template.as_ref().map(|template| template.schema()),
                invocation: template.as_ref().map(|template| {
                    template.invocation(target.label.trim(), self.call_schema(true))
                }),
            },
            original_url,
            unix_socket: target.unix_socket.clone(),
            url,
            client,
            template,
        })
    }

    pub(crate) fn client(&self, url: &Url, socket: Option<&str>) -> Result<Http> {
        Http::new(
            url.clone(),
            Options {
                proxy: self.proxy.as_deref(),
                ca_bundle: self.ca_bundle.as_deref(),
                socket,
                ..Default::default()
            },
        )
    }

    pub(crate) fn insert(&self, mut target: Target) -> Result<()> {
        target.info.label = target.info.label.trim().into();
        anyhow::ensure!(
            valid_label(&target.info.label),
            "invalid Harpoon target label"
        );
        anyhow::ensure!(
            matches!(target.url.scheme(), "http" | "https"),
            "Harpoon targets must use HTTP or HTTPS"
        );
        anyhow::ensure!(
            self.config.allow_plaintext_http || target.url.scheme() == "https",
            "Harpoon target base URL must use https"
        );
        let key = url_key(&target.original_url)?;
        target.unix_socket = target
            .unix_socket
            .map(|value| value.trim().into())
            .filter(|value: &String| !value.is_empty());
        target.info.description = target.info.description.trim().into();
        let category = target.info.category.trim().to_ascii_lowercase();
        target.info.category = if category.is_empty() {
            target.info.source.trim().to_ascii_lowercase()
        } else {
            category
        };
        target.info.source = target.info.category.clone();
        target.info.tags = target
            .info
            .tags
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect();
        target.info.tags.sort();
        target.info.tags.dedup();
        let mut targets = self.targets.write().expect("target registry lock poisoned");
        anyhow::ensure!(
            !targets.contains_key(&target.info.label),
            "duplicate Harpoon target {}",
            target.info.label
        );
        anyhow::ensure!(
            targets.len() < 10000,
            "Harpoon registry limit 10000 exceeded"
        );
        if target.template.is_none() {
            for existing in targets.values().filter(|target| target.template.is_none()) {
                anyhow::ensure!(
                    url_key(&existing.original_url)? != key
                        || existing.unix_socket == target.unix_socket,
                    "duplicate Harpoon target URL uses a different transport"
                );
            }
        }
        targets.insert(target.info.label.clone(), target);
        Ok(())
    }

    pub(crate) fn label(&self, base: &str) -> Result<String> {
        let targets = self.targets.read().expect("target registry lock poisoned");
        for index in 0..10000 {
            let candidate = if index == 0 {
                base.chars().take(64).collect::<String>()
            } else {
                let suffix = format!("-{index}");
                let prefix = base.chars().take(64 - suffix.len()).collect::<String>();
                format!("{}{suffix}", prefix.trim_end_matches(['-', '_']))
            };
            if !targets.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        anyhow::bail!("Harpoon target label namespace is exhausted")
    }

    pub fn targets(&self) -> Vec<TargetInfo> {
        self.targets
            .read()
            .expect("target registry lock poisoned")
            .values()
            .map(|target| target.info.clone())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.targets
            .read()
            .expect("target registry lock poisoned")
            .len()
    }
    pub fn is_empty(&self) -> bool {
        self.targets
            .read()
            .expect("target registry lock poisoned")
            .is_empty()
    }

    fn has_templates(&self) -> bool {
        self.targets
            .read()
            .expect("target registry lock poisoned")
            .values()
            .any(|target| target.template.is_some())
    }

    fn instructions(&self) -> &'static str {
        if self.has_templates() {
            TEMPLATE_INSTRUCTIONS
        } else {
            INSTRUCTIONS
        }
    }

    pub(crate) fn private(&self, url: &Url) -> bool {
        let host = url
            .host_str()
            .unwrap_or_default()
            .trim_matches(['[', ']'])
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if self.config.hosts_include_loopback && host == "localhost" {
            return true;
        }
        if let Ok(mut ip) = host.parse::<IpAddr>() {
            if let IpAddr::V6(value) = ip
                && let Some(value) = value.to_ipv4_mapped()
            {
                ip = IpAddr::V4(value);
            }
            if self.config.hosts_include_loopback && ip.is_loopback() {
                return true;
            }
            if self.config.hosts_include_private
                && match ip {
                    IpAddr::V4(ip) => ip.is_private(),
                    IpAddr::V6(ip) => ip.is_unique_local(),
                }
            {
                return true;
            }
        }
        self.config.hosts_include_suffix.iter().any(|suffix| {
            let suffix = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
            !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")))
        }) || self.patterns.iter().any(|pattern| pattern.is_match(&host))
    }

    fn target(&self, label: &str) -> Result<Target> {
        self.targets
            .read()
            .expect("target registry lock poisoned")
            .get(label.trim())
            .cloned()
            .context("unknown target")
    }

    fn destination(&self, url: &Url) -> Result<Target> {
        let key = url_key(url.as_str())?;
        self.targets
            .read()
            .expect("target registry lock poisoned")
            .values()
            .find(|target| {
                target.template.is_none()
                    && url_key(&target.original_url).is_ok_and(|value| value == key)
            })
            .cloned()
            .context("redirect blocked")
    }

    pub(crate) fn rewrite(&self, value: &mut Value) -> bool {
        let targets = self.targets.read().expect("target registry lock poisoned");
        rewrite_value(value, "", &targets)
    }

    pub(crate) fn rewrite_headers(&self, headers: &mut protocol::Headers) {
        static URLS: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r#"https?://[^\s<>\"']+"#).expect("URL pattern"));
        let targets = self.targets.read().expect("target registry lock poisoned");
        for (name, values) in headers {
            if ["location", "content-location", "link"]
                .contains(&name.to_ascii_lowercase().as_str())
            {
                for value in values {
                    *value = URLS
                        .replace_all(value, |capture: &regex::Captures<'_>| {
                            rewrite_url(&capture[0], "", &targets)
                                .unwrap_or_else(|| capture[0].to_owned())
                        })
                        .into_owned();
                }
            }
        }
    }

    fn tools(&self) -> Result<Value> {
        let templates = self.has_templates();
        let mut tools = vec![tool(
            "call_target",
            "Call Harpoon target",
            "Call an allowlisted HTTP target by label.",
            self.call_schema(false),
            self.response_schema(),
            false,
            Some(true),
        )];
        if templates {
            tools.push(tool(
                "call_target_template",
                "Call Harpoon target template",
                "Call a version-1 GET target template using only its declared string parameters and permitted headers. Discover the tool name, complete input schema, and available examples in each list_targets entry's invocation. The target fixes the destination and disables redirects.",
                self.call_schema(true),
                self.response_schema(),
                true,
                None,
            ));
        }
        tools.push(tool(
            "get_oauth_target_audience",
            "Get OAuth target audience",
            "Resolve the exact private_key_jwt audience for an OAuth token endpoint target.",
            self.audience_input_schema(),
            self.audience_output_schema(),
            true,
            Some(false),
        ));
        tools.push(tool(
            "list_targets",
            "List Harpoon targets",
            "List available Harpoon targets by label.",
            self.list_input_schema(),
            self.list_output_schema(templates),
            true,
            Some(false),
        ));
        Ok(json!({"ttlMs":0,"cacheScope":"public","tools":tools}))
    }
}

pub(crate) fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && label.as_bytes()[0].is_ascii_alphanumeric()
        && label
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(&c))
}

fn url_key(raw: &str) -> Result<String> {
    let (scheme, rest) = raw
        .split_once("://")
        .context("target URL must include scheme and host")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    anyhow::ensure!(
        !authority.is_empty(),
        "target URL must include scheme and host"
    );
    let suffix = &rest[end..];
    let path = suffix.split(['?', '#']).next().unwrap_or_default();
    let path = percent_decode_str(path).decode_utf8()?;
    for part in path.split('/') {
        let part = percent_decode_str(part).decode_utf8()?;
        anyhow::ensure!(
            !matches!(part.as_ref(), "." | ".."),
            "target URL contains invalid path segments"
        );
    }
    let authority = match authority.rsplit_once('@') {
        Some((user, host)) => format!("{user}@{}", host.to_ascii_lowercase()),
        None => authority.to_ascii_lowercase(),
    };
    Ok(format!(
        "{}://{authority}{suffix}",
        scheme.to_ascii_lowercase()
    ))
}

fn tool(
    name: &str,
    title: &str,
    description: &str,
    input: Value,
    output: Value,
    read_only: bool,
    open_world: Option<bool>,
) -> Value {
    let mut annotations = json!({"readOnlyHint":read_only,"idempotentHint":read_only});
    if let Some(open_world) = open_world {
        annotations["openWorldHint"] = json!(open_world);
    }
    json!({"name":name,"title":title,"description":description,"inputSchema":input,"outputSchema":output,"annotations":annotations})
}

fn rewrite_url(value: &str, key: &str, targets: &IndexMap<String, Target>) -> Option<String> {
    let url = url_key(value).ok()?;
    let candidates: Vec<_> = targets
        .values()
        .filter(|target| {
            target.template.is_none()
                && url_key(&target.original_url).is_ok_and(|candidate| candidate == url)
        })
        .collect();
    if key == "resource"
        && candidates.iter().any(|target| {
            ["protected-resource-metadata", "resource"]
                .iter()
                .all(|tag| target.info.tags.iter().any(|value| value == tag))
        })
    {
        return None;
    }
    let role = match key {
        "authorization_servers" => "authorization-server",
        "introspection_endpoint" => "introspection-endpoint",
        "issuer" => "issuer",
        "jwks_uri" => "jwks-uri",
        "registration_endpoint" => "registration-endpoint",
        "revocation_endpoint" => "revocation-endpoint",
        "token_endpoint" => "token-endpoint",
        _ => "",
    };
    let target = candidates
        .iter()
        .find(|target| target.info.tags.iter().any(|tag| tag == role))
        .copied()
        .or_else(|| candidates.first().copied())?;
    Some(format!("harpoon://{}", target.info.label))
}

fn rewrite_value(value: &mut Value, key: &str, targets: &IndexMap<String, Target>) -> bool {
    let mut changed = false;
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                changed |= rewrite_value(value, key, targets);
            }
        }
        Value::Array(values) => {
            for value in values {
                changed |= rewrite_value(value, key, targets);
            }
        }
        Value::String(value) => {
            if let Some(new) = rewrite_url(value, key, targets) {
                *value = new;
                changed = true;
            }
        }
        _ => {}
    }
    changed
}

#[async_trait]
impl Transport for Harpoon {
    async fn forward(&self, request: Request, sink: &dyn Sink) -> Result<()> {
        let envelope = protocol::view(&request.message)?;
        if envelope.id.is_none() {
            return sink.send(Reply::ack(202, "notify_ack")).await;
        }
        if let Err(message) = protocol::validate_meta(&request.message) {
            return sink
                .send(Reply::error(&request, 200, -32602, message)?)
                .await;
        }
        let modern = protocol::version(&request.message)
            .is_some_and(|version| version.as_str() >= protocol::MCP_VERSION);
        let identity = json!({
            "name":"harpoon",
            "title":"Harpoon (Constrained HTTP Client)",
            "version":env!("CARGO_PKG_VERSION")
        });
        let instructions = self.instructions();
        let mut result = match envelope.method.as_deref() {
            Some("server/discover") => {
                json!({
                    "supportedVersions":protocol::SUPPORTED_VERSIONS,
                    "capabilities":{"tools":{}},
                    "instructions":instructions,
                    "ttlMs":0,
                    "cacheScope":"public"
                })
            }
            Some("initialize") => {
                let requested = protocol::field(&request.message, "params")
                    .and_then(|params| protocol::field(&params, "protocolVersion"))
                    .and_then(|version| serde_json::from_str::<String>(version.get()).ok())
                    .unwrap_or_default();
                let version = if requested.as_str() < protocol::MCP_VERSION
                    && protocol::SUPPORTED_VERSIONS.contains(&requested.as_str())
                {
                    requested
                } else {
                    "2025-11-25".into()
                };
                json!({
                    "protocolVersion":version,
                    "serverInfo":identity,
                    "capabilities":{"tools":{}},
                    "instructions":instructions
                })
            }
            Some("ping") if !modern => json!({}),
            Some("tools/list") => self.tools()?,
            Some("tools/call") => {
                let params = protocol::field(&request.message, "params")
                    .context("tools/call has no parameters")?;
                let name = protocol::field(&params, "name").context("tool name is missing")?;
                let name: String = serde_json::from_str(name.get())?;
                let empty = RawValue::from_string("{}".into())?;
                let arguments = protocol::field(&params, "arguments").unwrap_or(empty);
                match self.call(&name, &arguments).await {
                    Ok(value) => {
                        let mut text = value.clone();
                        if name == "call_target" {
                            let fields = text.as_object_mut().expect("call result");
                            fields.remove("truncated");
                            if fields
                                .get("headers")
                                .and_then(Value::as_object)
                                .is_some_and(|value| value.is_empty())
                            {
                                fields.remove("headers");
                            }
                            if fields.get("body_base64").and_then(Value::as_str) == Some("") {
                                fields.remove("body_base64");
                            }
                        }
                        json!({
                            "content":[{"type":"text","text":serde_json::to_string(&text)?}],
                            "structuredContent":value
                        })
                    }
                    Err(error) => {
                        json!({
                            "isError":true,
                            "content":[{"type":"text","text":format!("{error:#}")}]
                        })
                    }
                }
            }
            _ => {
                return sink
                    .send(Reply::error(&request, 200, -32601, "Method not found")?)
                    .await;
            }
        };
        if modern {
            result["resultType"] = json!("complete");
            result["_meta"] = json!({"io.modelcontextprotocol/serverInfo":identity});
        }
        sink.send(protocol::result(&request, &to_raw_value(&result)?)?)
            .await
    }
    fn process_affinity(&self) -> bool {
        true
    }
    fn stateless(&self) -> bool {
        true
    }
    fn available(&self) -> bool {
        !self.is_empty()
    }
}

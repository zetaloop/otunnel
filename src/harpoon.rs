use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, LazyLock, RwLock},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, value::to_raw_value};
use url::Url;

use crate::{
    config,
    net::{Http, Options},
    protocol::{self, Reply, Request},
    transport::{Sink, Transport},
};

#[derive(Clone, Serialize, JsonSchema)]
pub struct TargetInfo {
    pub label: String,
    pub description: String,
    pub category: String,
    pub source: String,
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
    pub client: Http,
    pub template: Option<Arc<crate::template::Template>>,
}

pub struct Harpoon {
    config: config::Harpoon,
    ca_bundle: Option<String>,
    proxy: Option<String>,
    patterns: Vec<Regex>,
    targets: RwLock<BTreeMap<String, Target>>,
}

#[derive(Default, Deserialize, JsonSchema)]
struct ListTargets {
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
}
#[derive(Serialize, JsonSchema)]
struct TargetList {
    targets: Vec<TargetInfo>,
}
#[derive(Deserialize, JsonSchema)]
struct CallTarget {
    label: String,
    method: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: String,
    timeout_ms: Option<u64>,
    max_response_bytes: Option<usize>,
    follow_redirects: Option<bool>,
    max_redirects: Option<usize>,
}
#[derive(Deserialize, JsonSchema)]
struct CallTemplate {
    label: String,
    parameters: BTreeMap<String, String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    timeout_ms: Option<u64>,
    max_response_bytes: Option<usize>,
}
#[derive(Serialize, JsonSchema)]
struct CallResponse {
    status_code: u16,
    headers: protocol::Headers,
    body_base64: String,
    body_size_bytes: usize,
    truncated: bool,
}
#[derive(Deserialize, JsonSchema)]
struct AudienceQuery {
    label: String,
}
#[derive(Serialize, JsonSchema)]
struct Audience {
    audience: String,
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
                .map(|pattern| Regex::new(&format!("(?i:{pattern})")))
                .collect::<std::result::Result<_, _>>()?,
            targets: RwLock::new(BTreeMap::new()),
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
            template.is_none() || target.url.is_empty(),
            "Harpoon target selects either a URL or a template"
        );
        let url = match &template {
            Some(template) => template.origin().clone(),
            None => Url::parse(&config::resolve(&target.url)?)?,
        };
        let client = Http::new(
            url.clone(),
            Options {
                proxy: self.proxy.as_deref(),
                ca_bundle: self.ca_bundle.as_deref(),
                socket: target.unix_socket.as_deref(),
                ..Default::default()
            },
        )?;
        self.insert(Target {
            info: TargetInfo {
                label: target.label.clone(),
                description: target.description.clone(),
                category: "manual".into(),
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
                    template.invocation(&target.label, json!(schemars::schema_for!(CallTemplate)))
                }),
            },
            original_url: target.url.clone(),
            url,
            client,
            template,
        })
    }

    pub(crate) fn insert(&self, target: Target) -> Result<()> {
        anyhow::ensure!(
            matches!(target.url.scheme(), "http" | "https"),
            "Harpoon targets must use HTTP or HTTPS"
        );
        let mut targets = self.targets.write().expect("target registry lock poisoned");
        if let Some(existing) = targets.get(&target.info.label) {
            anyhow::ensure!(
                existing.info.source == "oauth" && target.info.source == "oauth",
                "duplicate Harpoon target {}",
                target.info.label
            );
        }
        targets.insert(target.info.label.clone(), target);
        Ok(())
    }

    pub fn targets(&self) -> Vec<TargetInfo> {
        self.targets
            .read()
            .expect("target registry lock poisoned")
            .values()
            .map(|target| target.info.clone())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.targets
            .read()
            .expect("target registry lock poisoned")
            .is_empty()
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
        if let Ok(ip) = host.parse::<IpAddr>() {
            if self.config.hosts_include_loopback && ip.is_loopback() {
                return true;
            }
            if self.config.hosts_include_private
                && match ip {
                    IpAddr::V4(ip) => ip.is_private(),
                    IpAddr::V6(ip) => {
                        ip.is_unique_local()
                            || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_private())
                    }
                }
            {
                return true;
            }
        }
        self.config.hosts_include_suffix.iter().any(|suffix| {
            let suffix = suffix.trim_matches('.').to_ascii_lowercase();
            !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")))
        }) || self.patterns.iter().any(|pattern| pattern.is_match(&host))
    }

    fn target(&self, label: &str) -> Result<Target> {
        self.targets
            .read()
            .expect("target registry lock poisoned")
            .get(label)
            .cloned()
            .with_context(|| format!("unknown Harpoon target {label}"))
    }

    fn destination(&self, url: &Url) -> Result<Target> {
        self.targets
            .read()
            .expect("target registry lock poisoned")
            .values()
            .find(|target| target.template.is_none() && target.url == *url)
            .cloned()
            .context("redirect destination is not a registered Harpoon target")
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
        let mut tools = vec![
            tool::<ListTargets, TargetList>(
                "list_targets",
                "List available HTTP targets by label and OAuth role.",
                true,
            )?,
            tool::<CallTarget, CallResponse>(
                "call_target",
                "Send an HTTP request to a configured target. Response bytes are returned as base64.",
                false,
            )?,
            tool::<AudienceQuery, Audience>(
                "get_oauth_target_audience",
                "Resolve the original token endpoint URL for a private_key_jwt audience.",
                true,
            )?,
        ];
        if self
            .targets
            .read()
            .expect("target registry lock poisoned")
            .values()
            .any(|target| target.template.is_some())
        {
            tools.push(tool::<CallTemplate, CallResponse>(
                "call_target_template",
                "Invoke a configured GET operation using its declared parameters and headers.",
                true,
            )?);
        }
        Ok(json!({"tools":tools}))
    }

    async fn call(&self, name: &str, arguments: Value) -> Result<Value> {
        match name {
            "list_targets" => {
                let filter: ListTargets = serde_json::from_value(arguments)?;
                let targets = self
                    .targets()
                    .into_iter()
                    .filter(|target| {
                        (filter.categories.is_empty()
                            || filter
                                .categories
                                .iter()
                                .any(|value| value.eq_ignore_ascii_case(&target.category)))
                            && (filter.sources.is_empty()
                                || filter
                                    .sources
                                    .iter()
                                    .any(|value| value.eq_ignore_ascii_case(&target.source)))
                            && filter.tags.iter().all(|value| {
                                target
                                    .tags
                                    .iter()
                                    .any(|tag| value.eq_ignore_ascii_case(tag))
                            })
                    })
                    .collect();
                Ok(serde_json::to_value(TargetList { targets })?)
            }
            "get_oauth_target_audience" => {
                let query: AudienceQuery = serde_json::from_value(arguments)?;
                let target = self.target(&query.label)?;
                anyhow::ensure!(
                    target.info.category == "oauth"
                        && target.info.tags.iter().any(|tag| tag == "token-endpoint"),
                    "target is not an OAuth token endpoint"
                );
                Ok(serde_json::to_value(Audience {
                    audience: target.original_url,
                })?)
            }
            "call_target" | "call_target_template" => {
                let (call, parameters) = if name == "call_target_template" {
                    let call: CallTemplate = serde_json::from_value(arguments)?;
                    (
                        CallTarget {
                            label: call.label,
                            method: "GET".into(),
                            headers: call.headers,
                            body: String::new(),
                            timeout_ms: call.timeout_ms,
                            max_response_bytes: call.max_response_bytes,
                            follow_redirects: Some(false),
                            max_redirects: Some(0),
                        },
                        Some(call.parameters),
                    )
                } else {
                    (serde_json::from_value::<CallTarget>(arguments)?, None)
                };
                let duration = Duration::from_millis(call.timeout_ms.unwrap_or(30_000));
                Ok(serde_json::to_value(
                    tokio::time::timeout(duration, self.request(call, parameters))
                        .await
                        .context("Harpoon request timed out")??,
                )?)
            }
            _ => bail!("unknown Harpoon tool {name}"),
        }
    }

    async fn request(
        &self,
        call: CallTarget,
        parameters: Option<BTreeMap<String, String>>,
    ) -> Result<CallResponse> {
        let mut target = self.target(&call.label)?;
        let mut method = Method::from_bytes(call.method.to_ascii_uppercase().as_bytes())?;
        anyhow::ensure!(
            matches!(method, Method::GET | Method::POST | Method::PUT),
            "unsupported Harpoon method"
        );
        let mut headers = HeaderMap::new();
        for (name, value) in &call.headers {
            headers.insert(HeaderName::try_from(name)?, HeaderValue::try_from(value)?);
        }
        match (&target.template, parameters) {
            (Some(template), Some(parameters)) => {
                (target.url, headers) = template.render(&parameters, headers)?;
            }
            (None, None) => {}
            _ => bail!("template targets use call_target_template with declared parameters"),
        }
        let nominated: Vec<_> = headers
            .get_all("connection")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(|v| v.trim().to_owned())
            .collect();
        for name in nominated {
            headers.remove(name);
        }
        for name in [
            "connection",
            "content-length",
            "host",
            "transfer-encoding",
            "keep-alive",
            "proxy-connection",
            "proxy-authorization",
            "te",
            "trailer",
            "upgrade",
        ] {
            headers.remove(name);
        }
        let mut body = Bytes::from(call.body);
        let redirects = if call.follow_redirects.unwrap_or(true) {
            call.max_redirects
                .unwrap_or(self.config.max_redirects)
                .min(self.config.max_redirects)
        } else {
            0
        };
        let limit = match (call.max_response_bytes, self.config.max_response_bytes) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        for hop in 0..=redirects {
            let mut response = target
                .client
                .send(method.clone(), &target.url, headers.clone(), body.clone())
                .await?;
            if hop < redirects
                && response.status.is_redirection()
                && let Some(location) = response.headers.get("location")
            {
                let next = target.url.join(location.to_str()?)?;
                if next.origin() != target.url.origin() {
                    headers.remove("authorization");
                    headers.remove("cookie");
                }
                if response.status == StatusCode::SEE_OTHER
                    || (method == Method::POST
                        && matches!(
                            response.status,
                            StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND
                        ))
                {
                    method = Method::GET;
                    body = Bytes::new();
                    headers.remove("content-type");
                }
                target = self.destination(&next)?;
                continue;
            }
            let status_code = response.status.as_u16();
            let mut response_headers = protocol::wire_headers(&response.headers, false);
            let mut bytes = BytesMut::new();
            while let Some(chunk) = response.body.next().await {
                let chunk = chunk?;
                anyhow::ensure!(
                    limit.is_none_or(|limit| chunk.len() <= limit.saturating_sub(bytes.len())),
                    "Harpoon response exceeds configured size limit"
                );
                bytes.extend_from_slice(&chunk);
            }
            let mut bytes = bytes.freeze();
            if let Ok(mut value) = serde_json::from_slice::<Value>(&bytes)
                && self.rewrite(&mut value)
            {
                bytes = Bytes::from(serde_json::to_vec(&value)?);
                response_headers.remove("content-length");
            }
            self.rewrite_headers(&mut response_headers);
            return Ok(CallResponse {
                status_code,
                headers: response_headers,
                body_base64: STANDARD.encode(&bytes),
                body_size_bytes: bytes.len(),
                truncated: false,
            });
        }
        unreachable!()
    }
}

fn tool<I: JsonSchema, O: JsonSchema>(
    name: &str,
    description: &str,
    read_only: bool,
) -> Result<Value> {
    Ok(
        json!({"name":name,"description":description,"inputSchema":schemars::schema_for!(I),"outputSchema":schemars::schema_for!(O),
        "annotations":{"readOnlyHint":read_only,"idempotentHint":read_only,"openWorldHint":!read_only}}),
    )
}

fn rewrite_url(value: &str, key: &str, targets: &BTreeMap<String, Target>) -> Option<String> {
    let url = Url::parse(value).ok()?;
    let matches: Vec<_> = targets
        .values()
        .filter(|target| target.template.is_none() && target.url == url)
        .collect();
    if key == "resource"
        && matches.iter().any(|target| {
            target
                .info
                .tags
                .iter()
                .any(|tag| tag == "protected-resource-metadata")
        })
    {
        return None;
    }
    let role = match key {
        "authorization_servers" => "authorization-server",
        "jwks_uri" => "jwks-uri",
        _ => key,
    };
    let role = role.replace('_', "-");
    let target = matches
        .iter()
        .find(|target| target.info.tags.contains(&role))
        .copied()
        .or_else(|| matches.first().copied())?;
    Some(format!("harpoon://{}", target.info.label))
}
fn rewrite_value(value: &mut Value, key: &str, targets: &BTreeMap<String, Target>) -> bool {
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
        let modern = protocol::version(&request.message).as_deref() == Some(protocol::MCP_VERSION);
        let identity = json!({"name":"harpoon","version":env!("CARGO_PKG_VERSION")});
        let mut result = match envelope.method.as_deref() {
            Some("server/discover") => {
                json!({"supportedVersions":[protocol::MCP_VERSION,"2025-11-25"],"capabilities":{"tools":{}},"instructions":"Use list_targets to discover HTTP targets and call_target to access them. OAuth targets retain their endpoint roles in tags.","ttlMs":0,"cacheScope":"private"})
            }
            Some("initialize") => {
                json!({"protocolVersion":"2025-11-25","serverInfo":identity,"capabilities":{"tools":{}},"instructions":"Use list_targets to discover HTTP targets and call_target to access them. OAuth targets retain their endpoint roles in tags."})
            }
            Some("ping") if !modern => json!({}),
            Some("tools/list") => self.tools()?,
            Some("tools/call") => {
                let params = protocol::field(&request.message, "params")
                    .context("tools/call has no parameters")?;
                let params: Value = serde_json::from_str(params.get())?;
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .context("tool name is missing")?;
                match self
                    .call(
                        name,
                        params
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({})),
                    )
                    .await
                {
                    Ok(value) => {
                        json!({"content":[{"type":"text","text":serde_json::to_string(&value)?}],"structuredContent":value})
                    }
                    Err(error) => {
                        json!({"isError":true,"content":[{"type":"text","text":format!("{error:#}")}]})
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

use std::{collections::BTreeMap, fmt, time::Duration};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor},
};
use serde_json::{Value, json, value::RawValue};

use super::{Harpoon, TargetInfo, headers};
use crate::protocol;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListTargets {
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
}
#[derive(Serialize)]
pub(super) struct TargetList {
    targets: Vec<TargetInfo>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CallTarget {
    label: String,
    method: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: String,
    #[serde(default, deserialize_with = "present")]
    timeout_ms: Option<i64>,
    #[serde(default, deserialize_with = "present")]
    max_response_bytes: Option<i64>,
    #[serde(default, deserialize_with = "present")]
    follow_redirects: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    max_redirects: Option<i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CallTemplate {
    label: String,
    #[serde(deserialize_with = "unique")]
    parameters: BTreeMap<String, String>,
    #[serde(default, deserialize_with = "unique")]
    headers: BTreeMap<String, String>,
    #[serde(default, deserialize_with = "present")]
    timeout_ms: Option<i64>,
    #[serde(default, deserialize_with = "present")]
    max_response_bytes: Option<i64>,
}
#[derive(Serialize)]
pub(super) struct CallResponse {
    status_code: u16,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    headers: protocol::Headers,
    #[serde(skip_serializing_if = "String::is_empty")]
    body_base64: String,
    body_size_bytes: usize,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    truncated: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AudienceQuery {
    label: String,
}
#[derive(Serialize)]
pub(super) struct Audience {
    audience: String,
}

fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn unique<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Entries;
    impl<'de> Visitor<'de> for Entries {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an object with distinct names and string values")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((name, value)) = map.next_entry::<String, String>()? {
                if result.insert(name, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate template argument"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Entries)
}

impl Harpoon {
    pub(super) fn call_schema(&self, template: bool) -> Value {
        let timeout = json!({"type":"integer","maximum":120000,"minimum":100,"default":30000});
        let response = json!({"type":"integer","maximum":self.response_limit(),"minimum":1,"default":self.response_limit()});
        let headers = json!({"additionalProperties":{"type":"string"},"propertyNames":{"type":"string","pattern":"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"},"type":"object","default":{}});
        if template {
            return json!({
                "$schema":"https://json-schema.org/draft/2020-12/schema",
                "$id":"https://github.com/openai/tunnel-client/pkg/runtimeharpoon/call-target-template-request",
                "properties":{
                    "label":{"type":"string","maxLength":64,"minLength":1,"pattern":"^[a-z0-9][a-z0-9_-]{0,63}$"},
                    "parameters":{"type":"object","description":"Required string values matching the target parameters_schema."},
                    "headers":headers,
                    "timeout_ms":timeout,
                    "max_response_bytes":response
                },
                "additionalProperties":false,
                "type":"object",
                "required":["label","parameters"],
                "title":"Call Harpoon target template",
                "description":"Call a configured GET operation with bounded string identifiers."
            });
        }
        let mut timeout = timeout;
        timeout["description"] = json!("Request timeout in milliseconds");
        let mut response = response;
        response["description"] = json!("Maximum response bytes to read");
        let mut headers = headers;
        headers["description"] = json!(
            "HTTP headers to include in the request; transport proxy forwarding headers plus client-managed identity headers plus caller-supplied fields nominated by Connection are blocked"
        );
        json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "$id":"https://github.com/openai/tunnel-client/pkg/runtimeharpoon/call-target-request",
            "properties":{
                "label":{"type":"string","maxLength":64,"minLength":1,"pattern":"^[a-z0-9][a-z0-9_-]{0,63}$","description":"Allowlisted target label"},
                "method":{"type":"string","enum":["GET","POST","PUT"],"description":"HTTP method for the outbound request"},
                "headers":headers,
                "body":{"type":"string","description":"Request body as a raw string"},
                "timeout_ms":timeout,
                "max_response_bytes":response,
                "follow_redirects":{"type":"boolean","description":"Whether to follow HTTP redirects","default":true},
                "max_redirects":{"type":"integer","maximum":self.redirect_limit(),"minimum":0,"description":"Maximum redirects to follow when follow_redirects is true","default":self.redirect_limit()}
            },
            "additionalProperties":false,
            "type":"object",
            "required":["label","method"],
            "title":"Call Harpoon target",
            "description":"Call an allowlisted HTTP target by label."
        })
    }

    pub(super) fn response_schema(&self) -> Value {
        json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "$id":"https://github.com/openai/tunnel-client/pkg/runtimeharpoon/call-target-response",
            "properties":{
                "status_code":{"type":"integer","maximum":599,"minimum":100,"description":"HTTP status code returned by the target."},
                "headers":{"additionalProperties":{"items":{"type":"string"},"type":"array"},"propertyNames":{"type":"string","pattern":"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"},"type":"object","description":"Response headers returned by the target."},
                "body_base64":{"type":"string","description":"Base64-encoded response body bytes.","contentEncoding":"base64"},
                "body_size_bytes":{"type":"integer","maximum":self.response_limit(),"minimum":0,"description":"Number of bytes in body_base64."},
                "truncated":{"type":"boolean","description":"Whether the response body was truncated."}
            },
            "additionalProperties":false,
            "type":"object",
            "required":["status_code","body_size_bytes"],
            "title":"Harpoon call result",
            "description":"Response details from the target."
        })
    }

    pub(super) fn audience_input_schema(&self) -> Value {
        json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "$id":"https://github.com/openai/tunnel-client/pkg/harpoon/oauth-target-audience-request",
            "properties":{"label":{"type":"string","maxLength":64,"minLength":1,"pattern":"^[a-z0-9][a-z0-9_-]{0,63}$","description":"OAuth token-endpoint target label."}},
            "additionalProperties":false,
            "type":"object",
            "required":["label"],
            "title":"Get OAuth target audience",
            "description":"Resolve the exact upstream URL for an allowlisted OAuth token endpoint."
        })
    }

    pub(super) fn audience_output_schema(&self) -> Value {
        json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "$id":"https://github.com/openai/tunnel-client/pkg/harpoon/oauth-target-audience-response",
            "properties":{"audience":{"type":"string","format":"uri","description":"Exact upstream OAuth token endpoint URL to use as a private_key_jwt audience."}},
            "additionalProperties":false,
            "type":"object",
            "required":["audience"],
            "title":"OAuth target audience",
            "description":"Exact private_key_jwt audience for an allowlisted OAuth token endpoint."
        })
    }

    pub(super) fn list_input_schema(&self) -> Value {
        json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "$id":"https://github.com/openai/tunnel-client/pkg/runtimeharpoon/list-targets-request",
            "properties":{
                "categories":{"items":{"type":"string"},"type":"array","description":"Target categories to include."},
                "sources":{"items":{"type":"string"},"type":"array","description":"Target sources to include."},
                "tags":{"items":{"type":"string"},"type":"array","description":"Target tags to include (all tags must match)."}
            },
            "additionalProperties":false,
            "type":"object",
            "title":"List Harpoon targets",
            "description":"List available allowlisted targets."
        })
    }

    pub(super) fn list_output_schema(&self, templates: bool) -> Value {
        let mut properties = serde_json::Map::new();
        if templates {
            properties.insert("template_version".into(), json!({"type":"integer","description":"Template contract version; absent for exact targets."}));
            properties.insert("parameters_schema".into(), json!({"type":"object","description":"Required string parameter schema for call_target_template."}));
            properties.insert("invocation".into(), json!({
                "properties":{
                    "tool_name":{"type":"string","description":"MCP tool to call with arguments matching input_schema."},
                    "input_schema":{"type":"object","description":"Complete argument schema for this target"},
                    "examples":{"items":{"type":"object"},"type":"array","description":"Complete validated example argument objects; omit optional call controls to use their defaults."}
                },
                "additionalProperties":false,
                "type":"object",
                "required":["tool_name","input_schema"],
                "description":"Self-contained template tool invocation contract; absent for exact targets."
            }));
        }
        properties.extend([
            ("label".into(), json!({"type":"string","maxLength":64,"minLength":1,"pattern":"^[a-z0-9][a-z0-9_-]{0,63}$","description":"Target label."})),
            ("description".into(), json!({"type":"string","description":"Target description."})),
            ("category".into(), json!({"type":"string","description":"Target category."})),
            ("source".into(), json!({"type":"string","description":"Target source."})),
            ("tags".into(), json!({"items":{"type":"string"},"type":"array","description":"Target tags."})),
            ("allowed_methods".into(), json!({"items":{"type":"string","enum":["GET","POST","PUT"]},"type":"array","description":"HTTP methods permitted for this target"})),
        ]);
        let description = if templates {
            "Allowlisted targets: use call_target for exact targets. For entries with template_version and parameters_schema, use call_target_template with the label and all parameters declared by parameters_schema; each value must satisfy that schema."
        } else {
            "Allowlisted targets available to call_target."
        };
        json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "$id":"https://github.com/openai/tunnel-client/pkg/runtimeharpoon/list-targets-response",
            "properties":{"targets":{"items":{"properties":properties,"additionalProperties":false,"type":"object","required":["label","allowed_methods"]},"type":"array","description":"Allowlisted targets."}},
            "additionalProperties":false,
            "type":"object",
            "required":["targets"],
            "title":"Harpoon target list",
            "description":description
        })
    }

    fn response_limit(&self) -> usize {
        self.config
            .max_response_bytes
            .filter(|limit| *limit > 0)
            .unwrap_or(102400)
    }

    fn redirect_limit(&self) -> usize {
        self.config.max_redirects
    }

    pub(super) async fn call(&self, name: &str, arguments: &RawValue) -> Result<Value> {
        match name {
            "list_targets" => {
                let mut filter: ListTargets = serde_json::from_str(arguments.get())
                    .context("label unknown: invalid parameters")?;
                for values in [
                    &mut filter.categories,
                    &mut filter.sources,
                    &mut filter.tags,
                ] {
                    *values = values
                        .iter()
                        .map(|value| value.trim().to_ascii_lowercase())
                        .filter(|value| !value.is_empty())
                        .collect();
                }
                let targets = self
                    .targets()
                    .into_iter()
                    .filter(|target| {
                        (filter.categories.is_empty()
                            || filter.categories.contains(&target.category))
                            && (filter.sources.is_empty()
                                || filter.sources.contains(&target.source))
                            && filter.tags.iter().all(|value| target.tags.contains(value))
                    })
                    .collect();
                Ok(serde_json::to_value(TargetList { targets })?)
            }
            "get_oauth_target_audience" => {
                let query: AudienceQuery = serde_json::from_str(arguments.get())
                    .context("label unknown: invalid parameters")?;
                let label = query.label.trim();
                let result = (|| {
                    anyhow::ensure!(!label.is_empty(), "label is required");
                    let target = self.target(label)?;
                    anyhow::ensure!(
                        target.info.category == "oauth"
                            && ["auth-server-metadata", "token-endpoint"]
                                .iter()
                                .all(|tag| target.info.tags.iter().any(|value| value == tag)),
                        "target is not an OAuth token endpoint"
                    );
                    anyhow::ensure!(
                        target.url.username().is_empty()
                            && target.url.password().is_none()
                            && target.url.fragment().is_none(),
                        "target URL cannot be used as an OAuth audience"
                    );
                    Ok::<_, anyhow::Error>(serde_json::to_value(Audience {
                        audience: target.original_url,
                    })?)
                })();
                result.with_context(|| {
                    format!("label {}", if label.is_empty() { "unknown" } else { label })
                })
            }
            "call_target" | "call_target_template" => {
                let (call, parameters) = if name == "call_target_template" {
                    anyhow::ensure!(
                        arguments.get().len() <= 32768,
                        "label unknown: invalid template arguments"
                    );
                    let call: CallTemplate = serde_json::from_str(arguments.get())
                        .context("label unknown: invalid template arguments")?;
                    anyhow::ensure!(
                        super::valid_label(&call.label),
                        "label unknown: invalid template arguments"
                    );
                    (
                        CallTarget {
                            label: call.label,
                            method: "GET".into(),
                            headers: call.headers,
                            body: String::new(),
                            timeout_ms: call.timeout_ms,
                            max_response_bytes: call.max_response_bytes,
                            follow_redirects: Some(false),
                            max_redirects: None,
                        },
                        Some(call.parameters),
                    )
                } else {
                    (
                        serde_json::from_str::<CallTarget>(arguments.get())
                            .context("label unknown: invalid parameters")?,
                        None,
                    )
                };
                let label = call.label.trim().to_owned();
                let result = async {
                    let milliseconds = call.timeout_ms.unwrap_or(30000);
                    anyhow::ensure!(milliseconds > 0, "timeout must be positive");
                    anyhow::ensure!(milliseconds >= 100, "timeout must be at least 100ms");
                    anyhow::ensure!(milliseconds <= 120000, "timeout must be at most 120000ms");
                    let response = tokio::time::timeout(Duration::from_millis(milliseconds as u64), self.request(call, parameters)).await.context("request failed")??;
                    if name == "call_target_template" {
                        Ok(serde_json::to_value(response)?)
                    } else {
                        Ok(json!({"status_code":response.status_code,"headers":response.headers,"body_base64":response.body_base64,"body_size_bytes":response.body_size_bytes,"truncated":response.truncated}))
                    }
                }.await;
                result.with_context(|| {
                    format!(
                        "label {}",
                        if label.is_empty() { "unknown" } else { &label }
                    )
                })
            }
            _ => bail!("unknown Harpoon tool {name}"),
        }
    }

    async fn request(
        &self,
        call: CallTarget,
        parameters: Option<BTreeMap<String, String>>,
    ) -> Result<CallResponse> {
        anyhow::ensure!(!call.label.trim().is_empty(), "label is required");
        let mut target = self.target(call.label.trim())?;
        let mut method = Method::from_bytes(call.method.trim().to_ascii_uppercase().as_bytes())?;
        anyhow::ensure!(
            matches!(method, Method::GET | Method::POST | Method::PUT),
            "invalid method"
        );
        let is_template = target.template.is_some();
        let mut headers = match (&target.template, parameters) {
            (Some(template), Some(parameters)) => {
                let mut caller = HeaderMap::new();
                for (name, value) in &call.headers {
                    let name = HeaderName::try_from(name)?;
                    anyhow::ensure!(!caller.contains_key(&name), "duplicate caller header name");
                    caller.insert(name, HeaderValue::try_from(value)?);
                }
                let (url, headers) = template.render(&parameters, caller)?;
                target.url = url;
                headers
            }
            (None, None) => headers::outbound(&call.headers)?,
            (Some(_), None) => bail!("template target requires call_target_template"),
            (None, Some(_)) => bail!("unknown template target"),
        };
        let limit = self.response_limit();
        let limit = match call.max_response_bytes {
            Some(value) => {
                anyhow::ensure!(value > 0, "max_response_bytes must be positive");
                anyhow::ensure!(
                    value as u64 <= limit as u64,
                    "max_response_bytes must be less than or equal to {limit}"
                );
                value as usize
            }
            None => limit,
        };
        let follow = call.follow_redirects.unwrap_or(true);
        let redirects = if follow {
            let limit = self.redirect_limit();
            match call.max_redirects {
                Some(value) => {
                    anyhow::ensure!(value >= 0, "max_redirects must be non-negative");
                    anyhow::ensure!(
                        value as u64 <= limit as u64,
                        "max_redirects must be less than or equal to {limit}"
                    );
                    value as usize
                }
                None => limit,
            }
        } else {
            0
        };
        anyhow::ensure!(call.body.len() <= limit, "request body exceeds size limit");
        let mut body = Bytes::from(call.body);
        let mut hop = 0;
        let initial_host = target.url.host_str().unwrap_or_default().to_owned();
        loop {
            let mut response = target
                .client
                .send(method.clone(), &target.url, headers.clone(), body.clone())
                .await
                .context("request failed")?;
            if follow
                && matches!(response.status.as_u16(), 301 | 302 | 303 | 307 | 308)
                && let Some(location) = response.headers.get("location")
            {
                anyhow::ensure!(hop < redirects, "redirect limit exceeded");
                let location = location.to_str().context("redirect blocked")?;
                let next = target.url.join(location).context("redirect blocked")?;
                let host = next.host_str().unwrap_or_default();
                if host != initial_host && !host.ends_with(&format!(".{initial_host}")) {
                    headers.remove("authorization");
                }
                if !matches!(method, Method::GET | Method::HEAD)
                    && matches!(response.status.as_u16(), 301..=303)
                {
                    method = Method::GET;
                    body = Bytes::new();
                }
                if !(target.url.scheme() == "https" && next.scheme() == "http") {
                    let mut referer = target.url.clone();
                    let _ = referer.set_username("");
                    let _ = referer.set_password(None);
                    headers.insert("referer", referer.as_str().parse()?);
                }
                target = self.destination(&next)?;
                hop += 1;
                continue;
            }
            let status_code = response.status.as_u16();
            let mut response_headers = headers::wire(&response.headers);
            let mut bytes = BytesMut::new();
            while let Some(chunk) = response.body.next().await {
                let chunk = chunk.context("response read failed")?;
                anyhow::ensure!(
                    chunk.len() <= limit.saturating_sub(bytes.len()),
                    "response exceeds size limit"
                );
                bytes.extend_from_slice(&chunk);
            }
            let body_size_bytes = bytes.len();
            let mut bytes = bytes.freeze();
            if !is_template {
                if let Ok(mut value) = serde_json::from_slice::<Value>(&bytes)
                    && self.rewrite(&mut value)
                {
                    bytes = Bytes::from(serde_json::to_vec(&value)?);
                }
                self.rewrite_headers(&mut response_headers);
            }
            return Ok(CallResponse {
                status_code,
                headers: response_headers,
                body_base64: STANDARD.encode(&bytes),
                body_size_bytes,
                truncated: false,
            });
        }
    }
}

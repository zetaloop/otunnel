use std::{fmt, time::Duration};

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use http::{HeaderMap, HeaderValue, Method};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use url::Url;

use crate::{
    config,
    net::{Http, Options},
};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub creator: String,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "identifiers"
    )]
    pub tenant_ids: Vec<String>,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "identifiers"
    )]
    pub workspace_ids: Vec<String>,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "identifiers"
    )]
    pub organization_ids: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub request_id: String,
}

fn identifiers<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    Ok(Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default())
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct TunnelList {
    pub tunnels: Option<Vec<Tunnel>>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub request_id: String,
}

#[derive(Debug)]
pub struct RequestError {
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub response_body: String,
    pub request_id: String,
    pub code: String,
    pub kind: String,
    pub message: String,
    pub mitigation: String,
}
impl fmt::Display for RequestError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "request {} {} failed: {} ",
            self.method, self.path, self.status_code
        )?;
        if self.method == "DELETE"
            && self.status_code == 404
            && self.response_body.contains("Invalid URL")
        {
            write!(
                output,
                "delete is not exposed on this control-plane base URL yet; get/list/create/update may still work ({})",
                self.response_body
            )?;
        } else {
            if !self.code.is_empty() {
                write!(output, "{}: ", self.code)?;
            }
            output.write_str(if self.message.is_empty() {
                &self.response_body
            } else {
                &self.message
            })?;
            if !self.mitigation.is_empty() {
                write!(output, " mitigation: {}", self.mitigation)?;
            }
        }
        if !self.request_id.is_empty() {
            write!(output, " (x-request-id: {})", self.request_id)?;
        }
        Ok(())
    }
}
impl std::error::Error for RequestError {}
impl RequestError {
    pub fn payload(&self) -> Value {
        let mut value = json!({"message":self.to_string(),"method":self.method,"path":self.path,"status_code":self.status_code});
        for (name, item) in [
            ("request_id", &self.request_id),
            ("code", &self.code),
            ("type", &self.kind),
            ("mitigation", &self.mitigation),
        ] {
            if !item.is_empty() {
                value[name] = json!(item);
            }
        }
        json!({"error":value})
    }
}

/// Tunnel management operations using an explicitly selected credential.
#[derive(Clone)]
pub struct Client {
    http: Http,
    root: Url,
    headers: HeaderMap,
}
impl Client {
    pub fn new(base: &str, prefix: &str, key: &str, ca_bundle: Option<&str>) -> Result<Self> {
        anyhow::ensure!(!key.is_empty(), "admin key is required");
        let base = Url::parse(base)?;
        let root = config::endpoint(&base, prefix, "v1/tunnels")?;
        let http = Http::new(
            base,
            Options {
                ca_bundle,
                ..Default::default()
            },
        )?;
        let mut headers = HeaderMap::new();
        let mut authorization = HeaderValue::try_from(format!("Bearer {key}"))?;
        authorization.set_sensitive(true);
        headers.insert("authorization", authorization);
        headers.insert("accept", HeaderValue::from_static("application/json"));
        headers.insert(
            "user-agent",
            HeaderValue::from_static(crate::harpoon::headers::USER_AGENT),
        );
        headers.insert("x-tunnel-client-name", HeaderValue::from_static("otunnel"));
        headers.insert(
            "x-tunnel-client-version",
            HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
        );
        headers.insert(
            "x-tunnel-client-instance-id",
            uuid::Uuid::new_v4().to_string().parse()?,
        );
        Ok(Self {
            http,
            root,
            headers,
        })
    }
    pub async fn create(&self, value: Value) -> Result<Tunnel> {
        self.request(Method::POST, None, &[], Some(value)).await
    }
    pub async fn get(&self, id: &str) -> Result<Tunnel> {
        self.request(Method::GET, Some(id), &[], None).await
    }
    pub async fn update(&self, id: &str, value: Value) -> Result<Tunnel> {
        self.request(Method::POST, Some(id), &[], Some(value)).await
    }
    pub async fn delete(&self, id: &str) -> Result<Tunnel> {
        self.request(Method::DELETE, Some(id), &[], None).await
    }
    pub async fn list(
        &self,
        organization: &str,
        workspace: &str,
        tenant: &str,
    ) -> Result<TunnelList> {
        let query: Vec<_> = [
            ("organization_id", organization),
            ("workspace_id", workspace),
            ("tenant_id", tenant),
        ]
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .collect();
        self.request(Method::GET, None, &query, None).await
    }
    async fn request<T: DeserializeOwned + Default>(
        &self,
        method: Method,
        id: Option<&str>,
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<T> {
        let mut url = self.root.clone();
        if let Some(id) = id {
            anyhow::ensure!(!id.is_empty(), "tunnel id is required");
            url.path_segments_mut()
                .map_err(|_| anyhow::anyhow!("invalid admin endpoint"))?
                .push(id);
        }
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query.iter().copied());
        }
        let mut headers = self.headers.clone();
        let body = if let Some(body) = body {
            headers.insert("content-type", HeaderValue::from_static("application/json"));
            Bytes::from(serde_json::to_vec(&body)?)
        } else {
            Bytes::new()
        };
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut response = self
                .http
                .follow(method.clone(), url.clone(), headers, body, 10)
                .await?;
            let request_id = response
                .headers
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            if !response.status.is_success() {
                let status_code = response.status.as_u16();
                let mut body = BytesMut::new();
                while let Some(chunk) = response.body.next().await {
                    let chunk = chunk?;
                    body.extend_from_slice(&chunk[..chunk.len().min(4096 - body.len())]);
                    if body.len() == 4096 {
                        break;
                    }
                }
                let raw = String::from_utf8_lossy(&body).trim().to_owned();
                let payload = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
                let error = payload
                    .get("error")
                    .filter(|value| value.is_object())
                    .unwrap_or(&payload);
                let code = error["code"].as_str().unwrap_or_default().to_owned();
                let kind = error["type"].as_str().unwrap_or_default().to_owned();
                let message = error["message"]
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| {
                        payload.get("detail").map_or_else(String::new, |value| {
                            value
                                .as_str()
                                .map(str::to_owned)
                                .unwrap_or_else(|| value.to_string())
                        })
                    });
                return Err(RequestError {
                    method: method.to_string(),
                    path: url.path().into(),
                    status_code,
                    response_body: raw,
                    request_id,
                    mitigation: mitigation(&code).into(),
                    code,
                    kind,
                    message,
                }
                .into());
            }
            let bytes = response.bytes().await?;
            if bytes.is_empty() {
                return Ok(T::default());
            }
            let mut value: Value = serde_json::from_slice(&bytes).context("decode response")?;
            if !request_id.is_empty() && value.is_object() {
                value["request_id"] = json!(request_id);
            }
            serde_json::from_value(value).context("decode response")
        })
        .await
        .context("admin request timed out")?
    }
}

fn mitigation(code: &str) -> &'static str {
    match code {
        "invalid_tunnel_id_format" => {
            "set --control-plane.tunnel-id, CONTROL_PLANE_TUNNEL_ID, or control_plane.tunnel_id to the exact tunnel_... ID from Platform tunnel settings"
        }
        "invalid_channel_format" => {
            "use only lowercase letters, digits, hyphens, or underscores in MCP channel names"
        }
        "rate_limit_exceeded" => {
            "reduce request concurrency or volume and let tunnel-client retry after backoff"
        }
        "request_body_too_large" => {
            "send a smaller MCP request body and avoid large inline payloads"
        }
        "invalid_json_payload" => {
            "fix the MCP caller or server to send a valid JSON object request body"
        }
        "missing_mcp_session_id" => {
            "send DELETE session termination requests with the Mcp-Session-Id header from the active MCP session"
        }
        "rfc9728_www_authenticate_unsupported" => {
            "use the well-known OAuth discovery endpoints instead of WWW-Authenticate probing"
        }
        "tunnel_missing_principals" => {
            "use a runtime API key associated with the intended organization or workspace"
        }
        "tunnel_management_permission_required" => {
            "use an admin key or account with Tunnels Read and Manage for the target org/workspace"
        }
        "tunnel_use_forbidden" => {
            "use credentials for a principal that has access to this tunnel, or recreate/connect the runtime in the owning org/workspace"
        }
        "tunnel_active_organization_required" => {
            "set --control-plane.organization-id, CONTROL_PLANE_ORGANIZATION_ID, or control_plane.organization_id to the tunnel's organization ID"
        }
        "tunnel_active_organization_context_required" => {
            "select or pass the intended organization ID before listing principals or managing principal-validation overrides"
        }
        "tunnel_principal_validation_override_management_permission_required" => {
            "use a credential authorized for tunnel principal-validation override management"
        }
        "tunnel_principal_validation_override_automatically_derivable" => {
            "create or update the tunnel directly; no reviewed override is needed for that principal set"
        }
        "tunnel_principal_association_unverified" => {
            "use an automatically verifiable org/workspace/tenant combination or request a reviewed association override"
        }
        "tunnel_principal_limit_exceeded" => {
            "reduce each of tenant_ids, workspace_ids, and organization_ids to the documented maximum"
        }
        "tunnel_request_mismatch" => {
            "verify the client uses the same control_plane.tunnel_id that received the command"
        }
        "pending_request_not_found" => {
            "ignore isolated races; if repeated, ensure only healthy clients acknowledge requests for this tunnel"
        }
        "tunnel_queue_full" => {
            "reduce MCP request concurrency or add enough healthy tunnel-client capacity to drain the tunnel"
        }
        "tunnel_client_not_seen" => {
            "start or restart tunnel-client with the matching control_plane.tunnel_id and control_plane.api_key"
        }
        "tunnel_client_not_connected" => {
            "start or restart tunnel-client, then check its /readyz endpoint and logs"
        }
        "oauth_shim_invalid_target_uri" => {
            "use an absolute http(s) URI or harpoon://<label> that matches harpoon.targets[].label"
        }
        "oauth_shim_unshimmable_endpoint" => {
            "configure supported OAuth metadata endpoints and grouped harpoon targets for auth-server metadata"
        }
        "oauth_shim_target_not_found" => {
            "add or correct the matching harpoon.targets[].label entry and restart tunnel-client"
        }
        "oauth_shim_harpoon_call_failed" => {
            "check the Harpoon target URL, upstream MCP server health, and tunnel-client logs"
        }
        "oauth_shim_upstream_timeout" => {
            "ensure the Harpoon target and upstream MCP server respond before the tunnel timeout"
        }
        _ => "",
    }
}

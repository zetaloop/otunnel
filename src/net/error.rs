use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Default)]
pub(crate) struct ErrorInfo {
    pub code: String,
    pub kind: String,
    pub message: String,
    pub body: String,
    pub mitigation: String,
}

impl ErrorInfo {
    pub fn parse(body: &[u8]) -> Self {
        #[derive(Default, Deserialize)]
        struct Fields {
            code: Option<String>,
            #[serde(rename = "type")]
            kind: Option<String>,
            message: Option<String>,
        }
        #[derive(Deserialize)]
        struct Payload {
            error: Option<Fields>,
            #[serde(flatten)]
            fields: Fields,
            detail: Option<Value>,
        }
        let raw = String::from_utf8_lossy(body);
        let raw = raw.trim();
        if raw.is_empty() {
            return Self::default();
        }
        let payload = match serde_json::from_str::<Option<Payload>>(raw) {
            Ok(Some(payload)) => payload,
            Ok(None) => return Self::default(),
            Err(_) => {
                let limit = raw.floor_char_boundary(1024);
                return Self {
                    body: if raw.len() > 1024 {
                        format!("{}...", &raw[..limit])
                    } else {
                        raw.into()
                    },
                    ..Self::default()
                };
            }
        };
        let nested = payload.error.is_some();
        let fields = payload.error.unwrap_or(payload.fields);
        let code = fields.code.unwrap_or_default();
        let mut message = fields.message.unwrap_or_default();
        if !nested
            && message.is_empty()
            && let Some(detail) = payload.detail
        {
            message = detail
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| detail.to_string());
        }
        Self {
            mitigation: mitigation(&code).into(),
            code,
            kind: fields.kind.unwrap_or_default(),
            message,
            body: String::new(),
        }
    }

    pub fn detail(&self) -> String {
        let message = if self.message.is_empty() {
            &self.body
        } else {
            &self.message
        };
        let mut detail = [&self.code, message]
            .into_iter()
            .filter(|value| !value.is_empty())
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(": ");
        if !self.mitigation.is_empty() {
            if !detail.is_empty() {
                detail.push(' ');
            }
            detail.push_str("mitigation: ");
            detail.push_str(&self.mitigation);
        }
        detail
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

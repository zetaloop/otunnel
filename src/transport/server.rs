use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response, Sse, sse::Event},
    routing::{MethodFilter, MethodRouter, get},
};
use bytes::Bytes;
use futures_util::stream;
use serde_json::value::RawValue;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    listener::{Peer, loopback_address},
    protocol::{self, Reply, Request},
    transport::{self, Transport},
};

#[derive(Clone)]
pub struct Server {
    transport: Arc<dyn Transport>,
    sessions: Arc<RwLock<BTreeMap<String, CancellationToken>>>,
    stop: CancellationToken,
    local_only: Option<&'static str>,
}

impl Server {
    pub fn new(transport: Arc<dyn Transport>, stop: CancellationToken) -> Self {
        Self {
            transport,
            stop,
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
            local_only: None,
        }
    }

    pub fn local_only(mut self, message: &'static str) -> Self {
        self.local_only = Some(message);
        self
    }

    pub fn route(self) -> MethodRouter {
        get(get_stream)
            .post(post)
            .delete(delete)
            .on(MethodFilter::HEAD, method)
            .fallback(method)
            .layer(DefaultBodyLimit::max(MCP_BODY_LIMIT))
            .layer(middleware::from_fn_with_state(self.clone(), access))
            .with_state(self)
    }
}

const MCP_BODY_LIMIT: usize = 4 * 1024 * 1024;

fn mcp_error(status: StatusCode, message: &str) -> Response {
    (status, format!("{message}\n")).into_response()
}

fn mcp_session(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
}

async fn access(
    State(server): State<Server>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if let Some(message) = server.local_only
        && peer.remote != "local"
        && !loopback_address(&peer.remote)
    {
        return mcp_error(StatusCode::FORBIDDEN, message);
    }
    let host = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if peer.remote != "local" && loopback_address(&peer.local) && !loopback_address(host) {
        return mcp_error(
            StatusCode::FORBIDDEN,
            &format!("Forbidden: invalid Host header {host:?}"),
        );
    }
    let version = request
        .headers()
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !version.is_empty()
        && version < protocol::MCP_VERSION
        && !protocol::SUPPORTED_VERSIONS.contains(&version)
    {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            &format!(
                "Bad Request: Unsupported protocol version (supported versions: {})",
                protocol::SUPPORTED_VERSIONS.join(",")
            ),
        );
    }
    next.run(request).await
}

async fn method() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [("allow", "GET, POST, DELETE")],
        "Method Not Allowed\n",
    )
}

fn accepts(headers: &HeaderMap) -> (bool, bool) {
    let mut accepted = (false, false);
    for value in headers
        .get_all("accept")
        .iter()
        .filter_map(|value| value.to_str().ok())
    {
        for item in value.split(',') {
            match item
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str()
            {
                "application/json" | "application/*" => accepted.0 = true,
                "text/event-stream" | "text/*" => accepted.1 = true,
                "*/*" => accepted = (true, true),
                _ => {}
            }
        }
    }
    accepted
}

fn sse_messages(messages: &[Box<RawValue>]) -> String {
    messages
        .iter()
        .map(|message| format!("event: message\ndata: {}\n\n", message.get()))
        .collect()
}

fn jsonrpc_error(message: &RawValue, code: i32, text: String) -> Response {
    let id = protocol::view(message)
        .ok()
        .and_then(|message| message.id)
        .and_then(|id| serde_json::from_str::<serde_json::Value>(id.get()).ok())
        .unwrap_or(serde_json::Value::Null);
    (
        StatusCode::BAD_REQUEST,
        [("content-type", "application/json")],
        serde_json::json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":text}})
            .to_string(),
    )
        .into_response()
}

fn validate_mcp_headers(
    headers: &HeaderMap,
    message: &RawValue,
) -> std::result::Result<(), String> {
    let version = headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if version < protocol::MCP_VERSION {
        return Ok(());
    }
    let envelope = protocol::view(message).map_err(|error| error.to_string())?;
    let Some(method) = envelope.method.as_deref() else {
        return Ok(());
    };
    let header = headers
        .get("mcp-method")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if header.is_empty() {
        return Err("missing required Mcp-Method header".into());
    }
    if header != method {
        return Err(format!(
            "header mismatch: Mcp-Method header value '{header}' does not match body value '{method}'"
        ));
    }
    let key = match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    };
    if let Some(key) = key {
        let name = headers
            .get("mcp-name")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if name.is_empty() {
            return Err(format!(
                "missing required Mcp-Name header for method {method:?}"
            ));
        }
        let body = protocol::field(message, "params")
            .and_then(|params| protocol::field(&params, key))
            .and_then(|value| serde_json::from_str::<String>(value.get()).ok())
            .ok_or_else(|| {
                format!("failed to extract name from parameters for method {method:?}")
            })?;
        if name != body {
            return Err(format!(
                "header mismatch: Mcp-Name header value '{name}' does not match body value '{body}'"
            ));
        }
    }
    Ok(())
}

async fn post(
    State(server): State<Server>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(error) => {
            return mcp_error(
                error.status(),
                if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    "request body too large"
                } else {
                    "failed to read body"
                },
            );
        }
    };
    if !headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        })
    {
        return mcp_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be 'application/json'",
        );
    }
    if accepts(&headers) != (true, true) {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            "Accept must contain both 'application/json' and 'text/event-stream'",
        );
    }
    if headers.contains_key("last-event-id") {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            "can't send Last-Event-ID for POST request",
        );
    }
    let trimmed = body
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map_or(&body[..], |start| &body[start..]);
    let is_batch = trimmed.first() == Some(&b'[');
    if is_batch
        && headers
            .get("mcp-protocol-version")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|version| version >= "2025-06-18")
    {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            &format!(
                "JSON-RPC batching is not supported in 2025-06-18 and later (request version: {})",
                headers["mcp-protocol-version"].to_str().unwrap_or_default()
            ),
        );
    }
    let messages: Vec<Box<RawValue>> = if is_batch {
        match serde_json::from_slice::<Vec<Box<RawValue>>>(trimmed) {
            Ok(messages) if !messages.is_empty() => messages,
            _ => return mcp_error(StatusCode::BAD_REQUEST, "invalid JSON-RPC batch"),
        }
    } else {
        match serde_json::from_slice(trimmed) {
            Ok(message) => vec![message],
            Err(_) => return mcp_error(StatusCode::BAD_REQUEST, "invalid JSON-RPC request"),
        }
    };
    if messages.len() == 1 {
        let version = headers
            .get("mcp-protocol-version")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let meta = protocol::version(&messages[0]).unwrap_or_default();
        if version >= protocol::MCP_VERSION || !meta.is_empty() {
            if mcp_session(&headers).is_some()
                && protocol::view(&messages[0])
                    .is_ok_and(|request| request.method.as_deref() != Some("server/discover"))
            {
                return mcp_error(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        "Bad Request: protocol version {version:?} is only supported on stateless HTTP servers (set StreamableHTTPOptions.Stateless = true)"
                    ),
                );
            }
            if version.is_empty() {
                return jsonrpc_error(&messages[0], -32020, "Mcp-Protocol-Version header is required for requests carrying \"io.modelcontextprotocol/protocolVersion\"".into());
            }
            if meta.is_empty() {
                return jsonrpc_error(
                    &messages[0],
                    -32602,
                    "missing or invalid _meta field \"io.modelcontextprotocol/protocolVersion\""
                        .into(),
                );
            }
            if version != meta {
                return jsonrpc_error(
                    &messages[0],
                    -32020,
                    format!(
                        "Mcp-Protocol-Version header {version:?} does not match request io.modelcontextprotocol/protocolVersion {meta:?}"
                    ),
                );
            }
        }
        if let Err(message) = validate_mcp_headers(&headers, &messages[0]) {
            return jsonrpc_error(&messages[0], -32020, message);
        }
        if let Err(message) = protocol::validate_meta(&messages[0]) {
            return jsonrpc_error(&messages[0], -32602, message);
        }
    }
    if messages
        .iter()
        .any(|message| protocol::view(message).is_err())
    {
        return mcp_error(StatusCode::BAD_REQUEST, "invalid JSON-RPC request");
    }
    let methods: Vec<_> = messages
        .iter()
        .filter_map(|message| {
            protocol::view(message)
                .ok()?
                .method
                .map(|method| method.into_owned())
        })
        .collect();
    let supplied_session = mcp_session(&headers).map(str::to_owned);
    let legacy = supplied_session.is_some()
        || methods
            .iter()
            .any(|method| matches!(method.as_str(), "initialize" | "notifications/initialized"));
    if let Some(session) = &supplied_session {
        if methods.iter().any(|method| method == "initialize") {
            return mcp_error(
                StatusCode::BAD_REQUEST,
                "initialize cannot use an existing Mcp-Session-Id",
            );
        }
        if !server
            .sessions
            .read()
            .expect("MCP session lock poisoned")
            .contains_key(session)
        {
            return mcp_error(StatusCode::NOT_FOUND, "session not found");
        }
    } else if methods
        .iter()
        .any(|method| method == "notifications/initialized")
    {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            "notifications/initialized requires an Mcp-Session-Id",
        );
    }
    let created_session =
        if supplied_session.is_none() && methods.iter().any(|method| method == "initialize") {
            let id = Uuid::new_v4().to_string();
            server
                .sessions
                .write()
                .expect("MCP session lock poisoned")
                .insert(id.clone(), CancellationToken::new());
            Some(id)
        } else {
            None
        };
    let session_stop = supplied_session
        .as_ref()
        .or(created_session.as_ref())
        .and_then(|id| {
            server
                .sessions
                .read()
                .expect("MCP session lock poisoned")
                .get(id)
                .cloned()
        })
        .unwrap_or_else(|| server.stop.child_token());
    let exchange = futures_util::future::join_all(messages.into_iter().map(|message| {
        let transport = server.transport.clone();
        let headers = headers.clone();
        async move {
            let request = Request {
                message,
                headers,
                discovery: false,
            };
            match transport::exchange(transport.as_ref(), request.clone()).await {
                Ok(reply) => reply,
                Err(error) => Reply::error(&request, 200, -32603, format!("{error:#}"))
                    .unwrap_or_else(|_| Reply::ack(500, "jsonrpc_response")),
            }
        }
    }));
    let replies = tokio::select! {
        replies = exchange => replies,
        () = session_stop.cancelled() => return mcp_error(StatusCode::NOT_FOUND, "session is closing"),
        () = server.stop.cancelled() => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let messages: Vec<_> = replies
        .into_iter()
        .filter_map(|reply| reply.message)
        .collect();
    let mut response = if messages.is_empty() {
        StatusCode::ACCEPTED.into_response()
    } else if legacy {
        (
            StatusCode::OK,
            [
                ("content-type", "text/event-stream"),
                ("cache-control", "no-cache, no-transform"),
                ("connection", "keep-alive"),
            ],
            sse_messages(&messages),
        )
            .into_response()
    } else {
        let body = if messages.len() == 1 && !is_batch {
            messages[0].get().to_owned()
        } else {
            format!(
                "[{}]",
                messages
                    .iter()
                    .map(|message| message.get())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        (StatusCode::OK, [("content-type", "application/json")], body).into_response()
    };
    if let Some(session) = created_session
        && let Ok(value) = session.parse()
    {
        response.headers_mut().insert("mcp-session-id", value);
    }
    response
}

async fn get_stream(State(server): State<Server>, headers: HeaderMap) -> Response {
    if !accepts(&headers).1 {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            "Accept must contain 'text/event-stream' for GET requests",
        );
    }
    let Some(session) = mcp_session(&headers) else {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            "Bad Request: GET requires an Mcp-Session-Id header",
        );
    };
    let token = server
        .sessions
        .read()
        .expect("MCP session lock poisoned")
        .get(session)
        .cloned();
    let Some(token) = token else {
        return mcp_error(StatusCode::NOT_FOUND, "session not found");
    };
    if headers.contains_key("last-event-id") {
        return mcp_error(StatusCode::BAD_REQUEST, "stream replay unsupported");
    }
    let stop = server.stop;
    let stream = stream::unfold((token, stop), |(session, stop)| async move {
        tokio::select! { () = session.cancelled() => {} () = stop.cancelled() => {} }
        None::<(
            std::result::Result<Event, Infallible>,
            (CancellationToken, CancellationToken),
        )>
    });
    Sse::new(stream)
        .keep_alive(Default::default())
        .into_response()
}

async fn delete(State(server): State<Server>, headers: HeaderMap) -> Response {
    let Some(session) = mcp_session(&headers) else {
        return mcp_error(
            StatusCode::BAD_REQUEST,
            "Bad Request: DELETE requires an Mcp-Session-Id header",
        );
    };
    let token = server
        .sessions
        .write()
        .expect("MCP session lock poisoned")
        .remove(session);
    let Some(token) = token else {
        return mcp_error(StatusCode::NOT_FOUND, "session not found");
    };
    token.cancel();
    StatusCode::NO_CONTENT.into_response()
}

use std::{fmt, io};

use anyhow::Result;
use serde::Serialize;
use serde_json::{json, value::to_raw_value};

use crate::protocol::{self, Reply, Request};

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Failure {
    version: u8,
    source: &'static str,
    transport_error_kind: &'static str,
    upstream_response_received: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_status: Option<u16>,
    #[serde(skip)]
    status: u16,
}
impl Failure {
    pub fn protocol(status: u16, kind: &'static str) -> Self {
        let upstream = (400..600).contains(&status);
        Self {
            version: 1,
            source: if upstream { "target_http" } else { "protocol" },
            transport_error_kind: kind,
            upstream_response_received: upstream,
            upstream_status: upstream.then_some(status),
            status: if status == 0 { 502 } else { status },
        }
    }

    pub fn from_error(error: &anyhow::Error) -> Self {
        if let Some(failure) = error.downcast_ref::<Self>() {
            return failure.clone();
        }
        let mut result = Self::protocol(502, "unknown");
        result.source = "client_internal";
        result.upstream_response_received = false;
        result.upstream_status = None;
        let mut assign = |source, kind| {
            result.source = source;
            result.transport_error_kind = kind;
        };
        for cause in error.chain() {
            if cause.is::<rustls::Error>() {
                assign("tls", "tls");
                break;
            }
            if cause.is::<serde_json::Error>() {
                assign("protocol", "invalid_protocol_response");
                break;
            }
            if cause.is::<tokio::time::error::Elapsed>() {
                assign("timeout", "timeout");
                break;
            }
            if let Some(error) = cause.downcast_ref::<io::Error>() {
                let classification = match error.kind() {
                    io::ErrorKind::BrokenPipe => Some(("transport_closed", "closed_pipe")),
                    io::ErrorKind::UnexpectedEof => Some(("transport_closed", "unexpected_eof")),
                    io::ErrorKind::ConnectionAborted => {
                        Some(("transport_closed", "connection_aborted"))
                    }
                    io::ErrorKind::ConnectionReset => {
                        Some(("transport_closed", "connection_reset"))
                    }
                    io::ErrorKind::NotConnected => Some(("transport_closed", "connection_closed")),
                    io::ErrorKind::ConnectionRefused => Some(("connect", "connection_refused")),
                    io::ErrorKind::NetworkUnreachable => Some(("connect", "network_unreachable")),
                    io::ErrorKind::HostUnreachable => Some(("connect", "host_unreachable")),
                    io::ErrorKind::TimedOut => Some(("timeout", "timeout")),
                    _ => None,
                };
                if let Some((source, kind)) = classification {
                    assign(source, kind);
                    break;
                }
            }
            if let Some(error) = cause.downcast_ref::<reqwest::Error>() {
                if error.is_timeout() {
                    assign("timeout", "timeout");
                    break;
                }
                if error.is_connect() {
                    assign("connect", "dial");
                }
            }
            if let Some(error) = cause.downcast_ref::<hyper::Error>()
                && (error.is_closed() || error.is_incomplete_message())
            {
                assign(
                    "transport_closed",
                    if error.is_closed() {
                        "connection_closed"
                    } else {
                        "unexpected_eof"
                    },
                );
            }
        }
        result
    }

    pub async fn response(request: &Request, mut response: crate::net::Response) -> Result<Reply> {
        use futures_util::StreamExt;
        let status = response.status.as_u16();
        let headers = protocol::wire_headers(&response.headers, true);
        let mut body = Vec::new();
        let mut failure = None;
        while let Some(chunk) = response.body.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => {
                    failure = Some("response_body_unreadable");
                    break;
                }
            };
            if chunk.len() > (100 * 1024usize).saturating_sub(body.len()) {
                failure = Some("response_body_too_large");
                break;
            }
            body.extend_from_slice(&chunk);
        }
        let parsed = serde_json::from_slice::<protocol::Json>(&body);
        let request_id = protocol::view(&request.message)?.id;
        let valid = parsed.as_ref().is_ok_and(|message| {
            let version = protocol::field(message, "jsonrpc");
            let error = protocol::field(message, "error");
            protocol::view(message).is_ok_and(|view| {
                request_id
                    .zip(view.id)
                    .is_some_and(|(expected, actual)| protocol::same_id(expected, actual))
                    && version.is_some_and(|value| {
                        serde_json::from_str::<String>(value.get())
                            .is_ok_and(|value| value == "2.0")
                    })
                    && protocol::field(message, "method").is_none()
                    && protocol::field(message, "result").is_none()
                    && error.is_some_and(|error| {
                        protocol::field(&error, "code")
                            .is_some_and(|value| serde_json::from_str::<i64>(value.get()).is_ok())
                            && protocol::field(&error, "message").is_some_and(|value| {
                                serde_json::from_str::<String>(value.get()).is_ok()
                            })
                    })
            })
        });
        let mut reply = if failure.is_none() && valid {
            let mut reply = Reply::json(parsed.expect("validated MCP error"));
            reply.status = status;
            reply
        } else {
            let kind = failure.unwrap_or(if body.is_empty() {
                "response_body_missing"
            } else if parsed.is_err() {
                "malformed_json"
            } else {
                "invalid_mcp_error"
            });
            Self::protocol(status, kind).reply(request)?
        };
        reply.headers.extend(headers);
        Ok(reply)
    }

    pub fn reply(&self, request: &Request) -> Result<Reply> {
        let id = protocol::view(&request.message)?.id;
        if id.is_none() {
            return Ok(Reply::ack(self.status, "notify_ack"));
        }
        let message = ::http::StatusCode::from_u16(self.status)
            .ok()
            .and_then(|status| status.canonical_reason())
            .unwrap_or("MCP transport error");
        let mut reply = Reply::json(to_raw_value(&json!({
            "jsonrpc":"2.0", "id":id,
            "error":{"code":-32603,"message":message,"data":{"tunnel_failure":self}}
        }))?);
        reply.status = self.status;
        Ok(reply)
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "MCP {}: {}",
            self.source, self.transport_error_kind
        )
    }
}
impl std::error::Error for Failure {}

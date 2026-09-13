use std::{collections::BTreeSet, sync::LazyLock, time::Duration};

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use http::{HeaderMap, Method};
use regex::Regex;
use serde_json::{Value, value::to_raw_value};
use url::Url;

use crate::{
    harpoon::{Target, TargetInfo},
    protocol::{self, Reply},
    transport::HttpTransport,
};

#[derive(Debug)]
pub(crate) struct DiscoveryError {
    pub optional: bool,
    pub retry: bool,
    error: anyhow::Error,
}
impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:#}", self.error)
    }
}
impl std::error::Error for DiscoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

struct Document {
    url: Url,
    value: Value,
    headers: HeaderMap,
    status: u16,
}

const METADATA_LIMIT: usize = 1024 * 1024;

struct Fetched {
    status: u16,
    headers: HeaderMap,
    body: Bytes,
    too_large: bool,
}

#[derive(Clone)]
struct Record {
    raw: String,
    role: &'static str,
    description: &'static str,
    index: usize,
    group: Option<String>,
}

impl Record {
    fn new(raw: impl Into<String>, role: &'static str, description: &'static str) -> Self {
        Self {
            raw: raw.into(),
            role,
            description,
            index: 0,
            group: None,
        }
    }

    fn group(mut self, group: &str) -> Self {
        self.group = Some(group.into());
        self
    }
}

fn auth_group(source: &Url) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(source.as_str().as_bytes());
    let id = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("auth-server:{id}:0")
}

fn role_tags(role: &str) -> Vec<String> {
    match role {
        "prmd-resource" => vec!["protected-resource-metadata".into(), "resource".into()],
        "prmd-auth-server" => {
            vec![
                "authorization-server".into(),
                "protected-resource-metadata".into(),
            ]
        }
        "prmd-source" => vec!["protected-resource-metadata".into(), "source-url".into()],
        "auth-server-metadata" => vec!["auth-server-metadata".into()],
        role => vec!["auth-server-metadata".into(), role.into()],
    }
}

fn http_url(raw: &str) -> Option<Url> {
    let url = Url::parse(raw).ok()?;
    (matches!(url.scheme(), "http" | "https") && url.host_str().is_some()).then_some(url)
}

fn resource_metadata(header: &str) -> Option<&str> {
    static PARAMETER: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)(?:^|[\s,])resource_metadata\s*=\s*(?:"([^"]*)"|([^,\s]+))"#)
            .expect("authentication parameter pattern")
    });
    let mut segments = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in header.char_indices() {
        match character {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                segments.push(&header[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    segments.push(&header[start..]);
    let mut scheme = "";
    for segment in segments {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parameters = trimmed;
        if let Some(split) = trimmed.find(char::is_whitespace) {
            let candidate = &trimmed[..split];
            if !candidate.contains('=') {
                scheme = candidate;
                parameters = trimmed[split..].trim();
            }
        }
        if !scheme.eq_ignore_ascii_case("bearer") {
            continue;
        }
        if let Some(capture) = PARAMETER.captures(parameters) {
            return capture
                .get(1)
                .or_else(|| capture.get(2))
                .map(|value| value.as_str());
        }
    }
    None
}

async fn discovery_candidates(transport: &HttpTransport) -> (Vec<Url>, bool) {
    let probe = tokio::time::timeout(Duration::from_secs(1), async {
        let incoming = HeaderMap::new();
        for method in [Method::POST, Method::GET] {
            let mut headers = HeaderMap::new();
            headers.insert("accept", "application/json".parse().expect("static header"));
            let Ok(response) = transport
                .send(
                    method,
                    transport.url.clone(),
                    headers,
                    Bytes::new(),
                    &incoming,
                    true,
                )
                .await
            else {
                continue;
            };
            if response.status != http::StatusCode::UNAUTHORIZED {
                continue;
            }
            let challenge = response
                .headers
                .get_all("www-authenticate")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect::<Vec<_>>()
                .join(", ");
            if let Some(url) = resource_metadata(&challenge).and_then(http_url) {
                return Some(url);
            }
        }
        None
    })
    .await
    .ok()
    .flatten();

    let advertised = probe.is_some();
    let mut candidates = Vec::new();
    if let Some(url) = probe {
        candidates.push(url);
    }
    let mut root = transport.url.clone();
    let _ = root.set_username("");
    let _ = root.set_password(None);
    root.set_query(None);
    root.set_fragment(None);
    let suffix = transport.url.path().trim_matches('/');
    if !suffix.is_empty() {
        if suffix.starts_with(".well-known/oauth-protected-resource") {
            root.set_path(&format!("/{suffix}"));
        } else {
            root.set_path(&format!("/.well-known/oauth-protected-resource/{suffix}"));
        }
        candidates.push(root.clone());
    }
    root.set_path("/.well-known/oauth-protected-resource");
    candidates.push(root);

    let mut seen = BTreeSet::new();
    candidates.retain(|url| seen.insert(url.as_str().to_owned()));
    (candidates, advertised)
}

fn timed_out(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.is::<tokio::time::error::Elapsed>()
            || cause
                .downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_timeout)
            || cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
    })
}

async fn request_document(transport: &HttpTransport, url: &Url, retry: bool) -> Result<Fetched> {
    for attempt in 0..if retry { 3 } else { 1 } {
        let deadline =
            retry.then(|| tokio::time::Instant::now() + Duration::from_secs(2 << attempt));
        let mut headers = HeaderMap::new();
        headers.insert("accept", "application/json".parse()?);
        let incoming = HeaderMap::new();
        let request = transport.send(
            Method::GET,
            url.clone(),
            headers,
            Bytes::new(),
            &incoming,
            true,
        );
        let response = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, request)
                .await
                .map_err(anyhow::Error::from)
                .and_then(|result| result),
            None => request.await,
        };
        let mut response = match response {
            Err(error) if retry && attempt < 2 && timed_out(&error) => continue,
            result => result?,
        };
        let read = async {
            let status = response.status.as_u16();
            let headers = response.headers.clone();
            let mut body = BytesMut::new();
            while let Some(chunk) = response.body.next().await {
                let chunk = chunk?;
                let remaining = (METADATA_LIMIT + 1).saturating_sub(body.len());
                body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                if body.len() > METADATA_LIMIT {
                    break;
                }
            }
            let too_large = body.len() > METADATA_LIMIT;
            Ok(Fetched {
                status,
                headers,
                body: body.freeze(),
                too_large,
            })
        };
        return match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, read).await?,
            None => read.await,
        };
    }
    unreachable!()
}

pub(crate) async fn discover(transport: &HttpTransport) -> Result<Reply> {
    let (candidates, advertised) = discovery_candidates(transport).await;
    let resource = fetch_resource(transport, candidates, advertised).await?;
    if transport.harpoon.is_some() {
        let group = auth_group(&resource.url);
        let resource_url = resource
            .value
            .get("resource")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let issuer = resource
            .value
            .pointer("/authorization_servers/0")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut records = Vec::new();
        if let Some(url) = resource_url {
            records.push(Record::new(url, "prmd-resource", "PRMD resource"));
        }
        if let Some(url) = issuer.clone() {
            records.push(
                Record::new(url, "prmd-auth-server", "PRMD authorization server").group(&group),
            );
        }
        records.push(Record::new(
            resource.url.as_str(),
            "prmd-source",
            "PRMD source URL",
        ));
        if let Some(issuer_url) = issuer.as_deref().and_then(http_url) {
            match fetch_authorization(transport, &issuer_url).await {
                Ok(metadata) => {
                    records.push(
                        Record::new(
                            metadata.url.as_str(),
                            "auth-server-metadata",
                            "Auth server metadata URL",
                        )
                        .group(&group),
                    );
                    for (key, role, description) in [
                        ("issuer", "issuer", "Auth server issuer"),
                        (
                            "token_endpoint",
                            "token-endpoint",
                            "Auth server token endpoint",
                        ),
                        ("jwks_uri", "jwks-uri", "Auth server JWKS URI"),
                        (
                            "introspection_endpoint",
                            "introspection-endpoint",
                            "Auth server introspection endpoint",
                        ),
                        (
                            "registration_endpoint",
                            "registration-endpoint",
                            "Auth server registration endpoint",
                        ),
                        (
                            "revocation_endpoint",
                            "revocation-endpoint",
                            "Auth server revocation endpoint",
                        ),
                    ] {
                        if let Some(url) = metadata.value.get(key).and_then(Value::as_str) {
                            records.push(Record::new(url, role, description).group(&group));
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(channel = %transport.channel, %error, "OAuth authorization server discovery failed")
                }
            }
        }
        let trusted_origins: BTreeSet<_> = records
            .iter()
            .filter(|record| matches!(record.role, "prmd-resource" | "prmd-source"))
            .filter_map(|record| http_url(&record.raw))
            .filter(|url| url.origin() == transport.url.origin())
            .map(|url| url.origin().ascii_serialization())
            .collect();
        for record in records {
            if let Err(error) = register(transport, record, &trusted_origins) {
                tracing::warn!(channel = %transport.channel, %error, "Harpoon OAuth target registration skipped");
            }
        }
    }
    Ok(Reply {
        message: Some(to_raw_value(&resource.value)?),
        headers: protocol::wire_headers(&resource.headers, true),
        status: resource.status,
        kind: "oauth_discovery_response",
    })
}

fn register(
    transport: &HttpTransport,
    record: Record,
    trusted_origins: &BTreeSet<String>,
) -> Result<()> {
    let registry = transport
        .harpoon
        .as_ref()
        .context("Harpoon registry is unavailable")?;
    let Some(url) = http_url(&record.raw) else {
        return Ok(());
    };
    let origin = url.origin().ascii_serialization();
    let trusted = trusted_origins.contains(&origin);
    if origin != transport.url.origin().ascii_serialization() && !trusted {
        return Ok(());
    }
    if !trusted && !registry.private(&url) {
        return Ok(());
    }
    let mut tags = role_tags(record.role);
    if let Some(group) = record.group {
        tags.push(format!("group={group}"));
    }
    let unix_socket = (url.origin() == transport.url.origin())
        .then(|| transport.unix_socket.clone())
        .flatten();
    let client = registry.client(&url, unix_socket.as_deref())?;
    registry.insert(Target {
        info: TargetInfo {
            label: registry.label(&format!("oauth-{}-{}", record.role, record.index))?,
            description: record.description.into(),
            category: "oauth".into(),
            source: "oauth".into(),
            tags,
            allowed_methods: vec!["GET".into(), "POST".into(), "PUT".into()],
            template_version: None,
            parameters_schema: None,
            invocation: None,
        },
        url,
        original_url: record.raw,
        client,
        unix_socket,
        template: None,
    })
}

async fn fetch_resource(
    transport: &HttpTransport,
    candidates: Vec<Url>,
    advertised: bool,
) -> Result<Document> {
    let count = candidates.len();
    for retry in [false, true] {
        let mut missing = count > 0 && !advertised;
        let mut timeouts = count > 0;
        let mut failure = anyhow::anyhow!("OAuth discovery has no metadata candidates");
        for (index, url) in candidates.iter().enumerate() {
            let fetched = match request_document(transport, url, retry).await {
                Ok(fetched) => fetched,
                Err(error) => {
                    missing = false;
                    timeouts &= timed_out(&error);
                    failure = error.context(format!("OAuth discovery GET {url}"));
                    continue;
                }
            };
            missing &= fetched.status == 404;
            timeouts = false;
            let next = matches!(fetched.status, 404 | 500..=599) && index + 1 < count;
            let result = (|| {
                anyhow::ensure!(
                    !fetched.too_large,
                    "OAuth discovery response body from {url} exceeds {METADATA_LIMIT} bytes"
                );
                anyhow::ensure!(
                    !fetched.body.is_empty(),
                    "OAuth discovery empty body from {url} (status {})",
                    fetched.status
                );
                anyhow::ensure!(
                    !next,
                    "OAuth discovery status {} from {url}",
                    fetched.status
                );
                let value: Value = serde_json::from_slice(&fetched.body)
                    .context("OAuth discovery invalid metadata")?;
                anyhow::ensure!(
                    value
                        .get("resource")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty()),
                    "protected resource metadata is missing resource"
                );
                if let Some(issuer) = value
                    .pointer("/authorization_servers/0")
                    .and_then(Value::as_str)
                {
                    issuer.parse::<http::Uri>().context(
                        "protected resource metadata has an invalid authorization server",
                    )?;
                }
                Ok::<_, anyhow::Error>(Document {
                    url: url.clone(),
                    value,
                    headers: fetched.headers,
                    status: fetched.status,
                })
            })();
            match result {
                Ok(document) => return Ok(document),
                Err(error) => {
                    failure = error;
                    if !next {
                        break;
                    }
                }
            }
        }
        if retry || !timeouts {
            return Err(DiscoveryError {
                optional: missing,
                retry: timeouts,
                error: failure,
            }
            .into());
        }
    }
    unreachable!()
}

fn authorization_candidates(issuer: &Url) -> Result<Vec<Url>> {
    let path = issuer.path().trim_matches('/');
    let mut candidates = Vec::new();
    for document in ["oauth-authorization-server", "openid-configuration"] {
        if path.is_empty() {
            candidates.push(issuer.join(&format!("/.well-known/{document}"))?);
        } else {
            candidates.push(issuer.join(&format!("/{path}/.well-known/{document}"))?);
            candidates.push(issuer.join(&format!("/.well-known/{document}/{path}"))?);
        }
    }
    let mut seen = BTreeSet::new();
    candidates.retain(|url| seen.insert(url.as_str().to_owned()));
    Ok(candidates)
}

async fn fetch_authorization(transport: &HttpTransport, issuer: &Url) -> Result<Document> {
    let candidates = authorization_candidates(issuer)?;
    for retry in [false, true] {
        let mut fallback = None;
        let mut failure = None;
        let mut timeouts = !candidates.is_empty();
        for url in &candidates {
            let fetched = match request_document(transport, url, retry).await {
                Ok(fetched) => fetched,
                Err(error) => {
                    timeouts &= timed_out(&error);
                    failure =
                        Some(error.context(format!("OAuth authorization metadata GET {url}")));
                    continue;
                }
            };
            timeouts = false;
            let result = (|| {
                anyhow::ensure!(
                    fetched.status == 200,
                    "OAuth authorization metadata returned HTTP {}",
                    fetched.status
                );
                anyhow::ensure!(
                    !fetched.too_large,
                    "OAuth authorization metadata exceeds {METADATA_LIMIT} bytes"
                );
                let content_type = fetched
                    .headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default();
                anyhow::ensure!(
                    content_type
                        .parse::<mime::Mime>()
                        .is_ok_and(|media_type| media_type.essence_str() == "application/json"),
                    "OAuth authorization metadata has bad content type {content_type:?}"
                );
                let value: Value = serde_json::from_slice(&fetched.body)
                    .context("OAuth authorization metadata is not JSON")?;
                anyhow::ensure!(
                    value
                        .get("issuer")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty()),
                    "OAuth authorization metadata has no issuer"
                );
                Ok::<_, anyhow::Error>(Document {
                    url: url.clone(),
                    value,
                    headers: fetched.headers,
                    status: fetched.status,
                })
            })();
            match result {
                Ok(document) => {
                    if document.value["issuer"] == issuer.as_str() {
                        return Ok(document);
                    }
                    if fallback.is_none() {
                        fallback = Some(document);
                    }
                }
                Err(error) => failure = Some(error),
            }
        }
        if fallback.is_some() || retry || !timeouts {
            return fallback.ok_or_else(|| {
                failure.unwrap_or_else(|| {
                    anyhow::anyhow!("OAuth authorization metadata was not found")
                })
            });
        }
    }
    unreachable!()
}

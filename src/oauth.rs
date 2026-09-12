use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http::{HeaderMap, Method};
use regex::Regex;
use serde_json::{Value, value::to_raw_value};
use url::Url;

use crate::{
    harpoon::{Target, TargetInfo},
    protocol::{self, Reply},
    transport::HttpTransport,
};

struct Document {
    url: Url,
    value: Value,
    headers: HeaderMap,
    status: u16,
}

pub(crate) async fn discover(transport: &HttpTransport) -> Result<Reply> {
    let challenge = transport
        .challenge
        .read()
        .expect("authentication lock poisoned")
        .clone();
    let challenge = match challenge {
        Some(headers) => headers,
        None => {
            transport
                .client
                .send(
                    Method::POST,
                    &transport.url,
                    transport.discovery_headers.clone(),
                    Bytes::new(),
                )
                .await?
                .headers
        }
    };
    let mut candidates = Vec::new();
    static PARAMETER: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)(?:^|[\s,])resource_metadata\s*=\s*(?:"([^"]*)"|([^,\s]+))"#)
            .expect("authentication parameter pattern")
    });
    for header in challenge.get_all("www-authenticate") {
        if let Ok(value) = header.to_str() {
            for capture in PARAMETER.captures_iter(value) {
                let raw = capture
                    .get(1)
                    .or_else(|| capture.get(2))
                    .expect("metadata parameter capture")
                    .as_str();
                let url = transport.url.join(raw)?;
                if url.origin() == transport.url.origin() {
                    candidates.push(url);
                }
            }
        }
    }
    let path = transport.url.path().trim_matches('/');
    if !path.is_empty() {
        candidates.push(
            transport
                .url
                .join(&format!("/.well-known/oauth-protected-resource/{path}"))?,
        );
    }
    candidates.push(
        transport
            .url
            .join("/.well-known/oauth-protected-resource")?,
    );
    let Some(mut resource) = fetch(transport, candidates, "resource").await? else {
        return Ok(Reply::ack(404, "oauth_discovery_response"));
    };
    if let Some(registry) = &transport.harpoon {
        register(
            transport,
            &resource.url,
            resource.url.as_str(),
            "protected-resource-metadata",
            &["protected-resource-metadata", "source"],
        )?;
        if let Some(url) = resource.value.get("resource").and_then(Value::as_str) {
            register(
                transport,
                &transport.url,
                url,
                "resource",
                &["protected-resource-metadata", "resource"],
            )?;
        }
        if let Some(issuer) = resource
            .value
            .pointer("/authorization_servers/0")
            .and_then(Value::as_str)
        {
            let issuer_url =
                Url::parse(issuer).context("OAuth authorization server URL is invalid")?;
            register(
                transport,
                &issuer_url,
                issuer,
                "authorization-server",
                &["protected-resource-metadata", "authorization-server"],
            )?;
            let mut urls = Vec::new();
            let path = issuer_url.path().trim_matches('/');
            for document in ["oauth-authorization-server", "openid-configuration"] {
                if !path.is_empty() {
                    urls.push(issuer_url.join(&format!("/{path}/.well-known/{document}"))?);
                    urls.push(issuer_url.join(&format!("/.well-known/{document}/{path}"))?);
                } else {
                    urls.push(issuer_url.join(&format!("/.well-known/{document}"))?);
                }
            }
            match fetch(transport, urls, "issuer").await {
                Ok(Some(metadata)) => {
                    register(
                        transport,
                        &issuer_url,
                        metadata.url.as_str(),
                        "auth-server-metadata",
                        &["auth-server-metadata", "metadata"],
                    )?;
                    for key in [
                        "issuer",
                        "token_endpoint",
                        "jwks_uri",
                        "introspection_endpoint",
                        "registration_endpoint",
                        "revocation_endpoint",
                    ] {
                        if let Some(url) = metadata.value.get(key).and_then(Value::as_str) {
                            let role = key.replace('_', "-");
                            register(
                                transport,
                                &issuer_url,
                                url,
                                &role,
                                &["auth-server-metadata", &role],
                            )?;
                        }
                    }
                }
                Ok(None) => {
                    tracing::warn!(channel = %transport.channel, "OAuth authorization server metadata was not found")
                }
                Err(error) => {
                    tracing::warn!(channel = %transport.channel, %error, "OAuth authorization server discovery failed")
                }
            }
        }
        registry.rewrite(&mut resource.value);
    }
    let mut reply = Reply {
        message: Some(to_raw_value(&resource.value)?),
        headers: protocol::wire_headers(&resource.headers, true),
        status: resource.status,
        kind: "oauth_discovery_response",
    };
    if let Some(registry) = &transport.harpoon {
        registry.rewrite_headers(&mut reply.headers);
    }
    Ok(reply)
}

fn register(
    transport: &HttpTransport,
    origin: &Url,
    raw: &str,
    role: &str,
    tags: &[&str],
) -> Result<()> {
    let registry = transport
        .harpoon
        .as_ref()
        .context("Harpoon registry is unavailable")?;
    let url = Url::parse(raw)?;
    if url.origin() != transport.url.origin() && !registry.private(&url) {
        return Ok(());
    }
    if url.origin() != origin.origin() && url.origin() != transport.url.origin() {
        return Ok(());
    }
    let mut tags: Vec<String> = tags.iter().map(|tag| (*tag).into()).collect();
    tags.push(format!("group=auth-server-{}", transport.channel));
    registry.insert(Target {
        info: TargetInfo {
            label: format!("oauth-{}-{role}", transport.channel),
            description: format!("OAuth {role}"),
            category: "oauth".into(),
            source: "oauth".into(),
            tags,
            allowed_methods: vec!["GET".into(), "POST".into(), "PUT".into()],
            template_version: None,
            parameters_schema: None,
            invocation: None,
        },
        url,
        original_url: raw.into(),
        client: transport.client.clone(),
        template: None,
    })
}

async fn fetch(
    transport: &HttpTransport,
    candidates: Vec<Url>,
    required: &str,
) -> Result<Option<Document>> {
    let mut visited = std::collections::BTreeSet::new();
    let mut failure = None;
    for url in candidates {
        if !visited.insert(url.to_string()) {
            continue;
        }
        let result = async {
            let mut current = url.clone();
            for hop in 0..=10 {
                let mut headers = if current.origin() == transport.url.origin() {
                    transport.discovery_headers.clone()
                } else {
                    HeaderMap::new()
                };
                headers.insert("accept", "application/json".parse()?);
                let response = transport
                    .client
                    .send(Method::GET, &current, headers, Bytes::new())
                    .await?;
                if response.status.is_redirection()
                    && let Some(location) = response.headers.get("location")
                {
                    anyhow::ensure!(hop < 10, "OAuth discovery exceeded its redirect limit");
                    let next = current.join(location.to_str()?)?;
                    anyhow::ensure!(
                        next.origin() == url.origin(),
                        "OAuth metadata redirected to a different origin"
                    );
                    current = next;
                    continue;
                }
                if matches!(response.status.as_u16(), 404 | 405) {
                    return Ok(None);
                }
                anyhow::ensure!(
                    response.status.is_success(),
                    "OAuth metadata returned HTTP {}",
                    response.status
                );
                let headers = response.headers.clone();
                let status = response.status.as_u16();
                let value: Value = serde_json::from_slice(&response.bytes().await?)
                    .context("OAuth metadata is not JSON")?;
                anyhow::ensure!(
                    value
                        .get(required)
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty()),
                    "OAuth metadata has no {required}"
                );
                return Ok::<_, anyhow::Error>(Some(Document {
                    url: current,
                    value,
                    headers,
                    status,
                }));
            }
            bail!("OAuth discovery could not resolve a document")
        }
        .await;
        match result {
            Ok(Some(document)) => return Ok(Some(document)),
            Ok(None) => {}
            Err(error) => {
                failure = Some(error);
            }
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

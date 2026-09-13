use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use http::{HeaderMap, HeaderName, HeaderValue};

use crate::protocol;

pub(crate) const USER_AGENT: &str = concat!("otunnel/", env!("CARGO_PKG_VERSION"));

pub(crate) fn blocked(name: &str) -> bool {
    matches!(
        name,
        "" | "accept-encoding"
            | "cf-connecting-ip"
            | "connection"
            | "content-length"
            | "cookie"
            | "forwarded"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "true-client-ip"
            | "upgrade"
            | "user-agent"
            | "via"
            | "x-client-ip"
            | "x-cluster-client-ip"
            | "x-custom-cf-witness-actor"
            | "x-custom-cf-witness-authorization"
            | "x-envoy-external-address"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-port"
            | "x-forwarded-proto"
            | "x-http-method"
            | "x-http-method-override"
            | "x-method-override"
            | "x-openai-actor-authorization"
            | "x-openai-authorization"
            | "x-openai-authorization-error"
            | "x-openai-internal-caller"
            | "x-openai-skip-auth"
            | "x-original-forwarded-for"
            | "x-real-ip"
            | "x-tunnel-traffic-source"
    )
}

pub(crate) fn outbound(values: &BTreeMap<String, String>) -> Result<HeaderMap> {
    let nominated: BTreeSet<_> = values
        .iter()
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name = name.trim().to_ascii_lowercase();
        if blocked(&name) || nominated.contains(&name) {
            continue;
        }
        headers.insert(HeaderName::try_from(name)?, HeaderValue::try_from(value)?);
    }
    headers.insert("user-agent", HeaderValue::from_static(USER_AGENT));
    Ok(headers)
}

pub(crate) fn template_name(name: &str) -> Result<HeaderName> {
    let normalized = name.to_ascii_lowercase();
    anyhow::ensure!(
        name.len() <= 128 && !blocked(&normalized),
        "invalid or forbidden template header name"
    );
    anyhow::ensure!(
        ![
            "x-forwarded-",
            "x-envoy-",
            "x-original-",
            "x-rewrite-",
            "x-auth-request-"
        ]
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
            && !matches!(
                normalized.as_str(),
                "remote-user" | "x-remote-user" | "x-authenticated-user"
            ),
        "routing and identity headers are forbidden for templates"
    );
    Ok(HeaderName::try_from(name)?)
}

pub(crate) fn credential(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    if normalized.split(['-', '_', '.']).any(|word| {
        matches!(
            word,
            "authorization" | "cookie" | "key" | "secret" | "token" | "password"
        )
    }) {
        return true;
    }
    let compact = normalized.replace(['-', '_', '.'], "");
    [
        "apikey",
        "apitoken",
        "apisecret",
        "authtoken",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "sessiontoken",
        "bearertoken",
        "clientsecret",
        "clientpassword",
        "clienttoken",
        "clientkey",
        "accesskey",
        "secretkey",
        "sessionkey",
        "privatekey",
        "authkey",
        "authsecret",
        "signingkey",
        "authorization",
        "authentication",
        "credential",
    ]
    .iter()
    .any(|word| compact.contains(word))
}

pub(crate) fn template_value(value: &str) -> Result<HeaderValue> {
    anyhow::ensure!(
        value.len() <= 8192 && value.chars().all(|c| c >= ' ' && c != '\u{7f}'),
        "invalid template header value"
    );
    Ok(HeaderValue::try_from(value)?)
}

pub(crate) fn template_size(headers: &HeaderMap) -> Result<()> {
    anyhow::ensure!(headers.keys_len() <= 33, "too many template headers");
    let size = headers
        .keys()
        .map(|name| {
            name.as_str().len()
                + headers
                    .get_all(name)
                    .iter()
                    .map(|value| value.len())
                    .sum::<usize>()
        })
        .sum::<usize>()
        + if headers.contains_key("user-agent") {
            0
        } else {
            10 + USER_AGENT.len()
        };
    anyhow::ensure!(size <= 8192, "template headers exceed size limit");
    Ok(())
}

pub(crate) fn canonical(name: &str) -> String {
    name.split('-')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

pub(crate) fn wire(headers: &HeaderMap) -> protocol::Headers {
    protocol::wire_headers(headers, false)
        .into_iter()
        .map(|(name, values)| (canonical(&name), values))
        .collect()
}

use std::{env, net::IpAddr};

use anyhow::{Context, Result};
use ipnet::IpNet;
use url::Url;

pub(crate) struct Proxy {
    fixed: Option<Url>,
    http: Option<Url>,
    https: Option<Url>,
    excluded: Vec<Exclusion>,
    cgi: bool,
}

enum Exclusion {
    All,
    Network(IpNet),
    Host {
        name: String,
        port: Option<u16>,
        subdomains: bool,
    },
}

impl Proxy {
    pub fn new(explicit: Option<&str>) -> Result<Self> {
        let fixed = explicit
            .map(|raw| {
                let raw = raw.trim();
                let value = match raw.strip_prefix("env:") {
                    Some(name) => env::var(name.trim()).with_context(|| {
                        format!("read proxy environment variable {}", name.trim())
                    })?,
                    None => raw.to_owned(),
                };
                let url =
                    Url::parse(value.trim()).context("proxy URL must include scheme and host")?;
                anyhow::ensure!(
                    url.host_str().is_some(),
                    "proxy URL must include scheme and host"
                );
                anyhow::ensure!(
                    matches!(url.scheme(), "http" | "https"),
                    "proxy URL scheme must be http or https, got {:?}",
                    url.scheme()
                );
                Ok::<_, anyhow::Error>(url)
            })
            .transpose()?;
        let variable = |upper: &str, lower: &str| {
            env::var(upper)
                .ok()
                .filter(|value| !value.is_empty())
                .or_else(|| env::var(lower).ok().filter(|value| !value.is_empty()))
        };
        let parse = |raw: String| {
            let url = Url::parse(&raw)
                .ok()
                .filter(|url| url.host_str().is_some())
                .or_else(|| Url::parse(&format!("http://{raw}")).ok())?;
            url.host_str().is_some().then_some(url)
        };
        let excluded = variable("NO_PROXY", "no_proxy")
            .unwrap_or_default()
            .split(',')
            .filter_map(Exclusion::parse)
            .collect();
        Ok(Self {
            fixed,
            http: variable("HTTP_PROXY", "http_proxy").and_then(parse),
            https: variable("HTTPS_PROXY", "https_proxy").and_then(parse),
            excluded,
            cgi: env::var("REQUEST_METHOD").is_ok_and(|value| !value.is_empty()),
        })
    }

    pub fn select(&self, target: &Url) -> Result<Option<&Url>> {
        if self.fixed.is_some() {
            return Ok(self.fixed.as_ref());
        }
        let proxy = match target.scheme() {
            "http" => self.http.as_ref(),
            "https" => self.https.as_ref(),
            _ => None,
        };
        if proxy.is_none() {
            return Ok(None);
        }
        anyhow::ensure!(
            !(self.cgi && target.scheme() == "http"),
            "refusing to use HTTP_PROXY value in CGI environment; see golang.org/s/cgihttpproxy"
        );
        let host = target
            .host_str()
            .unwrap_or_default()
            .trim_matches(['[', ']']);
        let address = host.parse::<IpAddr>().ok().map(|address| match address {
            IpAddr::V6(value) => value.to_ipv4_mapped().map_or(address, IpAddr::V4),
            _ => address,
        });
        if host == "localhost"
            || address.is_some_and(|address| address.is_loopback())
            || self
                .excluded
                .iter()
                .any(|rule| rule.matches(host, address, target.port_or_known_default()))
        {
            return Ok(None);
        }
        Ok(proxy)
    }
}

impl Exclusion {
    fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim().to_ascii_lowercase();
        if raw.is_empty() {
            return None;
        }
        if raw == "*" {
            return Some(Self::All);
        }
        if let Ok(network) = raw.parse::<IpNet>() {
            return Some(Self::Network(network));
        }
        let (name, port) = if raw.starts_with('[') {
            match raw.split_once("]:") {
                Some((name, port)) => (name.trim_start_matches('['), Some(port.parse().ok()?)),
                None => (raw.trim_matches(['[', ']']), None),
            }
        } else if raw.matches(':').count() == 1 {
            let (name, port) = raw.split_once(':')?;
            (name, Some(port.parse().ok()?))
        } else {
            (&*raw, None)
        };
        let name = if name.starts_with("*.") {
            &name[1..]
        } else {
            name
        };
        let subdomains = name.starts_with('.');
        Some(Self::Host {
            name: name.trim_start_matches('.').into(),
            port,
            subdomains,
        })
    }

    fn matches(&self, host: &str, address: Option<IpAddr>, port: Option<u16>) -> bool {
        match self {
            Self::All => true,
            Self::Network(network) => address.is_some_and(|address| network.contains(&address)),
            Self::Host {
                name,
                port: expected,
                subdomains,
            } => {
                if expected.is_some() && *expected != port {
                    return false;
                }
                if let Ok(ip) = name.parse::<IpAddr>() {
                    return address == Some(ip);
                }
                if address.is_some() {
                    return false;
                }
                host.ends_with(&format!(".{name}")) || !subdomains && host == name
            }
        }
    }
}

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use http::HeaderMap;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::{config, harpoon::headers};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Definition {
    pub version: u8,
    pub origin: String,
    pub method: String,
    pub path_template: String,
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    pub parameters: BTreeMap<String, Parameter>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub allowed_headers: Vec<String>,
    #[serde(default)]
    pub follow_redirects: bool,
}

impl Definition {
    /// Validate a profile without reading its credential references.
    pub fn validate(&self) -> Result<()> {
        let mut definition = self.clone();
        for value in definition.headers.values_mut() {
            if value.to_ascii_lowercase().starts_with("env:")
                || value.to_ascii_lowercase().starts_with("file:")
            {
                *value = "x".into();
            }
        }
        Template::new(&definition).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Parameter {
    #[serde(rename = "type")]
    pub kind: String,
    pub required: bool,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub examples: Vec<String>,
    #[serde(default)]
    pub pattern: String,
    #[serde(default, rename = "enum")]
    pub values: Vec<String>,
    #[serde(default)]
    pub min_length: usize,
    pub max_length: usize,
    #[serde(default)]
    pub reserved_values: Vec<String>,
}

struct Constraint {
    definition: Parameter,
    pattern: Option<Regex>,
}
impl Constraint {
    fn new(mut definition: Parameter) -> Result<Self> {
        anyhow::ensure!(
            definition.kind == "string" && definition.required,
            "only required string parameters are supported"
        );
        anyhow::ensure!(
            definition.description.len() <= 1024,
            "parameter description exceeds 1024 bytes"
        );
        anyhow::ensure!(
            definition.examples.len() <= 8,
            "parameter examples exceed size limit"
        );
        definition.min_length = definition.min_length.max(1);
        anyhow::ensure!(
            definition.min_length <= definition.max_length && definition.max_length <= 256,
            "length bounds must be within 1 to 256"
        );
        anyhow::ensure!(
            !definition.pattern.is_empty() || !definition.values.is_empty(),
            "a pattern or enum is required"
        );
        anyhow::ensure!(
            definition.pattern.len() <= 512
                && definition.values.len() <= 64
                && definition.reserved_values.len() <= 64,
            "parameter constraints exceed size limits"
        );
        let pattern = if definition.pattern.is_empty() {
            None
        } else {
            validate_pattern(&definition.pattern)?;
            Some(
                Regex::new(&format!(r"\A(?:{})\z", definition.pattern))
                    .context("invalid parameter pattern")?,
            )
        };
        let mut seen = BTreeSet::new();
        for value in &definition.reserved_values {
            anyhow::ensure!(
                value.len() <= 256 && identifier(value),
                "invalid reserved identifier"
            );
            anyhow::ensure!(
                seen.insert(value.to_ascii_lowercase()),
                "duplicate reserved identifier"
            );
        }
        let constraint = Self {
            definition,
            pattern,
        };
        for (values, kind) in [
            (&constraint.definition.values, "enum"),
            (&constraint.definition.examples, "example"),
        ] {
            let mut seen = BTreeSet::new();
            for value in values {
                constraint
                    .validate(value)
                    .with_context(|| format!("{kind} value violates parameter constraints"))?;
                anyhow::ensure!(seen.insert(value), "duplicate {kind} identifier");
            }
        }
        Ok(constraint)
    }

    fn validate(&self, value: &str) -> Result<()> {
        let definition = &self.definition;
        anyhow::ensure!(
            (definition.min_length..=definition.max_length).contains(&value.len()),
            "identifier length is outside its bounds"
        );
        anyhow::ensure!(
            identifier(value),
            "identifier contains forbidden characters or path segments"
        );
        anyhow::ensure!(
            !definition
                .reserved_values
                .iter()
                .any(|reserved| reserved.eq_ignore_ascii_case(value)),
            "identifier is reserved"
        );
        anyhow::ensure!(
            self.pattern
                .as_ref()
                .is_none_or(|pattern| pattern.is_match(value)),
            "identifier does not match its pattern"
        );
        anyhow::ensure!(
            definition.values.is_empty() || definition.values.iter().any(|entry| entry == value),
            "identifier is outside its enum"
        );
        Ok(())
    }
}

fn identifier(value: &str) -> bool {
    !matches!(value, "" | "." | "..")
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.~-".contains(&c))
}

fn text(value: &str) -> bool {
    value.chars().all(|c| c >= ' ' && c != '\u{7f}')
}

fn parameter_name(value: &str) -> bool {
    value.len() <= 64
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn validate_pattern(pattern: &str) -> Result<()> {
    anyhow::ensure!(
        pattern.bytes().all(|c| (0x20..=0x7e).contains(&c)),
        "parameter pattern must contain only printable ASCII"
    );
    let mut bytes = pattern.bytes().enumerate();
    while let Some((index, byte)) = bytes.next() {
        if byte == b'\\' {
            anyhow::ensure!(
                bytes
                    .next()
                    .is_some_and(|(_, c)| br"dDsSwW\.^$|?*+()[]{}/-".contains(&c)),
                "parameter pattern uses an unsupported escape"
            );
            continue;
        }
        let rest = &pattern[index..];
        anyhow::ensure!(
            !rest.starts_with("(?") || rest.starts_with("(?:"),
            "parameter pattern uses unsupported group syntax"
        );
        anyhow::ensure!(
            !rest.starts_with("[[:"),
            "parameter pattern cannot use POSIX character classes"
        );
        anyhow::ensure!(
            !rest.starts_with("[]") && !rest.starts_with("[^]"),
            "parameter pattern must escape an initial closing bracket in a character class"
        );
    }
    Ok(())
}

enum Part {
    Literal(String),
    Parameter(String),
}
impl Part {
    fn parse(
        value: &str,
        parameters: &BTreeMap<String, Constraint>,
        used: &mut BTreeSet<String>,
    ) -> Result<Self> {
        if !value.contains(['{', '}']) {
            return Ok(Self::Literal(value.into()));
        }
        let name = value
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
            .context("placeholder must occupy an entire path segment or query value")?;
        anyhow::ensure!(parameter_name(name), "invalid template placeholder");
        anyhow::ensure!(
            parameters.contains_key(name),
            "template uses an undeclared parameter"
        );
        used.insert(name.into());
        Ok(Self::Parameter(name.into()))
    }

    fn value<'a>(&'a self, parameters: &'a BTreeMap<String, String>) -> &'a str {
        match self {
            Self::Literal(value) => value,
            Self::Parameter(name) => &parameters[name],
        }
    }
}

pub(crate) struct Template {
    origin: Url,
    path: Vec<Part>,
    query: BTreeMap<String, Part>,
    parameters: BTreeMap<String, Constraint>,
    headers: HeaderMap,
    allowed_headers: BTreeSet<String>,
}

impl Template {
    pub fn new(definition: &Definition) -> Result<Self> {
        anyhow::ensure!(definition.version == 1, "template version must be 1");
        anyhow::ensure!(definition.method == "GET", "template method must be GET");
        anyhow::ensure!(
            !definition.follow_redirects,
            "template redirects must be disabled"
        );
        anyhow::ensure!(
            !definition.origin.is_empty()
                && definition.origin.len() <= 4096
                && !definition.origin.contains(['{', '}', '\\', '%', '#'])
                && text(&definition.origin),
            "invalid template HTTPS origin"
        );
        let origin = Url::parse(&definition.origin)?;
        anyhow::ensure!(
            origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.username().is_empty()
                && origin.password().is_none()
                && !definition.origin.trim_end_matches('/').ends_with(':')
                && origin.port() != Some(0),
            "template origin must contain only an HTTPS scheme, host, and optional port"
        );
        anyhow::ensure!(
            (1..=16).contains(&definition.parameters.len()),
            "template must declare 1 to 16 parameters"
        );
        let mut parameters = BTreeMap::new();
        for (name, definition) in &definition.parameters {
            anyhow::ensure!(parameter_name(name), "invalid template parameter name");
            parameters.insert(
                name.clone(),
                Constraint::new(definition.clone()).with_context(|| format!("parameter {name}"))?,
            );
        }
        anyhow::ensure!(
            definition.path_template.len() <= 4096,
            "template path exceeds size limit"
        );
        let mut used = BTreeSet::new();
        let mut path = Vec::new();
        for value in definition
            .path_template
            .strip_prefix('/')
            .context("template path must be absolute and bounded")?
            .split('/')
        {
            let part = Part::parse(value, &parameters, &mut used)?;
            if matches!(part, Part::Literal(_)) {
                anyhow::ensure!(
                    value.is_empty() && definition.path_template == "/" || identifier(value),
                    "template path contains an invalid literal segment"
                );
            }
            path.push(part);
        }
        anyhow::ensure!(
            definition.query.len() <= 32,
            "template has too many query fields"
        );
        let mut query = BTreeMap::new();
        for (key, value) in &definition.query {
            anyhow::ensure!(
                key.len() <= 64 && identifier(key),
                "invalid template query field name"
            );
            let part = Part::parse(value, &parameters, &mut used)?;
            if matches!(part, Part::Literal(_)) {
                anyhow::ensure!(
                    value.len() <= 256 && text(value),
                    "invalid template query literal"
                );
            }
            query.insert(key.clone(), part);
        }
        anyhow::ensure!(
            used.len() == parameters.len(),
            "template contains unused parameters"
        );
        anyhow::ensure!(
            definition.headers.len() + definition.allowed_headers.len() <= 32,
            "template has too many headers"
        );
        let mut headers = HeaderMap::new();
        for (name, value) in &definition.headers {
            let name = headers::template_name(name)?;
            anyhow::ensure!(
                !headers.contains_key(&name),
                "duplicate template header name"
            );
            headers.insert(name, headers::template_value(&config::resolve(value)?)?);
        }
        let mut allowed_headers = BTreeSet::new();
        for name in &definition.allowed_headers {
            let name = headers::template_name(name)?.to_string();
            anyhow::ensure!(
                !headers::credential(&name),
                "template authentication headers must be fixed by the operator"
            );
            anyhow::ensure!(
                !headers.contains_key(&name),
                "template caller header conflicts with a fixed header"
            );
            anyhow::ensure!(
                allowed_headers.insert(name),
                "duplicate template caller header name"
            );
        }
        headers::template_size(&headers)?;
        let template = Self {
            origin,
            path,
            query,
            parameters,
            headers,
            allowed_headers,
        };
        let longest = template
            .parameters
            .iter()
            .map(|(name, parameter)| (name.clone(), "x".repeat(parameter.definition.max_length)))
            .collect();
        anyhow::ensure!(
            template.url(&longest).as_str().len() <= 4096,
            "template maximum rendered URL exceeds size limit"
        );
        Ok(template)
    }

    pub fn origin(&self) -> &Url {
        &self.origin
    }

    fn url(&self, values: &BTreeMap<String, String>) -> Url {
        const QUERY: &percent_encoding::AsciiSet = &NON_ALPHANUMERIC
            .remove(b'-')
            .remove(b'.')
            .remove(b'_')
            .remove(b'~');
        let encode = |value: &str| {
            utf8_percent_encode(value, QUERY)
                .to_string()
                .replace("%20", "+")
        };
        let mut url = self.origin.clone();
        {
            let mut path = url.path_segments_mut().expect("HTTPS origin");
            path.clear();
            for part in &self.path {
                path.push(part.value(values));
            }
        }
        if !self.query.is_empty() {
            let query = self
                .query
                .iter()
                .map(|(key, part)| format!("{}={}", encode(key), encode(part.value(values))))
                .collect::<Vec<_>>()
                .join("&");
            url.set_query(Some(&query));
        }
        url
    }

    pub fn render(
        &self,
        values: &BTreeMap<String, String>,
        caller: HeaderMap,
    ) -> Result<(Url, HeaderMap)> {
        anyhow::ensure!(
            values.len() == self.parameters.len(),
            "template parameter keys must match the declared schema"
        );
        for (name, constraint) in &self.parameters {
            constraint
                .validate(
                    values
                        .get(name)
                        .with_context(|| format!("parameter {name} must be a string"))?,
                )
                .with_context(|| format!("parameter {name}"))?;
        }
        let url = self.url(values);
        anyhow::ensure!(
            url.as_str().len() <= 4096,
            "rendered URL exceeds size limit"
        );
        anyhow::ensure!(caller.keys_len() <= 32, "too many template headers");
        let mut headers = self.headers.clone();
        for name in caller.keys() {
            headers::template_name(name.as_str())?;
            anyhow::ensure!(
                self.allowed_headers.contains(name.as_str()),
                "caller header is not permitted by the target"
            );
            anyhow::ensure!(
                caller.get_all(name).iter().count() == 1,
                "duplicate caller header name"
            );
            headers.insert(
                name.clone(),
                headers::template_value(caller[name].to_str()?)?,
            );
        }
        headers::template_size(&headers)?;
        headers.insert(
            "user-agent",
            http::HeaderValue::from_static(headers::USER_AGENT),
        );
        Ok((url, headers))
    }

    pub fn schema(&self) -> Value {
        let mut properties = serde_json::Map::new();
        for (name, constraint) in &self.parameters {
            let parameter = &constraint.definition;
            let mut schema = json!({"type":"string","minLength":parameter.min_length,"maxLength":parameter.max_length,
                "allOf":[{"not":{"pattern":"[^A-Za-z0-9_.~-]"}},{"not":{"enum":[".",".."]}}]});
            if !parameter.description.is_empty() {
                schema["description"] = json!(parameter.description);
            }
            if !parameter.pattern.is_empty() {
                schema["pattern"] = json!(format!("^(?:{})$", parameter.pattern));
            }
            if !parameter.values.is_empty() {
                schema["enum"] = json!(parameter.values);
            }
            if !parameter.examples.is_empty() {
                schema["examples"] = json!(parameter.examples);
            }
            if !parameter.reserved_values.is_empty() {
                let values = parameter
                    .reserved_values
                    .iter()
                    .map(|value| {
                        value
                            .to_ascii_lowercase()
                            .chars()
                            .map(|c| {
                                if c.is_ascii_lowercase() {
                                    format!("[{c}{}]", c.to_ascii_uppercase())
                                } else {
                                    regex::escape(&c.to_string())
                                }
                            })
                            .collect::<String>()
                    })
                    .collect::<Vec<_>>()
                    .join("|");
                schema["not"] = json!({"pattern":format!("^(?:{values})$")});
            }
            properties.insert(name.clone(), schema);
        }
        json!({"type":"object","properties":properties,"required":self.parameters.keys().collect::<Vec<_>>(),"additionalProperties":false})
    }

    pub fn invocation(&self, label: &str, mut schema: Value) -> Value {
        schema["properties"]["label"]["const"] = json!(label);
        schema["properties"]["parameters"] = self.schema();
        let headers: serde_json::Map<_, _> = self.allowed_headers.iter().map(|name| {
            (headers::canonical(name), json!({"type":"string","maxLength":8192,"not":{"pattern":"[\u{0000}-\u{001f}\u{007f}]"}}))
        }).collect();
        schema["properties"]["headers"] = json!({"type":"object","properties":headers,"additionalProperties":false,"maxProperties":32,"default":{}});
        let mut invocation = json!({"tool_name":"call_target_template","input_schema":schema});
        let example: Option<BTreeMap<_, _>> = self
            .parameters
            .iter()
            .map(|(name, constraint)| {
                let value = constraint
                    .definition
                    .examples
                    .first()
                    .or_else(|| constraint.definition.values.iter().min())?;
                Some((name.clone(), value.clone()))
            })
            .collect();
        if let Some(parameters) = example
            && self.render(&parameters, HeaderMap::new()).is_ok()
        {
            invocation["examples"] = json!([{"label":label,"parameters":parameters}]);
        }
        invocation
    }
}

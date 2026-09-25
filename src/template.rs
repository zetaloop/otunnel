use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{HeaderMap, Method};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{config, harpoon::headers};

mod policy;
mod rules;
pub(crate) use policy::{encode, hex};
pub use rules::{Header, HeaderRule, HeaderValidation};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub version: u8,
    pub origin: String,
    pub method: String,
    #[serde(default)]
    pub body_policy: Option<BodyPolicy>,
    pub path_template: String,
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    pub parameters: BTreeMap<String, Parameter>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(
        default,
        deserialize_with = "rules::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub allowed_headers: Option<Vec<HeaderRule>>,
    #[serde(
        default,
        deserialize_with = "rules::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub header_rules: Option<Vec<HeaderRule>>,
    #[serde(default)]
    pub follow_redirects: bool,
}

impl Definition {
    pub(crate) fn rules(&self) -> Result<&[HeaderRule]> {
        anyhow::ensure!(
            self.allowed_headers.is_none() || self.header_rules.is_none(),
            "header_rules and allowed_headers cannot be combined"
        );
        Ok(self
            .header_rules
            .as_deref()
            .or(self.allowed_headers.as_deref())
            .unwrap_or_default())
    }

    pub(crate) fn rich(&self) -> bool {
        self.header_rules
            .iter()
            .chain(self.allowed_headers.iter())
            .flatten()
            .any(|rule| matches!(rule, HeaderRule::Rule(_)))
    }

    /// Validate a profile without reading its credential references.
    pub fn validate(&self) -> Result<()> {
        let mut definition = self.clone();
        for value in definition.headers.values_mut() {
            if value.trim().starts_with("env:") || value.trim().starts_with("file:") {
                *value = "x".into();
            }
        }
        Template::new(&definition).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BodyPolicy {
    pub content_types: Vec<String>,
    pub max_bytes: usize,
    pub required: Option<bool>,
    pub validation: Option<BodyValidation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BodyValidation {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub json: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pattern: String,
    #[serde(default, rename = "enum", skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}

struct CompiledBodyPolicy {
    definition: BodyPolicy,
    pattern: Option<Regex>,
}

impl CompiledBodyPolicy {
    fn new(method: &str, definition: Option<&BodyPolicy>) -> Result<Option<Self>> {
        if method == "GET" {
            anyhow::ensure!(
                definition.is_none(),
                "template GET cannot configure a body policy"
            );
            return Ok(None);
        }
        let definition = definition.context("template writes require an explicit body policy")?;
        let required = definition
            .required
            .context("template writes require an explicit required setting")?;
        let validation = definition
            .validation
            .clone()
            .context("template writes require explicit body validation")?;
        anyhow::ensure!(
            (1..=100 * 1024).contains(&definition.max_bytes),
            "template body byte limit must be within 1 to 102400"
        );
        anyhow::ensure!(
            (1..=16).contains(&definition.content_types.len()),
            "template body policy must allow 1 to 16 content types"
        );
        anyhow::ensure!(
            validation.json || !validation.pattern.is_empty() || !validation.values.is_empty(),
            "template body policy requires JSON, pattern, or enum validation"
        );
        anyhow::ensure!(
            validation.pattern.len() <= 512 && validation.values.len() <= 64,
            "template body validation exceeds size limits"
        );
        let mut seen = BTreeSet::new();
        for value in &definition.content_types {
            let parsed: mime::Mime = value.parse().context("invalid template content type")?;
            anyhow::ensure!(
                value.len() <= 128
                    && value.contains('/')
                    && !value.contains('*')
                    && parsed.params().next().is_none()
                    && parsed.to_string() == *value,
                "template content types must be canonical media types without parameters or wildcards"
            );
            anyhow::ensure!(
                !(value == "application/json" || value.ends_with("+json")) || validation.json,
                "JSON content types require JSON body validation"
            );
            anyhow::ensure!(
                seen.insert(value.clone()),
                "duplicate template content type"
            );
        }
        let pattern = if validation.pattern.is_empty() {
            None
        } else {
            validate_body_pattern(&validation.pattern)?;
            Some(compile_pattern(&validation.pattern).context("invalid template body pattern")?)
        };
        let result = Self {
            definition: BodyPolicy {
                content_types: definition.content_types.clone(),
                max_bytes: definition.max_bytes,
                required: Some(required),
                validation: Some(validation),
            },
            pattern,
        };
        let validation = result
            .definition
            .validation
            .as_ref()
            .expect("compiled body validation");
        let mut total = 0;
        let mut seen = BTreeSet::new();
        for value in &validation.values {
            total += value.len();
            anyhow::ensure!(
                total <= 100 * 1024
                    && result
                        .validate(Some(value), Some(&result.definition.content_types[0]))
                        .is_ok(),
                "template body enum violates body policy or size limits"
            );
            anyhow::ensure!(seen.insert(value), "duplicate template body enum value");
        }
        Ok(Some(result))
    }

    fn validate(&self, body: Option<&str>, content_type: Option<&str>) -> Result<()> {
        let required = self.definition.required.expect("compiled required setting");
        if body.is_none() && content_type.is_none() && !required {
            return Ok(());
        }
        let body = body.context("template body and content_type must be supplied together")?;
        let content_type =
            content_type.context("template body and content_type must be supplied together")?;
        anyhow::ensure!(
            self.definition
                .content_types
                .iter()
                .any(|value| value == content_type),
            "template content type is not permitted"
        );
        anyhow::ensure!(
            body.len() <= self.definition.max_bytes && (!required || !body.is_empty()),
            "template body violates its byte limit or required-body policy"
        );
        let validation = self
            .definition
            .validation
            .as_ref()
            .expect("compiled body validation");
        anyhow::ensure!(
            !validation.json || serde_json::from_str::<Value>(body).is_ok(),
            "template body must be valid JSON"
        );
        anyhow::ensure!(
            self.pattern
                .as_ref()
                .is_none_or(|pattern| pattern.is_match(body)),
            "template body does not match its pattern"
        );
        anyhow::ensure!(
            validation.values.is_empty() || validation.values.iter().any(|value| value == body),
            "template body is outside its enum"
        );
        Ok(())
    }

    fn canonical(&self) -> BodyPolicy {
        let mut definition = self.definition.clone();
        definition.content_types.sort();
        definition
            .validation
            .as_mut()
            .expect("compiled body validation")
            .values
            .sort();
        definition
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Parameter {
    #[serde(rename = "type")]
    pub kind: String,
    pub required: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pattern: String,
    #[serde(default, rename = "enum", skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default)]
    pub min_length: usize,
    pub max_length: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
            Some(compile_pattern(&definition.pattern).context("invalid parameter pattern")?)
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

fn compile_pattern(pattern: &str) -> Result<Regex> {
    let mut normalized = String::with_capacity(pattern.len());
    let mut class = false;
    let mut escaped = false;
    for character in pattern.chars() {
        if escaped {
            normalized.push(character);
            escaped = false;
        } else if character == '\\' {
            normalized.push(character);
            escaped = true;
        } else {
            match character {
                '[' if class => normalized.push_str(r"\["),
                '[' => {
                    class = true;
                    normalized.push(character);
                }
                ']' => {
                    class = false;
                    normalized.push(character);
                }
                '&' | '~' if class => {
                    normalized.push_str(&format!(r"\x{:02x}", character as u32));
                }
                _ => normalized.push(character),
            }
        }
    }
    Ok(Regex::new(&format!(r"\A(?:{normalized})\z"))?)
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

fn validate_body_pattern(pattern: &str) -> Result<()> {
    validate_pattern(pattern)?;
    let bytes = pattern.as_bytes();
    let mut class = false;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                index += 1;
                let escaped = bytes[index];
                anyhow::ensure!(
                    !b"dDsSwW".contains(&escaped) && (escaped != b'-' || class),
                    "body patterns require explicit ASCII classes and escaped syntax punctuation"
                );
            }
            b'[' => {
                anyhow::ensure!(
                    !class && bytes.get(index + 1) != Some(&b'^'),
                    "body patterns cannot use nested or negated classes"
                );
                class = true;
            }
            b']' => {
                anyhow::ensure!(class, "body patterns must escape literal closing brackets");
                class = false;
            }
            b'.' if !class => anyhow::bail!("body patterns cannot use wildcard dots"),
            b'^' | b'$'
                if !class
                    && bytes
                        .get(index + 1)
                        .is_some_and(|value| b"*+?{".contains(value)) =>
            {
                anyhow::bail!("body patterns cannot quantify anchors directly")
            }
            b'{' if !class => {
                let start = index + 1;
                index = start;
                while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                    index += 1;
                }
                anyhow::ensure!(
                    index > start && (index - start == 1 || bytes[start] != b'0'),
                    "body patterns must escape literal opening braces"
                );
                if bytes.get(index) == Some(&b',') {
                    let start = index + 1;
                    index = start;
                    while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                        index += 1;
                    }
                    anyhow::ensure!(
                        index - start <= 1 || bytes[start] != b'0',
                        "body patterns cannot use leading zeros in repetition bounds"
                    );
                }
                anyhow::ensure!(
                    bytes.get(index) == Some(&b'}'),
                    "body patterns require valid repetition bounds"
                );
            }
            b'}' if !class => {
                anyhow::bail!("body patterns must escape literal closing braces")
            }
            _ => {}
        }
        index += 1;
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
    method: Method,
    body_policy: Option<CompiledBodyPolicy>,
    operation: Option<String>,
    origin: Url,
    path: Vec<Part>,
    query: BTreeMap<String, Part>,
    parameters: BTreeMap<String, Constraint>,
    headers: HeaderMap,
    header_rules: BTreeMap<String, rules::Rule>,
    pub(super) digest: String,
}

impl Template {
    pub fn new(definition: &Definition) -> Result<Self> {
        anyhow::ensure!(definition.version == 1, "template version must be 1");
        anyhow::ensure!(
            matches!(definition.method.as_str(), "GET" | "POST" | "PUT"),
            "template method must be GET, POST, or PUT"
        );
        let method = Method::from_bytes(definition.method.as_bytes())?;
        let body_policy =
            CompiledBodyPolicy::new(definition.method.as_str(), definition.body_policy.as_ref())?;
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
        let rules = definition.rules()?;
        anyhow::ensure!(
            definition.headers.len() + rules.len() + usize::from(body_policy.is_some()) <= 32,
            "template has too many headers"
        );
        let headers = config::headers(&definition.headers)?;
        for (name, value) in &headers {
            headers::template_name(name.as_str())?;
            anyhow::ensure!(
                body_policy.is_none()
                    || !matches!(name.as_str(), "content-type" | "content-encoding"),
                "template writes require the body policy content type and unencoded body bytes"
            );
            headers::template_value(std::str::from_utf8(value.as_bytes())?)?;
        }
        let header_rules = rules::compile(rules, &headers, body_policy.is_some())?;
        headers::template_size(&headers)?;
        let mut template = Self {
            method,
            body_policy,
            operation: None,
            origin,
            path,
            query,
            parameters,
            headers,
            header_rules,
            digest: String::new(),
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
        template.digest = template.policy(definition)?;
        if let Some(policy) = &template.body_policy {
            #[derive(Serialize)]
            struct Operation<'a> {
                method: &'a str,
                body_policy: BodyPolicy,
                parameters_schema: Value,
            }
            let encoded = encode(&Operation {
                method: template.method.as_str(),
                body_policy: policy.canonical(),
                parameters_schema: template.schema(),
            })?;
            template.operation = Some(format!("write-v1:{}", hex(&Sha256::digest(encoded))));
        }
        Ok(template)
    }

    pub fn rich(&self) -> bool {
        self.header_rules.values().any(|rule| !rule.legacy)
    }

    pub(crate) fn header_error(&self, code: &str, error: impl std::fmt::Display) -> anyhow::Error {
        if self.rich() {
            anyhow::anyhow!("{code}: {error}")
        } else {
            anyhow::anyhow!("{error}")
        }
    }

    fn caller_headers(&self, caller: HeaderMap) -> Result<HeaderMap> {
        if caller.keys_len() > 32 {
            return Err(self.header_error("header_budget_exceeded", "too many template headers"));
        }
        let mut headers = self.headers.clone();
        let mut sources = self.headers.clone();
        for name in caller.keys() {
            headers::template_name(name.as_str())
                .map_err(|error| self.header_error("header_invalid", error))?;
            let canonical = headers::canonical(name.as_str());
            let rule = self.header_rules.get(&canonical).ok_or_else(|| {
                self.header_error(
                    "header_not_allowed",
                    "caller header is not permitted by the target",
                )
            })?;
            if caller.get_all(name).iter().count() != 1 {
                return Err(self.header_error("header_duplicate", "duplicate caller header name"));
            }
            let value = std::str::from_utf8(caller[name].as_bytes())
                .map_err(|_| self.header_error("header_invalid", "invalid caller header value"))?;
            rule.validate(value)
                .map_err(|error| self.header_error("header_invalid", error))?;
            sources.insert(name.clone(), caller[name].clone());
            headers.insert(
                http::HeaderName::try_from(&rule.schema.forward_as)?,
                caller[name].clone(),
            );
        }
        for rule in self.header_rules.values() {
            if rule.schema.required && !caller.contains_key(&rule.schema.name) {
                return Err(
                    self.header_error("header_required", "required caller header is missing")
                );
            }
        }
        headers::template_size(&sources)
            .map_err(|error| self.header_error("header_budget_exceeded", error))?;
        headers::template_size(&headers)
            .map_err(|error| self.header_error("header_budget_exceeded", error))?;
        Ok(headers)
    }

    pub fn method(&self) -> &str {
        self.method.as_str()
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
        let mut headers = self.caller_headers(caller)?;
        headers.insert(
            "user-agent",
            http::HeaderValue::from_static(headers::USER_AGENT),
        );
        Ok((url, headers))
    }

    pub fn request(
        &self,
        values: &BTreeMap<String, String>,
        caller: HeaderMap,
        operation: Option<&str>,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<(Method, Url, HeaderMap, Bytes)> {
        match &self.body_policy {
            Some(policy) => {
                anyhow::ensure!(
                    operation == self.operation.as_deref(),
                    "write operation must match the discovered invocation schema"
                );
                policy.validate(body, content_type)?;
            }
            None => {
                anyhow::ensure!(
                    operation.is_none(),
                    "GET templates do not accept a write operation"
                );
                anyhow::ensure!(
                    body.is_none() && content_type.is_none(),
                    "template GET requests cannot contain body or content_type arguments"
                );
            }
        }
        let (url, mut headers) = self.render(values, caller)?;
        if let Some(content_type) = content_type {
            headers.insert("content-type", http::HeaderValue::try_from(content_type)?);
            headers::template_size(&headers)?;
        }
        let body = if self.method == Method::GET {
            Bytes::new()
        } else {
            Bytes::copy_from_slice(body.unwrap_or_default().as_bytes())
        };
        Ok((self.method.clone(), url, headers, body))
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
        let root = schema.as_object_mut().expect("template call schema object");
        root.remove("$id");
        root.remove("title");
        schema["properties"]["label"] = json!({"type":"string","const":label});
        schema["properties"]["parameters"] = self.schema();
        schema["description"] = json!(format!(
            "Arguments for this fixed-origin HTTPS {} operation. Supply raw parameter values without URL encoding; the client renders them. The method, path structure, and query names are fixed. Redirects are disabled. GET rejects bodies; writes enforce the advertised body policy and are never automatically replayed.",
            self.method
        ));
        match &self.body_policy {
            Some(policy) => {
                schema["properties"]["operation"] = json!({"type":"string","const":self.operation});
                schema["required"]
                    .as_array_mut()
                    .expect("template call schema required fields")
                    .push(json!("operation"));
                let policy = policy.canonical();
                let validation = policy
                    .validation
                    .as_ref()
                    .expect("compiled body validation");
                let mut body = json!({
                    "type":"string",
                    "maxLength":policy.max_bytes,
                    "x-maxBytes":policy.max_bytes,
                    "description":"Raw UTF-8 body. x-maxBytes is an enforced byte limit; maxLength is a character limit. All configured JSON, full-string pattern, and exact raw-string enum checks must pass."
                });
                if policy.required == Some(true) {
                    body["minLength"] = json!(1);
                    schema["required"]
                        .as_array_mut()
                        .expect("template call schema required fields")
                        .extend([json!("body"), json!("content_type")]);
                }
                if validation.json {
                    body["contentMediaType"] = json!("application/json");
                }
                if !validation.pattern.is_empty() {
                    body["pattern"] = json!(format!("^(?:{})$", validation.pattern));
                    body["not"] = json!({"pattern":"[^ -~]"});
                }
                if !validation.values.is_empty() {
                    body["enum"] = json!(validation.values);
                }
                schema["properties"]["body"] = body;
                schema["properties"]["content_type"] =
                    json!({"type":"string","enum":policy.content_types});
                schema["dependentRequired"] =
                    json!({"body":["content_type"],"content_type":["body"]});
            }
            None => {
                let properties = schema["properties"]
                    .as_object_mut()
                    .expect("template call schema properties");
                properties.remove("operation");
                properties.remove("body");
                properties.remove("content_type");
            }
        }
        let required: Vec<_> = self
            .header_rules
            .values()
            .filter(|rule| rule.schema.required)
            .map(|rule| rule.schema.name.clone())
            .collect();
        let properties: BTreeMap<_, _> = self
            .header_rules
            .iter()
            .map(|(name, rule)| (name, rule.public()))
            .collect();
        let mut headers = json!({
            "type":"object", "properties":properties, "additionalProperties":false, "maxProperties":32,
            "description":"Caller headers using the advertised spelling; runtime names are case-insensitive. Values must be valid UTF-8 without control characters. Pattern-bearing rules require printable ASCII; length bounds count Unicode code points. The client also enforces an 8192-byte total header budget including managed headers."
        });
        if required.is_empty() {
            headers["default"] = json!({});
        } else {
            headers["required"] = json!(required);
            schema["required"]
                .as_array_mut()
                .expect("template required fields")
                .push(json!("headers"));
        }
        schema["properties"]["headers"] = headers;
        let mut invocation = json!({"tool_name":"call_target","input_schema":schema});
        if !required.is_empty() {
            return invocation;
        }
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
        if let Some(parameters) = example {
            let mut example = json!({"label":label,"parameters":parameters});
            if let Some(policy) = &self.body_policy {
                example["operation"] = json!(self.operation);
                let policy = policy.canonical();
                let validation = policy.validation.expect("compiled body validation");
                if let Some(body) = validation.values.iter().min() {
                    let content_type = policy
                        .content_types
                        .iter()
                        .min()
                        .expect("compiled content type");
                    example["body"] = json!(body);
                    example["content_type"] = json!(content_type);
                } else if policy.required == Some(true) {
                    return invocation;
                }
            }
            let parameters: BTreeMap<String, String> =
                serde_json::from_value(example["parameters"].clone())
                    .expect("validated template example");
            if self
                .request(
                    &parameters,
                    HeaderMap::new(),
                    example.get("operation").and_then(Value::as_str),
                    example.get("body").and_then(Value::as_str),
                    example.get("content_type").and_then(Value::as_str),
                )
                .is_ok()
            {
                invocation["examples"] = json!([example]);
            }
        }
        invocation
    }
}

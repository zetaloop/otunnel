use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use http::{HeaderMap, HeaderName};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::config;

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
    fn validate(&self, value: &str) -> Result<()> {
        let length = value.chars().count();
        let definition = &self.definition;
        anyhow::ensure!(
            (definition.min_length..=definition.max_length).contains(&length),
            "parameter length does not match its schema"
        );
        anyhow::ensure!(
            definition.values.is_empty() || definition.values.iter().any(|entry| entry == value),
            "parameter is not an enumerated value"
        );
        anyhow::ensure!(
            !definition
                .reserved_values
                .iter()
                .any(|entry| entry == value),
            "parameter is reserved"
        );
        anyhow::ensure!(
            self.pattern
                .as_ref()
                .is_none_or(|pattern| pattern.is_match(value)),
            "parameter does not match its pattern"
        );
        Ok(())
    }
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
        if let Some(name) = value
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
        {
            anyhow::ensure!(
                parameters.contains_key(name),
                "template references undeclared parameter {name}"
            );
            used.insert(name.to_owned());
            Ok(Self::Parameter(name.to_owned()))
        } else {
            anyhow::ensure!(
                !value.contains(['{', '}']),
                "template parameters occupy a complete path segment or query value"
            );
            Ok(Self::Literal(value.to_owned()))
        }
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
        anyhow::ensure!(
            definition.version == 1 && definition.method == "GET" && !definition.follow_redirects,
            "Harpoon templates use version 1, GET, and a fixed destination"
        );
        let origin = Url::parse(&definition.origin)?;
        anyhow::ensure!(
            origin.scheme() == "https"
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.username().is_empty()
                && origin.password().is_none(),
            "template origin must be an HTTPS origin"
        );
        let mut parameters = BTreeMap::new();
        for (name, definition) in &definition.parameters {
            anyhow::ensure!(
                definition.kind == "string"
                    && definition.required
                    && definition.min_length <= definition.max_length,
                "invalid template parameter {name}"
            );
            let constraint = Constraint {
                definition: definition.clone(),
                pattern: if definition.pattern.is_empty() {
                    None
                } else {
                    Some(Regex::new(&definition.pattern)?)
                },
            };
            for example in &definition.examples {
                constraint
                    .validate(example)
                    .with_context(|| format!("example for parameter {name}"))?;
            }
            parameters.insert(name.clone(), constraint);
        }
        let mut used = BTreeSet::new();
        let path = definition
            .path_template
            .strip_prefix('/')
            .context("template path must be absolute")?
            .split('/')
            .map(|value| Part::parse(value, &parameters, &mut used))
            .collect::<Result<Vec<_>>>()?;
        let query = definition
            .query
            .iter()
            .map(|(key, value)| Ok((key.clone(), Part::parse(value, &parameters, &mut used)?)))
            .collect::<Result<_>>()?;
        anyhow::ensure!(
            used.len() == parameters.len(),
            "template contains unused parameters"
        );
        let headers = config::headers(&definition.headers)?;
        let mut allowed_headers = BTreeSet::new();
        for name in &definition.allowed_headers {
            let name = HeaderName::try_from(name)?.to_string();
            anyhow::ensure!(
                !headers.contains_key(&name),
                "caller header {name} conflicts with a fixed header"
            );
            allowed_headers.insert(name);
        }
        Ok(Self {
            origin,
            path,
            query,
            parameters,
            headers,
            allowed_headers,
        })
    }

    pub fn origin(&self) -> &Url {
        &self.origin
    }

    pub fn render(
        &self,
        values: &BTreeMap<String, String>,
        caller: HeaderMap,
    ) -> Result<(Url, HeaderMap)> {
        anyhow::ensure!(
            values.len() == self.parameters.len(),
            "template parameters do not match the target schema"
        );
        for (name, constraint) in &self.parameters {
            constraint
                .validate(
                    values
                        .get(name)
                        .with_context(|| format!("missing template parameter {name}"))?,
                )
                .with_context(|| format!("invalid template parameter {name}"))?;
        }
        let mut url = self.origin.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| anyhow::anyhow!("template origin cannot hold path segments"))?;
            path.clear();
            for part in &self.path {
                let value = part.value(values);
                anyhow::ensure!(
                    !matches!(value, "." | ".."),
                    "template path parameter is a dot segment"
                );
                path.push(value);
            }
        }
        if !self.query.is_empty() {
            let mut query = url.query_pairs_mut();
            for (key, part) in &self.query {
                query.append_pair(key, part.value(values));
            }
        }
        let mut headers = self.headers.clone();
        for name in caller.keys() {
            anyhow::ensure!(
                self.allowed_headers.contains(name.as_str()),
                "header {name} is not declared by the template"
            );
            for value in caller.get_all(name) {
                headers.append(name.clone(), value.clone());
            }
        }
        Ok((url, headers))
    }

    pub fn schema(&self) -> Value {
        let mut properties = serde_json::Map::new();
        for (name, constraint) in &self.parameters {
            let parameter = &constraint.definition;
            let mut schema = json!({"type":"string","minLength":parameter.min_length,"maxLength":parameter.max_length});
            if !parameter.description.is_empty() {
                schema["description"] = json!(parameter.description);
            }
            if !parameter.pattern.is_empty() {
                schema["pattern"] = json!(parameter.pattern);
            }
            if !parameter.values.is_empty() {
                schema["enum"] = json!(parameter.values);
            }
            if !parameter.reserved_values.is_empty() {
                schema["not"] = json!({"enum":parameter.reserved_values});
            }
            if !parameter.examples.is_empty() {
                schema["examples"] = json!(parameter.examples);
            }
            properties.insert(name.clone(), schema);
        }
        json!({"type":"object","properties":properties,"required":self.parameters.keys().collect::<Vec<_>>(),"additionalProperties":false})
    }

    pub fn invocation(&self, label: &str, mut schema: Value) -> Value {
        schema["properties"]["label"]["const"] = json!(label);
        schema["properties"]["parameters"] = self.schema();
        let headers: serde_json::Map<_, _> = self
            .allowed_headers
            .iter()
            .map(|name| (name.clone(), json!({"type":"string"})))
            .collect();
        schema["properties"]["headers"] =
            json!({"type":"object","properties":headers,"additionalProperties":false});
        let mut invocation = json!({"tool_name":"call_target_template","input_schema":schema});
        let example: Option<BTreeMap<_, _>> = self
            .parameters
            .iter()
            .map(|(name, constraint)| {
                let value = constraint
                    .definition
                    .examples
                    .first()
                    .or_else(|| constraint.definition.values.first())?;
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

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use http::HeaderMap;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};

use crate::harpoon::headers;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HeaderRule {
    Name(String),
    Rule(Header),
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub credential: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub forward_as: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub validation: Option<HeaderValidation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderValidation {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pattern: String,
    #[serde(
        default,
        rename = "enum",
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub values: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_length: Option<usize>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_length: Option<usize>,
}

pub(super) fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)?
        .map(Some)
        .ok_or_else(|| serde::de::Error::custom("header rule field cannot be null"))
}

pub(super) struct Rule {
    pub schema: Header,
    pub legacy: bool,
    pattern: Option<Regex>,
}

impl Rule {
    pub fn validate(&self, value: &str) -> Result<()> {
        anyhow::ensure!(super::text(value), "invalid caller header value");
        let Some(validation) = &self.schema.validation else {
            return Ok(());
        };
        let length = value.chars().count();
        anyhow::ensure!(
            validation
                .min_length
                .is_none_or(|minimum| length >= minimum)
                && validation
                    .max_length
                    .is_none_or(|maximum| length <= maximum),
            "caller header length is outside its bounds"
        );
        if let Some(pattern) = &self.pattern {
            anyhow::ensure!(
                value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
                "caller header pattern requires printable ASCII"
            );
            anyhow::ensure!(
                pattern.is_match(value),
                "caller header does not match its pattern"
            );
        }
        anyhow::ensure!(
            validation
                .values
                .as_ref()
                .is_none_or(|values| values.iter().any(|item| item == value)),
            "caller header is outside its enum"
        );
        Ok(())
    }

    pub fn public(&self) -> Value {
        let mut schema = json!({"type":"string", "maxLength":8192, "not":{"pattern":"[\u{0000}-\u{001f}\u{007f}]"}});
        if !self.schema.description.is_empty() {
            schema["description"] = json!(self.schema.description);
        }
        if let Some(validation) = &self.schema.validation {
            if let Some(minimum) = validation.min_length {
                schema["minLength"] = json!(minimum);
            }
            if let Some(maximum) = validation.max_length {
                schema["maxLength"] = json!(maximum);
            }
            if !self.schema.credential
                && let Some(values) = &validation.values
            {
                schema["enum"] = json!(values);
            }
            if !validation.pattern.is_empty() {
                schema["pattern"] = json!(format!("^(?:{})$", validation.pattern));
                schema["not"] = json!({"pattern":"[^ -~]"});
            }
        }
        schema
    }

    pub fn canonical(&self) -> HeaderRule {
        if self.legacy {
            return HeaderRule::Name(self.schema.name.clone());
        }
        let mut schema = self.schema.clone();
        if let Some(validation) = &mut schema.validation
            && let Some(values) = &mut validation.values
        {
            values.sort();
        }
        HeaderRule::Rule(schema)
    }
}

pub(super) fn compile(
    rules: &[HeaderRule],
    fixed: &HeaderMap,
    write: bool,
) -> Result<BTreeMap<String, Rule>> {
    let mut compiled = BTreeMap::new();
    let mut destinations = BTreeSet::new();
    for rule in rules {
        let (mut schema, legacy) = match rule {
            HeaderRule::Name(name) => (
                Header {
                    name: name.clone(),
                    ..Header::default()
                },
                true,
            ),
            HeaderRule::Rule(schema) => (schema.clone(), false),
        };
        let source = headers::template_name(&schema.name)?;
        let destination = if schema.forward_as.is_empty() {
            source.clone()
        } else {
            headers::template_name(&schema.forward_as)?
        };
        if !legacy {
            anyhow::ensure!(
                !schema.description.trim().is_empty()
                    && schema.description.len() <= 1024
                    && super::text(&schema.description),
                "template header rules require a bounded nonempty description"
            );
        }
        for name in [&source, &destination] {
            if !legacy {
                anyhow::ensure!(
                    !["proxy-", "mcp-", "x-mcp-", "x-tunnel-", "x-openai-"]
                        .iter()
                        .any(|prefix| name.as_str().starts_with(prefix)),
                    "reserved transport or identity header cannot be a runtime rule"
                );
            }
            anyhow::ensure!(
                !write || !matches!(name.as_str(), "content-type" | "content-encoding"),
                "template writes require the body policy content type and unencoded body bytes"
            );
            anyhow::ensure!(
                !fixed.contains_key(name),
                "template caller header conflicts with a fixed header"
            );
            anyhow::ensure!(
                !headers::credential(name.as_str())
                    || schema.credential && credential(name.as_str()),
                "template authentication headers must be fixed by the operator or explicitly supported by a credential rule"
            );
        }
        anyhow::ensure!(
            !schema.credential || credential(source.as_str()) || credential(destination.as_str()),
            "template credential rule must use a supported credential header"
        );
        schema.name = headers::canonical(source.as_str());
        schema.forward_as = headers::canonical(destination.as_str());
        anyhow::ensure!(
            !compiled.contains_key(&schema.name),
            "duplicate template caller header name"
        );
        anyhow::ensure!(
            destinations.insert(schema.forward_as.clone()),
            "duplicate template outgoing header name"
        );
        if schema.credential {
            anyhow::ensure!(
                schema
                    .validation
                    .as_ref()
                    .is_none_or(|validation| validation.values.is_none()),
                "template credential rules cannot configure enum values"
            );
            anyhow::ensure!(
                schema
                    .validation
                    .as_ref()
                    .is_some_and(
                        |validation| validation.min_length.is_some_and(|value| value > 0)
                            && validation.max_length.is_some_and(|value| value > 0)
                            && !validation.pattern.is_empty()
                    ),
                "template credential rules require positive length bounds and a pattern"
            );
        }
        let pattern = if let Some(validation) = &schema.validation {
            anyhow::ensure!(
                validation
                    .values
                    .as_ref()
                    .is_none_or(|values| !values.is_empty()),
                "template header enum must not be empty"
            );
            let minimum = validation.min_length.unwrap_or(0);
            let maximum = validation.max_length.unwrap_or(8192);
            anyhow::ensure!(
                minimum <= maximum && maximum <= 8192,
                "template header length bounds must be within 0 to 8192"
            );
            anyhow::ensure!(
                validation.pattern.len() <= 512
                    && validation
                        .values
                        .as_ref()
                        .is_none_or(|values| values.len() <= 64),
                "template header constraints exceed size limits"
            );
            if validation.pattern.is_empty() {
                None
            } else {
                super::validate_body_pattern(&validation.pattern)
                    .context("unsupported template header pattern")?;
                Some(
                    super::compile_pattern(&validation.pattern)
                        .context("invalid template header pattern")?,
                )
            }
        } else {
            None
        };
        let rule = Rule {
            schema,
            legacy,
            pattern,
        };
        if let Some(values) = rule
            .schema
            .validation
            .as_ref()
            .and_then(|validation| validation.values.as_ref())
        {
            let mut size = 0;
            let mut seen = BTreeSet::new();
            for value in values {
                size += value.len();
                anyhow::ensure!(
                    size <= 8192 && rule.validate(value).is_ok(),
                    "template header enum violates its constraints or size limits"
                );
                anyhow::ensure!(seen.insert(value), "duplicate template header enum value");
            }
        }
        compiled.insert(rule.schema.name.clone(), rule);
    }
    for rule in compiled.values() {
        anyhow::ensure!(
            rule.schema.name == rule.schema.forward_as
                || !compiled.contains_key(&rule.schema.forward_as),
            "template header source and destination names overlap"
        );
    }
    Ok(compiled)
}

fn credential(name: &str) -> bool {
    matches!(name, "authorization" | "x-api-key" | "api-key")
}

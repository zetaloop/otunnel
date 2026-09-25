use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{BodyPolicy, Definition, HeaderRule, Parameter, Template};
use crate::harpoon::headers;

pub(crate) fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    Ok(serde_json::to_string(value)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        .into_bytes())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Template {
    pub(super) fn policy(&self, definition: &Definition) -> Result<String> {
        #[derive(Serialize)]
        struct Policy {
            version: u8,
            origin: String,
            method: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            body_policy: Option<BodyPolicy>,
            path_template: String,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            query: BTreeMap<String, String>,
            parameters: BTreeMap<String, Parameter>,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            headers: BTreeMap<String, String>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            allowed_headers: Vec<String>,
            follow_redirects: bool,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            header_rules: Vec<HeaderRule>,
        }
        let mut parameters: BTreeMap<_, _> = self
            .parameters
            .iter()
            .map(|(name, value)| (name.clone(), value.definition.clone()))
            .collect();
        for parameter in parameters.values_mut() {
            parameter.values.sort();
            for value in &mut parameter.reserved_values {
                value.make_ascii_lowercase();
            }
            parameter.reserved_values.sort();
        }
        let rich = self.rich();
        let policy = Policy {
            version: 1,
            origin: definition
                .origin
                .strip_suffix('/')
                .unwrap_or(&definition.origin)
                .into(),
            method: self.method.to_string(),
            body_policy: self.body_policy.as_ref().map(|policy| policy.canonical()),
            path_template: definition.path_template.clone(),
            query: definition.query.clone(),
            parameters,
            headers: self
                .headers
                .iter()
                .map(|(name, value)| {
                    Ok((
                        headers::canonical(name.as_str()),
                        std::str::from_utf8(value.as_bytes())?.to_owned(),
                    ))
                })
                .collect::<Result<_>>()?,
            allowed_headers: if rich {
                Vec::new()
            } else {
                self.header_rules.keys().cloned().collect()
            },
            follow_redirects: false,
            header_rules: if rich {
                self.header_rules
                    .values()
                    .map(|rule| rule.canonical())
                    .collect()
            } else {
                Vec::new()
            },
        };
        Ok(hex(&Sha256::digest(encode(&policy)?)))
    }
}

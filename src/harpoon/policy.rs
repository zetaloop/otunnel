use std::fmt;

use anyhow::{Context, Result};
use hmac::{Hmac, KeyInit, Mac};
use serde::{
    Deserializer,
    de::{MapAccess, Visitor},
};
use serde_json::value::RawValue;
use sha2::Sha256;

use super::{Harpoon, Target, valid_label};
use crate::{
    config,
    template::{Template, hex},
};

pub(super) fn mac(key: &[u8], values: &[&str]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key length");
    for value in values {
        mac.update(value.as_bytes());
        mac.update(&[0]);
    }
    mac
}

pub(super) fn key(control: &config::ControlPlane) -> Result<[u8; 32]> {
    if control.api_key.is_empty() || control.tunnel_id.is_empty() {
        return Ok(rand::random());
    }
    let key = config::resolve(&control.api_key)?;
    Ok(mac(
        key.as_bytes(),
        &[
            "tunnel-client/harpoon/header-rules/key/v1",
            &control.tunnel_id,
        ],
    )
    .finalize()
    .into_bytes()
    .into())
}

pub(super) fn bound(label: &str) -> Option<(&str, [u8; 32])> {
    let (digest, name) = label.strip_prefix("hr1:")?.split_once(':')?;
    if digest.len() != 64
        || !valid_label(name)
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = [0; 32];
    for (index, value) in bytes.iter_mut().enumerate() {
        *value = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some((name, bytes))
}

pub(super) fn contains_bound(arguments: &RawValue) -> bool {
    struct Labels;
    impl<'de> Visitor<'de> for Labels {
        type Value = bool;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("tool arguments")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
            let mut found = false;
            while let Some((name, value)) = map.next_entry::<String, Box<RawValue>>()? {
                found |= name == "label"
                    && serde_json::from_str::<String>(value.get())
                        .is_ok_and(|label| label.starts_with("hr1:"));
            }
            Ok(found)
        }
    }
    serde_json::Deserializer::from_str(arguments.get())
        .deserialize_map(Labels)
        .unwrap_or(false)
}

impl Harpoon {
    fn invocation_mac(&self, name: &str, template: &Template) -> Hmac<Sha256> {
        mac(
            &self.policy_key,
            &[
                "tunnel-client/harpoon/header-rules/invocation/v1",
                name,
                &template.digest,
            ],
        )
    }

    pub(super) fn invocation_label(&self, name: &str, template: &Template) -> String {
        if template.rich() {
            format!(
                "hr1:{}:{name}",
                hex(&self.invocation_mac(name, template).finalize().into_bytes())
            )
        } else {
            name.into()
        }
    }

    pub(super) fn template_target(&self, label: &str) -> Result<Target> {
        if let Some((name, digest)) = bound(label) {
            let target = self.target(name).context("unknown template target")?;
            let template = target
                .template
                .as_ref()
                .context("unknown template target")?;
            anyhow::ensure!(
                template.rich()
                    && self
                        .invocation_mac(name, template)
                        .verify_slice(&digest)
                        .is_ok(),
                "unknown template target"
            );
            return Ok(target);
        }
        let target = self.target(label).context("unknown template target")?;
        anyhow::ensure!(
            target
                .template
                .as_ref()
                .is_some_and(|template| !template.rich()),
            "unknown template target"
        );
        Ok(target)
    }
}

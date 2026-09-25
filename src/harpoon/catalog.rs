use anyhow::Result;
use serde_json::{Value, json};

use super::Target;
use crate::template::encode;

pub(super) const LIMIT: usize = 448 * 1024;

pub(super) fn size(target: &Target, mut schema: Value) -> Result<usize> {
    let mut info = target.info.clone();
    if let Some(template) = &target.template {
        schema["properties"]["max_response_bytes"]["maximum"] = json!(isize::MAX);
        schema["properties"]["max_response_bytes"]["default"] = json!(isize::MAX);
        let label = if template.rich() {
            format!("hr1:{}:{}", "0".repeat(64), info.label)
        } else {
            info.label.clone()
        };
        info.invocation = Some(template.invocation(&label, schema));
    }
    let payload = encode(&info)?;
    if payload.len() > LIMIT {
        return Ok(LIMIT + 1);
    }
    let escaped = encode(&std::str::from_utf8(&payload)?)?;
    Ok((payload.len() + escaped.len()).min(LIMIT + 1))
}

impl super::Harpoon {
    pub(crate) fn log_catalog(&self, control: &crate::config::ControlPlane) -> Result<()> {
        use hmac::Mac;
        use serde::Serialize;

        #[derive(Serialize)]
        struct Entry<'a> {
            #[serde(skip_serializing_if = "str::is_empty")]
            template_policy: &'a str,
            label: &'a str,
            base_url: String,
            oauth_audience_url: &'a str,
            unix_socket_path: &'a str,
            source: &'a str,
            category: &'a str,
            tags: Option<&'a [String]>,
        }
        #[derive(Serialize)]
        struct Catalog<'a> {
            version: u8,
            targets: Vec<Entry<'a>>,
        }

        if control.api_key.is_empty() || control.tunnel_id.is_empty() {
            return Ok(());
        }
        let registry = self.targets.read().expect("target registry lock poisoned");
        let mut targets = registry
            .values()
            .map(|target| {
                let info = &target.info;
                let audience = info.category == "oauth"
                    && ["auth-server-metadata", "token-endpoint"]
                        .iter()
                        .all(|tag| info.tags.iter().any(|value| value == tag))
                    && matches!(target.url.scheme(), "http" | "https")
                    && target.url.username().is_empty()
                    && target.url.password().is_none()
                    && target.url.fragment().is_none();
                Ok(Entry {
                    template_policy: target
                        .template
                        .as_ref()
                        .map_or("", |template| template.digest.as_str()),
                    label: &info.label,
                    base_url: super::url_key(&target.original_url)?,
                    oauth_audience_url: if audience { &target.original_url } else { "" },
                    unix_socket_path: target.unix_socket.as_deref().unwrap_or_default(),
                    source: &info.source,
                    category: &info.category,
                    tags: (!info.tags.is_empty()).then_some(info.tags.as_slice()),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        targets.sort_by(|left, right| left.label.cmp(right.label));
        let count = targets.len();
        let payload = encode(&Catalog {
            version: 1,
            targets,
        })?;
        let key = crate::config::resolve(&control.api_key)?;
        let key = super::policy::mac(
            key.as_bytes(),
            &[
                "tunnel-client/harpoon/startup-catalog-digest/key/v1",
                &control.tunnel_id,
            ],
        )
        .finalize()
        .into_bytes();
        let mut mac = super::policy::mac(
            &key,
            &["tunnel-client/harpoon/startup-catalog-digest/payload/v1"],
        );
        mac.update(&payload);
        let digest = format!(
            "hmac-sha256:v1:{}",
            crate::template::hex(&mac.finalize().into_bytes())
        );
        tracing::info!(
            component = "harpoon",
            catalog_digest = digest,
            catalog_digest_version = 1,
            target_count = count,
            digest_scope = "startup",
            comparability_scope = "same_tunnel_and_runtime_key",
            "harpoon startup catalog digest"
        );
        Ok(())
    }
}

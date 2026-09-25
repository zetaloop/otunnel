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

use std::collections::BTreeMap;

use yaml_serde::Value;

use super::Span;
use crate::template::{BodyPolicy, BodyValidation, Definition, Parameter};

pub(super) trait Coerce {
    fn coerce(value: &mut Value);
}

impl Coerce for String {
    fn coerce(value: &mut Value) {
        match value {
            Value::Null => *value = Value::String(String::new()),
            Value::Bool(boolean) => *value = Value::String(boolean.to_string()),
            Value::Number(number) => *value = Value::String(number.to_string()),
            _ => {}
        }
    }
}

impl Coerce for bool {
    fn coerce(value: &mut Value) {
        if let Value::String(text) = value {
            match text.as_str() {
                "y" | "Y" | "yes" | "Yes" | "YES" | "on" | "On" | "ON" => {
                    *value = Value::Bool(true)
                }
                "n" | "N" | "no" | "No" | "NO" | "off" | "Off" | "OFF" => {
                    *value = Value::Bool(false)
                }
                _ => {}
            }
        }
    }
}

impl Coerce for usize {
    fn coerce(value: &mut Value) {
        if let Value::Number(number) = value
            && number.is_f64()
            && let Some(float) = number.as_f64()
            && float >= 0.0
            && float < i64::MAX as f64
        {
            *value = Value::Number((float as u64).into());
        }
    }
}

impl Coerce for u8 {
    fn coerce(value: &mut Value) {
        usize::coerce(value);
    }
}

impl Coerce for Span {
    fn coerce(value: &mut Value) {
        String::coerce(value);
    }
}

impl<T: Coerce> Coerce for Option<T> {
    fn coerce(value: &mut Value) {
        if !value.is_null() {
            T::coerce(value);
        }
    }
}

impl<T: Coerce> Coerce for Vec<T> {
    fn coerce(value: &mut Value) {
        if let Value::Sequence(values) = value {
            for value in values {
                T::coerce(value);
            }
        }
    }
}

impl<T: Coerce> Coerce for BTreeMap<String, T> {
    fn coerce(value: &mut Value) {
        if let Value::Mapping(values) = value {
            for value in values.values_mut() {
                T::coerce(value);
            }
        }
    }
}

macro_rules! fields {
    ($kind:ty { $($name:literal: $field:ty),* $(,)? }) => {
        impl Coerce for $kind {
            fn coerce(value: &mut Value) {
                $(if let Some(value) = value.get_mut($name) { <$field>::coerce(value); })*
            }
        }
    };
}

fields!(Definition {
    "version": u8, "origin": String, "method": String, "body_policy": Option<BodyPolicy>,
    "path_template": String, "query": BTreeMap<String, String>,
    "parameters": BTreeMap<String, Parameter>, "headers": BTreeMap<String, String>,
    "follow_redirects": bool,
});
fields!(Parameter {
    "type": String, "required": bool, "description": String, "examples": Vec<String>,
    "enum": Vec<String>, "pattern": String, "min_length": usize, "max_length": usize,
    "reserved_values": Vec<String>,
});
fields!(BodyPolicy {
    "content_types": Vec<String>, "max_bytes": usize, "required": Option<bool>,
    "validation": Option<BodyValidation>,
});
fields!(BodyValidation { "json": bool, "pattern": String, "enum": Vec<String> });

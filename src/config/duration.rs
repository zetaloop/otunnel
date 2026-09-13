use std::{fmt, str::FromStr, time::Duration};

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug)]
pub struct Span(pub Duration);

impl FromStr for Span {
    type Err = anyhow::Error;
    fn from_str(input: &str) -> Result<Self> {
        let negative = input.starts_with('-');
        let mut value = input.strip_prefix(['+', '-']).unwrap_or(input);
        if value == "0" {
            return Ok(Self(Duration::ZERO));
        }
        anyhow::ensure!(!value.is_empty(), "invalid duration {input:?}");
        let mut total = 0_u64;
        while !value.is_empty() {
            let digits = value.bytes().take_while(u8::is_ascii_digit).count();
            let whole = if digits == 0 {
                0
            } else {
                value[..digits]
                    .parse::<u64>()
                    .context("duration overflow")?
            };
            value = &value[digits..];
            let mut fraction = "";
            if let Some(rest) = value.strip_prefix('.') {
                let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
                fraction = &rest[..digits];
                value = &rest[digits..];
            }
            anyhow::ensure!(
                digits > 0 || !fraction.is_empty(),
                "invalid duration {input:?}"
            );
            let (suffix, unit) = [
                ("ns", 1_u64),
                ("us", 1_000),
                ("µs", 1_000),
                ("μs", 1_000),
                ("ms", 1_000_000),
                ("s", 1_000_000_000),
                ("m", 60_000_000_000),
                ("h", 3_600_000_000_000),
            ]
            .into_iter()
            .find(|(suffix, _)| value.starts_with(suffix))
            .with_context(|| format!("invalid duration unit in {input:?}"))?;
            value = &value[suffix.len()..];
            let mut nanos = whole.checked_mul(unit).context("duration overflow")?;
            if !fraction.is_empty() {
                let fraction: f64 = format!("0.{fraction}").parse()?;
                nanos = nanos
                    .checked_add((fraction * unit as f64) as u64)
                    .context("duration overflow")?;
            }
            total = total.checked_add(nanos).context("duration overflow")?;
            anyhow::ensure!(total <= i64::MAX as u64, "duration overflow");
        }
        anyhow::ensure!(!negative || total == 0, "duration must not be negative");
        Ok(Self(Duration::from_nanos(total)))
    }
}

impl fmt::Display for Span {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let nanos = self.0.as_nanos();
        if nanos == 0 {
            return formatter.write_str("0s");
        }
        let (unit, scale) = match nanos {
            0..1000 => ("ns", 1_u128),
            1000..1_000_000 => ("µs", 1_000),
            1_000_000..1_000_000_000 => ("ms", 1_000_000),
            _ => ("s", 1_000_000_000),
        };
        if self.0.as_secs() >= 3600 {
            write!(formatter, "{}h", self.0.as_secs() / 3600)?;
        }
        if self.0.as_secs() >= 60 {
            write!(formatter, "{}m", self.0.as_secs() / 60 % 60)?;
        }
        let whole = if scale == 1_000_000_000 {
            nanos / scale % 60
        } else {
            nanos / scale
        };
        write!(formatter, "{whole}")?;
        let fraction = nanos % scale;
        if fraction != 0 {
            let digits = scale.ilog10() as usize;
            write!(
                formatter,
                ".{}",
                format!("{fraction:0digits$}").trim_end_matches('0')
            )?;
        }
        formatter.write_str(unit)
    }
}

impl Serialize for Span {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for Span {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

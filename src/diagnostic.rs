use std::collections::BTreeMap;

use serde::Serialize;

use crate::transport::Probe;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Pass,
    Fail,
    Skip,
}
impl std::fmt::Display for Status {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        })
    }
}

#[derive(Serialize)]
pub struct Check {
    pub id: String,
    pub status: Status,
    pub summary: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub why: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub next: Vec<String>,
}
impl Check {
    pub fn new(id: impl Into<String>, status: Status, summary: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status,
            summary: summary.into(),
            why: String::new(),
            evidence: Vec::new(),
            next: Vec::new(),
        }
    }
    pub fn pass(id: impl Into<String>, summary: impl Into<String>) -> Self {
        Self::new(id, Status::Pass, summary)
    }
    pub fn skip(id: impl Into<String>, summary: impl Into<String>) -> Self {
        Self::new(id, Status::Skip, summary)
    }
    pub fn fail(id: impl Into<String>, error: impl std::fmt::Display) -> Self {
        let mut check = Self::new(id, Status::Fail, error.to_string());
        check.evidence.push(check.summary.clone());
        check
    }
}

#[derive(Serialize)]
pub struct Report {
    pub result: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failed_checks: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub next: String,
    pub checks: Vec<Check>,
    #[serde(skip)]
    pub channels: BTreeMap<String, Probe>,
}
impl Report {
    pub fn new(checks: Vec<Check>, channels: BTreeMap<String, Probe>, next: String) -> Self {
        let failed_checks: Vec<_> = checks
            .iter()
            .filter(|check| check.status == Status::Fail)
            .map(|check| check.id.clone())
            .collect();
        let passed = failed_checks.is_empty();
        Self {
            result: if passed { "ok" } else { "fail" },
            failed_checks,
            next: if passed { next } else { String::new() },
            checks,
            channels,
        }
    }
    pub fn passed(&self) -> bool {
        self.failed_checks.is_empty()
    }
}

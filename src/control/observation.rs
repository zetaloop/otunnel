use anyhow::Result;
use serde::Serialize;
use tokio::sync::watch;

use super::{Observation, StatusError, now};

#[derive(Clone, Default, Serialize)]
pub struct Upload {
    pub in_progress: u64,
    pub last_accepted: f64,
    pub last_completed: f64,
    pub last_failure: f64,
    pub disposition: &'static str,
    pub failure_category: &'static str,
    pub http_status: u16,
    pub attempts: u64,
    pub retries: u64,
    pub accepted: u64,
    pub completed: u64,
    pub terminal_failures: u64,
}

pub(super) struct Receipt<'a> {
    state: &'a watch::Sender<Observation>,
    finished: bool,
}
impl<'a> Receipt<'a> {
    pub fn new(state: &'a watch::Sender<Observation>) -> Self {
        state.send_modify(|state| state.upload.in_progress += 1);
        Self {
            state,
            finished: false,
        }
    }
    pub fn attempt(&self, retry: bool) {
        self.state.send_modify(|state| {
            state.upload.attempts += 1;
            state.upload.retries += u64::from(retry);
        });
    }
    pub fn failure(&self, category: &'static str, status: u16) {
        self.state.send_modify(|state| {
            state.upload.last_failure = now();
            state.upload.failure_category = category;
            state.upload.http_status = status;
        });
    }
    pub fn finish(mut self, result: &Result<u16>) {
        match result {
            Ok(404) => self.settle("already_fulfilled_or_unknown", "", 404),
            Ok(status) => self.settle("accepted", "", *status),
            Err(error) => self.settle(
                "failed",
                category(error),
                error
                    .downcast_ref::<StatusError>()
                    .map_or(0, |error| error.status),
            ),
        }
    }
    fn settle(&mut self, disposition: &'static str, category: &'static str, status: u16) {
        self.finished = true;
        self.state.send_modify(|state| {
            let upload = &mut state.upload;
            let now = now();
            upload.in_progress -= 1;
            upload.last_completed = now;
            upload.disposition = disposition;
            upload.failure_category = category;
            upload.http_status = status;
            if disposition == "failed" {
                upload.last_failure = now;
                upload.terminal_failures += 1;
            } else if disposition != "canceled" {
                upload.completed += 1;
                if disposition == "accepted" {
                    upload.accepted += 1;
                    upload.last_accepted = now;
                }
            }
        });
    }
}
impl Drop for Receipt<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.settle("canceled", "canceled", 0);
        }
    }
}

pub(super) fn category(error: &anyhow::Error) -> &'static str {
    if error.is::<StatusError>() {
        return "http_error";
    }
    if error.is::<tokio::time::error::Elapsed>()
        || error.chain().any(|cause| {
            cause
                .downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_timeout)
                || cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
        })
    {
        return "timeout";
    }
    if error
        .chain()
        .any(|cause| cause.is::<reqwest::Error>() || cause.is::<std::io::Error>())
    {
        "network_error"
    } else {
        "request_error"
    }
}

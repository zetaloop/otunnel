use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use http::HeaderMap;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::watch;

use crate::control;

#[derive(Clone, Serialize)]
struct Observation {
    probe_id: String,
    origin: &'static str,
    probe_type: &'static str,
    method: String,
    started_at: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_at: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<f64>,
    disposition: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_request_id: Option<String>,
}

#[derive(Default)]
struct State {
    active: BTreeMap<u64, Observation>,
    recent: VecDeque<Observation>,
    limited: bool,
}

pub(crate) struct History {
    state: Mutex<State>,
    observation: watch::Sender<Value>,
}
impl Default for History {
    fn default() -> Self {
        let (observation, _) = watch::channel(serde_json::json!({"limited": false}));
        Self {
            state: Mutex::default(),
            observation,
        }
    }
}
impl History {
    pub fn subscribe(&self) -> watch::Receiver<Value> {
        self.observation.subscribe()
    }
    fn update<T>(&self, update: impl FnOnce(&mut State) -> T) -> T {
        let mut state = self.state.lock().expect("OAuth observation mutex poisoned");
        let result = update(&mut state);
        let mut snapshot = serde_json::json!({"limited": state.limited});
        if !state.active.is_empty() {
            snapshot["active_probes"] =
                serde_json::json!(state.active.values().collect::<Vec<_>>());
        }
        if !state.recent.is_empty() {
            snapshot["recent_probes"] = serde_json::json!(state.recent);
        }
        self.observation.send_replace(snapshot);
        result
    }
}

// One startup discovery pass owns the last HTTP exchange until its caller decides how to proceed.
pub(crate) struct Session {
    history: Arc<History>,
    current: Mutex<Option<u64>>,
    kind: Mutex<&'static str>,
}
impl Session {
    pub fn new(history: Arc<History>) -> Self {
        Self {
            history,
            current: Mutex::new(None),
            kind: Mutex::new("www_authenticate"),
        }
    }
    pub fn kind(&self, kind: &'static str) {
        *self.kind.lock().expect("OAuth probe mutex poisoned") = kind;
    }
    pub fn begin(&self, method: &str) {
        self.finish("fallback");
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let kind = *self.kind.lock().expect("OAuth probe mutex poisoned");
        let mut current = self.current.lock().expect("OAuth probe mutex poisoned");
        *current = self.history.update(|state| {
            let sequence = SEQUENCE
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .ok();
            if state.active.len() == 16 || sequence.is_none() {
                state.limited = true;
                return None;
            }
            let sequence = sequence.expect("probe sequence");
            let method = match method {
                "GET" | "POST" => method,
                _ => {
                    state.limited = true;
                    "OTHER"
                }
            };
            state.active.insert(
                sequence,
                Observation {
                    probe_id: format!("probe-{sequence:016x}"),
                    origin: "startup",
                    probe_type: kind,
                    method: method.into(),
                    started_at: control::now(),
                    response_at: None,
                    status_code: None,
                    completed_at: None,
                    disposition: "pending",
                    response_request_id: None,
                },
            );
            Some(sequence)
        });
    }
    pub fn response(&self, status: u16, headers: &HeaderMap) {
        let Some(sequence) = *self.current.lock().expect("OAuth probe mutex poisoned") else {
            return;
        };
        let (id, limited) = request_id(headers);
        self.history.update(|state| {
            if let Some(probe) = state.active.get_mut(&sequence) {
                probe.response_at = Some(control::now());
                probe.status_code = (100..1000).contains(&status).then_some(status);
                probe.response_request_id = id;
                state.limited |= limited || probe.status_code.is_none();
            }
        });
    }
    pub fn finish(&self, disposition: &'static str) {
        let Some(sequence) = self
            .current
            .lock()
            .expect("OAuth probe mutex poisoned")
            .take()
        else {
            return;
        };
        self.history.update(|state| {
            if let Some(mut probe) = state.active.remove(&sequence) {
                probe.disposition = disposition;
                probe.completed_at = Some(control::now());
                if state.recent.len() == 16 {
                    state.recent.pop_front();
                    state.limited = true;
                }
                state.recent.push_back(probe);
            }
        });
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.finish("cancelled");
    }
}

fn request_id(headers: &HeaderMap) -> (Option<String>, bool) {
    if headers.keys_len() > 128 {
        return (None, true);
    }
    let mut values = headers.get_all("x-request-id").iter();
    let Some(value) = values.next() else {
        return (None, false);
    };
    if values.next().is_some()
        || !(1..=128).contains(&value.len())
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(byte))
    {
        return (None, true);
    }
    let mut count = 0;
    let mut bytes = 0;
    for connection in headers.get_all("connection") {
        count += 1;
        bytes += connection.len();
        if count > 32 || bytes > 1024 {
            return (None, true);
        }
        if connection
            .as_bytes()
            .split(|byte| *byte == b',')
            .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"x-request-id"))
        {
            return (None, true);
        }
    }
    (
        Some(value.to_str().expect("ASCII request ID").into()),
        false,
    )
}

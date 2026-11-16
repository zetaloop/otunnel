use std::{
    fs::OpenOptions,
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{SyncSender, sync_channel},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{sync::oneshot, time::Instant};

use crate::{
    config,
    metrics::Metrics,
    protocol::{self, Command, Reply},
};

const COUNTERS: [&str; 7] = [
    "tunnel_client_tracing_commands_total",
    "tunnel_client_tracing_missing_total",
    "tunnel_client_tracing_invalid_total",
    "tunnel_client_tracing_unsampled_total",
    "tunnel_client_tracing_exported_total",
    "tunnel_client_tracing_dropped_total",
    "tunnel_client_tracing_failed_total",
];
const SCOPE: &str = "tunnel-client/tracing";

pub(crate) struct Recorder {
    config: config::Tracing,
    metrics: Arc<Metrics>,
    sender: Mutex<Option<SyncSender<Record>>>,
    done: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
    abort: Arc<AtomicBool>,
}
impl Recorder {
    pub fn new(config: &config::Tracing, metrics: Arc<Metrics>) -> Self {
        if config.enabled {
            for name in COUNTERS {
                metrics.add(SCOPE, name, &[], 0);
            }
        }
        Self {
            config: config.clone(),
            metrics,
            sender: Mutex::new(None),
            done: tokio::sync::Mutex::new(None),
            abort: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn enabled(&self) -> bool {
        self.config.enabled
    }
    pub fn start(&self) -> Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&self.config.file)
            .context("create new local trace file")?;
        let (sender, receiver) = sync_channel::<Record>(1024);
        let (finished, done) = oneshot::channel();
        let metrics = self.metrics.clone();
        let abort = self.abort.clone();
        std::thread::Builder::new()
            .name("otunnel-trace".into())
            .spawn(move || {
                let mut written = 0;
                let mut failed = false;
                for record in receiver {
                    if failed || abort.load(Ordering::Acquire) {
                        metrics.increment(SCOPE, COUNTERS[5], &[]);
                        continue;
                    }
                    let result = (|| -> Result<()> {
                        let mut bytes = serde_json::to_vec(&record)?;
                        bytes.push(b'\n');
                        anyhow::ensure!(
                            written + bytes.len() <= 64 * 1024 * 1024,
                            "local trace file limit reached"
                        );
                        file.write_all(&bytes)?;
                        written += bytes.len();
                        Ok(())
                    })();
                    if result.is_err() {
                        metrics.increment(SCOPE, COUNTERS[6], &[]);
                        failed = true;
                    } else {
                        metrics.increment(SCOPE, COUNTERS[4], &[]);
                    }
                }
                drop(file);
                let _ = finished.send(());
            })?;
        *self.sender.lock().expect("trace mutex poisoned") = Some(sender);
        *self.done.try_lock().expect("trace startup") = Some(done);
        Ok(())
    }
    pub async fn shutdown(&self) -> Result<()> {
        self.sender.lock().expect("trace mutex poisoned").take();
        if let Some(done) = self.done.lock().await.take()
            && tokio::time::timeout(Duration::from_secs(1), done)
                .await
                .is_err()
        {
            self.abort.store(true, Ordering::Release);
            anyhow::bail!("local trace shutdown timed out");
        }
        Ok(())
    }
    fn export(&self, record: Record) {
        if self
            .sender
            .lock()
            .expect("trace mutex poisoned")
            .as_ref()
            .is_none_or(|sender| sender.try_send(record).is_err())
        {
            self.metrics.increment(SCOPE, COUNTERS[5], &[]);
        }
    }
    pub fn command(self: &Arc<Self>, command: &Command) -> Option<CommandTrace> {
        if !self.enabled() {
            return None;
        }
        self.metrics.increment(SCOPE, COUNTERS[0], &[]);
        let carrier = command
            .trace_context
            .as_deref()
            .filter(|_| command.command_type == "jsonrpc")
            .and_then(super::carrier);
        let Some((parent, _)) = carrier else {
            self.metrics.increment(SCOPE, COUNTERS[1], &[]);
            return None;
        };
        if !super::valid_parent(&parent) {
            self.metrics.increment(SCOPE, COUNTERS[2], &[]);
            return None;
        }
        let flags = u8::from_str_radix(&parent[53..], 16).expect("validated trace flags");
        if flags & 1 == 0 {
            self.metrics.increment(SCOPE, COUNTERS[3], &[]);
        }
        Some(CommandTrace {
            dispatch: Span::new(
                self.clone(),
                "tunnel.client.dispatch",
                &parent[3..35],
                &parent[36..52],
                flags,
            ),
            target: Mutex::new(None),
            completed: AtomicBool::new(false),
        })
    }
}

pub(crate) struct CommandTrace {
    dispatch: Span,
    target: Mutex<Option<Span>>,
    completed: AtomicBool,
}
impl CommandTrace {
    pub fn target(&self) -> String {
        let target = self.dispatch.child("tunnel.client.mcp");
        let carrier = target.carrier();
        *self.target.lock().expect("trace mutex poisoned") = Some(target);
        carrier
    }
    pub fn upload(&self, reply: &Reply) -> Span {
        if reply.status >= 400
            || reply.message.as_deref().is_some_and(|message| {
                protocol::view(message).is_ok_and(|message| message.error.is_some())
            })
        {
            self.fail();
        }
        if reply.kind != "jsonrpc_notify" {
            self.target.lock().expect("trace mutex poisoned").take();
        }
        self.dispatch.child("tunnel.client.upload")
    }
    pub fn fail(&self) {
        self.dispatch.fail();
        if let Some(target) = self.target.lock().expect("trace mutex poisoned").as_ref() {
            target.fail();
        }
    }
    pub fn complete(&self) {
        self.completed.store(true, Ordering::Release);
    }
}
impl Drop for CommandTrace {
    fn drop(&mut self) {
        if !self.completed.load(Ordering::Acquire) {
            self.fail();
        }
        self.target.get_mut().expect("trace mutex poisoned").take();
    }
}

#[derive(Serialize)]
struct Record {
    name: &'static str,
    trace_id: String,
    span_id: String,
    parent_span_id: String,
    start_time: String,
    end_time: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_ms: Option<f64>,
}
pub(crate) struct Span {
    recorder: Arc<Recorder>,
    record: Option<Record>,
    started: Instant,
    flags: u8,
    failed: AtomicBool,
}
impl Span {
    fn new(
        recorder: Arc<Recorder>,
        name: &'static str,
        trace: &str,
        parent: &str,
        flags: u8,
    ) -> Self {
        Self {
            recorder,
            started: Instant::now(),
            flags,
            failed: AtomicBool::new(false),
            record: Some(Record {
                name,
                trace_id: trace.into(),
                span_id: format!("{:016x}", rand::random::<u64>().max(1)),
                parent_span_id: parent.into(),
                start_time: timestamp(),
                end_time: String::new(),
                status: "Unset",
                attempt: None,
                http_status: None,
                outcome: None,
                elapsed_ms: None,
            }),
        }
    }
    fn child(&self, name: &'static str) -> Self {
        let parent = self.record.as_ref().expect("active trace span");
        Self::new(
            self.recorder.clone(),
            name,
            &parent.trace_id,
            &parent.span_id,
            self.flags,
        )
    }
    fn carrier(&self) -> String {
        let record = self.record.as_ref().expect("active trace span");
        format!(
            "00-{}-{}-{:02x}",
            record.trace_id, record.span_id, self.flags
        )
    }
    pub fn fail(&self) {
        self.failed.store(true, Ordering::Release);
    }
    pub fn attempt(&self, attempt: u32) -> Self {
        let mut span = self.child("tunnel.client.upload_attempt");
        span.record.as_mut().expect("new trace span").attempt = Some(attempt);
        span
    }
    pub fn outcome(&mut self, status: u16, outcome: &'static str) {
        let outcome = match outcome {
            "accepted"
            | "already_fulfilled_or_unknown"
            | "http_error"
            | "timeout"
            | "canceled"
            | "network_error" => outcome,
            _ => "request_error",
        };
        if let Some(record) = &mut self.record {
            record.http_status = (100..600).contains(&status).then_some(status);
            record.outcome = Some(outcome);
            if !matches!(outcome, "accepted" | "already_fulfilled_or_unknown") {
                self.fail();
            }
            self.finish();
        }
    }
    fn finish(&mut self) {
        let Some(mut record) = self.record.take() else {
            return;
        };
        if self.flags & 1 == 0 {
            return;
        }
        if record.attempt.is_some() {
            if record.outcome.is_none() {
                record.outcome = Some("canceled");
                self.fail();
            }
            record.elapsed_ms = Some(self.started.elapsed().as_secs_f64() * 1000.0);
        }
        record.end_time = timestamp();
        record.status = if self.failed.load(Ordering::Acquire) {
            "Error"
        } else {
            "Unset"
        };
        self.recorder.export(record);
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        self.finish();
    }
}
fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("UTC trace timestamp")
}

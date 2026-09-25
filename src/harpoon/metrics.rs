use std::time::Instant;

use super::Harpoon;

pub(super) struct Call<'a> {
    harpoon: &'a Harpoon,
    started: Instant,
    template: bool,
    pub label: String,
    pub status: u16,
    pub bytes: usize,
    pub outcome: &'static str,
}

impl<'a> Call<'a> {
    pub fn new(harpoon: &'a Harpoon, template: bool) -> Self {
        Self {
            harpoon,
            started: Instant::now(),
            template,
            label: "__unknown__".into(),
            status: 0,
            bytes: 0,
            outcome: "invalid_input",
        }
    }
}

impl Drop for Call<'_> {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        let status = if (100..600).contains(&self.status) {
            format!("{}xx", self.status / 100)
        } else {
            "none".into()
        };
        let attributes = [
            ("label", self.label.as_str()),
            ("status_class", status.as_str()),
            ("outcome", self.outcome),
        ];
        self.harpoon
            .metrics
            .increment("harpoon", "harpoon_call_total", &attributes);
        self.harpoon.metrics.observe(
            "harpoon",
            "harpoon_call_latency_milliseconds",
            &attributes,
            elapsed.as_secs_f64() * 1000.0,
        );
        self.harpoon.metrics.observe(
            "harpoon",
            "harpoon_response_size_bytes",
            &attributes,
            self.bytes as f64,
        );
        if self.template {
            tracing::info!(component = "harpoon", label = %self.label, outcome = self.outcome, status_code = self.status, latency_ms = elapsed.as_millis() as u64, "harpoon template request completed");
        }
    }
}

impl Harpoon {
    pub fn metrics(&self) -> String {
        self.metrics.render()
    }
}

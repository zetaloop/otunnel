use std::{collections::BTreeMap, fmt::Write, sync::Mutex};

const BUCKETS: [f64; 15] = [
    0.0, 5.0, 10.0, 25.0, 50.0, 75.0, 100.0, 250.0, 500.0, 750.0, 1000.0, 2500.0, 5000.0, 7500.0,
    10000.0,
];

type Key = (&'static str, &'static str, String);

#[derive(Default)]
pub(crate) struct Metrics(Mutex<BTreeMap<Key, Metric>>);

enum Metric {
    Counter(u64),
    Histogram {
        count: u64,
        sum: f64,
        buckets: [u64; 15],
    },
}

impl Metrics {
    pub fn increment(&self, scope: &'static str, name: &'static str, attributes: &[(&str, &str)]) {
        let mut metrics = self.0.lock().expect("metrics mutex poisoned");
        let metric = metrics
            .entry((name, scope, labels(attributes)))
            .or_insert(Metric::Counter(0));
        if let Metric::Counter(count) = metric {
            *count += 1;
        }
    }

    pub fn observe(
        &self,
        scope: &'static str,
        name: &'static str,
        attributes: &[(&str, &str)],
        value: f64,
    ) {
        let mut metrics = self.0.lock().expect("metrics mutex poisoned");
        let metric =
            metrics
                .entry((name, scope, labels(attributes)))
                .or_insert(Metric::Histogram {
                    count: 0,
                    sum: 0.0,
                    buckets: [0; 15],
                });
        if let Metric::Histogram {
            count,
            sum,
            buckets,
        } = metric
        {
            *count += 1;
            *sum += value;
            for (bound, count) in BUCKETS.iter().zip(buckets) {
                if value <= *bound {
                    *count += 1;
                }
            }
        }
    }

    pub fn render(&self) -> String {
        let metrics = self.0.lock().expect("metrics mutex poisoned");
        let mut output = String::new();
        let mut previous = "";
        for ((name, scope, attributes), metric) in metrics.iter() {
            if previous != *name {
                let kind = match metric {
                    Metric::Counter(_) => "counter",
                    Metric::Histogram { .. } => "histogram",
                };
                writeln!(output, "# TYPE {name} {kind}").expect("metric output");
                previous = name;
            }
            let labels = format!(
                "{attributes}otel_scope_name={scope:?},otel_scope_schema_url=\"\",otel_scope_version=\"\""
            );
            match metric {
                Metric::Counter(count) => {
                    writeln!(output, "{name}{{{labels}}} {count}").expect("metric output");
                }
                Metric::Histogram {
                    count,
                    sum,
                    buckets,
                } => {
                    for (bound, count) in BUCKETS.iter().zip(buckets) {
                        writeln!(output, "{name}_bucket{{{labels},le=\"{bound}\"}} {count}")
                            .expect("metric output");
                    }
                    writeln!(output, "{name}_bucket{{{labels},le=\"+Inf\"}} {count}\n{name}_sum{{{labels}}} {sum}\n{name}_count{{{labels}}} {count}").expect("metric output");
                }
            }
        }
        output
    }
}

fn labels(attributes: &[(&str, &str)]) -> String {
    let mut attributes = attributes.to_vec();
    attributes.sort_unstable();
    attributes
        .into_iter()
        .map(|(key, value)| {
            let value = value
                .replace('\\', "\\\\")
                .replace('\n', "\\n")
                .replace('"', "\\\"");
            format!("{key}=\"{value}\",")
        })
        .collect()
}

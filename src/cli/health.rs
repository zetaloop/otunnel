use std::{fs, time::Duration};

use anyhow::{Context, Result};
use clap::{Arg, ArgMatches, Command};
use otunnel::{health::Target, process};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Default, Serialize)]
struct Endpoint {
    #[serde(skip_serializing_if = "String::is_empty")]
    url: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "String::is_empty")]
    body: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

pub fn command() -> Command {
    Command::new("health")
        .about("Probe /healthz and /readyz for a live daemon")
        .arg(
            Arg::new("url")
                .long("url")
                .help("Health base URL or /healthz or /readyz URL"),
        )
        .arg(
            Arg::new("url-file")
                .long("url-file")
                .help("File containing the health base URL"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_parser(clap::value_parser!(i64))
                .allow_negative_numbers(true)
                .default_value("0"),
        )
        .arg(
            Arg::new("pid")
                .long("pid")
                .value_parser(clap::value_parser!(i64))
                .allow_negative_numbers(true)
                .default_value("0"),
        )
        .arg(Arg::new("pid-file").long("pid-file"))
        .arg(super::flag("json"))
        .arg(super::flag("require-control-plane-poll"))
}

pub async fn execute(arguments: &ArgMatches) -> Result<u8> {
    let text = |name| {
        arguments
            .get_one::<String>(name)
            .map_or("", |value| value.trim())
    };
    let url = text("url");
    let file = text("url-file");
    let port = *arguments.get_one::<i64>("port").expect("default port");
    let pid = *arguments.get_one::<i64>("pid").expect("default PID");
    let pid_file = text("pid-file");
    anyhow::ensure!(
        usize::from(!url.is_empty()) + usize::from(!file.is_empty()) + usize::from(port != 0) == 1,
        "choose exactly one of --url, --url-file, or --port"
    );
    anyhow::ensure!(port >= 0, "--port must be positive");
    anyhow::ensure!(pid >= 0, "--pid must be positive");
    anyhow::ensure!(
        pid == 0 || pid_file.is_empty(),
        "choose at most one of --pid or --pid-file"
    );
    let (mut locator, resolved) = if !url.is_empty() {
        (json!({"kind":"url","url":url}), Ok(url.to_owned()))
    } else if !file.is_empty() {
        (
            json!({"kind":"url_file","url_file":file}),
            fs::read_to_string(file).with_context(|| format!("read {file}")),
        )
    } else {
        (
            json!({"kind":"port","port":port}),
            Ok(format!("http://127.0.0.1:{port}")),
        )
    };
    let base = match resolved {
        Ok(value) => {
            let base = Target::normalize(&value);
            if base.is_empty() {
                locator["error"] = json!("health URL is empty after normalization");
            } else {
                locator["resolved_base_url"] = json!(base);
            }
            base
        }
        Err(error) => {
            locator["error"] = json!(format!("{error:#}"));
            String::new()
        }
    };
    let mut report = json!({"locator":locator,"healthz":Endpoint::default(),"readyz":Endpoint::default(),"result":"fail"});
    let mut passed = !base.is_empty();
    if !base.is_empty() {
        report["base_url"] = json!(base);
        for (key, path) in [("healthz", "/healthz"), ("readyz", "/readyz")] {
            let endpoint = probe(&base, path).await;
            passed &= endpoint.ok;
            report[key] = serde_json::to_value(endpoint)?;
        }
        if arguments.get_flag("require-control-plane-poll") {
            let metric = metric(&base).await;
            passed &= metric["ok"] == true;
            report["control_plane_poll"] = metric;
        }
    }
    if pid > 0 || !pid_file.is_empty() {
        let mut process = json!({"running":false});
        let resolved = if pid_file.is_empty() {
            Ok(pid)
        } else {
            process["pid_file"] = json!(pid_file);
            fs::read_to_string(pid_file)
                .with_context(|| format!("read {pid_file}"))
                .and_then(|value| {
                    value
                        .trim()
                        .parse::<i64>()
                        .with_context(|| format!("parse {pid_file} as pid: {value:?}"))
                })
        };
        match resolved.and_then(|value| {
            anyhow::ensure!(value > 0, "PID must be positive");
            Ok(value)
        }) {
            Ok(pid) => {
                process["pid"] = json!(pid);
                process["running"] = json!(u32::try_from(pid).is_ok_and(process::running));
            }
            Err(error) => process["error"] = json!(format!("{error:#}")),
        }
        passed &= process["running"] == true;
        report["process"] = process;
    }
    if passed {
        report["result"] = json!("ok");
    }
    if arguments.get_flag("json") {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print(&report);
    }
    Ok(if passed { 0 } else { 2 })
}

async fn probe(base: &str, path: &str) -> Endpoint {
    let mut endpoint = Endpoint {
        url: format!("{base}{path}"),
        ..Default::default()
    };
    let outcome = async {
        Target::new(base)?
            .request(path, Duration::from_millis(500), Some(4096))
            .await
    }
    .await;
    match outcome {
        Ok((status, body)) => {
            endpoint.ok = (200..300).contains(&status);
            endpoint.status = Some(status);
            endpoint.body = String::from_utf8_lossy(&body).trim().to_owned();
        }
        Err(error) => endpoint.error = format!("{error:#}"),
    }
    endpoint
}

async fn metric(base: &str) -> Value {
    let mut probe = json!({"url":format!("{base}/metrics"),"ok":false});
    let outcome = async {
        let (code, body) = Target::new(base)?
            .request("/metrics", Duration::from_secs(2), None)
            .await?;
        anyhow::ensure!(code == 200, "metrics returned HTTP {code}");
        let body = String::from_utf8_lossy(&body);
        let name = "commands_poll_last_successful_timestamp_seconds";
        for line in body.lines().map(str::trim) {
            anyhow::ensure!(line.len() <= 1 << 20, "metrics line exceeds 1 MiB");
            if let Some(rest) = line.strip_prefix(name)
                && (rest.starts_with(' ') || rest.starts_with('{'))
                && let Some(value) = line
                    .split_whitespace()
                    .next_back()
                    .and_then(|value| value.parse::<f64>().ok())
            {
                return Ok(value);
            }
        }
        anyhow::bail!("missing {name} metric")
    }
    .await;
    match outcome {
        Ok(value) => {
            if value != 0.0 {
                probe["value"] = json!(value);
            }
            probe["ok"] = json!(value > 0.0);
            if value <= 0.0 {
                probe["error"] = json!("no successful control-plane poll observed");
            }
        }
        Err(error) => probe["error"] = json!(format!("{error:#}")),
    }
    probe
}

fn print(report: &Value) {
    let text = |value: &Value| value.as_str().unwrap_or_default().to_owned();
    let locator = &report["locator"];
    let field = match locator["kind"].as_str() {
        Some("url_file") => "url_file",
        Some("port") => "port",
        _ => "url",
    };
    let value = locator[field]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| locator[field].to_string());
    println!("Locator: {field}={value}");
    if locator["error"].is_string() {
        println!("Locator error: {}", text(&locator["error"]));
    }
    if let Some(base) = report["base_url"].as_str() {
        println!("Base URL: {base}");
    }
    for (label, key) in [
        ("Healthz", "healthz"),
        ("Readyz", "readyz"),
        ("Control-plane poll", "control_plane_poll"),
        ("Process", "process"),
    ] {
        let Some(value) = report.get(key) else {
            continue;
        };
        let passed = value["ok"] == true || value["running"] == true;
        let mut parts = vec![if passed {
            "PASS".to_owned()
        } else {
            "FAIL".to_owned()
        }];
        if value["url"].is_string() {
            parts.push(text(&value["url"]));
        }
        if let Some(status) = value["status"].as_u64() {
            parts.push(format!("HTTP {status}"));
        }
        if let Some(pid) = value["pid"].as_i64() {
            parts.push(format!("pid={pid}"));
        }
        if value["pid_file"].is_string() {
            parts.push(format!("pid_file={}", text(&value["pid_file"])));
        }
        if key == "control_plane_poll" && passed {
            parts.push(format!(
                "last_success_unix_seconds={:.0}",
                value["value"].as_f64().unwrap_or_default()
            ));
        }
        if value["error"].is_string() {
            parts.push(text(&value["error"]));
        } else if value["body"].is_string() {
            parts.push(text(&value["body"]));
        }
        println!("{label}: {}", parts.join(" | "));
    }
    println!("Result: {}", text(&report["result"]).to_ascii_uppercase());
}

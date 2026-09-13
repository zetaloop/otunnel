use std::{collections::BTreeSet, env};

use anyhow::{Context, Result};
use clap::{Arg, ArgAction, ArgMatches, Command};
use otunnel::{
    admin::{Client, RequestError, Tunnel},
    config,
};
use serde_json::{Value, json};

pub fn command() -> Command {
    let scope = |command: Command| {
        command
            .arg(
                Arg::new("organization-id")
                    .long("organization-id")
                    .action(ArgAction::Append),
            )
            .arg(
                Arg::new("workspace-id")
                    .long("workspace-id")
                    .action(ArgAction::Append),
            )
    };
    Command::new("admin")
        .about("Administrative operations for the tunnel control plane")
        .subcommand_required(true)
        .arg(
            Arg::new("control-plane.base-url")
                .long("control-plane.base-url")
                .env("CONTROL_PLANE_BASE_URL")
                .global(true)
                .default_value("https://api.openai.com"),
        )
        .arg(
            Arg::new("control-plane.url-path")
                .long("control-plane.url-path")
                .env("CONTROL_PLANE_URL_PATH")
                .global(true),
        )
        .arg(
            Arg::new("ca-bundle")
                .long("ca-bundle")
                .env("CA_BUNDLE")
                .global(true),
        )
        .arg(
            Arg::new("admin-key")
                .long("admin-key")
                .global(true)
                .hide_env_values(true),
        )
        .arg(super::flag("json").global(true))
        .subcommand(
            Command::new("tunnels")
                .about("Inspect or manage tunnels")
                .subcommand_required(true)
                .subcommand(scope(
                    Command::new("create")
                        .about("Create a tunnel")
                        .arg(Arg::new("name").long("name").required(true))
                        .arg(Arg::new("description").long("description").required(true)),
                ))
                .subcommand(
                    Command::new("get")
                        .about("Fetch a tunnel by id")
                        .arg(Arg::new("id").required(true)),
                )
                .subcommand(scope(
                    Command::new("list")
                        .about("List tunnels")
                        .arg(Arg::new("tenant-id").long("tenant-id")),
                ))
                .subcommand(
                    scope(
                        Command::new("update")
                            .about("Update a tunnel")
                            .arg(Arg::new("id").required(true))
                            .arg(Arg::new("name").long("name")),
                    )
                    .arg(Arg::new("description").long("description")),
                )
                .subcommand(scope(
                    Command::new("delete")
                        .about("Delete a tunnel")
                        .arg(Arg::new("id").required(true))
                        .arg(super::flag("confirm")),
                )),
        )
}

pub async fn execute(arguments: &ArgMatches) -> Result<u8> {
    let (_, group) = arguments.subcommand().context("missing admin command")?;
    let (command, arguments) = group.subcommand().context("missing tunnel command")?;
    let result = run(command, arguments).await;
    match result {
        Ok(()) => Ok(0),
        Err(error) if arguments.get_flag("json") => {
            let payload = error.downcast_ref::<RequestError>().map_or_else(
                || json!({"error":{"message":format!("{error:#}")}}),
                RequestError::payload,
            );
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(1)
        }
        Err(error) => Err(error),
    }
}

async fn run(command: &str, arguments: &ArgMatches) -> Result<()> {
    if command == "delete" {
        anyhow::ensure!(
            arguments.get_flag("confirm"),
            "refusing to delete without --confirm"
        );
    }
    if command == "create" {
        anyhow::ensure!(
            !super::value(arguments, "name").trim().is_empty(),
            "name is required (set --name)"
        );
        anyhow::ensure!(
            !super::value(arguments, "description").trim().is_empty(),
            "description is required (set --description)"
        );
    }
    let organizations = strings(arguments, "organization-id")?;
    let workspaces = strings(arguments, "workspace-id")?;
    let client = client(arguments, command == "get")?;
    let json = arguments.get_flag("json");
    let id = super::value(arguments, "id");
    match command {
        "create" => {
            anyhow::ensure!(
                !organizations.is_empty() || !workspaces.is_empty(),
                "at least one of --organization-id or --workspace-id is required"
            );
            let mut body = json!({"name":super::value(arguments,"name"),"description":super::value(arguments,"description")});
            if !organizations.is_empty() {
                body["organization_ids"] = json!(organizations);
            }
            if !workspaces.is_empty() {
                body["workspace_ids"] = json!(workspaces);
            }
            print(&client.create(body).await?, json)?;
            if !json {
                println!(
                    "Note: wait 25-30 seconds before expecting a newly created tunnel to be active and ready."
                );
            }
        }
        "get" => print(&client.get(id).await?, json)?,
        "list" => {
            let tenant = super::value(arguments, "tenant-id");
            anyhow::ensure!(
                usize::from(!organizations.is_empty())
                    + usize::from(!workspaces.is_empty())
                    + usize::from(!tenant.is_empty())
                    == 1,
                "provide exactly one of --organization-id, --workspace-id, or --tenant-id"
            );
            let list = client
                .list(
                    organizations.first().map_or("", String::as_str),
                    workspaces.first().map_or("", String::as_str),
                    tenant,
                )
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                for tunnel in list.tunnels.unwrap_or_default() {
                    print(&tunnel, false)?;
                }
            }
        }
        "update" => {
            let mut body = serde_json::Map::new();
            for name in ["name", "description"] {
                if arguments.value_source(name) == Some(clap::parser::ValueSource::CommandLine) {
                    let value = super::value(arguments, name);
                    body.insert(
                        name.into(),
                        json!(if name == "name" { value.trim() } else { value }),
                    );
                }
            }
            for (flag, key, values) in [
                ("organization-id", "organization_ids", organizations),
                ("workspace-id", "workspace_ids", workspaces),
            ] {
                if arguments.value_source(flag) == Some(clap::parser::ValueSource::CommandLine) {
                    body.insert(key.into(), json!(values));
                }
            }
            anyhow::ensure!(!body.is_empty(), "provide at least one field to update");
            print(&client.update(id, Value::Object(body)).await?, json)?;
        }
        "delete" => print(&client.delete(id).await?, json)?,
        _ => unreachable!(),
    }
    Ok(())
}

pub(super) fn strings(arguments: &ArgMatches, name: &str) -> Result<Vec<String>> {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for argument in arguments
        .try_get_many::<String>(name)
        .ok()
        .flatten()
        .into_iter()
        .flatten()
    {
        if argument.is_empty() {
            continue;
        }
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(argument.as_bytes());
        if let Some(record) = reader.records().next() {
            for value in &record? {
                let value = value.trim();
                if value.is_empty() {
                    continue;
                }
                anyhow::ensure!(
                    seen.insert(value.to_owned()),
                    "duplicate {name} values: {value}"
                );
                result.push(value.to_owned());
            }
        }
    }
    Ok(result)
}

fn client(arguments: &ArgMatches, read_only: bool) -> Result<Client> {
    let reference = super::value(arguments, "admin-key");
    let admin = env::var("OPENAI_ADMIN_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let key = if read_only && admin.is_none() && matches!(reference, "" | "env:OPENAI_ADMIN_KEY") {
        env::var("CONTROL_PLANE_API_KEY").ok().filter(|value| !value.trim().is_empty())
            .or_else(|| env::var("OPENAI_API_KEY").ok().filter(|value| !value.trim().is_empty()))
            .context("tunnel get requires a runtime or admin key; set CONTROL_PLANE_API_KEY, OPENAI_API_KEY, OPENAI_ADMIN_KEY, or --admin-key")?
    } else if reference.is_empty() {
        admin.context("admin key is required; set --admin-key or OPENAI_ADMIN_KEY")?
    } else {
        anyhow::ensure!(
            reference.starts_with("env:") || reference.starts_with("file:"),
            "admin-key must use env: or file: prefixes"
        );
        config::resolve(reference)?
    };
    let base = super::value(arguments, "control-plane.base-url");
    let prefix = super::value(arguments, "control-plane.url-path");
    let ca = super::value(arguments, "ca-bundle");
    Client::new(base, prefix, key.trim(), (!ca.is_empty()).then_some(ca))
}

fn print(tunnel: &Tunnel, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(tunnel)?);
        return Ok(());
    }
    println!(
        "Tunnel {}\n  Name: {}\n  Description: {}",
        tunnel.id, tunnel.name, tunnel.description
    );
    if !tunnel.creator.is_empty() {
        println!("  Creator: {}", tunnel.creator);
    }
    println!(
        "  Organizations: {}\n  Workspaces: {}",
        tunnel.organization_ids.join(", "),
        tunnel.workspace_ids.join(", ")
    );
    if !tunnel.tenant_ids.is_empty() {
        println!("  Tenants: {}", tunnel.tenant_ids.join(", "));
    }
    Ok(())
}

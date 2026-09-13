use anyhow::{Context, Result};
use clap::{Arg, ArgAction, ArgMatches, Command};
use otunnel::management::{
    Manager,
    runtimes::{Connect, Create, Outcome, Remote, Scope},
};

use super::{flag, value};

pub fn profiles_command() -> Command {
    Command::new("admin-profiles")
        .about("Manage admin profiles used by runtimes commands")
        .subcommand_required(true)
        .arg(flag("json").global(true))
        .subcommand(Command::new("list").about("List saved admin profiles"))
        .subcommand(
            Command::new("set")
                .about("Create or update an admin profile")
                .arg(Arg::new("name").required(true))
                .arg(Arg::new("control-plane-base-url").long("control-plane-base-url"))
                .arg(Arg::new("control-plane-url-path").long("control-plane-url-path"))
                .arg(Arg::new("admin-key").long("admin-key"))
                .arg(flag("activate").default_value("true")),
        )
        .subcommand(
            Command::new("activate")
                .about("Mark an existing profile as active")
                .arg(Arg::new("name").required(true)),
        )
        .subcommand(
            Command::new("delete")
                .about("Delete an unused admin profile")
                .arg(Arg::new("name").required(true)),
        )
}

pub fn profiles(arguments: &ArgMatches) -> Result<u8> {
    let (action, arguments) = arguments
        .subcommand()
        .context("missing admin-profiles command")?;
    let manager = Manager::default();
    let name = value(arguments, "name");
    let result = match action {
        "list" => manager.profiles()?,
        "set" => manager.set_profile(
            name,
            value(arguments, "control-plane-base-url"),
            value(arguments, "control-plane-url-path"),
            value(arguments, "admin-key"),
            arguments.get_flag("activate"),
        )?,
        "activate" => manager.activate_profile(name)?,
        "delete" => manager.delete_profile(name)?,
        _ => unreachable!(),
    };
    if arguments.get_flag("json") {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        match action {
            "list" => {
                let profiles = result["profiles"]
                    .as_array()
                    .context("profile list is missing")?;
                if profiles.is_empty() {
                    println!(
                        "No admin profiles found in {}",
                        result["path"].as_str().unwrap_or_default()
                    );
                }
                for profile in profiles {
                    println!(
                        "{}\t{}{}",
                        profile["name"].as_str().unwrap_or_default(),
                        profile["control_plane_base_url"]
                            .as_str()
                            .unwrap_or_default(),
                        if profile["active"] == true {
                            "\t(active)"
                        } else {
                            ""
                        }
                    );
                }
            }
            "set" => println!(
                "Saved admin profile {} ({})",
                result["profile"]["name"].as_str().unwrap_or_default(),
                result["profile"]["control_plane_base_url"]
                    .as_str()
                    .unwrap_or_default()
            ),
            "activate" => println!(
                "Activated admin profile {}",
                result["profile"]["name"].as_str().unwrap_or_default()
            ),
            "delete" => println!("Deleted admin profile {name}"),
            _ => unreachable!(),
        }
    }
    Ok(0)
}

pub fn runtimes_command() -> Command {
    let scope = |command: Command| {
        command.args(
            ["organization-id", "workspace-id"]
                .map(|name| Arg::new(name).long(name).action(ArgAction::Append)),
        )
    };
    let create = |name, about| {
        scope(
            Command::new(name)
                .about(about)
                .arg(Arg::new("alias").long("alias").required(true))
                .arg(Arg::new("name").long("name"))
                .arg(Arg::new("description").long("description")),
        )
    };
    Command::new("runtimes")
        .about("Manage native tunnel-client runtimes")
        .subcommand_required(true)
        .args(
            [
                "admin-profile",
                "admin-key",
                "control-plane-base-url",
                "control-plane-url-path",
            ]
            .map(|name| Arg::new(name).long(name).global(true)),
        )
        .arg(flag("json").global(true))
        .subcommand(create("create", "Create or reuse a remote tunnel alias"))
        .subcommand(
            create(
                "connect",
                "Create or reuse a tunnel alias and run a native profile locally",
            )
            .args(
                [
                    "tunnel-id",
                    "profile",
                    "profile-dir",
                    "mcp-server-url",
                    "mcp-command",
                    "runtime-api-key",
                    "tunnel-client-bin",
                ]
                .map(|name| Arg::new(name).long(name)),
            ),
        )
        .subcommand(
            scope(Command::new("list").about("List local aliases and remote scoped tunnels"))
                .arg(Arg::new("tenant-id").long("tenant-id")),
        )
        .subcommand(
            Command::new("cleanup")
                .about("Inspect and optionally remove stale local runtime alias metadata")
                .arg(flag("apply")),
        )
        .subcommand(
            Command::new("status")
                .about("Inspect a local alias and its runtime state")
                .arg(Arg::new("alias").required(true)),
        )
        .subcommand(
            Command::new("stop")
                .visible_alias("disconnect")
                .about("Stop the managed local runtime for an alias")
                .arg(Arg::new("alias").required(true)),
        )
        .subcommand(
            Command::new("rm")
                .visible_alias("remove")
                .about("Remove local runtime metadata")
                .arg(Arg::new("alias").required(true)),
        )
}

pub async fn runtimes(arguments: &ArgMatches) -> Result<u8> {
    let (action, arguments) = arguments.subcommand().context("missing runtimes command")?;
    let manager = Manager::default();
    let alias = value(arguments, "alias");
    let remote = Remote {
        profile: value(arguments, "admin-profile").into(),
        key: value(arguments, "admin-key").into(),
        base_url: value(arguments, "control-plane-base-url").into(),
        url_path: value(arguments, "control-plane-url-path").into(),
    };
    let scope = Scope {
        organizations: scope_values(arguments, "organization-id")?,
        workspaces: scope_values(arguments, "workspace-id")?,
        tenant: value(arguments, "tenant-id").into(),
    };
    let outcome = match action {
        "create" | "connect" => {
            let create = Create {
                alias: alias.into(),
                name: value(arguments, "name").into(),
                description: value(arguments, "description").into(),
                remote,
                scope,
            };
            if action == "create" {
                Outcome {
                    payload: manager.create(create).await?,
                    code: 0,
                }
            } else {
                manager
                    .connect(Connect {
                        create,
                        tunnel_id: value(arguments, "tunnel-id").into(),
                        profile: value(arguments, "profile").into(),
                        profile_dir: value(arguments, "profile-dir").into(),
                        server_url: value(arguments, "mcp-server-url").into(),
                        command: value(arguments, "mcp-command").into(),
                        key: value(arguments, "runtime-api-key").into(),
                        binary: value(arguments, "tunnel-client-bin").into(),
                    })
                    .await?
            }
        }
        "list" => Outcome {
            payload: manager.list(remote, scope).await?,
            code: 0,
        },
        "cleanup" => Outcome {
            payload: manager.cleanup(arguments.get_flag("apply")).await?,
            code: 0,
        },
        "status" => manager.status(alias, remote).await?,
        "stop" => manager.stop(alias, remote).await?,
        "rm" => Outcome {
            payload: manager.remove(alias)?,
            code: 0,
        },
        _ => unreachable!(),
    };
    let payload = outcome.payload;
    if arguments.get_flag("json") {
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(outcome.code);
    }
    if outcome.code != 0 {
        for name in ["error", "remote_error"] {
            if let Some(error) = payload[name].as_str().filter(|value| !value.is_empty()) {
                anyhow::bail!("{error}");
            }
        }
        return Ok(outcome.code);
    }
    let text = |name: &str| payload[name].as_str().unwrap_or_default();
    match action {
        "create" => println!(
            "Created alias {} for tunnel {}",
            text("alias"),
            payload["tunnel"]["id"].as_str().unwrap_or_default(),
        ),
        "connect" => println!("Connected {} using {} mode", text("alias"), text("mode")),
        "list" | "cleanup" => {
            let entries = payload[if action == "list" {
                "aliases"
            } else {
                "entries"
            }]
            .as_array()
            .context("runtime entries are missing")?;
            if entries.is_empty() {
                println!("No runtime aliases found in {}", text("state_root"));
                return Ok(0);
            }
            for entry in entries {
                let alias = entry["alias"].as_str().unwrap_or_default();
                let tunnel = entry["tunnel_id"].as_str().unwrap_or_default();
                if action == "cleanup" {
                    println!(
                        "{alias}\t{}\t{tunnel}",
                        entry["classification"].as_str().unwrap_or_default()
                    );
                } else {
                    println!("{alias}\t{tunnel}");
                }
            }
            if action == "cleanup" && !arguments.get_flag("apply") {
                println!(
                    "Dry run only. Re-run with --apply to remove entries classified as stale_alias."
                );
            }
        }
        "status" => println!(
            "{}\t{}\t{}",
            text("alias"),
            text("runtime_state"),
            text("tunnel_id")
        ),
        "stop" => println!("Stopped {alias}"),
        "rm" => println!("Removed local runtime metadata for {alias}"),
        _ => unreachable!(),
    }
    Ok(0)
}

fn scope_values(arguments: &ArgMatches, name: &str) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for argument in arguments
        .try_get_many::<String>(name)
        .ok()
        .flatten()
        .into_iter()
        .flatten()
    {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(argument.as_bytes());
        if let Some(record) = reader.records().next() {
            result.extend(record?.iter().map(str::to_owned));
        }
    }
    Ok(result)
}

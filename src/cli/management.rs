use anyhow::{Context, Result};
use clap::{Arg, ArgMatches, Command};
use otunnel::management::Manager;

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

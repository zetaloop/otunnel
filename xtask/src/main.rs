use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use xshell::{Shell, cmd};
use zip::{ZipWriter, write::SimpleFileOptions};

const TARGETS: &[(&str, &str)] = &[
    ("x86_64-pc-windows-msvc", "windows-latest"),
    ("aarch64-pc-windows-msvc", "windows-11-arm"),
    ("x86_64-apple-darwin", "macos-26-intel"),
    ("aarch64-apple-darwin", "macos-latest"),
    ("x86_64-unknown-linux-gnu", "ubuntu-latest"),
    ("aarch64-unknown-linux-gnu", "ubuntu-24.04-arm"),
];

#[derive(Parser)]
#[command(about = "Build tasks for otunnel")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Print the release job matrix
    Matrix,
    /// Build and package the native release into dist/
    Dist,
}

fn main() -> Result<()> {
    let shell = Shell::new()?;
    shell.change_dir(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("workspace root is unavailable")?,
    );
    match Cli::parse().command {
        Task::Matrix => {
            let include: Vec<_> = TARGETS
                .iter()
                .map(|(target, os)| json!({"target":target,"os":os}))
                .collect();
            println!("{}", json!({"include":include}));
        }
        Task::Dist => dist(&shell)?,
    }
    Ok(())
}

fn dist(shell: &Shell) -> Result<()> {
    let target = cmd!(shell, "rustc --print=host-tuple").read()?;
    let metadata: Value = serde_json::from_str(
        &cmd!(
            shell,
            "cargo metadata --no-deps --format-version 1 --locked"
        )
        .read()?,
    )?;
    let package = metadata["packages"]
        .as_array()
        .context("missing Cargo packages")?
        .iter()
        .find(|package| package["name"] == "otunnel")
        .context("missing otunnel package")?;
    let version = package["version"]
        .as_str()
        .context("missing package version")?;
    if std::env::var("GITHUB_REF_TYPE").as_deref() == Ok("tag") {
        anyhow::ensure!(
            std::env::var("GITHUB_REF_NAME")? == format!("v{version}"),
            "release tag does not match Cargo version {version}"
        );
    }
    cmd!(shell, "cargo build --package otunnel --release --locked").run()?;
    let executable = if cfg!(windows) {
        "otunnel.exe"
    } else {
        "otunnel"
    };
    let binary = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .context("missing target directory")?,
    )
    .join("release")
    .join(executable);
    let mut entries = vec![(executable.to_owned(), fs::read(&binary)?, 0o755)];
    for filename in ["LICENSE", "README.md", "examples/embedded.rs"] {
        entries.push((filename.to_owned(), fs::read(filename)?, 0o644));
    }
    let mut docs: Vec<_> = fs::read_dir("docs")?.collect::<std::io::Result<_>>()?;
    docs.sort_by_key(|entry| entry.file_name());
    for document in docs {
        if document.file_type()?.is_file() {
            let filename = format!(
                "docs/{}",
                document
                    .file_name()
                    .to_str()
                    .context("non-UTF-8 document name")?
            );
            entries.push((filename, fs::read(document.path())?, 0o644));
        }
    }
    for (name, filename) in [
        ("bash", "otunnel.bash"),
        ("elvish", "otunnel.elv"),
        ("fish", "otunnel.fish"),
        ("powershell", "otunnel.ps1"),
        ("zsh", "_otunnel"),
    ] {
        entries.push((
            format!("completions/{filename}"),
            cmd!(shell, "{binary} completion {name}")
                .read()?
                .into_bytes(),
            0o644,
        ));
    }
    fs::create_dir_all("dist")?;
    let name = format!("dist/otunnel-{target}-v{version}");
    if cfg!(windows) {
        let filename = format!("{name}.zip");
        let mut archive = ZipWriter::new(File::create(&filename)?);
        for (name, bytes, mode) in entries {
            archive.start_file(name, SimpleFileOptions::default().unix_permissions(mode))?;
            archive.write_all(&bytes)?;
        }
        archive.finish()?;
        println!("{filename}");
    } else {
        let filename = format!("{name}.tar.gz");
        let mut archive = tar::Builder::new(GzEncoder::new(
            File::create(&filename)?,
            Compression::default(),
        ));
        for (name, bytes, mode) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(mode);
            header.set_cksum();
            archive.append_data(&mut header, name, bytes.as_slice())?;
        }
        archive.into_inner()?.finish()?;
        println!("{filename}");
    }
    Ok(())
}

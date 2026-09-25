use std::{path::Path, process::Command};

use anyhow::{Context, Result, bail};

const EDITORS: &[(&str, &[&str])] = &[
    ("vim", &["-f", "--nofork", "-n", "-R"]),
    ("nvim", &["-f", "--nofork", "-n", "-R"]),
    (
        "nano",
        &[
            "-w",
            "--nowrap",
            "-l",
            "--linenumbers",
            "-m",
            "--mouse",
            "-E",
            "--tabstospaces",
        ],
    ),
    (
        "emacs",
        &[
            "-nw",
            "--no-window-system",
            "-Q",
            "--quick",
            "-q",
            "--no-init-file",
            "--no-site-file",
        ],
    ),
    (
        "code",
        &[
            "-w",
            "--wait",
            "-n",
            "--new-window",
            "-r",
            "--reuse-window",
            "--disable-extensions",
        ],
    ),
    (
        "subl",
        &["-w", "--wait", "-n", "--new-window", "-b", "--background"],
    ),
    ("notepad", &[]),
    ("vi", &["-R", "-n"]),
];

pub(super) fn command(editor: &str, profile: &Path) -> Result<Command> {
    let parts = split(editor).context("invalid VISUAL or EDITOR")?;
    let selected = Path::new(&parts[0]);
    let mut name = selected
        .file_name()
        .context("editor executable is required")?
        .to_string_lossy()
        .to_lowercase();
    if cfg!(windows) {
        name = name.strip_suffix(".exe").unwrap_or(&name).into();
    }
    if name == "editor" {
        let alias = which::which(selected).context("find installed editor alias")?;
        name = EDITORS
            .iter()
            .find_map(|(name, _)| {
                let executable = which::which(name).ok()?;
                same_file::is_same_file(&alias, executable)
                    .ok()?
                    .then_some(*name)
            })
            .context("editor alias must select a supported editor installed in PATH")?
            .into();
    }
    let (_, allowed) = EDITORS.iter().find(|(editor, _)| *editor == name)
        .with_context(|| format!("unsupported profile editor {name:?}; use vi, vim, nvim, nano, emacs, code, subl, or notepad"))?;
    for argument in &parts[1..] {
        anyhow::ensure!(
            allowed.contains(&argument.as_str()),
            "unsupported option {argument:?} for profile editor {name:?}; shell commands and editor evaluation options are not allowed"
        );
    }
    let executable =
        which::which(&name).with_context(|| format!("find installed profile editor {name:?}"))?;
    if selected
        .file_name()
        .is_none_or(|file| file != selected.as_os_str())
    {
        anyhow::ensure!(
            same_file::is_same_file(&executable, selected)
                .context("inspect selected profile editor")?,
            "profile editor path must select the installed {name:?} executable found in PATH"
        );
    }
    let mut command = Command::new(executable);
    command.args(&parts[1..]).arg(std::path::absolute(profile)?);
    Ok(command)
}

fn split(value: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut part = String::new();
    let mut quote = None;
    let mut started = false;
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        anyhow::ensure!(
            !matches!(character, '\0' | '\n' | '\r'),
            "editor command must not contain control characters"
        );
        if character == '\\' && quote != Some('\'') && !cfg!(windows) {
            let escaped = characters.next().context("unterminated escape sequence")?;
            anyhow::ensure!(
                !matches!(escaped, '\0' | '\n' | '\r'),
                "editor command must not contain control characters"
            );
            part.push(escaped);
            started = true;
        } else if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            } else {
                part.push(character);
            }
        } else {
            match character {
                '\'' | '"' => {
                    quote = Some(character);
                    started = true;
                }
                ' ' | '\t' => {
                    if started {
                        parts.push(std::mem::take(&mut part));
                        started = false;
                    }
                }
                _ => {
                    part.push(character);
                    started = true;
                }
            }
        }
    }
    anyhow::ensure!(quote.is_none(), "unterminated quoted string");
    if started {
        parts.push(part);
    }
    if parts.first().is_none_or(String::is_empty) {
        bail!("editor executable is required");
    }
    Ok(parts)
}

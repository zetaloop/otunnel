use std::{env, path::Path, process::Stdio, time::Duration};

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::{
    process::{Child, Command},
    time::{Instant, sleep, timeout},
};

use super::{
    files::{self, Files},
    identity::Identity,
    inspect,
    state::{Alias, Process, Root},
};

#[derive(Default, Serialize)]
pub struct Launch {
    pub mode: &'static str,
    pub command: String,
    pub launched: bool,
    pub started: bool,
    pub running: bool,
    pub healthy: bool,
    pub ready: bool,
    pub already_running: bool,
    pub health_url: String,
    pub session_name: String,
    pub log_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub log_tail: String,
    #[serde(skip)]
    pub identity: Identity,
    #[serde(skip)]
    child: Option<Child>,
}
impl Drop for Launch {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.start_kill();
        }
    }
}
impl Launch {
    pub fn release(&mut self) {
        self.child.take();
    }
}

pub fn executable(explicit: &str) -> Result<std::path::PathBuf> {
    let current = env::current_exe()?;
    anyhow::ensure!(
        explicit.trim().is_empty() || same_file::is_same_file(&current, explicit.trim())?,
        "--tunnel-client-bin only accepts the current executable"
    );
    Ok(current)
}

pub async fn start(
    root: &Root,
    record: &Alias,
    previous: &Process,
    replace: bool,
    key: &str,
) -> Result<Launch> {
    let alias = record.alias.as_str();
    let profile = record.profile_name.as_str();
    let directory = Path::new(&record.profile_dir);
    let binary = env::current_exe()?;
    let directory = directory.to_string_lossy();
    let args = ["run", "--profile-dir", &directory, "--profile", profile];
    let command = shell_words::join(
        std::iter::once(binary.to_string_lossy().as_ref()).chain(args.iter().copied()),
    );
    let log_path = root.path.join("logs").join(format!("{alias}.log"));
    let mut launch = Launch {
        mode: "process",
        command,
        log_path: log_path.to_string_lossy().into_owned(),
        launched: false,
        started: false,
        running: false,
        healthy: false,
        ready: false,
        already_running: false,
        health_url: String::new(),
        session_name: String::new(),
        pid: None,
        exit_code: None,
        log_tail: String::new(),
        identity: Identity::default(),
        child: None,
    };
    if previous.mode == "tmux" {
        if let Some(socket) = tmux(root, alias, previous).await? {
            tmux_stop(root, alias, previous, &socket).await?;
        }
    } else if let Some(pid) = previous.pid.filter(|pid| crate::process::running(*pid)) {
        let identity = previous.identity();
        if identity.matches(pid)? {
            if replace {
                identity.stop(pid).await?;
            } else {
                launch.pid = Some(pid);
                launch.identity = identity;
                launch.already_running = true;
                observe(root, alias, &mut launch).await;
                return Ok(launch);
            }
        }
    }
    let health = root.path.join("health").join(format!("{alias}.url"));
    if let Ok(files) = Files::open(root, "health", false) {
        files.remove(&health)?;
    }
    let file = Files::open(root, "logs", true)?.file(&log_path, true)?;
    let mut command = Command::new(&binary);
    command
        .args(args)
        .args(["--log.file", ""])
        .stdin(Stdio::null())
        .stdout(file.try_clone()?)
        .stderr(file);
    if let Some(name) = key.strip_prefix("env:")
        && let Ok(value) = crate::config::resolve(key)
    {
        command.env(name, value.trim());
    }
    #[cfg(unix)]
    {
        // A managed runtime owns a session independently of the launching terminal.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
    }
    launch.child = Some(command.spawn().context("start managed runtime")?);
    launch.launched = true;
    let child = launch.child.as_mut().context("managed child is missing")?;
    let pid = child.id().context("managed child has exited")?;
    if let Ok(result) = timeout(Duration::from_millis(50), child.wait()).await {
        launch.exit_code = Some(result?.code().unwrap_or(-1));
        launch.log_tail = files::log_tail(root, &launch.log_path);
        return Ok(launch);
    }
    match Identity::capture(pid) {
        Ok(identity) => {
            launch.identity = identity;
            launch.pid = Some(pid);
        }
        Err(error) => {
            if let Some(status) = child.try_wait()? {
                launch.exit_code = Some(status.code().unwrap_or(-1));
            } else {
                child.kill().await?;
                return Err(error);
            }
        }
    }
    if launch.exit_code.is_none() {
        observe(root, alias, &mut launch).await;
    } else {
        launch.log_tail = files::log_tail(root, &launch.log_path);
    }
    Ok(launch)
}

async fn observe(root: &Root, alias: &str, launch: &mut Launch) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(child) = launch.child.as_mut()
            && let Ok(Some(code)) = child.try_wait()
        {
            launch.exit_code = Some(code.code().unwrap_or(-1));
        }
        launch.running = launch.exit_code.is_none()
            && launch
                .pid
                .is_some_and(|pid| launch.identity.matches(pid).unwrap_or_default());
        let raw = files::health_url(
            root,
            &root
                .path
                .join("health")
                .join(format!("{alias}.url"))
                .to_string_lossy(),
        );
        let probe = inspect::probe(&raw).await;
        launch.health_url = probe["healthz"]["url"].as_str().unwrap_or_default().into();
        launch.healthy = probe["healthz"]["ok"] == true;
        launch.ready = probe["readyz"]["ok"] == true;
        launch.started = launch.healthy;
        if launch.healthy || !launch.running || Instant::now() >= deadline {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    launch.log_tail = files::log_tail(root, &launch.log_path);
}

impl Process {
    pub fn identity(&self) -> Identity {
        Identity {
            start: self.pid_start_time.clone(),
            executable: self.pid_executable.clone(),
        }
    }
    pub fn running(&self) -> bool {
        self.pid
            .is_some_and(|pid| self.identity().matches(pid).unwrap_or_default())
    }
}

pub fn session_name(root: &Root, alias: &str) -> String {
    let digest = Sha256::digest(root.path.to_string_lossy().as_bytes());
    format!(
        "tunnel-mcp__{alias}__{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    )
}
fn owned_session(root: &Root, alias: &str, process: &Process) -> Result<String> {
    let expected = session_name(root, alias);
    anyhow::ensure!(
        process.session_name.trim().is_empty() || process.session_name == expected,
        "recorded tmux session does not match {expected}"
    );
    Ok(expected)
}
async fn tmux_command(socket: &str, command: &str, session: &str) -> Result<std::process::Output> {
    let selector = if socket.is_empty() {
        ["-L", "default"]
    } else {
        anyhow::ensure!(
            Path::new(socket).is_absolute() && !socket.contains(['\0', '\r', '\n']),
            "tmux socket path must be absolute"
        );
        ["-S", socket]
    };
    Ok(Command::new("tmux")
        .args(selector)
        .args([command, "-t", &format!("={session}")])
        .output()
        .await?)
}
pub async fn tmux(root: &Root, alias: &str, process: &Process) -> Result<Option<String>> {
    let session = owned_session(root, alias, process)?;
    let sockets = if !process.tmux_socket.trim().is_empty() {
        vec![process.tmux_socket.trim().to_owned()]
    } else {
        let mut sockets = Vec::new();
        if let Ok(value) = env::var("TMUX")
            && let Some(socket) = value.split(',').next()
            && Path::new(socket).is_absolute()
            && !socket.contains(['\0', '\r', '\n'])
        {
            sockets.push(socket.into());
        }
        sockets.push(String::new());
        sockets
    };
    for socket in sockets {
        let output = tmux_command(&socket, "has-session", &session).await?;
        if output.status.success() {
            return Ok(Some(socket));
        }
        let text = if output.stderr.is_empty() {
            &output.stdout
        } else {
            &output.stderr
        };
        let text = String::from_utf8_lossy(text).to_ascii_lowercase();
        anyhow::ensure!(
            output.status.code() == Some(1)
                && (text.contains("can't find session:")
                    || text.contains("no server running on ")
                    || (text.contains("error connecting to ")
                        && text.contains("no such file or directory"))),
            "tmux has-session failed: {}",
            text.trim()
        );
    }
    anyhow::ensure!(
        !process.tmux_socket.trim().is_empty(),
        "recorded legacy tmux runtime has no socket provenance and no owned session was found on the ambient or default socket"
    );
    Ok(None)
}
pub async fn tmux_stop(root: &Root, alias: &str, process: &Process, socket: &str) -> Result<()> {
    let output = tmux_command(
        socket,
        "kill-session",
        &owned_session(root, alias, process)?,
    )
    .await?;
    anyhow::ensure!(
        output.status.success(),
        "tmux kill-session failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

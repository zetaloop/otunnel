use std::{collections::BTreeMap, process::Stdio};

use anyhow::{Context, Result};
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout, Command};
use tokio_util::sync::CancellationToken;

use crate::config::{Invocation, resolve};

pub struct Process {
    child: Box<dyn ChildWrapper>,
}
impl Process {
    pub fn spawn(
        invocation: &Invocation,
        cwd: Option<&str>,
        env: &BTreeMap<String, String>,
        piped: bool,
    ) -> Result<Self> {
        let args = invocation.args()?;
        let mut command = Command::new(&args[0]);
        command
            .args(&args[1..])
            .stdin(Stdio::piped())
            .stderr(Stdio::inherit());
        if piped {
            command.stdout(Stdio::piped());
        } else {
            command.stdout(Stdio::inherit());
        }
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        for (key, value) in env {
            command.env(key, resolve(value)?);
        }
        Self::launch(command)
    }
    pub fn launch(command: Command) -> Result<Self> {
        let program = command
            .as_std()
            .get_program()
            .to_string_lossy()
            .into_owned();
        let mut command = CommandWrap::from(command);
        command.wrap(KillOnDrop);
        #[cfg(unix)]
        command.wrap(process_wrap::tokio::ProcessGroup::leader());
        #[cfg(windows)]
        command.wrap(process_wrap::tokio::JobObject);
        Ok(Self {
            child: command
                .spawn()
                .with_context(|| format!("start {program}"))?,
        })
    }
    pub fn stderr(&mut self) -> Result<ChildStderr> {
        self.child
            .stderr()
            .take()
            .context("child stderr is unavailable")
    }
    pub fn pipes(&mut self) -> Result<(ChildStdout, ChildStdin)> {
        let child = &mut self.child;
        Ok((
            child
                .stdout()
                .take()
                .context("child stdout is unavailable")?,
            child.stdin().take().context("child stdin is unavailable")?,
        ))
    }
    pub async fn supervise(mut self, stop: CancellationToken) -> Result<()> {
        // Retain stdin while waiting: Tokio closes a child's owned stdin in wait().
        let input = self.child.stdin().take();
        tokio::select! {
            result = self.child.wait() => {
                let status = result?;
                if stop.is_cancelled() { return Ok(()); }
                anyhow::bail!("child exited: {status}");
            }
            () = stop.cancelled() => {}
        }
        drop(input);
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        #[cfg(unix)]
        if let Err(error) = self.child.signal(libc::SIGTERM)
            && error.raw_os_error() != Some(libc::ESRCH)
        {
            return Err(error.into());
        }
        match tokio::time::timeout(std::time::Duration::from_secs(5), self.child.wait()).await {
            Ok(result) => {
                result?;
            }
            Err(_) => {
                self.child.start_kill()?;
                self.child.wait().await?;
            }
        }
        Ok(())
    }
}

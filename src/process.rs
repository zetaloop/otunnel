use std::{collections::BTreeMap, process::Stdio};

use anyhow::{Context, Result};
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use tokio::process::{ChildStdin, ChildStdout, Command};
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
        let mut command = CommandWrap::from(command);
        command.wrap(KillOnDrop);
        #[cfg(unix)]
        command.wrap(process_wrap::tokio::ProcessGroup::leader());
        #[cfg(windows)]
        command.wrap(process_wrap::tokio::JobObject);
        Ok(Self {
            child: command
                .spawn()
                .with_context(|| format!("start {}", args[0]))?,
        })
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
        tokio::select! {
            result = self.child.wait() => { anyhow::bail!("child exited: {}", result?); }
            () = stop.cancelled() => {
                self.child.stdin().take();
                self.child.start_kill()?;
                self.child.wait().await?;
                Ok(())
            }
        }
    }
}

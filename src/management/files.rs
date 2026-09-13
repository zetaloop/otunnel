use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use same_file::Handle;

use super::state::Root;

pub struct Files {
    directory: Dir,
    path: PathBuf,
    logs: bool,
}
impl Files {
    pub fn open(root: &Root, name: &str, create: bool) -> Result<Self> {
        anyhow::ensure!(
            matches!(name, "logs" | "health"),
            "unknown managed directory {name}"
        );
        if create {
            fs::create_dir_all(&root.path)?;
        }
        let parent = Dir::open_ambient_dir(&root.path, ambient_authority())?;
        if create {
            parent.create_dir_all(name)?;
        }
        anyhow::ensure!(
            parent.symlink_metadata(name)?.is_dir(),
            "managed {name} directory must be a directory"
        );
        let directory = parent.open_dir(name)?;
        anyhow::ensure!(
            parent.symlink_metadata(name)?.is_dir(),
            "managed {name} directory changed while opening"
        );
        let current = parent.open_dir(name)?;
        anyhow::ensure!(
            Handle::from_file(directory.try_clone()?.into_std_file())?
                == Handle::from_file(current.into_std_file())?,
            "managed {name} directory changed while opening"
        );
        Ok(Self {
            directory,
            path: root.path.join(name),
            logs: name == "logs",
        })
    }
    fn name(&self, path: &Path) -> Result<PathBuf> {
        let name = path.file_name().context("managed file path is required")?;
        let parent = Dir::open_ambient_dir(
            path.parent().context("managed file directory is missing")?,
            ambient_authority(),
        )?;
        anyhow::ensure!(
            Handle::from_file(parent.into_std_file())?
                == Handle::from_file(self.directory.try_clone()?.into_std_file())?,
            "managed file must be directly within {}",
            self.path.display()
        );
        Ok(PathBuf::from(name))
    }
    pub fn file(&self, path: &Path, write: bool) -> Result<fs::File> {
        let name = self.name(path)?;
        if let Ok(metadata) = self.directory.symlink_metadata(&name) {
            anyhow::ensure!(
                !self.logs || !metadata.is_symlink(),
                "log file must not be a symlink"
            );
            anyhow::ensure!(
                self.directory.metadata(&name)?.is_file(),
                "managed file must be regular"
            );
        }
        let mut options = OpenOptions::new();
        options.read(!write).append(write).create(write);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NONBLOCK | if self.logs { libc::O_NOFOLLOW } else { 0 });
        }
        let file = self.directory.open_with(&name, &options)?.into_std();
        anyhow::ensure!(file.metadata()?.is_file(), "managed file must be regular");
        if self.logs {
            anyhow::ensure!(
                !self.directory.symlink_metadata(&name)?.is_symlink(),
                "log file changed while opening"
            );
            let current = self.directory.open(&name)?.into_std();
            anyhow::ensure!(
                Handle::from_file(file.try_clone()?)? == Handle::from_file(current)?,
                "log file changed while opening"
            );
        }
        #[cfg(unix)]
        if write {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        Ok(file)
    }
    pub fn remove(&self, path: &Path) -> Result<()> {
        match self.directory.remove_file(self.name(path)?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    pub fn names(&self) -> Result<Vec<PathBuf>> {
        let mut names = self
            .directory
            .entries()?
            .map(|entry| entry.map(|entry| self.path.join(entry.file_name())))
            .collect::<io::Result<Vec<_>>>()?;
        names.sort();
        Ok(names)
    }
}

pub fn health_url(root: &Root, path: &str) -> String {
    let result = (|| -> Result<String> {
        let mut value = String::new();
        Files::open(root, "health", false)?
            .file(Path::new(path), false)?
            .take(8193)
            .read_to_string(&mut value)?;
        anyhow::ensure!(value.len() <= 8192, "health URL is too long");
        Ok(value.trim().to_owned())
    })();
    result.unwrap_or_default()
}

pub fn log_tail(root: &Root, path: &str) -> String {
    let result = (|| -> Result<String> {
        let mut value = String::new();
        Files::open(root, "logs", false)?
            .file(Path::new(path), false)?
            .read_to_string(&mut value)?;
        let value = value.replace("\r\n", "\n");
        let lines: Vec<_> = value.trim_end_matches('\n').split('\n').collect();
        Ok(lines[lines.len().saturating_sub(20)..].join("\n"))
    })();
    result.unwrap_or_default()
}

use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

use cap_std::fs::{Dir, OpenOptions};

pub(super) fn read(root: &Dir, name: &Path) -> io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = root.open_with(name, &options)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("profile must be a regular file"));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

pub(super) fn temporary(root: &Dir, directory: &Path) -> io::Result<tempfile::NamedTempFile> {
    tempfile::Builder::new()
        .prefix(".profile-")
        .suffix(".yaml")
        .make_in(directory, |path| {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            root.open_with(path.file_name().expect("temporary filename"), &options)
                .map(|file| file.into_std())
        })
}

pub(super) fn replace(
    root: &Dir,
    directory: &Path,
    name: &Path,
    contents: &[u8],
) -> io::Result<()> {
    match root.metadata(name) {
        Ok(metadata) if !metadata.is_file() => {
            return Err(io::Error::other("profile must be a regular file"));
        }
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file = temporary(root, directory)?;
    file.write_all(contents)?;
    let temporary = file.into_temp_path();
    root.rename(
        temporary.file_name().expect("temporary filename"),
        root,
        name,
    )
}

pub(super) fn create(root: &Dir, name: &Path, force: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(force).create_new(!force);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NONBLOCK);
    }
    let file = root.open_with(name, &options)?.into_std();
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("profile must be a regular file"));
    }
    if force {
        file.set_len(0)?;
    }
    Ok(file)
}

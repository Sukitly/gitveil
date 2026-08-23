//! Platform path confinement: descriptor-relative access that keeps managed
//! paths inside the workspace root without following symlinks.

use std::fs;
use std::path::{Component, Path};

use crate::error::{GitveilError, Result};
use crate::path::ManagedPath;

/// Validates that every existing component of `path` under `root` is a
/// regular directory or file reached without following symlinks, and that no
/// submodule boundary is crossed. Missing components are allowed so targets
/// can be created afterwards.
#[cfg(unix)]
pub(crate) fn validate_managed_path(root: &Path, path: &ManagedPath) -> Result<()> {
    let _ = open_existing(root, path)?;
    Ok(())
}

/// Opens an existing managed leaf through descriptor-relative traversal.
///
/// Returns `None` when any component is missing. Every opened component uses
/// `NOFOLLOW`; callers can therefore read metadata/content or change mode on
/// the returned descriptor without a validation-to-use symlink race.
#[cfg(unix)]
pub(crate) fn open_existing(root: &Path, path: &ManagedPath) -> Result<Option<fs::File>> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, openat, statat};

    let root_fd = fs::File::open(root).map_err(|error| {
        GitveilError::io("open workspace root", Some(root.to_path_buf()), &error)
    })?;
    let mut current = openat(
        &root_fd,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        GitveilError::path(path, &format!("could not open workspace root: {error}"))
    })?;
    let components = path.as_path().components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            return Err(GitveilError::path(path, "path is not normalized"));
        };
        let leaf = index + 1 == components.len();
        let flags = if leaf {
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK
        } else {
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
        };
        let opened = match openat(&current, *component, flags, Mode::empty()) {
            Ok(opened) => opened,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(error) => {
                return Err(GitveilError::path(
                    path,
                    &format!("component cannot be opened without following links: {error}"),
                ));
            }
        };
        let stat = fstat(&opened).map_err(|error| {
            GitveilError::path(path, &format!("component metadata is unavailable: {error}"))
        })?;
        let file_type = FileType::from_raw_mode(stat.st_mode);
        if leaf {
            if !file_type.is_file() {
                return Err(GitveilError::path(
                    path,
                    "managed leaf is not a regular file",
                ));
            }
            return Ok(Some(fs::File::from(opened)));
        }
        if !file_type.is_dir() {
            return Err(GitveilError::path(
                path,
                "managed parent is not a directory",
            ));
        }
        match statat(&opened, ".git", AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => {
                return Err(GitveilError::path(
                    path,
                    "submodule boundary is not allowed",
                ));
            }
            Err(error) if error == rustix::io::Errno::NOENT => {}
            Err(error) => {
                return Err(GitveilError::path(
                    path,
                    &format!("could not inspect submodule boundary: {error}"),
                ));
            }
        }
        current = opened;
    }
    Ok(None)
}

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use tempfile::{Builder, NamedTempFile, TempPath};

use crate::error::{GitveilError, Result};

#[derive(Clone, Debug)]
pub struct PrivateRuntime {
    root: PathBuf,
}

impl PrivateRuntime {
    pub fn open(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root).map_err(|error| {
            GitveilError::io("create runtime directory", Some(root.clone()), &error)
        })?;
        set_owner_only_directory(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn create(&self, prefix: &str, secret: bool) -> Result<RuntimeFile> {
        let file = Builder::new()
            .prefix(prefix)
            .tempfile_in(&self.root)
            .map_err(|error| {
                GitveilError::io("create runtime file", Some(self.root.clone()), &error)
            })?;
        set_owner_only_file(file.path())?;
        Ok(RuntimeFile { file, secret })
    }

    pub fn write_closed(&self, prefix: &str, bytes: &[u8]) -> Result<ClosedRuntimeFile> {
        let mut file = Builder::new()
            .prefix(prefix)
            .tempfile_in(&self.root)
            .map_err(|error| {
                GitveilError::io("create runtime file", Some(self.root.clone()), &error)
            })?;
        set_owner_only_file(file.path())?;
        file.as_file_mut()
            .write_all(bytes)
            .and_then(|()| file.as_file_mut().sync_all())
            .map_err(|error| {
                GitveilError::io(
                    "write runtime file",
                    Some(file.path().to_path_buf()),
                    &error,
                )
            })?;
        Ok(ClosedRuntimeFile {
            path: file.into_temp_path(),
        })
    }

    pub(crate) fn create_named_path(&self, name: &str) -> Result<PathBuf> {
        if name.contains(['/', '\\']) || name == "." || name == ".." {
            return Err(GitveilError::configuration("invalid runtime filename"));
        }
        Ok(self.root.join(name))
    }

    pub(crate) fn cleanup_orphans(&self) -> Result<()> {
        let entries = fs::read_dir(&self.root).map_err(|error| {
            GitveilError::io("scan runtime directory", Some(self.root.clone()), &error)
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                GitveilError::io("read runtime entry", Some(self.root.clone()), &error)
            })?;
            // The operation lock coordinates concurrent processes and the
            // `state/` directory holds persistent baseline records; neither is
            // ephemeral scratch.
            if matches!(entry.file_name().to_str(), Some("operation.lock" | "state")) {
                continue;
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                GitveilError::io("inspect runtime residue", Some(path.clone()), &error)
            })?;
            if metadata.file_type().is_symlink() {
                return Err(GitveilError::new(
                    crate::error::ErrorCategory::Path,
                    format!("unsafe runtime residue at {}", path.display()),
                ));
            }
            if metadata.is_dir() {
                fs::remove_dir_all(&path).map_err(|error| {
                    GitveilError::io("remove runtime residue", Some(path), &error)
                })?;
            } else {
                fs::remove_file(&path).map_err(|error| {
                    GitveilError::io("remove runtime residue", Some(path), &error)
                })?;
            }
        }
        Ok(())
    }
}

pub struct RuntimeFile {
    file: NamedTempFile,
    secret: bool,
}

pub struct ClosedRuntimeFile {
    path: TempPath,
}

impl ClosedRuntimeFile {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl RuntimeFile {
    pub fn path(&self) -> &Path {
        self.file.path()
    }

    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.file
            .as_file_mut()
            .set_len(0)
            .and_then(|()| self.file.as_file_mut().seek(SeekFrom::Start(0)).map(|_| ()))
            .and_then(|()| self.file.as_file_mut().write_all(bytes))
            .and_then(|()| self.file.as_file_mut().sync_all())
            .map_err(|error| {
                GitveilError::io(
                    "write runtime file",
                    Some(self.file.path().to_path_buf()),
                    &error,
                )
            })
    }

    pub(crate) fn read_public(&mut self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.file
            .as_file_mut()
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.as_file_mut().read_to_end(&mut bytes))
            .map_err(|error| {
                GitveilError::io(
                    "read runtime file",
                    Some(self.file.path().to_path_buf()),
                    &error,
                )
            })?;
        Ok(bytes)
    }
}

impl Drop for RuntimeFile {
    fn drop(&mut self) {
        if self.secret
            && let Ok(metadata) = self.file.as_file().metadata()
        {
            let remaining = metadata.len();
            if self.file.as_file_mut().seek(SeekFrom::Start(0)).is_ok() {
                let zeros = [0_u8; 8192];
                let mut written = 0_u64;
                while written < remaining {
                    let Ok(count) = usize::try_from((remaining - written).min(zeros.len() as u64))
                    else {
                        break;
                    };
                    if self.file.as_file_mut().write_all(&zeros[..count]).is_err() {
                        break;
                    }
                    written += count as u64;
                }
                let _ = self.file.as_file_mut().sync_all();
            }
        }
    }
}

#[cfg(unix)]
fn set_owner_only_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        GitveilError::io("secure runtime directory", Some(path.to_path_buf()), &error)
    })
}

#[cfg(unix)]
fn set_owner_only_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| GitveilError::io("secure runtime file", Some(path.to_path_buf()), &error))
}

pub(super) fn open_lock_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| GitveilError::io("open operation lock", Some(path.to_path_buf()), &error))
}

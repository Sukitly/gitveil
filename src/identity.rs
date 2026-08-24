use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags, RenameFlags, open, renameat_with};

use crate::age::AgeKeygenBinary;
use crate::error::{ErrorCategory, GitveilError, Result};
use crate::recipient::AgeRecipient;

pub(crate) struct GeneratedIdentity {
    path: PathBuf,
    recipient: AgeRecipient,
    durability: PublishDurability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublishDurability {
    Confirmed,
    Unconfirmed(io::ErrorKind),
}

impl GeneratedIdentity {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn recipient(&self) -> &AgeRecipient {
        &self.recipient
    }

    pub(crate) const fn durability(&self) -> PublishDurability {
        self.durability
    }
}

pub(crate) fn generate(
    current: &Path,
    gitveil_binary: &Path,
    requested: Option<&Path>,
) -> Result<GeneratedIdentity> {
    let destination = resolve_generation_destination(current, requested)?;
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            return Err(GitveilError::configuration(format!(
                "identity path already exists: {}",
                destination.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(GitveilError::io(
                "inspect identity destination",
                Some(destination.clone()),
                &error,
            ));
        }
    }
    let age_keygen = AgeKeygenBinary::discover(gitveil_binary)?;
    let parent = destination
        .parent()
        .ok_or_else(|| GitveilError::configuration("identity path has no parent directory"))?;
    ensure_parent(parent)?;

    let staging = tempfile::Builder::new()
        .prefix(".gitveil-identity-")
        .tempdir_in(parent)
        .map_err(|error| {
            GitveilError::io(
                "create private identity staging directory",
                Some(parent.to_path_buf()),
                &error,
            )
        })?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700)).map_err(|error| {
        GitveilError::io(
            "secure identity staging directory",
            Some(staging.path().to_path_buf()),
            &error,
        )
    })?;
    let staged_path = staging.path().join("identity");
    let staged_secret = StagedSecret::new(staged_path.clone());
    age_keygen.generate(&staged_path)?;
    secure_generated_identity(&staged_path)?;
    let mut recipients = age_keygen.recipients(&staged_path)?;
    if recipients.len() != 1 {
        return Err(GitveilError::new(
            ErrorCategory::Protocol,
            "age-keygen generated an unexpected number of recipients",
        ));
    }
    let recipient = recipients.remove(0);
    let durability = publish_no_replace(&staged_path, &destination)?;
    drop(staged_secret);
    Ok(GeneratedIdentity {
        path: destination,
        recipient,
        durability,
    })
}

pub(crate) fn recipients(
    current: &Path,
    gitveil_binary: &Path,
    requested: Option<&Path>,
) -> Result<Vec<AgeRecipient>> {
    let identity = resolve_recipient_input(current, requested)?;
    AgeKeygenBinary::discover(gitveil_binary)?.recipients(&identity)
}

fn resolve_generation_destination(current: &Path, requested: Option<&Path>) -> Result<PathBuf> {
    resolve_selected_identity_file(current, requested)
}

fn resolve_recipient_input(current: &Path, requested: Option<&Path>) -> Result<PathBuf> {
    resolve_selected_identity_file(current, requested)
}

fn resolve_selected_identity_file(current: &Path, requested: Option<&Path>) -> Result<PathBuf> {
    let selected = if let Some(path) = requested {
        path.to_path_buf()
    } else if let Some(path) = nonempty_environment_path("SOPS_AGE_KEY_FILE")? {
        path
    } else if let Some(config) = nonempty_environment_path("XDG_CONFIG_HOME")? {
        config.join("sops/age/keys.txt")
    } else {
        let home = nonempty_environment_path("HOME")?.ok_or_else(|| {
            GitveilError::configuration("HOME is unavailable; pass an explicit identity path")
        })?;
        #[cfg(target_os = "macos")]
        let path = home.join("Library/Application Support/sops/age/keys.txt");
        #[cfg(target_os = "linux")]
        let path = home.join(".config/sops/age/keys.txt");
        path
    };
    if selected.as_os_str().is_empty() {
        return Err(GitveilError::configuration("identity path cannot be empty"));
    }
    Ok(if selected.is_absolute() {
        selected
    } else {
        current.join(selected)
    })
}

fn nonempty_environment_path(name: &str) -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Err(GitveilError::configuration(format!(
            "{name} cannot be empty"
        )));
    }
    Ok(Some(PathBuf::from(value)))
}

fn ensure_parent(parent: &Path) -> Result<()> {
    let mut missing = Vec::new();
    let mut cursor = parent;
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(metadata) if metadata.is_dir() => break,
            Ok(_) => {
                return Err(GitveilError::configuration(format!(
                    "identity directory path is not a directory: {}",
                    cursor.display()
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor.parent().ok_or_else(|| {
                    GitveilError::configuration("identity directory has no existing ancestor")
                })?;
            }
            Err(error) => {
                return Err(GitveilError::io(
                    "inspect identity directory",
                    Some(cursor.to_path_buf()),
                    &error,
                ));
            }
        }
    }

    for directory in missing.into_iter().rev() {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&directory) {
            Ok(()) => {
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(
                    |error| {
                        GitveilError::io(
                            "secure created identity directory",
                            Some(directory.clone()),
                            &error,
                        )
                    },
                )?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&directory).map_err(|inspect_error| {
                    GitveilError::io(
                        "inspect concurrently created identity directory",
                        Some(directory.clone()),
                        &inspect_error,
                    )
                })?;
                if !metadata.is_dir() {
                    return Err(GitveilError::configuration(format!(
                        "identity directory path is not a directory: {}",
                        directory.display()
                    )));
                }
            }
            Err(error) => {
                return Err(GitveilError::io(
                    "create private identity directory",
                    Some(directory),
                    &error,
                ));
            }
        }
    }
    Ok(())
}

fn secure_generated_identity(path: &Path) -> Result<()> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        GitveilError::io(
            "inspect generated identity path",
            Some(path.to_path_buf()),
            &error,
        )
    })?;
    if !path_metadata.is_file()
        || path_metadata.file_type().is_symlink()
        || path_metadata.nlink() != 1
    {
        return Err(GitveilError::new(
            ErrorCategory::Protocol,
            "age-keygen did not create an independent regular identity file",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
        GitveilError::io(
            "set generated identity permissions",
            Some(path.to_path_buf()),
            &error,
        )
    })?;

    let file = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        GitveilError::new(
            ErrorCategory::Protocol,
            format!("age-keygen did not create a safe identity file: {error}"),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        GitveilError::io(
            "inspect generated identity",
            Some(path.to_path_buf()),
            &error,
        )
    })?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(GitveilError::new(
            ErrorCategory::Protocol,
            "age-keygen did not create an independent regular identity file",
        ));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            GitveilError::io(
                "secure generated identity",
                Some(path.to_path_buf()),
                &error,
            )
        })
}

fn publish_no_replace(staged: &Path, destination: &Path) -> Result<PublishDurability> {
    publish_no_replace_with_sync(staged, destination, File::sync_all)
}

fn publish_no_replace_with_sync(
    staged: &Path,
    destination: &Path,
    sync_destination_directory: impl FnOnce(&File) -> io::Result<()>,
) -> Result<PublishDurability> {
    let staged_parent = staged.parent().ok_or_else(|| {
        GitveilError::configuration("staged identity path has no parent directory")
    })?;
    let staged_name = staged
        .file_name()
        .ok_or_else(|| GitveilError::configuration("staged identity path has no file name"))?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| GitveilError::configuration("identity path has no destination directory"))?;
    let destination_name = destination
        .file_name()
        .ok_or_else(|| GitveilError::configuration("identity path must name a destination file"))?;
    let staging_directory = File::open(staged_parent).map_err(|error| {
        GitveilError::io(
            "open identity staging directory",
            Some(staged_parent.to_path_buf()),
            &error,
        )
    })?;
    let destination_directory = File::open(destination_parent).map_err(|error| {
        GitveilError::io(
            "open identity destination directory",
            Some(destination_parent.to_path_buf()),
            &error,
        )
    })?;
    renameat_with(
        &staging_directory,
        staged_name,
        &destination_directory,
        destination_name,
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            GitveilError::configuration(format!(
                "identity path already exists: {}",
                destination.display()
            ))
        } else {
            GitveilError::new(
                ErrorCategory::Io,
                format!(
                    "publish generated identity at {} failed: {error}",
                    destination.display()
                ),
            )
        }
    })?;
    Ok(match sync_destination_directory(&destination_directory) {
        Ok(()) => PublishDurability::Confirmed,
        Err(error) => PublishDurability::Unconfirmed(error.kind()),
    })
}

struct StagedSecret {
    path: PathBuf,
}

impl StagedSecret {
    const fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for StagedSecret {
    fn drop(&mut self) {
        let Ok(path_metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if !path_metadata.is_file()
            || path_metadata.file_type().is_symlink()
            || path_metadata.nlink() != 1
        {
            return;
        }
        if fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).is_err() {
            return;
        }
        let Ok(mut file) = open(
            &self.path,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from) else {
            return;
        };
        let Ok(metadata) = file.metadata() else {
            return;
        };
        if !metadata.is_file() || metadata.nlink() != 1 {
            return;
        }
        let length = metadata.len();
        if file.seek(SeekFrom::Start(0)).is_err() {
            return;
        }
        let zeros = [0_u8; 8192];
        let mut written = 0_u64;
        while written < length {
            let Ok(count) = usize::try_from((length - written).min(zeros.len() as u64)) else {
                break;
            };
            if file.write_all(&zeros[..count]).is_err() {
                break;
            }
            written += count as u64;
        }
        let _ = file.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::Path;

    use super::{PublishDurability, publish_no_replace_with_sync, resolve_selected_identity_file};

    #[test]
    fn explicit_relative_identity_paths_are_resolved_from_the_current_directory() {
        assert_eq!(
            resolve_selected_identity_file(
                Path::new("/work"),
                Some(Path::new("credentials/identity.txt"))
            )
            .expect("identity path"),
            Path::new("/work/credentials/identity.txt")
        );
    }

    #[test]
    fn a_directory_sync_failure_is_a_committed_publication_outcome() {
        let root = tempfile::tempdir().expect("publication fixture");
        let staging = root.path().join("staging");
        fs::create_dir(&staging).expect("staging directory");
        let staged = staging.join("generated-identity");
        fs::write(&staged, b"private identity canary").expect("staged identity");
        let destination = root.path().join("published-identity");

        let durability = publish_no_replace_with_sync(&staged, &destination, |_| {
            Err(io::Error::other("injected directory sync failure"))
        })
        .expect("rename commits before directory sync");

        assert_eq!(
            durability,
            PublishDurability::Unconfirmed(io::ErrorKind::Other)
        );
        assert_eq!(
            fs::read(&destination).expect("published identity"),
            b"private identity canary"
        );
        assert!(!staged.exists());
    }
}

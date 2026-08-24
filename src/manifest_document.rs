//! Safe read-modify-republish of repository configuration documents.
//!
//! Both configuration-mutation features (`configure` for `init`/`add`,
//! `recipients` for authorization changes) share this boundary: root-only
//! repository discovery, manifest loading that retains the original bytes
//! and mode for freshness checks, canonical serialization, and atomic
//! publication that never overwrites a concurrently changed document.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::confine;
use crate::error::{ErrorCategory, GitveilError, Result};
use crate::git::{Repository, RepositoryDiscoveryError};
use crate::manifest::{MANIFEST_FILE_NAME, Manifest};
use crate::path::ManagedPath;
use crate::recipient::PolicyName;

pub(crate) const DEFAULT_MODE: u32 = 0o644;

/// Injection point identifiers for publication fault tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicationPoint {
    BeforePersist,
    BeforeDirectorySync,
}

pub(crate) trait PublicationFault {
    fn check(&self, _path: &ManagedPath, _point: PublicationPoint) -> Result<()> {
        Ok(())
    }
}

pub(crate) struct NoPublicationFault;

impl PublicationFault for NoPublicationFault {}

/// A loaded manifest document: parsed content plus the original bytes and
/// mode needed to republish it without clobbering concurrent writes.
pub(crate) struct ManifestPreparation {
    path: ManagedPath,
    original: Vec<u8>,
    mode: u32,
}

impl ManifestPreparation {
    pub(crate) const fn new(path: ManagedPath, original: Vec<u8>, mode: u32) -> Self {
        Self {
            path,
            original,
            mode,
        }
    }

    pub(crate) fn path(&self) -> &ManagedPath {
        &self.path
    }

    pub(crate) const fn mode(&self) -> u32 {
        self.mode
    }

    /// Whether the document on disk still carries the loaded bytes.
    pub(crate) fn is_fresh(&self, root: &Path) -> Result<bool> {
        Ok(read_optional(root, &self.path)?.as_deref() == Some(self.original.as_slice()))
    }
}

pub(crate) fn load_manifest(root: &Path) -> Result<(ManifestPreparation, Manifest)> {
    let path = ManagedPath::new(MANIFEST_FILE_NAME)
        .map_err(|error| GitveilError::configuration(error.to_string()))?;
    let bytes = read_optional(root, &path)?.ok_or_else(|| {
        GitveilError::configuration(format!(
            "{MANIFEST_FILE_NAME} not found at the repository root; run gitveil init first"
        ))
    })?;
    let manifest =
        Manifest::parse(&bytes).map_err(|error| GitveilError::configuration(error.to_string()))?;
    let mode = file_mode(root, &path)?.unwrap_or(DEFAULT_MODE);
    Ok((ManifestPreparation::new(path, bytes, mode), manifest))
}

pub(crate) fn serialize_manifest(manifest: &Manifest) -> Result<Vec<u8>> {
    manifest.to_json_bytes().map_err(|_| {
        GitveilError::new(
            ErrorCategory::Integrity,
            "Gitveil manifest writer violated its internal reader contract",
        )
    })
}

/// Publishes a manifest candidate atomically, refusing when the document
/// changed since it was loaded.
pub(crate) fn publish_if_fresh(
    root: &Path,
    preparation: &ManifestPreparation,
    candidate: &[u8],
    command: &str,
) -> Result<()> {
    if !preparation.is_fresh(root)? {
        return Err(GitveilError::new(
            ErrorCategory::Concurrency,
            format!("{MANIFEST_FILE_NAME} changed while {command} was running; retry"),
        ));
    }
    write_atomic(root, &preparation.path, candidate, preparation.mode, true)
}

pub(crate) fn select_recipient_policy(
    manifest: &Manifest,
    requested: Option<&str>,
    flag: &str,
) -> Result<PolicyName> {
    if let Some(requested) = requested {
        let requested = PolicyName::new(requested)
            .map_err(|error| GitveilError::configuration(error.to_string()))?;
        if manifest.recipient_policy(&requested).is_none() {
            return Err(GitveilError::configuration(format!(
                "recipient policy {requested} is not declared in {MANIFEST_FILE_NAME}"
            )));
        }
        return Ok(requested);
    }
    if let Some(only) = manifest.only_policy_name() {
        return Ok(only.clone());
    }
    let names = manifest
        .policy_names()
        .into_iter()
        .map(PolicyName::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if names.is_empty() {
        Err(GitveilError::configuration(format!(
            "{MANIFEST_FILE_NAME} has no recipient policy; declare one before adding files"
        )))
    } else {
        Err(GitveilError::configuration(format!(
            "multiple recipient policies are declared ({names}); pass {flag}"
        )))
    }
}

/// Root-only repository discovery for configuration-mutation commands.
pub(crate) fn mutation_repository(current: &Path) -> Result<Repository> {
    let repository = match Repository::discover(current) {
        Ok(repository) => repository,
        Err(RepositoryDiscoveryError::NotRepository) => {
            if fs::symlink_metadata(current.join(".git")).is_ok() {
                return Err(GitveilError::new(
                    ErrorCategory::Process,
                    "Git repository metadata exists but could not be read",
                ));
            }
            return Err(GitveilError::configuration(
                "no Git repository metadata found in the current directory; run this command from a Git repository root",
            ));
        }
        Err(RepositoryDiscoveryError::Failure(error)) => return Err(error),
    };
    let current = current.canonicalize().map_err(|error| {
        GitveilError::io(
            "resolve current directory",
            Some(current.to_path_buf()),
            &error,
        )
    })?;
    let root = repository.root().canonicalize().map_err(|error| {
        GitveilError::io(
            "resolve Git repository root",
            Some(repository.root().to_path_buf()),
            &error,
        )
    })?;
    if current != root {
        return Err(GitveilError::configuration(format!(
            "configuration commands must be run from the Git repository root: {}",
            root.display()
        )));
    }
    let marker = root.join(".git");
    let metadata = fs::symlink_metadata(&marker).map_err(|_| {
        GitveilError::configuration(
            "no Git repository metadata found in the current directory; expected .git",
        )
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() || !(file_type.is_file() || file_type.is_dir()) {
        return Err(GitveilError::configuration(
            "Git repository metadata .git must be a regular file or directory",
        ));
    }
    repository.ensure_supported_version()?;
    Ok(repository)
}

pub(crate) fn read_optional(root: &Path, path: &ManagedPath) -> Result<Option<Vec<u8>>> {
    let Some(mut file) = confine::open_existing(root, path)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        GitveilError::io(
            "read repository configuration",
            Some(path.join_to(root)),
            &error,
        )
    })?;
    Ok(Some(bytes))
}

pub(crate) fn file_mode(root: &Path, path: &ManagedPath) -> Result<Option<u32>> {
    let Some(file) = confine::open_existing(root, path)? else {
        return Ok(None);
    };
    file.metadata()
        .map(|metadata| Some(metadata.permissions().mode() & 0o777))
        .map_err(|error| {
            GitveilError::io(
                "read repository file metadata",
                Some(path.join_to(root)),
                &error,
            )
        })
}

pub(crate) fn write_atomic(
    root: &Path,
    path: &ManagedPath,
    bytes: &[u8],
    mode: u32,
    replace: bool,
) -> Result<()> {
    write_atomic_with_fault(root, path, bytes, mode, replace, &NoPublicationFault)
}

pub(crate) fn write_atomic_with_fault<F: PublicationFault>(
    root: &Path,
    path: &ManagedPath,
    bytes: &[u8],
    mode: u32,
    replace: bool,
    fault: &F,
) -> Result<()> {
    confine::validate_managed_path(root, path)?;
    let target = path.join_to(root);
    let parent = target
        .parent()
        .ok_or_else(|| GitveilError::configuration("repository path has no parent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        GitveilError::io(
            "create repository configuration replacement",
            Some(parent.to_path_buf()),
            &error,
        )
    })?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))
        .and_then(|()| temporary.write_all(bytes))
        .and_then(|()| temporary.as_file_mut().sync_all())
        .map_err(|error| {
            GitveilError::io(
                "write repository configuration replacement",
                Some(target.clone()),
                &error,
            )
        })?;
    fault.check(path, PublicationPoint::BeforePersist)?;
    if replace {
        temporary.persist(&target).map_err(|error| {
            GitveilError::io(
                "replace repository configuration",
                Some(target.clone()),
                &error.error,
            )
        })?;
    } else {
        temporary.persist_noclobber(&target).map_err(|error| {
            if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                GitveilError::configuration(format!(
                    "{path} already exists; init never replaces a manifest"
                ))
            } else {
                GitveilError::io(
                    "create repository configuration",
                    Some(target.clone()),
                    &error.error,
                )
            }
        })?;
    }
    fault.check(path, PublicationPoint::BeforeDirectorySync)?;
    sync_directory(parent)?;
    Ok(())
}

pub(crate) fn sync_directory(directory: &Path) -> Result<()> {
    fs::File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            GitveilError::io(
                "sync repository directory",
                Some(PathBuf::from(directory)),
                &error,
            )
        })
}

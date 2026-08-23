//! Workspace discovery and the file boundary shared by every command.
//!
//! A workspace is anchored by `.gitveilrc.json`. Inside a Git repository the
//! manifest must live at the repository root and the private runtime and
//! baseline state live under `.git/gitveil/`; outside a repository the
//! workspace still works with an ephemeral runtime and no persistent
//! baseline (conservative mode).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::baseline::BaselineStore;
use crate::confine;
use crate::error::{ErrorCategory, GitveilError, Result};
use crate::git::Repository;
use crate::manifest::{MANIFEST_FILE_NAME, Manifest, ManifestEntry, ResolvedManifestEntry};
use crate::path::ManagedPath;
use crate::profile::ProfileName;
use crate::runtime::{OperationLock, PrivateRuntime, acquire_lock};
use crate::sops::{SopsBinary, SopsClient, SopsPaths};

const LOCK_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct Workspace {
    root: PathBuf,
    manifest: Manifest,
    repository: Option<Repository>,
    runtime: PrivateRuntime,
    _ephemeral: Option<tempfile::TempDir>,
    gitveil_binary: PathBuf,
}

impl Workspace {
    pub(crate) fn discover(start: &Path, gitveil_binary: &Path) -> Result<Self> {
        let (root, repository) = match Repository::discover(start) {
            Ok(repository) => {
                let root = repository.root().to_path_buf();
                if !root.join(MANIFEST_FILE_NAME).is_file() {
                    return Err(GitveilError::configuration(format!(
                        "{MANIFEST_FILE_NAME} not found at the repository root; \
                         create it to declare managed files"
                    )));
                }
                (root, Some(repository))
            }
            Err(_) => (find_manifest_root(start)?, None),
        };
        let manifest_path = root.join(MANIFEST_FILE_NAME);
        let bytes = fs::read(&manifest_path).map_err(|error| {
            GitveilError::io("read manifest", Some(manifest_path.clone()), &error)
        })?;
        let manifest = Manifest::parse(&bytes)
            .map_err(|error| GitveilError::configuration(error.to_string()))?;
        let (runtime, ephemeral) = if let Some(repository) = &repository {
            (
                PrivateRuntime::open(repository.runtime_path().to_path_buf())?,
                None,
            )
        } else {
            let directory = tempfile::tempdir()
                .map_err(|error| GitveilError::io("create ephemeral runtime", None, &error))?;
            let runtime = PrivateRuntime::open(directory.path().join("gitveil"))?;
            (runtime, Some(directory))
        };
        Ok(Self {
            root,
            manifest,
            repository,
            runtime,
            _ephemeral: ephemeral,
            gitveil_binary: gitveil_binary.to_path_buf(),
        })
    }

    pub(crate) fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub(crate) fn repository(&self) -> Option<&Repository> {
        self.repository.as_ref()
    }

    pub(crate) fn require_repository(&self) -> Result<&Repository> {
        let repository = self.repository.as_ref().ok_or_else(|| {
            GitveilError::new(
                ErrorCategory::Configuration,
                "this command requires a Git repository",
            )
        })?;
        repository.ensure_supported_version()?;
        Ok(repository)
    }

    /// Resolves entries selected by managed paths and an optional profile.
    ///
    /// No selectors means every manifest entry. Paths and profile compose as
    /// a constrained intersection: every requested path must belong to the
    /// profile, and the complete selection is validated before effects begin.
    pub(crate) fn entries<'a>(
        &'a self,
        paths: &[String],
        profile: Option<&str>,
    ) -> Result<Vec<ResolvedManifestEntry<'a>>> {
        let paths = paths
            .iter()
            .map(|path| {
                ManagedPath::new(path)
                    .map_err(|error| GitveilError::new(ErrorCategory::Path, error.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        let profile = profile
            .map(ProfileName::new)
            .transpose()
            .map_err(|error| GitveilError::configuration(error.to_string()))?;
        self.manifest
            .select(&paths, profile.as_ref())
            .map_err(|error| GitveilError::configuration(error.to_string()))?
            .into_iter()
            .map(|entry| self.resolve_entry(entry))
            .collect()
    }

    fn resolve_entry<'a>(&'a self, entry: &'a ManifestEntry) -> Result<ResolvedManifestEntry<'a>> {
        self.manifest.resolve_entry(entry).ok_or_else(|| {
            GitveilError::new(
                ErrorCategory::Integrity,
                format!(
                    "validated manifest entry {} lost recipient policy {}",
                    entry.path(),
                    entry.recipient_policy()
                ),
            )
        })
    }

    /// Reads a workspace file after confinement validation; missing files
    /// yield `None`.
    pub(crate) fn read(&self, path: &ManagedPath) -> Result<Option<Vec<u8>>> {
        confine::validate_managed_path(&self.root, path)?;
        let target = path.join_to(&self.root);
        match fs::read(&target) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(GitveilError::io(
                "read workspace file",
                Some(target),
                &error,
            )),
        }
    }

    /// Atomically writes a plaintext file with owner-only permissions.
    pub(crate) fn write_plaintext(&self, path: &ManagedPath, bytes: &[u8]) -> Result<()> {
        self.write(path, bytes, 0o600)
    }

    /// Atomically writes a ciphertext file with conventional permissions.
    pub(crate) fn write_ciphertext(&self, path: &ManagedPath, bytes: &[u8]) -> Result<()> {
        self.write(path, bytes, 0o644)
    }

    fn write(&self, path: &ManagedPath, bytes: &[u8], mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        confine::validate_managed_path(&self.root, path)?;
        let target = path.join_to(&self.root);
        let parent = target
            .parent()
            .ok_or_else(|| GitveilError::configuration("workspace path has no parent"))?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
            GitveilError::io(
                "create workspace replacement",
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
                GitveilError::io("write workspace file", Some(target.clone()), &error)
            })?;
        temporary.persist(&target).map_err(|error| {
            GitveilError::io("replace workspace file", Some(target), &error.error)
        })?;
        Ok(())
    }

    /// Baseline store; `None` outside a Git repository (conservative mode).
    pub(crate) fn baseline_store(&self) -> Option<BaselineStore> {
        self.repository
            .as_ref()
            .map(|repository| BaselineStore::new(repository.runtime_path().join("state")))
    }

    /// Creates the SOPS adapter after the caller acquires the operation lock;
    /// lock acquisition removes stale runtime files before the adapter writes
    /// its private neutral configuration.
    pub(crate) fn sops(&self) -> Result<SopsClient> {
        SopsClient::new(
            SopsBinary::discover(None, &self.gitveil_binary)?,
            SopsPaths {
                repository: self.root.clone(),
                gitveil_binary: self.gitveil_binary.clone(),
            },
            self.runtime.clone(),
        )
    }

    pub(crate) fn lock(&self) -> Result<OperationLock> {
        acquire_lock(&self.runtime, LOCK_TIMEOUT)
    }
}

fn find_manifest_root(start: &Path) -> Result<PathBuf> {
    let start = start.canonicalize().map_err(|error| {
        GitveilError::io(
            "resolve working directory",
            Some(start.to_path_buf()),
            &error,
        )
    })?;
    let mut current = Some(start.as_path());
    while let Some(directory) = current {
        if directory.join(MANIFEST_FILE_NAME).is_file() {
            return Ok(directory.to_path_buf());
        }
        current = directory.parent();
    }
    Err(GitveilError::configuration(format!(
        "{MANIFEST_FILE_NAME} not found in this directory or any parent; \
         create it to declare managed files"
    )))
}

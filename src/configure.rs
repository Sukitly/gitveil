//! Repository configuration mutation for `gitveil init` and `gitveil add`.
//!
mod plan;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::SourceFormat;
use crate::confine;
use crate::envelope::CiphertextEnvelope;
use crate::error::{ErrorCategory, GitveilError, Result};
use crate::git::{IgnoreMatch, Repository, RepositoryDiscoveryError};
use crate::manifest::{CIPHERTEXT_SUFFIX, GITIGNORE_FILE_NAME, MANIFEST_FILE_NAME, Manifest};
use crate::path::ManagedPath;
use crate::profile::ProfileName;
use crate::recipient::{AgeRecipient, AgeRecipientPolicy, PolicyName};
use crate::runtime::{PrivateRuntime, acquire_lock};
use crate::source;

use plan::{
    IgnoreRuleSnapshot, IgnoreState, RegistrationKind, RegistrationPlan, RegistrationRequest,
    merge_protection_paths, plan_registration, render_managed_ignore, visibility_violations,
};

const LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MODE: u32 = 0o644;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationPoint {
    BeforePersist,
    BeforeDirectorySync,
}

trait PublicationFault {
    fn check(&self, _path: &ManagedPath, _point: PublicationPoint) -> Result<()> {
        Ok(())
    }
}

struct NoPublicationFault;

impl PublicationFault for NoPublicationFault {}

pub(crate) struct InitOutcome {
    policy: PolicyName,
    recipient_count: usize,
}

impl InitOutcome {
    pub(crate) fn policy(&self) -> &PolicyName {
        &self.policy
    }

    pub(crate) const fn recipient_count(&self) -> usize {
        self.recipient_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddOutcomeKind {
    AddedExisting,
    AddedMissing,
    AlreadyManaged,
}

pub(crate) struct AddOutcome {
    path: ManagedPath,
    kind: AddOutcomeKind,
    plaintext_exists: bool,
}

impl AddOutcome {
    pub(crate) fn path(&self) -> &ManagedPath {
        &self.path
    }

    pub(crate) const fn kind(&self) -> AddOutcomeKind {
        self.kind
    }

    pub(crate) const fn plaintext_exists(&self) -> bool {
        self.plaintext_exists
    }
}

pub(crate) fn initialize(
    current: &Path,
    policy: &str,
    recipients: &[String],
) -> Result<InitOutcome> {
    let repository = mutation_repository(current)?;
    let runtime = PrivateRuntime::open(repository.runtime_path().to_path_buf())?;
    let _lock = acquire_lock(&runtime, LOCK_TIMEOUT)?;
    let root = repository.root();
    let manifest_path = ManagedPath::new(MANIFEST_FILE_NAME)
        .map_err(|error| GitveilError::configuration(error.to_string()))?;
    if read_optional(root, &manifest_path)?.is_some() {
        return Err(GitveilError::configuration(format!(
            "{MANIFEST_FILE_NAME} already exists; init never replaces or merges a manifest"
        )));
    }

    let policy =
        PolicyName::new(policy).map_err(|error| GitveilError::configuration(error.to_string()))?;
    let recipients = recipients
        .iter()
        .enumerate()
        .map(|(index, recipient)| {
            AgeRecipient::new(recipient).map_err(|error| {
                GitveilError::configuration(format!(
                    "invalid public age recipient at index {index}: {error}"
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let recipient_count = recipients.len();
    let recipient_policy = AgeRecipientPolicy::new(policy.clone(), recipients)
        .map_err(|error| GitveilError::configuration(error.to_string()))?;
    let manifest = Manifest::initial(recipient_policy);
    let bytes = serialize_manifest(&manifest)?;
    write_atomic(root, &manifest_path, &bytes, DEFAULT_MODE, false)?;
    Ok(InitOutcome {
        policy,
        recipient_count,
    })
}

pub(crate) fn add(
    current: &Path,
    paths: &[String],
    format: &str,
    profile: Option<&str>,
    recipient_policy: Option<&str>,
) -> Result<Vec<AddOutcome>> {
    add_with_publication_fault(
        current,
        paths,
        format,
        profile,
        recipient_policy,
        &NoPublicationFault,
    )
}

fn add_with_publication_fault<F: PublicationFault>(
    current: &Path,
    paths: &[String],
    format: &str,
    profile: Option<&str>,
    recipient_policy: Option<&str>,
    fault: &F,
) -> Result<Vec<AddOutcome>> {
    let repository = mutation_repository(current)?;
    let runtime = PrivateRuntime::open(repository.runtime_path().to_path_buf())?;
    let _lock = acquire_lock(&runtime, LOCK_TIMEOUT)?;
    let root = repository.root();

    let (manifest_files, manifest) = load_manifest(root)?;

    let (format, managed_paths, plan) =
        registration_plan(manifest, paths, format, profile, recipient_policy)?;
    let manifest_candidate = serialize_manifest(plan.manifest())?;

    let existing_plaintext = validate_requested_pairs(root, &repository, &managed_paths, format)?;

    let ignore = prepare_ignore(root, &plan)?;
    publish_registration(
        root,
        &repository,
        &RegistrationPublication {
            manifest: &manifest_files,
            plan: &plan,
            existing_plaintext: &existing_plaintext,
            ignore: &ignore,
            manifest_candidate: &manifest_candidate,
        },
        fault,
    )?;
    Ok(add_outcomes(&plan, &existing_plaintext))
}

struct ManifestPreparation {
    path: ManagedPath,
    original: Vec<u8>,
    mode: u32,
}

struct IgnorePreparation {
    path: ManagedPath,
    original: Option<Vec<u8>>,
    candidate: Vec<u8>,
    mode: u32,
}

struct RegistrationPublication<'a> {
    manifest: &'a ManifestPreparation,
    plan: &'a RegistrationPlan,
    existing_plaintext: &'a HashSet<ManagedPath>,
    ignore: &'a IgnorePreparation,
    manifest_candidate: &'a [u8],
}

fn load_manifest(root: &Path) -> Result<(ManifestPreparation, Manifest)> {
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
    Ok((
        ManifestPreparation {
            path,
            original: bytes,
            mode,
        },
        manifest,
    ))
}

fn registration_plan(
    manifest: Manifest,
    paths: &[String],
    format: &str,
    profile: Option<&str>,
    recipient_policy: Option<&str>,
) -> Result<(SourceFormat, Vec<ManagedPath>, RegistrationPlan)> {
    let format = format
        .parse::<SourceFormat>()
        .map_err(|error| GitveilError::configuration(error.to_string()))?;
    let profile = profile
        .map(ProfileName::new)
        .transpose()
        .map_err(|error| GitveilError::configuration(error.to_string()))?
        .unwrap_or_default();
    let recipient_policy = select_recipient_policy(&manifest, recipient_policy)?;
    let managed_paths = paths
        .iter()
        .map(|path| validate_registration_path(path))
        .collect::<Result<Vec<_>>>()?;
    let requests = managed_paths
        .iter()
        .cloned()
        .map(|path| RegistrationRequest {
            path,
            format,
            recipient_policy: recipient_policy.clone(),
            profile: profile.clone(),
        })
        .collect();
    let plan = plan_registration(manifest, requests)
        .map_err(|error| GitveilError::configuration(error.to_string()))?;
    Ok((format, managed_paths, plan))
}

fn validate_registration_path(path: &str) -> Result<ManagedPath> {
    ManagedPath::new(path)
        .map_err(|error| GitveilError::new(ErrorCategory::Path, error.to_string()))
}

fn validate_requested_pairs(
    root: &Path,
    repository: &Repository,
    paths: &[ManagedPath],
    format: SourceFormat,
) -> Result<HashSet<ManagedPath>> {
    let tracked = repository.tracked_paths(paths)?;
    if let Some(path) = paths.iter().find(|path| tracked.contains(*path)) {
        return Err(GitveilError::configuration(format!(
            "plaintext path {path} is tracked by Git; remove it from the index with `git rm --cached -- PATH` and retry"
        )));
    }
    let mut existing = HashSet::new();
    for path in paths {
        if let Some(bytes) = read_optional(root, path)? {
            source::parse(format, &bytes)
                .map_err(|error| GitveilError::source(path, format, &error.to_string()))?;
            existing.insert(path.clone());
        }
        validate_existing_ciphertext(root, path, format)?;
    }
    Ok(existing)
}

fn validate_existing_ciphertext(
    root: &Path,
    path: &ManagedPath,
    format: SourceFormat,
) -> Result<()> {
    let ciphertext = ManagedPath::new(format!("{}{CIPHERTEXT_SUFFIX}", path.as_str()))
        .map_err(|error| GitveilError::configuration(error.to_string()))?;
    if let Some(bytes) = read_optional(root, &ciphertext)? {
        CiphertextEnvelope::parse(&bytes, format)
            .map_err(|error| GitveilError::ciphertext(&ciphertext, &error.to_string()))?;
    }
    Ok(())
}

fn prepare_ignore(root: &Path, plan: &RegistrationPlan) -> Result<IgnorePreparation> {
    let path = ManagedPath::new(GITIGNORE_FILE_NAME)
        .map_err(|error| GitveilError::configuration(error.to_string()))?;
    let original = read_optional(root, &path)?;
    let mode = file_mode(root, &path)?.unwrap_or(DEFAULT_MODE);
    let paths = manifest_paths(plan.manifest());
    let candidate = render_managed_ignore(original.as_deref().unwrap_or_default(), &paths)
        .map_err(|error| GitveilError::configuration(error.to_string()))?;
    Ok(IgnorePreparation {
        path,
        original,
        candidate,
        mode,
    })
}

fn publish_registration<F: PublicationFault>(
    root: &Path,
    repository: &Repository,
    publication: &RegistrationPublication<'_>,
    fault: &F,
) -> Result<()> {
    let existing_paths = publication
        .existing_plaintext
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let previous_matches = repository.ignore_matches(&existing_paths)?;
    ensure_configuration_fresh(root, publication.manifest, publication.ignore)?;

    write_atomic_with_fault(
        root,
        &publication.ignore.path,
        &publication.ignore.candidate,
        publication.ignore.mode,
        true,
        fault,
    )?;
    let visibility_matches =
        repository.ignore_matches(&visibility_paths(publication.plan.manifest()))?;

    ensure_ignore_candidate_fresh(root, publication.ignore)?;
    if !manifest_is_fresh(root, publication.manifest)? {
        recover_concurrent_manifest(root, publication.plan, publication.ignore)?;
        return Err(manifest_changed_error());
    }

    let states = ignore_states(visibility_matches);
    let violations = visibility_violations(publication.plan.manifest(), &states)
        .map_err(|error| GitveilError::new(ErrorCategory::Integrity, error.to_string()))?;
    if !violations.is_empty() {
        if publication.existing_plaintext.iter().all(|path| {
            previous_matches
                .get(path)
                .is_some_and(IgnoreMatch::is_ignored)
        }) {
            restore_ignore_candidate(root, publication.ignore)?;
        }
        return Err(GitveilError::configuration(
            violations
                .iter()
                .map(plan::VisibilityViolation::describe)
                .collect::<Vec<_>>()
                .join("\n"),
        ));
    }

    finish_registration_publication(root, publication, fault)
}

fn finish_registration_publication<F: PublicationFault>(
    root: &Path,
    publication: &RegistrationPublication<'_>,
    fault: &F,
) -> Result<()> {
    tighten_plaintext_permissions(root, publication.existing_plaintext)?;
    ensure_ignore_candidate_fresh(root, publication.ignore)?;
    if !manifest_is_fresh(root, publication.manifest)? {
        recover_concurrent_manifest(root, publication.plan, publication.ignore)?;
        return Err(manifest_changed_error());
    }
    write_atomic_with_fault(
        root,
        &publication.manifest.path,
        publication.manifest_candidate,
        publication.manifest.mode,
        true,
        fault,
    )
}

fn visibility_paths(manifest: &Manifest) -> Vec<ManagedPath> {
    let mut paths = Vec::with_capacity(manifest.entries().len() * 2);
    for entry in manifest.entries() {
        paths.push(entry.path().clone());
        paths.push(entry.ciphertext_path());
    }
    paths
}

fn manifest_paths(manifest: &Manifest) -> Vec<ManagedPath> {
    manifest
        .entries()
        .iter()
        .map(|entry| entry.path().clone())
        .collect()
}

fn ignore_states(matches: HashMap<ManagedPath, IgnoreMatch>) -> HashMap<ManagedPath, IgnoreState> {
    matches
        .into_iter()
        .map(|(path, outcome)| {
            let state = match outcome {
                IgnoreMatch::Unmatched => IgnoreState::Unmatched,
                IgnoreMatch::Rule(rule) => IgnoreState::Matched(IgnoreRuleSnapshot::new(
                    rule.source().to_owned(),
                    rule.line(),
                    rule.pattern().to_owned(),
                    rule.is_ignored(),
                )),
            };
            (path, state)
        })
        .collect()
}

fn serialize_manifest(manifest: &Manifest) -> Result<Vec<u8>> {
    manifest.to_json_bytes().map_err(|_| {
        GitveilError::new(
            ErrorCategory::Integrity,
            "Gitveil manifest writer violated its internal reader contract",
        )
    })
}

fn ensure_configuration_fresh(
    root: &Path,
    manifest: &ManifestPreparation,
    ignore: &IgnorePreparation,
) -> Result<()> {
    if !manifest_is_fresh(root, manifest)? {
        return Err(manifest_changed_error());
    }
    if read_optional(root, &ignore.path)? != ignore.original {
        return Err(GitveilError::new(
            ErrorCategory::Concurrency,
            format!("{GITIGNORE_FILE_NAME} changed while gitveil add was running; retry"),
        ));
    }
    Ok(())
}

fn manifest_is_fresh(root: &Path, manifest: &ManifestPreparation) -> Result<bool> {
    Ok(read_optional(root, &manifest.path)?.as_deref() == Some(manifest.original.as_slice()))
}

fn ensure_ignore_candidate_fresh(root: &Path, ignore: &IgnorePreparation) -> Result<()> {
    if read_optional(root, &ignore.path)?.as_deref() != Some(ignore.candidate.as_slice()) {
        return Err(GitveilError::new(
            ErrorCategory::Concurrency,
            format!("{GITIGNORE_FILE_NAME} changed while gitveil add was running; retry"),
        ));
    }
    Ok(())
}

fn manifest_changed_error() -> GitveilError {
    GitveilError::new(
        ErrorCategory::Concurrency,
        format!("{MANIFEST_FILE_NAME} changed while gitveil add was running; retry"),
    )
}

fn recover_concurrent_manifest(
    root: &Path,
    plan: &RegistrationPlan,
    ignore: &IgnorePreparation,
) -> Result<()> {
    let latest_paths = read_optional(
        root,
        &ManagedPath::new(MANIFEST_FILE_NAME)
            .map_err(|error| GitveilError::configuration(error.to_string()))?,
    )?
    .and_then(|bytes| Manifest::parse(&bytes).ok())
    .map_or_else(Vec::new, |manifest| manifest_paths(&manifest));
    let candidate_paths = manifest_paths(plan.manifest());
    let protected = merge_protection_paths(&latest_paths, &candidate_paths);
    let current = read_optional(root, &ignore.path)?.unwrap_or_default();
    let mode = file_mode(root, &ignore.path)?.unwrap_or(ignore.mode);
    let recovered = render_managed_ignore(&current, &protected)
        .map_err(|error| GitveilError::configuration(error.to_string()))?;
    if current != recovered {
        if read_optional(root, &ignore.path)?.as_deref() != Some(current.as_slice()) {
            return Err(GitveilError::new(
                ErrorCategory::Concurrency,
                format!("{GITIGNORE_FILE_NAME} changed during concurrency recovery; retry"),
            ));
        }
        write_atomic(root, &ignore.path, &recovered, mode, true)?;
    }
    Ok(())
}

fn restore_ignore_candidate(root: &Path, ignore: &IgnorePreparation) -> Result<()> {
    ensure_ignore_candidate_fresh(root, ignore)?;
    restore_optional(root, &ignore.path, ignore.original.as_deref(), ignore.mode)
}

fn tighten_plaintext_permissions(root: &Path, paths: &HashSet<ManagedPath>) -> Result<()> {
    for path in paths {
        let file = confine::open_existing(root, path)?.ok_or_else(|| {
            GitveilError::new(
                ErrorCategory::Concurrency,
                format!("plaintext path {path} disappeared while gitveil add was running"),
            )
        })?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                GitveilError::io(
                    "set owner-only plaintext permissions",
                    Some(path.join_to(root)),
                    &error,
                )
            })?;
    }
    Ok(())
}

fn add_outcomes(
    plan: &RegistrationPlan,
    existing_plaintext: &HashSet<ManagedPath>,
) -> Vec<AddOutcome> {
    plan.outcomes()
        .iter()
        .map(|(path, kind)| AddOutcome {
            path: path.clone(),
            plaintext_exists: existing_plaintext.contains(path),
            kind: match kind {
                RegistrationKind::AlreadyManaged => AddOutcomeKind::AlreadyManaged,
                RegistrationKind::Added if existing_plaintext.contains(path) => {
                    AddOutcomeKind::AddedExisting
                }
                RegistrationKind::Added => AddOutcomeKind::AddedMissing,
            },
        })
        .collect()
}

fn select_recipient_policy(manifest: &Manifest, requested: Option<&str>) -> Result<PolicyName> {
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
            "multiple recipient policies are declared ({names}); pass --recipient-policy"
        )))
    }
}

fn mutation_repository(current: &Path) -> Result<Repository> {
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

fn read_optional(root: &Path, path: &ManagedPath) -> Result<Option<Vec<u8>>> {
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

fn file_mode(root: &Path, path: &ManagedPath) -> Result<Option<u32>> {
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

fn write_atomic(
    root: &Path,
    path: &ManagedPath,
    bytes: &[u8],
    mode: u32,
    replace: bool,
) -> Result<()> {
    write_atomic_with_fault(root, path, bytes, mode, replace, &NoPublicationFault)
}

fn write_atomic_with_fault<F: PublicationFault>(
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

fn restore_optional(
    root: &Path,
    path: &ManagedPath,
    original: Option<&[u8]>,
    mode: u32,
) -> Result<()> {
    if let Some(original) = original {
        write_atomic(root, path, original, mode, true)
    } else {
        confine::validate_managed_path(root, path)?;
        let target = path.join_to(root);
        match fs::remove_file(&target) {
            Ok(()) => sync_directory(root),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(GitveilError::io(
                "remove failed Gitignore candidate",
                Some(target),
                &error,
            )),
        }
    }
}

fn sync_directory(directory: &Path) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::{
        ErrorCategory, GITIGNORE_FILE_NAME, GitveilError, IgnorePreparation, MANIFEST_FILE_NAME,
        ManagedPath, Manifest, ManifestPreparation, PublicationFault, PublicationPoint,
        RegistrationPublication, finish_registration_publication, manifest_paths,
        registration_plan, render_managed_ignore, serialize_manifest,
    };

    const RECIPIENT: &str = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq";

    struct ManifestPublicationFault(PublicationPoint);

    impl PublicationFault for ManifestPublicationFault {
        fn check(&self, path: &ManagedPath, point: PublicationPoint) -> super::Result<()> {
            if path.as_str() == MANIFEST_FILE_NAME && point == self.0 {
                return Err(GitveilError::new(
                    ErrorCategory::Io,
                    "injected manifest publication failure",
                ));
            }
            Ok(())
        }
    }

    fn initial_manifest_bytes() -> Vec<u8> {
        format!(
            r#"{{
              "version": 1,
              "recipientPolicies": {{ "default": {{ "age": ["{RECIPIENT}"] }} }},
              "files": []
            }}"#
        )
        .into_bytes()
    }

    #[test]
    fn manifest_publication_failures_leave_only_old_or_complete_manifest_and_retry_converges() {
        for point in [
            PublicationPoint::BeforePersist,
            PublicationPoint::BeforeDirectorySync,
        ] {
            let root = tempfile::tempdir().expect("repository root");
            let original = initial_manifest_bytes();
            fs::write(root.path().join(MANIFEST_FILE_NAME), &original).expect("manifest");
            fs::write(root.path().join(".env"), "A=1\n").expect("plaintext");
            fs::set_permissions(root.path().join(".env"), fs::Permissions::from_mode(0o644))
                .expect("plaintext mode");

            let manifest = Manifest::parse(&original).expect("initial manifest");
            let (_, _, plan) =
                registration_plan(manifest, &[".env".to_owned()], "dotenv", None, None)
                    .expect("registration plan");
            let candidate = serialize_manifest(plan.manifest()).expect("candidate manifest");
            let ignore_path = ManagedPath::new(GITIGNORE_FILE_NAME).expect("ignore path");
            let ignore_candidate = render_managed_ignore(b"", &manifest_paths(plan.manifest()))
                .expect("ignore candidate");
            fs::write(root.path().join(GITIGNORE_FILE_NAME), &ignore_candidate)
                .expect("published ignore");
            let manifest_preparation = ManifestPreparation {
                path: ManagedPath::new(MANIFEST_FILE_NAME).expect("manifest path"),
                original: original.clone(),
                mode: 0o644,
            };
            let ignore_preparation = IgnorePreparation {
                path: ignore_path,
                original: None,
                candidate: ignore_candidate,
                mode: 0o644,
            };
            let existing = HashSet::from([ManagedPath::new(".env").expect("plaintext path")]);

            let publication = RegistrationPublication {
                manifest: &manifest_preparation,
                plan: &plan,
                existing_plaintext: &existing,
                ignore: &ignore_preparation,
                manifest_candidate: &candidate,
            };
            let error = finish_registration_publication(
                root.path(),
                &publication,
                &ManifestPublicationFault(point),
            )
            .expect_err("manifest publication must fail");
            assert_eq!(error.category(), ErrorCategory::Io);
            assert_eq!(
                fs::metadata(root.path().join(".env"))
                    .expect("plaintext metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            let after_failure = fs::read(root.path().join(MANIFEST_FILE_NAME)).expect("manifest");
            assert!(
                after_failure == original || after_failure == candidate,
                "manifest must be old or the complete candidate"
            );
            assert!(
                fs::read(root.path().join(GITIGNORE_FILE_NAME))
                    .expect("ignore")
                    .windows(b"/.env\n".len())
                    .any(|window| window == b"/.env\n")
            );

            let retry_manifest = Manifest::parse(&after_failure).expect("retry manifest");
            let (_, _, retry_plan) =
                registration_plan(retry_manifest, &[".env".to_owned()], "dotenv", None, None)
                    .expect("retry plan");
            let retry_candidate =
                serialize_manifest(retry_plan.manifest()).expect("retry candidate");
            let retry_preparation = ManifestPreparation {
                path: ManagedPath::new(MANIFEST_FILE_NAME).expect("manifest path"),
                original: after_failure,
                mode: 0o644,
            };
            finish_registration_publication(
                root.path(),
                &RegistrationPublication {
                    manifest: &retry_preparation,
                    plan: &retry_plan,
                    existing_plaintext: &existing,
                    ignore: &ignore_preparation,
                    manifest_candidate: &retry_candidate,
                },
                &super::NoPublicationFault,
            )
            .expect("retry converges");
            assert_eq!(
                Manifest::parse(
                    &fs::read(root.path().join(MANIFEST_FILE_NAME)).expect("final manifest")
                )
                .expect("final manifest")
                .entries()
                .len(),
                1
            );
        }
    }
}

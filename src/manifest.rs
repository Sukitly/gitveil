//! `.gitveilrc.json` manifest: the authoritative declaration of managed pairs and recipients.
//!
//! The manifest lives at the workspace root, is tracked by Git as an ordinary
//! file, and declares every managed plaintext path, source format, profile,
//! and named age recipient policy. Gitveil does not read repository SOPS configuration.
//!

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::SourceFormat;
use crate::path::{ManagedPath, PathError};
use crate::profile::{ProfileError, ProfileName};
use crate::recipient::{AgeRecipient, AgeRecipientPolicy, PolicyName, RecipientError};

pub const MANIFEST_FILE_NAME: &str = ".gitveilrc.json";
pub const GITIGNORE_FILE_NAME: &str = ".gitignore";
pub const CIPHERTEXT_SUFFIX: &str = ".gitveil";
const MANIFEST_VERSION: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    path: ManagedPath,
    format: SourceFormat,
    recipient_policy: PolicyName,
    profile: ProfileName,
}

impl ManifestEntry {
    pub(crate) fn new(
        path: ManagedPath,
        format: SourceFormat,
        recipient_policy: PolicyName,
        profile: ProfileName,
    ) -> Self {
        Self {
            path,
            format,
            recipient_policy,
            profile,
        }
    }

    pub fn path(&self) -> &ManagedPath {
        &self.path
    }

    pub const fn format(&self) -> SourceFormat {
        self.format
    }

    pub fn recipient_policy(&self) -> &PolicyName {
        &self.recipient_policy
    }

    pub fn profile(&self) -> &ProfileName {
        &self.profile
    }

    /// Returns the sibling ciphertext path (`<path>.gitveil`).
    ///
    /// # Panics
    /// Never panics: appending the fixed suffix to a validated managed path
    /// yields a validated managed path.
    pub fn ciphertext_path(&self) -> ManagedPath {
        ManagedPath::new(format!("{}{CIPHERTEXT_SUFFIX}", self.path.as_str()))
            .expect("appending the ciphertext suffix preserves managed-path validity")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedManifestEntry<'a> {
    entry: &'a ManifestEntry,
    recipient_policy: &'a AgeRecipientPolicy,
}

impl<'a> ResolvedManifestEntry<'a> {
    const fn new(entry: &'a ManifestEntry, recipient_policy: &'a AgeRecipientPolicy) -> Self {
        Self {
            entry,
            recipient_policy,
        }
    }

    pub(crate) fn path(&self) -> &ManagedPath {
        self.entry.path()
    }

    pub(crate) const fn format(&self) -> SourceFormat {
        self.entry.format()
    }

    pub(crate) const fn recipient_policy(&self) -> &AgeRecipientPolicy {
        self.recipient_policy
    }

    pub(crate) fn policy_name(&self) -> &PolicyName {
        self.entry.recipient_policy()
    }

    pub(crate) fn ciphertext_path(&self) -> ManagedPath {
        self.entry.ciphertext_path()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    entries: Vec<ManifestEntry>,
    recipient_policies: IndexMap<PolicyName, AgeRecipientPolicy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    version: u64,
    #[serde(rename = "recipientPolicies")]
    recipient_policies: IndexMap<String, RawPolicy>,
    files: Vec<RawEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    age: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    path: String,
    format: String,
    #[serde(rename = "recipientPolicy")]
    recipient_policy: String,
    #[serde(default = "default_profile")]
    profile: String,
}

#[derive(Serialize)]
struct SerializedManifest<'a> {
    version: u64,
    #[serde(rename = "recipientPolicies")]
    recipient_policies: IndexMap<&'a str, SerializedPolicy<'a>>,
    files: Vec<SerializedEntry<'a>>,
}

#[derive(Serialize)]
struct SerializedPolicy<'a> {
    age: Vec<&'a str>,
}

#[derive(Serialize)]
struct SerializedEntry<'a> {
    path: &'a str,
    format: &'a str,
    #[serde(rename = "recipientPolicy")]
    recipient_policy: &'a str,
    profile: &'a str,
}

fn default_profile() -> String {
    ProfileName::DEFAULT.to_owned()
}

impl Manifest {
    pub(crate) fn initial(policy: AgeRecipientPolicy) -> Self {
        let mut recipient_policies = IndexMap::new();
        recipient_policies.insert(policy.name().clone(), policy);
        Self {
            entries: Vec::new(),
            recipient_policies,
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| ManifestError::Json(error.to_string()))?;
        if value
            .as_object()
            .is_some_and(|object| object.contains_key("files") && !object.contains_key("version"))
        {
            return Err(ManifestError::LegacySchema);
        }
        let raw: RawManifest = serde_json::from_value(value)
            .map_err(|error| ManifestError::Json(error.to_string()))?;
        if raw.version != MANIFEST_VERSION {
            return Err(ManifestError::Version(raw.version));
        }

        let mut recipient_policies = IndexMap::with_capacity(raw.recipient_policies.len());
        for (raw_name, raw_policy) in raw.recipient_policies {
            let name = PolicyName::new(&raw_name)
                .map_err(|error| ManifestError::Policy(raw_name.clone(), error))?;
            let recipients = raw_policy
                .age
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    AgeRecipient::new(value).map_err(|error| ManifestError::Recipient {
                        policy: raw_name.clone(),
                        index,
                        source: error,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let policy = AgeRecipientPolicy::new(name.clone(), recipients)
                .map_err(|error| ManifestError::Policy(raw_name, error))?;
            recipient_policies.insert(name, policy);
        }

        let mut entries = Vec::with_capacity(raw.files.len());
        let mut seen = std::collections::HashSet::with_capacity(raw.files.len());
        for entry in raw.files {
            let path = ManagedPath::new(&entry.path)
                .map_err(|error| ManifestError::Path(entry.path.clone(), error))?;
            if path.as_str().ends_with(CIPHERTEXT_SUFFIX) {
                return Err(ManifestError::CiphertextSuffix(entry.path));
            }
            if is_repository_configuration_path(&path) {
                return Err(ManifestError::ReservedPath(entry.path));
            }
            let format = entry
                .format
                .parse::<SourceFormat>()
                .map_err(|_| ManifestError::Format(entry.format.clone()))?;
            if !seen.insert(path.case_collision_key()) {
                return Err(ManifestError::Duplicate(entry.path));
            }
            let policy_name = PolicyName::new(&entry.recipient_policy)
                .map_err(|error| ManifestError::Policy(entry.recipient_policy.clone(), error))?;
            if !recipient_policies.contains_key(&policy_name) {
                return Err(ManifestError::MissingPolicy {
                    path: entry.path,
                    policy: entry.recipient_policy,
                });
            }
            let profile =
                ProfileName::new(&entry.profile).map_err(|source| ManifestError::Profile {
                    path: entry.path.clone(),
                    profile: entry.profile,
                    source,
                })?;
            entries.push(ManifestEntry {
                path,
                format,
                recipient_policy: policy_name,
                profile,
            });
        }
        Ok(Self {
            entries,
            recipient_policies,
        })
    }

    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    pub fn recipient_policy(&self, name: &PolicyName) -> Option<&AgeRecipientPolicy> {
        self.recipient_policies.get(name)
    }

    pub(crate) fn policy_names(&self) -> Vec<&PolicyName> {
        self.recipient_policies.keys().collect()
    }

    pub(crate) fn only_policy_name(&self) -> Option<&PolicyName> {
        (self.recipient_policies.len() == 1)
            .then(|| self.recipient_policies.keys().next())
            .flatten()
    }

    pub(crate) fn add_entry(
        &mut self,
        entry: ManifestEntry,
    ) -> Result<ManifestEntryAddOutcome, ManifestMutationError> {
        if entry.path().as_str().ends_with(CIPHERTEXT_SUFFIX) {
            return Err(ManifestMutationError::CiphertextSuffix(
                entry.path().clone(),
            ));
        }
        if is_repository_configuration_path(entry.path()) {
            return Err(ManifestMutationError::ReservedPath(entry.path().clone()));
        }
        if !self
            .recipient_policies
            .contains_key(entry.recipient_policy())
        {
            return Err(ManifestMutationError::MissingPolicy(
                entry.recipient_policy().clone(),
            ));
        }
        if let Some(existing) = self.find(entry.path()) {
            if existing.format() == entry.format()
                && existing.recipient_policy() == entry.recipient_policy()
                && existing.profile() == entry.profile()
            {
                return Ok(ManifestEntryAddOutcome::AlreadyManaged);
            }
            return Err(ManifestMutationError::ConflictingEntry(
                entry.path().clone(),
            ));
        }
        let folded = entry.path().case_collision_key();
        if self
            .entries
            .iter()
            .any(|existing| existing.path().case_collision_key() == folded)
        {
            return Err(ManifestMutationError::CaseCollision(entry.path().clone()));
        }
        self.entries.push(entry);
        Ok(ManifestEntryAddOutcome::Added)
    }

    /// Replaces the recipient list of an existing policy.
    ///
    /// This is the manifest side of `gitveil recipient add`/`remove`; policy
    /// invariants (non-empty, unique recipients) are enforced by the same
    /// domain constructor the reader uses.
    pub(crate) fn set_policy_recipients(
        &mut self,
        name: &PolicyName,
        recipients: Vec<AgeRecipient>,
    ) -> Result<(), ManifestMutationError> {
        let Some(slot) = self.recipient_policies.get_mut(name) else {
            return Err(ManifestMutationError::MissingPolicy(name.clone()));
        };
        *slot = AgeRecipientPolicy::new(name.clone(), recipients).map_err(|source| {
            ManifestMutationError::Policy {
                policy: name.clone(),
                source,
            }
        })?;
        Ok(())
    }

    pub(crate) fn to_json_bytes(&self) -> Result<Vec<u8>, ManifestWriteError> {
        let recipient_policies = self
            .recipient_policies
            .iter()
            .map(|(name, policy)| {
                (
                    name.as_str(),
                    SerializedPolicy {
                        age: policy
                            .recipients()
                            .iter()
                            .map(AgeRecipient::as_str)
                            .collect(),
                    },
                )
            })
            .collect();
        let files = self
            .entries
            .iter()
            .map(|entry| SerializedEntry {
                path: entry.path().as_str(),
                format: entry.format().as_str(),
                recipient_policy: entry.recipient_policy().as_str(),
                profile: entry.profile().as_str(),
            })
            .collect();
        let mut bytes = serde_json::to_vec_pretty(&SerializedManifest {
            version: MANIFEST_VERSION,
            recipient_policies,
            files,
        })
        .map_err(|_| ManifestWriteError::Serialization)?;
        bytes.push(b'\n');
        let reparsed = Self::parse(&bytes).map_err(|_| ManifestWriteError::Invariant)?;
        if &reparsed != self {
            return Err(ManifestWriteError::Invariant);
        }
        Ok(bytes)
    }

    pub(crate) fn resolve_entry<'a>(
        &'a self,
        entry: &'a ManifestEntry,
    ) -> Option<ResolvedManifestEntry<'a>> {
        self.recipient_policy(entry.recipient_policy())
            .map(|policy| ResolvedManifestEntry::new(entry, policy))
    }

    pub fn find(&self, path: &ManagedPath) -> Option<&ManifestEntry> {
        self.entries.iter().find(|entry| entry.path() == path)
    }

    /// Selects entries by optional managed paths and profile.
    ///
    /// An empty path list means all entries. When both selectors are present,
    /// every requested path must belong to the selected profile; mismatches
    /// fail instead of silently broadening or narrowing the operation.
    pub fn select<'a>(
        &'a self,
        paths: &[ManagedPath],
        profile: Option<&ProfileName>,
    ) -> Result<Vec<&'a ManifestEntry>, ManifestSelectionError> {
        if let Some(profile) = profile
            && !self.entries.iter().any(|entry| entry.profile() == profile)
        {
            return Err(ManifestSelectionError::UnknownProfile(profile.clone()));
        }

        let selected = if paths.is_empty() {
            self.entries.iter().collect::<Vec<_>>()
        } else {
            paths
                .iter()
                .map(|path| {
                    self.find(path)
                        .ok_or_else(|| ManifestSelectionError::UndeclaredPath(path.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        if let Some(profile) = profile {
            if !paths.is_empty() {
                for entry in &selected {
                    if entry.profile() != profile {
                        return Err(ManifestSelectionError::ProfileMismatch {
                            path: entry.path().clone(),
                            expected: profile.clone(),
                            actual: entry.profile().clone(),
                        });
                    }
                }
            }
            return Ok(selected
                .into_iter()
                .filter(|entry| entry.profile() == profile)
                .collect());
        }
        Ok(selected)
    }
}

fn is_repository_configuration_path(path: &ManagedPath) -> bool {
    matches!(path.as_str(), MANIFEST_FILE_NAME | GITIGNORE_FILE_NAME)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManifestEntryAddOutcome {
    Added,
    AlreadyManaged,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(crate) enum ManifestMutationError {
    #[error("plaintext path {0} must not carry the {CIPHERTEXT_SUFFIX} suffix")]
    CiphertextSuffix(ManagedPath),
    #[error("path {0} is reserved for Gitveil repository configuration")]
    ReservedPath(ManagedPath),
    #[error("path {0} is already managed with different format, profile, or recipient policy")]
    ConflictingEntry(ManagedPath),
    #[error("path {0} collides case-insensitively with an existing managed path")]
    CaseCollision(ManagedPath),
    #[error("recipient policy {0} is not declared in {MANIFEST_FILE_NAME}")]
    MissingPolicy(PolicyName),
    #[error("invalid recipient policy {policy}: {source}")]
    Policy {
        policy: PolicyName,
        source: RecipientError,
    },
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum ManifestWriteError {
    #[error("manifest serialization failed")]
    Serialization,
    #[error("serialized manifest violated the manifest reader contract")]
    Invariant,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ManifestSelectionError {
    #[error("path {0} is not declared in {MANIFEST_FILE_NAME}")]
    UndeclaredPath(ManagedPath),
    #[error("profile {0} is not used by any file in {MANIFEST_FILE_NAME}")]
    UnknownProfile(ProfileName),
    #[error("path {path} belongs to profile {actual}, not requested profile {expected}")]
    ProfileMismatch {
        path: ManagedPath,
        expected: ProfileName,
        actual: ProfileName,
    },
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("invalid {MANIFEST_FILE_NAME}: {0}")]
    Json(String),
    #[error(
        "legacy {MANIFEST_FILE_NAME} schema is unsupported; add version, recipientPolicies, and recipientPolicy fields"
    )]
    LegacySchema,
    #[error("unsupported {MANIFEST_FILE_NAME} version {0}; expected {MANIFEST_VERSION}")]
    Version(u64),
    #[error("invalid recipient policy {0:?}: {1}")]
    Policy(String, RecipientError),
    #[error("invalid age recipient at policy {policy:?} index {index}: {source}")]
    Recipient {
        policy: String,
        index: usize,
        source: RecipientError,
    },
    #[error("manifest path {path:?} references missing recipient policy {policy:?}")]
    MissingPolicy { path: String, policy: String },
    #[error("manifest path {path:?} has invalid profile {profile:?}: {source}")]
    Profile {
        path: String,
        profile: String,
        source: ProfileError,
    },
    #[error("invalid manifest path {0:?}: {1}")]
    Path(String, PathError),
    #[error("manifest path {0:?} must not carry the {CIPHERTEXT_SUFFIX} suffix")]
    CiphertextSuffix(String),
    #[error("manifest path {0:?} is reserved for Gitveil repository configuration")]
    ReservedPath(String),
    #[error("unsupported manifest format {0:?}; expected dotenv, json, yaml, or toml")]
    Format(String),
    #[error("duplicate manifest path {0:?}")]
    Duplicate(String),
}

#[cfg(test)]
mod tests {
    use super::{
        Manifest, ManifestEntry, ManifestEntryAddOutcome, ManifestMutationError, ManifestWriteError,
    };
    use crate::config::SourceFormat;
    use crate::path::ManagedPath;
    use crate::profile::ProfileName;
    use crate::recipient::PolicyName;

    const RECIPIENT: &str = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq";

    fn manifest() -> Manifest {
        Manifest::parse(
            format!(
                r#"{{
                  "version": 1,
                  "recipientPolicies": {{ "default": {{ "age": ["{RECIPIENT}"] }} }},
                  "files": []
                }}"#
            )
            .as_bytes(),
        )
        .expect("manifest")
    }

    fn entry(path: &str, policy: &str, profile: &str) -> ManifestEntry {
        ManifestEntry::new(
            ManagedPath::new(path).expect("managed path"),
            SourceFormat::Dotenv,
            PolicyName::new(policy).expect("policy"),
            ProfileName::new(profile).expect("profile"),
        )
    }

    #[test]
    fn mutation_rejects_ciphertext_suffix_paths_like_the_reader() {
        let mut manifest = manifest();
        assert_eq!(
            manifest.add_entry(entry("secret.env.gitveil", "default", "default")),
            Err(ManifestMutationError::CiphertextSuffix(
                ManagedPath::new("secret.env.gitveil").expect("managed path")
            ))
        );
    }

    #[test]
    fn mutation_enforces_reserved_policy_collision_and_conflict_invariants() {
        let mut manifest = manifest();
        assert!(matches!(
            manifest.add_entry(entry(".gitignore", "default", "default")),
            Err(ManifestMutationError::ReservedPath(_))
        ));
        assert!(matches!(
            manifest.add_entry(entry("secret.env", "missing", "default")),
            Err(ManifestMutationError::MissingPolicy(_))
        ));
        assert_eq!(
            manifest
                .add_entry(entry("secret.env", "default", "default"))
                .expect("first registration"),
            ManifestEntryAddOutcome::Added
        );
        assert_eq!(
            manifest
                .add_entry(entry("secret.env", "default", "default"))
                .expect("idempotent registration"),
            ManifestEntryAddOutcome::AlreadyManaged
        );
        assert!(matches!(
            manifest.add_entry(entry("secret.env", "default", "dev")),
            Err(ManifestMutationError::ConflictingEntry(_))
        ));
        assert!(matches!(
            manifest.add_entry(entry("SECRET.env", "default", "default")),
            Err(ManifestMutationError::CaseCollision(_))
        ));
    }

    #[test]
    fn policy_recipient_replacement_enforces_the_reader_invariants() {
        let mut manifest = manifest();
        let name = PolicyName::new("default").expect("policy name");
        let recipient = crate::recipient::AgeRecipient::new(RECIPIENT).expect("recipient");
        assert!(matches!(
            manifest.set_policy_recipients(
                &PolicyName::new("missing").expect("policy name"),
                vec![recipient.clone()]
            ),
            Err(ManifestMutationError::MissingPolicy(_))
        ));
        assert!(matches!(
            manifest.set_policy_recipients(&name, Vec::new()),
            Err(ManifestMutationError::Policy { .. })
        ));
        manifest
            .set_policy_recipients(&name, vec![recipient.clone()])
            .expect("replacement");
        assert_eq!(
            manifest
                .recipient_policy(&name)
                .expect("policy")
                .recipients(),
            &[recipient]
        );
        manifest.to_json_bytes().expect("writer round-trip");
    }

    #[test]
    fn writer_reports_reader_disagreement_as_an_internal_invariant() {
        let mut manifest = manifest();
        manifest
            .entries
            .push(entry("secret.env.gitveil", "default", "default"));
        assert_eq!(manifest.to_json_bytes(), Err(ManifestWriteError::Invariant));
    }
}

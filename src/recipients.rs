//! `gitveil recipient add` / `gitveil recipient remove`: the only commands
//! that change which recipients can decrypt managed ciphertext.
//!
//! Data commands (`seal`, `resolve`) fail closed on recipient drift; this
//! module is the single authorization entry point. Each command converges
//! envelopes only in its own direction and only for the recipients named on
//! the command line; residual drift against the policy is reported with
//! full recipient values and keeps `seal` fail-closed. The manifest is
//! published before file convergence, so any mid-run failure leaves drift
//! that an idempotent rerun converges.

mod plan;

use std::path::Path;
use std::time::Duration;

use crate::baseline::{BaselineRecord, BaselineStore, CipherSummary};
use crate::envelope::{CiphertextEnvelope, DecryptedEnvelope};
use crate::error::{ErrorCategory, GitveilError, Result, SecretBytes};
use crate::manifest::{Manifest, ManifestEntry, ResolvedManifestEntry};
use crate::manifest_document::{
    load_manifest, mutation_repository, publish_if_fresh, read_optional, select_recipient_policy,
    serialize_manifest,
};
use crate::path::ManagedPath;
use crate::recipient::{AgeRecipient, AgeRecipientPolicy, PolicyName};
use crate::runtime::{PrivateRuntime, acquire_lock};
use crate::seal::decrypt_source;
use crate::sops::{SopsBinary, SopsClient, SopsPaths};
use crate::source::SourceDocument;
use crate::workspace::write_ciphertext_file;

pub(crate) use plan::{ConvergenceAction, PolicyDelta};
use plan::{FilePlan, FileRecipientFacts, RecipientMutation, plan_authorization};

const LOCK_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecipientFileOutcome {
    Rewrapped,
    DataKeyRotated,
    /// The named recipients required no change on this envelope.
    NoChangeNeeded,
}

/// One file's committed convergence result plus the residual drift that
/// remains against the policy (full values: the operator acts on them).
pub(crate) struct FileConvergence {
    pub outcome: RecipientFileOutcome,
    pub pending_additions: Vec<AgeRecipient>,
    pub pending_removals: Vec<AgeRecipient>,
}

pub(crate) struct RecipientFileReport {
    pub path: ManagedPath,
    pub result: Result<FileConvergence>,
}

/// What happened to the manifest document itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManifestDisposition {
    /// The policy already carried the requested state.
    Unchanged,
    Published,
    /// Nothing was published: every required convergence failed preflight.
    Withheld,
}

pub(crate) struct AuthorizationOutcome {
    pub policy: PolicyName,
    /// Manifest-level effects; the CLI renders them only after publication.
    pub deltas: Vec<PolicyDelta>,
    pub manifest: ManifestDisposition,
    pub reports: Vec<RecipientFileReport>,
}

pub(crate) fn add(
    current: &Path,
    gitveil_binary: &Path,
    policy: Option<&str>,
    recipients: &[String],
) -> Result<AuthorizationOutcome> {
    authorize(current, gitveil_binary, policy, recipients, Direction::Add)
}

pub(crate) fn remove(
    current: &Path,
    gitveil_binary: &Path,
    policy: Option<&str>,
    recipients: &[String],
) -> Result<AuthorizationOutcome> {
    authorize(
        current,
        gitveil_binary,
        policy,
        recipients,
        Direction::Remove,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Add,
    Remove,
}

struct AffectedFile<'a> {
    entry: &'a ManifestEntry,
    ciphertext: Vec<u8>,
}

fn authorize(
    current: &Path,
    gitveil_binary: &Path,
    requested_policy: Option<&str>,
    requested: &[String],
    direction: Direction,
) -> Result<AuthorizationOutcome> {
    let parsed = parse_requested(requested)?;
    let repository = mutation_repository(current)?;
    let runtime = PrivateRuntime::open(repository.runtime_path().to_path_buf())?;
    let _lock = acquire_lock(&runtime, LOCK_TIMEOUT)?;
    let root = repository.root().to_path_buf();
    let store = BaselineStore::new(repository.runtime_path().join("state"));

    let (manifest_preparation, manifest) = load_manifest(&root)?;
    let policy_name = select_recipient_policy(&manifest, requested_policy, "--policy")?;
    let policy = manifest.recipient_policy(&policy_name).ok_or_else(|| {
        GitveilError::new(
            ErrorCategory::Integrity,
            "selected recipient policy disappeared from the parsed manifest",
        )
    })?;

    let files = collect_policy_files(&root, &manifest, &policy_name)?;
    let mut reports = files.broken;

    let mutation = match direction {
        Direction::Add => RecipientMutation::Add(parsed),
        Direction::Remove => RecipientMutation::Remove(parsed),
    };
    let plan = plan_authorization(policy, &mutation, &files.facts)
        .map_err(|rejection| GitveilError::configuration(rejection.to_string()))?;

    let mut candidate = manifest.clone();
    candidate
        .set_policy_recipients(&policy_name, plan.desired_recipients.clone())
        .map_err(|error| GitveilError::new(ErrorCategory::Integrity, error.to_string()))?;
    let candidate_bytes = serialize_manifest(&candidate)?;

    let mut convergences = Vec::new();
    for file_plan in &plan.files {
        if file_plan.action == ConvergenceAction::AlreadyAligned {
            reports.push(RecipientFileReport {
                path: file_plan.path.clone(),
                result: Ok(FileConvergence {
                    outcome: RecipientFileOutcome::NoChangeNeeded,
                    pending_additions: file_plan.pending_additions.clone(),
                    pending_removals: file_plan.pending_removals.clone(),
                }),
            });
            continue;
        }
        let file = files
            .affected
            .iter()
            .find(|file| file.entry.path() == &file_plan.path)
            .ok_or_else(|| {
                GitveilError::new(
                    ErrorCategory::Integrity,
                    format!(
                        "authorization plan references unknown file {}",
                        file_plan.path
                    ),
                )
            })?;
        convergences.push((file, file_plan));
    }

    let engine = ConvergenceEngine {
        root: &root,
        runtime: &runtime,
        gitveil_binary,
        store: &store,
        manifest: &manifest,
        policy_name: &policy_name,
    };
    let manifest_disposition =
        engine.run(convergences, &mut reports, plan.manifest_changed, || {
            publish_if_fresh(
                &root,
                &manifest_preparation,
                &candidate_bytes,
                "gitveil recipient",
            )
        })?;

    Ok(AuthorizationOutcome {
        policy: policy_name,
        deltas: plan.deltas,
        manifest: manifest_disposition,
        reports,
    })
}

fn parse_requested(requested: &[String]) -> Result<Vec<AgeRecipient>> {
    requested
        .iter()
        .enumerate()
        .map(|(index, value)| {
            AgeRecipient::new(value).map_err(|error| {
                GitveilError::configuration(format!(
                    "invalid public age recipient at index {index}: {error}"
                ))
            })
        })
        .collect()
}

struct PolicyFiles<'a> {
    facts: Vec<FileRecipientFacts>,
    affected: Vec<AffectedFile<'a>>,
    /// Per-file reports for ciphertexts that could not be parsed; they are
    /// excluded from the plan and their drift stays visible to `seal`.
    broken: Vec<RecipientFileReport>,
}

fn collect_policy_files<'a>(
    root: &Path,
    manifest: &'a Manifest,
    policy_name: &PolicyName,
) -> Result<PolicyFiles<'a>> {
    let mut files = PolicyFiles {
        facts: Vec::new(),
        affected: Vec::new(),
        broken: Vec::new(),
    };
    for entry in manifest.entries() {
        if entry.recipient_policy() != policy_name {
            continue;
        }
        let cipher_path = entry.ciphertext_path();
        match read_optional(root, &cipher_path)? {
            None => files.facts.push(FileRecipientFacts {
                path: entry.path().clone(),
                envelope_recipients: None,
            }),
            Some(bytes) => match CiphertextEnvelope::parse(&bytes, entry.format()) {
                Ok(envelope) => {
                    files.facts.push(FileRecipientFacts {
                        path: entry.path().clone(),
                        envelope_recipients: Some(envelope.age_recipients().to_vec()),
                    });
                    files.affected.push(AffectedFile {
                        entry,
                        ciphertext: bytes,
                    });
                }
                Err(error) => files.broken.push(RecipientFileReport {
                    path: entry.path().clone(),
                    result: Err(GitveilError::ciphertext(&cipher_path, &error.to_string())),
                }),
            },
        }
    }
    Ok(files)
}

struct ConvergenceEngine<'a> {
    root: &'a Path,
    runtime: &'a PrivateRuntime,
    gitveil_binary: &'a Path,
    store: &'a BaselineStore,
    manifest: &'a Manifest,
    policy_name: &'a PolicyName,
}

impl ConvergenceEngine<'_> {
    fn run(
        &self,
        convergences: Vec<(&AffectedFile<'_>, &FilePlan)>,
        reports: &mut Vec<RecipientFileReport>,
        manifest_changed: bool,
        publish: impl FnOnce() -> Result<()>,
    ) -> Result<ManifestDisposition> {
        let disposition = |published: bool| {
            if published {
                ManifestDisposition::Published
            } else {
                ManifestDisposition::Unchanged
            }
        };
        if convergences.is_empty() {
            if manifest_changed {
                publish()?;
            }
            return Ok(disposition(manifest_changed));
        }
        let sops = SopsClient::new(
            SopsBinary::discover(None, self.gitveil_binary)?,
            SopsPaths {
                repository: self.root.to_path_buf(),
                gitveil_binary: self.gitveil_binary.to_path_buf(),
            },
            self.runtime.clone(),
        )?;

        // Preflight: prove the current envelopes are decryptable before any
        // publication. When nothing can be decrypted (no identity, or every
        // file failed) the manifest is withheld and nothing changes.
        let mut ready = Vec::new();
        let mut failures = Vec::new();
        for (file, file_plan) in convergences {
            let resolved = self.manifest.resolve_entry(file.entry).ok_or_else(|| {
                GitveilError::new(
                    ErrorCategory::Integrity,
                    format!(
                        "manifest entry {} lost its recipient policy",
                        file.entry.path()
                    ),
                )
            })?;
            match decrypt_source(&sops, &file.ciphertext, &resolved) {
                Ok(document) => ready.push((file, file_plan, resolved, document)),
                Err(error) => failures.push(RecipientFileReport {
                    path: file.entry.path().clone(),
                    result: Err(error),
                }),
            }
        }
        if ready.is_empty() {
            reports.extend(failures);
            return Ok(ManifestDisposition::Withheld);
        }

        if manifest_changed {
            publish()?;
        }

        for (file, file_plan, resolved, document) in ready {
            let result = self
                .converge_file(&sops, &resolved, &file.ciphertext, &document, file_plan)
                .map(|outcome| FileConvergence {
                    outcome,
                    pending_additions: file_plan.pending_additions.clone(),
                    pending_removals: file_plan.pending_removals.clone(),
                });
            reports.push(RecipientFileReport {
                path: file.entry.path().clone(),
                result,
            });
        }
        reports.extend(failures);
        Ok(disposition(manifest_changed))
    }

    fn converge_file(
        &self,
        sops: &SopsClient,
        resolved: &ResolvedManifestEntry<'_>,
        ciphertext: &[u8],
        document: &SourceDocument,
        file_plan: &FilePlan,
    ) -> Result<RecipientFileOutcome> {
        let path = resolved.path();
        let cipher_path = resolved.ciphertext_path();
        let target = AgeRecipientPolicy::new(
            self.policy_name.clone(),
            file_plan.target_recipients.clone(),
        )
        .map_err(|error| {
            GitveilError::new(
                ErrorCategory::Integrity,
                format!("authorization plan produced an invalid target set: {error}"),
            )
        })?;
        let (converged, outcome) = match file_plan.action {
            ConvergenceAction::AlreadyAligned => {
                return Ok(RecipientFileOutcome::NoChangeNeeded);
            }
            ConvergenceAction::Rewrap => {
                let rewrapped = sops.rewrap(ciphertext, &target)?;
                verify_rewrap(ciphertext, &rewrapped, resolved, &target)?;
                (rewrapped, RecipientFileOutcome::Rewrapped)
            }
            ConvergenceAction::Rotate => {
                // The content truth source is the decrypted current envelope;
                // workspace plaintext (and any unsealed local edit) is never
                // read or consumed by an authorization command.
                let desired_bytes = DecryptedEnvelope::from_source(document)
                    .and_then(|envelope| envelope.to_yaml())
                    .map(SecretBytes::new)
                    .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))?;
                let rotated = sops.encrypt_new(&desired_bytes, path, &target)?;
                let envelope = CiphertextEnvelope::parse(&rotated, resolved.format())
                    .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))?;
                verify_target_recipients(&envelope, &target, path)?;
                let roundtrip = decrypt_source(sops, &rotated, resolved)?;
                if !roundtrip.semantic_eq(document) {
                    return Err(GitveilError::new(
                        ErrorCategory::Integrity,
                        format!("rotated ciphertext failed semantic verification at {path}"),
                    ));
                }
                (rotated, RecipientFileOutcome::DataKeyRotated)
            }
        };
        write_ciphertext_file(self.root, &cipher_path, &converged)?;
        let envelope = CiphertextEnvelope::parse(&converged, resolved.format())
            .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))?;
        let record = BaselineRecord::capture(
            document,
            &CipherSummary::from_envelope(&envelope),
            BaselineStore::fresh_salt(),
        );
        self.store.save(path, &record)?;
        Ok(outcome)
    }
}

/// Verifies a rewrap changed only the wrapped data key: the recipient set
/// is exactly the per-file target and every encrypted leaf stayed
/// byte-for-byte stable.
fn verify_rewrap(
    before: &[u8],
    after: &[u8],
    resolved: &ResolvedManifestEntry<'_>,
    target: &AgeRecipientPolicy,
) -> Result<()> {
    let path = resolved.path();
    let before = CiphertextEnvelope::parse(before, resolved.format())
        .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))?;
    let after = CiphertextEnvelope::parse(after, resolved.format())
        .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))?;
    verify_target_recipients(&after, target, path)?;
    if before.leaf_ciphertexts() != after.leaf_ciphertexts()
        || before.layout_ciphertext() != after.layout_ciphertext()
    {
        return Err(GitveilError::new(
            ErrorCategory::Integrity,
            format!("SOPS recipient update changed encrypted data at {path}"),
        ));
    }
    Ok(())
}

fn verify_target_recipients(
    envelope: &CiphertextEnvelope,
    target: &AgeRecipientPolicy,
    path: &ManagedPath,
) -> Result<()> {
    if target.matches(envelope.age_recipients()) {
        return Ok(());
    }
    Err(GitveilError::new(
        ErrorCategory::Integrity,
        format!("SOPS result recipients do not match the authorized target set at {path}"),
    ))
}

//! `gitveil recipient add` / `gitveil recipient remove`: the only commands
//! that change which recipients can decrypt managed ciphertext.
//!
//! Data commands (`seal`, `resolve`) fail closed on recipient drift; this
//! module is the single authorization entry point. The operator's command
//! line names every recipient whose access changes, and the pure plan
//! rejects any manifest/envelope difference that the command line does not
//! explain. The manifest is published first: any mid-run failure leaves
//! drift that `seal` refuses and an idempotent rerun converges.

mod plan;

use std::path::Path;
use std::time::Duration;

use crate::baseline::{BaselineRecord, BaselineStore, CipherSummary};
use crate::configure::{
    ManifestPreparation, load_manifest, mutation_repository, read_optional,
    select_recipient_policy, serialize_manifest, write_atomic,
};
use crate::envelope::{CiphertextEnvelope, DecryptedEnvelope};
use crate::error::{ErrorCategory, GitveilError, Result, SecretBytes};
use crate::manifest::{MANIFEST_FILE_NAME, Manifest, ManifestEntry, ResolvedManifestEntry};
use crate::path::ManagedPath;
use crate::recipient::{AgeRecipient, AgeRecipientPolicy, PolicyName};
use crate::runtime::{PrivateRuntime, acquire_lock};
use crate::seal::decrypt_source;
use crate::sops::{SopsBinary, SopsClient, SopsPaths};
use crate::source::SourceDocument;

pub(crate) use plan::{ConvergenceAction, GrantEcho};
use plan::{FileRecipientFacts, RecipientMutation, plan_authorization};

const LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const CIPHERTEXT_MODE: u32 = 0o644;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecipientFileOutcome {
    Rewrapped,
    DataKeyRotated,
    AlreadyAligned,
}

pub(crate) struct RecipientFileReport {
    pub path: ManagedPath,
    pub result: Result<RecipientFileOutcome>,
}

pub(crate) struct AuthorizationOutcome {
    pub policy: PolicyName,
    pub grants: Vec<GrantEcho>,
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

    let desired_policy =
        AgeRecipientPolicy::new(policy_name.clone(), plan.desired_recipients.clone()).map_err(
            |error| {
                GitveilError::new(
                    ErrorCategory::Integrity,
                    format!("authorization plan produced an invalid policy: {error}"),
                )
            },
        )?;
    let mut candidate = manifest.clone();
    candidate
        .set_policy_recipients(&policy_name, plan.desired_recipients.clone())
        .map_err(|error| GitveilError::new(ErrorCategory::Integrity, error.to_string()))?;
    let candidate_bytes = serialize_manifest(&candidate)?;

    let mut convergences = Vec::new();
    for (path, action) in &plan.files {
        if *action == ConvergenceAction::AlreadyAligned {
            reports.push(RecipientFileReport {
                path: path.clone(),
                result: Ok(RecipientFileOutcome::AlreadyAligned),
            });
            continue;
        }
        let file = files
            .affected
            .iter()
            .find(|file| file.entry.path() == path)
            .ok_or_else(|| {
                GitveilError::new(
                    ErrorCategory::Integrity,
                    format!("authorization plan references unknown file {path}"),
                )
            })?;
        convergences.push((file, *action));
    }

    let engine = ConvergenceEngine {
        root: &root,
        runtime: &runtime,
        gitveil_binary,
        store: &store,
        manifest: &manifest,
        preparation: &manifest_preparation,
        candidate: &candidate_bytes,
        manifest_changed: plan.manifest_changed,
        desired_policy: &desired_policy,
    };
    engine.run(convergences, &mut reports)?;

    Ok(AuthorizationOutcome {
        policy: policy_name,
        grants: plan.grants,
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
    preparation: &'a ManifestPreparation,
    candidate: &'a [u8],
    manifest_changed: bool,
    desired_policy: &'a AgeRecipientPolicy,
}

impl ConvergenceEngine<'_> {
    fn run(
        &self,
        convergences: Vec<(&AffectedFile<'_>, ConvergenceAction)>,
        reports: &mut Vec<RecipientFileReport>,
    ) -> Result<()> {
        if convergences.is_empty() {
            return self.publish_manifest_if_changed();
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
        // file failed) the manifest is not published and nothing changes.
        let mut ready = Vec::new();
        let mut failures = Vec::new();
        for (file, action) in convergences {
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
                Ok(document) => ready.push((file, action, resolved, document)),
                Err(error) => failures.push(RecipientFileReport {
                    path: file.entry.path().clone(),
                    result: Err(error),
                }),
            }
        }
        if ready.is_empty() {
            let failure = failures
                .into_iter()
                .next()
                .and_then(|report| report.result.err())
                .unwrap_or_else(|| {
                    GitveilError::new(
                        ErrorCategory::Integrity,
                        "recipient convergence preflight produced no result",
                    )
                });
            return Err(failure);
        }

        self.publish_manifest_if_changed()?;

        for (file, action, resolved, document) in ready {
            let result = self.converge_file(&sops, &resolved, &file.ciphertext, &document, action);
            reports.push(RecipientFileReport {
                path: file.entry.path().clone(),
                result,
            });
        }
        reports.extend(failures);
        Ok(())
    }

    fn publish_manifest_if_changed(&self) -> Result<()> {
        if !self.manifest_changed {
            return Ok(());
        }
        let current = read_optional(self.root, &self.preparation.path)?;
        if current.as_deref() != Some(self.preparation.original.as_slice()) {
            return Err(GitveilError::new(
                ErrorCategory::Concurrency,
                format!("{MANIFEST_FILE_NAME} changed while gitveil recipient was running; retry"),
            ));
        }
        write_atomic(
            self.root,
            &self.preparation.path,
            self.candidate,
            self.preparation.mode,
            true,
        )
    }

    fn converge_file(
        &self,
        sops: &SopsClient,
        resolved: &ResolvedManifestEntry<'_>,
        ciphertext: &[u8],
        document: &SourceDocument,
        action: ConvergenceAction,
    ) -> Result<RecipientFileOutcome> {
        let path = resolved.path();
        let cipher_path = resolved.ciphertext_path();
        let (converged, outcome) = match action {
            ConvergenceAction::AlreadyAligned => return Ok(RecipientFileOutcome::AlreadyAligned),
            ConvergenceAction::Rewrap => {
                let rewrapped = sops.rewrap(ciphertext, self.desired_policy)?;
                self.verify_rewrap(ciphertext, &rewrapped, resolved)?;
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
                let rotated = sops.encrypt_new(&desired_bytes, path, self.desired_policy)?;
                let envelope = CiphertextEnvelope::parse(&rotated, resolved.format())
                    .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))?;
                self.verify_desired_recipients(&envelope, path)?;
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
        write_atomic(self.root, &cipher_path, &converged, CIPHERTEXT_MODE, true)?;
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

    /// Verifies a rewrap changed only the wrapped data key: the recipient
    /// set is exactly the desired policy and every encrypted leaf stayed
    /// byte-for-byte stable.
    fn verify_rewrap(
        &self,
        before: &[u8],
        after: &[u8],
        resolved: &ResolvedManifestEntry<'_>,
    ) -> Result<()> {
        let path = resolved.path();
        let before = CiphertextEnvelope::parse(before, resolved.format())
            .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))?;
        let after = CiphertextEnvelope::parse(after, resolved.format())
            .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))?;
        self.verify_desired_recipients(&after, path)?;
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

    fn verify_desired_recipients(
        &self,
        envelope: &CiphertextEnvelope,
        path: &ManagedPath,
    ) -> Result<()> {
        if self.desired_policy.matches(envelope.age_recipients()) {
            return Ok(());
        }
        Err(GitveilError::new(
            ErrorCategory::Integrity,
            format!(
                "SOPS result recipients do not match the authorized set of policy {} at {path}",
                self.desired_policy.name()
            ),
        ))
    }
}

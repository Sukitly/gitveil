//! `gitveil seal`: plaintext → incremental ciphertext.

use crate::baseline::{BaselineRecord, BaselineStore, CipherSummary};
use crate::envelope::{CiphertextEnvelope, DecryptedEnvelope};
use crate::error::{ErrorCategory, GitveilError, Result, SecretBytes};
use crate::manifest::ResolvedManifestEntry;
use crate::path::ManagedPath;
use crate::sops::{SopsClient, SopsFailure};
use crate::source::{SourceDocument, parse};
use crate::workspace::Workspace;

mod plan;

pub(crate) use plan::ciphertext_has_conflict_markers;

use crate::recipient::RecipientAction;
use plan::{SealAction, SealBaseline, plan_seal, resembles_envelope, result_matches};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SealOutcome {
    Sealed { data_key_rotated: bool },
    Unchanged,
}

pub(crate) struct SealReport {
    pub path: ManagedPath,
    pub result: Result<SealOutcome>,
}

/// Seals the selected managed pairs; per-pair failures do not abort the
/// remaining pairs.
pub(crate) fn seal(
    workspace: &Workspace,
    paths: &[String],
    profile: Option<&str>,
) -> Result<Vec<SealReport>> {
    let entries = workspace.entries(paths, profile)?;
    let _lock = workspace.lock()?;
    let sops = workspace.sops()?;
    let store = workspace.baseline_store();
    Ok(entries
        .into_iter()
        .map(|entry| SealReport {
            path: entry.path().clone(),
            result: seal_entry(workspace, &sops, store.as_ref(), &entry),
        })
        .collect())
}

fn seal_entry(
    workspace: &Workspace,
    sops: &SopsClient,
    store: Option<&BaselineStore>,
    entry: &ResolvedManifestEntry<'_>,
) -> Result<SealOutcome> {
    let path = entry.path();
    let cipher_path = entry.ciphertext_path();
    let plaintext = workspace.read(path)?.ok_or_else(|| {
        GitveilError::configuration(format!(
            "plaintext {path} is missing; run gitveil open or remove the manifest entry"
        ))
    })?;
    if resembles_envelope(&plaintext) {
        return Err(GitveilError::source(
            path,
            entry.format(),
            "plaintext looks like a gitveil envelope; restore the real plaintext first",
        ));
    }
    let desired = parse(entry.format(), &plaintext)
        .map_err(|error| GitveilError::source(path, entry.format(), &error.to_string()))?;
    let baseline_bytes = workspace.read(&cipher_path)?;
    if let Some(bytes) = &baseline_bytes
        && ciphertext_has_conflict_markers(bytes)
    {
        return Err(GitveilError::new(
            ErrorCategory::Conflict,
            format!("{cipher_path} contains merge conflict markers; run gitveil resolve first"),
        ));
    }
    let baseline_envelope = baseline_bytes
        .as_deref()
        .map(|bytes| {
            let format = CiphertextEnvelope::detect_format(bytes)
                .map_err(|error| GitveilError::ciphertext(&cipher_path, &error.to_string()))?;
            if format != entry.format() {
                return Err(GitveilError::configuration(format!(
                    "{cipher_path} carries format {format} but the manifest declares {}",
                    entry.format()
                )));
            }
            CiphertextEnvelope::parse(bytes, entry.format())
                .map_err(|error| GitveilError::ciphertext(&cipher_path, &error.to_string()))
        })
        .transpose()?;
    // Every alignment direction requires decrypting the existing ciphertext,
    // so an unavailable identity fails here without touching any file; seal
    // never blindly rebuilds ciphertext it cannot read.
    let baseline_document = baseline_bytes
        .as_deref()
        .map(|bytes| decrypt_source(sops, bytes, entry))
        .transpose()?;
    let plan = plan_seal(
        &desired,
        baseline_envelope
            .as_ref()
            .zip(baseline_document.as_ref())
            .map(|(envelope, document)| SealBaseline {
                document,
                recipient_drift: entry.recipient_policy().diff(envelope.age_recipients()),
            }),
    );

    let baseline_ciphertext = || {
        baseline_bytes.as_deref().ok_or_else(|| {
            GitveilError::new(
                ErrorCategory::Integrity,
                "seal plan disagrees with baseline presence",
            )
        })
    };
    let mut ciphertext = match plan.action {
        // First-time seal and rotation both encrypt the desired plaintext
        // directly to the policy; a rotation's fresh data key is what makes
        // the exclusion real, and pending edits ride along in the same commit
        // without ever touching the old key.
        SealAction::EncryptNew => sops.encrypt_new(
            &desired_envelope(&desired, path)?,
            path,
            entry.recipient_policy(),
        )?,
        SealAction::PreserveBaseline => baseline_ciphertext()?.to_vec(),
        SealAction::EditExisting => sops.edit(
            baseline_ciphertext()?,
            &desired_envelope(&desired, path)?,
            path,
        )?,
    };
    if plan.recipient_action == RecipientAction::Rewrap {
        ciphertext = rewrap_updatekeys(sops, &ciphertext, entry)?;
    } else if matches!(plan.action, SealAction::PreserveBaseline) {
        // Aligned and semantically unchanged: byte-idempotent.
        update_baseline(store, entry, &desired, &ciphertext)?;
        return Ok(SealOutcome::Unchanged);
    }
    verify_result(sops, &ciphertext, &desired, entry)?;
    workspace.write_ciphertext(&cipher_path, &ciphertext)?;
    update_baseline(store, entry, &desired, &ciphertext)?;
    Ok(SealOutcome::Sealed {
        data_key_rotated: matches!(plan.recipient_action, RecipientAction::Rotate),
    })
}

fn update_baseline(
    store: Option<&BaselineStore>,
    entry: &ResolvedManifestEntry<'_>,
    desired: &SourceDocument,
    ciphertext: &[u8],
) -> Result<()> {
    let Some(store) = store else {
        return Ok(());
    };
    let envelope = CiphertextEnvelope::parse(ciphertext, entry.format())
        .map_err(|error| GitveilError::ciphertext(entry.path(), &error.to_string()))?;
    let record = BaselineRecord::capture(
        desired,
        &CipherSummary::from_envelope(&envelope),
        BaselineStore::fresh_salt(),
    );
    store.save(entry.path(), &record)
}

fn desired_envelope(source: &SourceDocument, path: &ManagedPath) -> Result<SecretBytes> {
    DecryptedEnvelope::from_source(source)
        .and_then(|envelope| envelope.to_yaml())
        .map(SecretBytes::new)
        .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))
}

pub(crate) fn decrypt_source(
    sops: &SopsClient,
    ciphertext: &[u8],
    entry: &ResolvedManifestEntry<'_>,
) -> Result<SourceDocument> {
    let decrypted = sops.decrypt(ciphertext, entry.path()).map_err(|failure| {
        let category = match failure {
            SopsFailure::IdentityUnavailable => ErrorCategory::IdentityUnavailable,
            SopsFailure::Integrity => ErrorCategory::Integrity,
            SopsFailure::Configuration => ErrorCategory::Configuration,
            SopsFailure::Execution => ErrorCategory::Process,
        };
        GitveilError::new(category, format!("SOPS decrypt failed at {}", entry.path()))
    })?;
    DecryptedEnvelope::from_yaml(decrypted.as_slice(), entry.format())
        .and_then(DecryptedEnvelope::into_source)
        .map_err(|error| GitveilError::ciphertext(entry.path(), &error.to_string()))
}

fn verify_result(
    sops: &SopsClient,
    ciphertext: &[u8],
    desired: &SourceDocument,
    entry: &ResolvedManifestEntry<'_>,
) -> Result<()> {
    let envelope = CiphertextEnvelope::parse(ciphertext, entry.format())
        .map_err(|error| GitveilError::ciphertext(entry.path(), &error.to_string()))?;
    verify_recipient_policy(&envelope, entry)?;
    let actual = decrypt_source(sops, ciphertext, entry)?;
    if !result_matches(desired, &actual) {
        return Err(GitveilError::new(
            ErrorCategory::Integrity,
            format!(
                "SOPS result does not match desired source at {}",
                entry.path()
            ),
        ));
    }
    Ok(())
}

/// Rewraps the same data key to the entry policy via `updatekeys` and
/// verifies every encrypted leaf stayed byte-for-byte stable.
///
/// This handles additions only; a removal must instead re-encrypt from its
/// plaintext truth source under a fresh data key.
pub(crate) fn rewrap_updatekeys(
    sops: &SopsClient,
    ciphertext: &[u8],
    entry: &ResolvedManifestEntry<'_>,
) -> Result<Vec<u8>> {
    let rewrapped = sops.rewrap(ciphertext, entry.recipient_policy())?;
    verify_rewrap_result(ciphertext, &rewrapped, entry)?;
    Ok(rewrapped)
}

fn verify_rewrap_result(
    before: &[u8],
    after: &[u8],
    entry: &ResolvedManifestEntry<'_>,
) -> Result<()> {
    let before = CiphertextEnvelope::parse(before, entry.format())
        .map_err(|error| GitveilError::ciphertext(entry.path(), &error.to_string()))?;
    let after = CiphertextEnvelope::parse(after, entry.format())
        .map_err(|error| GitveilError::ciphertext(entry.path(), &error.to_string()))?;
    verify_recipient_policy(&after, entry)?;
    if before.leaf_ciphertexts() != after.leaf_ciphertexts()
        || before.layout_ciphertext() != after.layout_ciphertext()
    {
        return Err(GitveilError::new(
            ErrorCategory::Integrity,
            format!(
                "SOPS recipient update changed encrypted data at {}",
                entry.path()
            ),
        ));
    }
    Ok(())
}

pub(crate) fn verify_recipient_policy(
    envelope: &CiphertextEnvelope,
    entry: &ResolvedManifestEntry<'_>,
) -> Result<()> {
    if entry.recipient_policy().matches(envelope.age_recipients()) {
        return Ok(());
    }
    Err(GitveilError::new(
        ErrorCategory::Integrity,
        format!(
            "SOPS result recipients do not match policy {} at {}",
            entry.recipient_policy().name(),
            entry.path()
        ),
    ))
}

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

use crate::recipient::RecipientSetDiff;
use plan::{SealAction, plan_seal, resembles_envelope, result_matches};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SealOutcome {
    Sealed,
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
    // Seal is a data command and never changes authorization: any recipient
    // drift fails closed here, keyless, before any decryption or effect.
    // Authorization changes only through `gitveil recipient add/remove`.
    match &baseline_envelope {
        Some(envelope) => {
            let drift = entry.recipient_policy().diff(envelope.age_recipients());
            if !drift.is_empty() {
                return Err(recipient_drift_error(&cipher_path, entry, drift));
            }
        }
        // A first seal has no envelope to anchor authorization, so the
        // policy's other existing ciphertexts serve as the anchor: drift
        // there blocks encrypting new files to a possibly tampered policy.
        None => ensure_policy_ciphertexts_aligned(workspace, entry)?,
    }
    // The incremental edit path requires decrypting the existing ciphertext,
    // so an unavailable identity fails here without touching any file; seal
    // never blindly rebuilds ciphertext it cannot read.
    let baseline_document = baseline_bytes
        .as_deref()
        .map(|bytes| decrypt_source(sops, bytes, entry))
        .transpose()?;
    let action = plan_seal(&desired, baseline_document.as_ref());

    let baseline_ciphertext = || {
        baseline_bytes.as_deref().ok_or_else(|| {
            GitveilError::new(
                ErrorCategory::Integrity,
                "seal plan disagrees with baseline presence",
            )
        })
    };
    let ciphertext = match action {
        SealAction::EncryptNew => sops.encrypt_new(
            &desired_envelope(&desired, path)?,
            path,
            entry.recipient_policy(),
        )?,
        SealAction::PreserveBaseline => {
            // Aligned and semantically unchanged: byte-idempotent.
            update_baseline(store, entry, &desired, baseline_ciphertext()?)?;
            return Ok(SealOutcome::Unchanged);
        }
        SealAction::EditExisting => sops.edit(
            baseline_ciphertext()?,
            &desired_envelope(&desired, path)?,
            path,
        )?,
    };
    verify_result(sops, &ciphertext, &desired, entry)?;
    workspace.write_ciphertext(&cipher_path, &ciphertext)?;
    update_baseline(store, entry, &desired, &ciphertext)?;
    Ok(SealOutcome::Sealed)
}

fn recipient_drift_error(
    cipher_path: &ManagedPath,
    entry: &ResolvedManifestEntry<'_>,
    drift: RecipientSetDiff,
) -> GitveilError {
    GitveilError::configuration(format!(
        "{cipher_path} recipient set differs from policy {} (add {}, remove {}); \
         data commands never change authorization; run gitveil recipient add or \
         gitveil recipient remove first",
        entry.recipient_policy().name(),
        drift.added,
        drift.removed
    ))
}

/// First-seal policy cross-check: every other existing ciphertext under the
/// same policy must be aligned before a new file is encrypted to it.
fn ensure_policy_ciphertexts_aligned(
    workspace: &Workspace,
    entry: &ResolvedManifestEntry<'_>,
) -> Result<()> {
    for other in workspace.manifest().entries() {
        if other.path() == entry.path()
            || other.recipient_policy() != entry.recipient_policy().name()
        {
            continue;
        }
        let cipher = other.ciphertext_path();
        let Some(bytes) = workspace.read(&cipher)? else {
            continue;
        };
        let envelope = CiphertextEnvelope::parse(&bytes, other.format()).map_err(|error| {
            GitveilError::ciphertext(
                &cipher,
                &format!("cannot verify policy alignment before a first seal: {error}"),
            )
        })?;
        let drift = entry.recipient_policy().diff(envelope.age_recipients());
        if !drift.is_empty() {
            return Err(GitveilError::configuration(format!(
                "policy {} has drifted ciphertext at {cipher} (add {}, remove {}); \
                 run gitveil recipient add or gitveil recipient remove before \
                 sealing new files under this policy",
                entry.recipient_policy().name(),
                drift.added,
                drift.removed
            )));
        }
    }
    Ok(())
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

fn verify_recipient_policy(
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

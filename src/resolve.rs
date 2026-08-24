//! `gitveil resolve`: key-wise three-way merge for ciphertext files left in
//! a Git merge conflict. Reads the clean stage 1/2/3 blobs from the index
//! (read-only plumbing), never touches the index itself.

use crate::baseline::{BaselineRecord, BaselineStore, CipherSummary};
use crate::envelope::{CiphertextEnvelope, DecryptedEnvelope};
use crate::error::{ErrorCategory, GitveilError, Result, SecretBytes};
use crate::manifest::ResolvedManifestEntry;
use crate::path::ManagedPath;
use crate::recipient::{AgeRecipient, AgeRecipientPolicy};
use crate::seal::decrypt_source;
use crate::sops::SopsClient;
use crate::source::{Layout, LineEnding, Node, NodePath, SourceDocument};
use crate::workspace::Workspace;

mod plan;

use plan::{MergePlan, plan_merge};

const MARKER_SIZE: usize = 7;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResolveOutcome {
    /// The merge was completed; ciphertext and plaintext were rewritten.
    /// `data_key_rotated` reports that policy-removed recipients were
    /// excluded from the merged envelope under a fresh data key;
    /// `recipient_drift` reports pending additions for `gitveil recipient`.
    Resolved {
        data_key_rotated: bool,
        recipient_drift: bool,
    },
    /// Same-key conflicts remain: the plaintext holds a conflict document to
    /// edit, the working ciphertext was normalized to the local (ours) side,
    /// and `gitveil seal` finishes the resolution.
    ConflictWritten(NodePath),
}

pub(crate) struct ResolveReport {
    pub path: ManagedPath,
    pub result: Result<ResolveOutcome>,
}

pub(crate) fn resolve(workspace: &Workspace, paths: &[String]) -> Result<Vec<ResolveReport>> {
    let repository = workspace.require_repository()?;
    let entries = workspace.entries(paths, None)?;
    let _lock = workspace.lock()?;
    let sops = workspace.sops()?;
    let store = workspace.baseline_store();
    let mut reports = Vec::new();
    for entry in entries {
        let cipher_path = entry.ciphertext_path();
        let ours = repository.index_blob(&cipher_path, 2)?;
        let theirs = repository.index_blob(&cipher_path, 3)?;
        let (Some(ours), Some(theirs)) = (ours, theirs) else {
            continue;
        };
        let base = repository.index_blob(&cipher_path, 1)?;
        reports.push(ResolveReport {
            path: entry.path().clone(),
            result: resolve_entry(
                workspace,
                &sops,
                store.as_ref(),
                &entry,
                base.as_deref(),
                &ours,
                &theirs,
            ),
        });
    }
    if reports.is_empty() {
        return Err(GitveilError::new(
            ErrorCategory::Conflict,
            "no conflicted managed ciphertext in the index; nothing to resolve",
        ));
    }
    Ok(reports)
}

fn resolve_entry(
    workspace: &Workspace,
    sops: &SopsClient,
    store: Option<&BaselineStore>,
    entry: &ResolvedManifestEntry<'_>,
    base: Option<&[u8]>,
    ours: &[u8],
    theirs: &[u8],
) -> Result<ResolveOutcome> {
    let path = entry.path();
    let cipher_path = entry.ciphertext_path();
    let base_document = match base {
        Some(bytes) => decrypt_stage(sops, bytes, entry, "base")?,
        None => empty_document(entry),
    };
    let ours_document = decrypt_stage(sops, ours, entry, "ours")?;
    let theirs_document = decrypt_stage(sops, theirs, entry, "theirs")?;
    match plan_merge(
        &base_document,
        &ours_document,
        &theirs_document,
        MARKER_SIZE,
    )
    .map_err(|error| GitveilError::source(path, entry.format(), &error.to_string()))?
    {
        MergePlan::Merged(merged) => {
            let desired = DecryptedEnvelope::from_source(&merged)
                .and_then(|envelope| envelope.to_yaml())
                .map(SecretBytes::new)
                .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))?;
            // Resolve is a data command: it never extends access. The merged
            // content (which includes theirs-side values) is encrypted to the
            // intersection of the ours-side envelope set and the policy, so a
            // policy-removed recipient never gains the merged values, and no
            // recipient outside the ours envelope is granted anything.
            // Pending additions stay for `gitveil recipient add`.
            let ours_envelope = CiphertextEnvelope::parse(ours, entry.format())
                .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))?;
            let policy_recipients = entry.recipient_policy().recipients();
            let target = ours_envelope
                .age_recipients()
                .iter()
                .filter(|recipient| policy_recipients.contains(recipient))
                .cloned()
                .collect::<Vec<_>>();
            if target.is_empty() {
                return Err(GitveilError::configuration(format!(
                    "no recipient of {cipher_path} remains in policy {}; converge \
                     authorization with gitveil recipient before resolving",
                    entry.recipient_policy().name()
                )));
            }
            let data_key_rotated = target.len() != ours_envelope.age_recipients().len();
            let ciphertext = if data_key_rotated {
                let narrowed = AgeRecipientPolicy::new(
                    entry.recipient_policy().name().clone(),
                    target.clone(),
                )
                .map_err(|error| {
                    GitveilError::new(
                        ErrorCategory::Integrity,
                        format!("narrowed recipient set is invalid at {path}: {error}"),
                    )
                })?;
                sops.encrypt_new(&desired, path, &narrowed)?
            } else {
                sops.edit(ours, &desired, path)?
            };
            let envelope = CiphertextEnvelope::parse(&ciphertext, entry.format())
                .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))?;
            verify_recipients_exact(&envelope, &target, path)?;
            let verified = decrypt_source(sops, &ciphertext, entry)?;
            if !verified.semantic_eq(&merged) {
                return Err(GitveilError::new(
                    ErrorCategory::Integrity,
                    format!("merge result failed semantic verification at {path}"),
                ));
            }
            let plaintext = merged
                .generate()
                .map_err(|error| GitveilError::source(path, entry.format(), &error.to_string()))?;
            workspace.write_ciphertext(&cipher_path, &ciphertext)?;
            workspace.write_plaintext(path, &plaintext)?;
            if let Some(store) = store {
                let record = BaselineRecord::capture(
                    &merged,
                    &CipherSummary::from_envelope(&envelope),
                    BaselineStore::fresh_salt(),
                );
                store.save(path, &record)?;
            }
            let recipient_drift = !entry
                .recipient_policy()
                .diff(envelope.age_recipients())
                .is_empty();
            Ok(ResolveOutcome::Resolved {
                data_key_rotated,
                recipient_drift,
            })
        }
        MergePlan::Conflict {
            path: node,
            document,
        } => {
            // Normalize the working ciphertext to the valid local side so a
            // later `seal` has an incremental baseline, then hand the
            // conflict document to the user through the plaintext file.
            workspace.write_ciphertext(&cipher_path, ours)?;
            workspace.write_plaintext(path, document.as_slice())?;
            Ok(ResolveOutcome::ConflictWritten(node))
        }
    }
}

/// The merged envelope's recipient set must equal the computed narrowed
/// target exactly: nothing outside the ours envelope, nothing the policy
/// already removed.
fn verify_recipients_exact(
    envelope: &CiphertextEnvelope,
    target: &[AgeRecipient],
    path: &ManagedPath,
) -> Result<()> {
    let mut actual = envelope
        .age_recipients()
        .iter()
        .map(AgeRecipient::as_str)
        .collect::<Vec<_>>();
    let mut expected = target.iter().map(AgeRecipient::as_str).collect::<Vec<_>>();
    actual.sort_unstable();
    expected.sort_unstable();
    if actual == expected {
        return Ok(());
    }
    Err(GitveilError::new(
        ErrorCategory::Integrity,
        format!("merge produced an envelope outside the narrowed recipient set at {path}"),
    ))
}

fn decrypt_stage(
    sops: &SopsClient,
    ciphertext: &[u8],
    entry: &ResolvedManifestEntry<'_>,
    stage: &str,
) -> Result<SourceDocument> {
    CiphertextEnvelope::parse(ciphertext, entry.format()).map_err(|error| {
        GitveilError::ciphertext(
            entry.path(),
            &format!("invalid {stage} ciphertext: {error}"),
        )
    })?;
    decrypt_source(sops, ciphertext, entry)
}

fn empty_document(entry: &ResolvedManifestEntry<'_>) -> SourceDocument {
    SourceDocument::new(
        entry.format(),
        Node::Mapping(indexmap::IndexMap::new()),
        Layout::new(LineEnding::Lf, true),
    )
}

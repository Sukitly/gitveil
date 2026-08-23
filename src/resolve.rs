//! `gitveil resolve`: key-wise three-way merge for ciphertext files left in
//! a Git merge conflict. Reads the clean stage 1/2/3 blobs from the index
//! (read-only plumbing), never touches the index itself.

use crate::baseline::{BaselineRecord, BaselineStore, CipherSummary};
use crate::envelope::{CiphertextEnvelope, DecryptedEnvelope};
use crate::error::{ErrorCategory, GitveilError, Result, SecretBytes};
use crate::manifest::ResolvedManifestEntry;
use crate::path::ManagedPath;
use crate::recipient::RecipientAction;
use crate::seal::{decrypt_source, rewrap_updatekeys, verify_recipient_policy};
use crate::sops::SopsClient;
use crate::source::{Layout, LineEnding, Node, NodePath, SourceDocument};
use crate::workspace::Workspace;

mod plan;

use plan::{MergePlan, plan_merge};

const MARKER_SIZE: usize = 7;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResolveOutcome {
    /// The merge was completed; ciphertext and plaintext were rewritten.
    Resolved { data_key_rotated: bool },
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
            // The alignment direction is decided from the ours-side envelope
            // an edit would preserve. A removal re-encrypts the
            // merged result directly under a fresh data key the removed party
            // cannot unwrap; the old key never touches the merged values.
            let ours_envelope = CiphertextEnvelope::parse(ours, entry.format())
                .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))?;
            let recipient_action = entry
                .recipient_policy()
                .diff(ours_envelope.age_recipients())
                .action();
            let data_key_rotated = matches!(recipient_action, RecipientAction::Rotate);
            let ciphertext = match recipient_action {
                RecipientAction::Rotate => {
                    sops.encrypt_new(&desired, path, entry.recipient_policy())?
                }
                RecipientAction::Aligned => sops.edit(ours, &desired, path)?,
                RecipientAction::Rewrap => {
                    let edited = sops.edit(ours, &desired, path)?;
                    rewrap_updatekeys(sops, &edited, entry)?
                }
            };
            let envelope = CiphertextEnvelope::parse(&ciphertext, entry.format())
                .map_err(|error| GitveilError::ciphertext(path, &error.to_string()))?;
            verify_recipient_policy(&envelope, entry)?;
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
            Ok(ResolveOutcome::Resolved { data_key_rotated })
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

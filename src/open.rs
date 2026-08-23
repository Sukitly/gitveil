//! `gitveil open`: ciphertext → plaintext with key-wise merging.

use crate::baseline::{BaselineRecord, BaselineStore, CipherSummary};
use crate::envelope::CiphertextEnvelope;
use crate::error::{ErrorCategory, GitveilError, Result};
use crate::manifest::ResolvedManifestEntry;
use crate::path::ManagedPath;
use crate::seal::decrypt_source;
use crate::sops::SopsClient;
use crate::source::{SourceDocument, SourceError, parse};
use crate::workspace::Workspace;

mod plan;

pub(crate) use plan::OpenConflict;

use plan::plan_open;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OpenOutcome {
    /// The plaintext file was written (created or merged).
    Opened,
    /// The plaintext file already held the result.
    UpToDate,
    /// Some keys could not be arbitrated; the local side was kept for them.
    Conflicts(Vec<OpenConflict>),
}

pub(crate) struct OpenReport {
    pub path: ManagedPath,
    pub result: Result<OpenOutcome>,
}

/// Opens the selected managed pairs; per-pair failures do not abort the
/// remaining pairs.
pub(crate) fn open(
    workspace: &Workspace,
    paths: &[String],
    profile: Option<&str>,
) -> Result<Vec<OpenReport>> {
    let entries = workspace.entries(paths, profile)?;
    let _lock = workspace.lock()?;
    let sops = workspace.sops()?;
    let store = workspace.baseline_store();
    Ok(entries
        .into_iter()
        .map(|entry| OpenReport {
            path: entry.path().clone(),
            result: open_entry(workspace, &sops, store.as_ref(), &entry),
        })
        .collect())
}

fn open_entry(
    workspace: &Workspace,
    sops: &SopsClient,
    store: Option<&BaselineStore>,
    entry: &ResolvedManifestEntry<'_>,
) -> Result<OpenOutcome> {
    let path = entry.path();
    let cipher_path = entry.ciphertext_path();
    let ciphertext = workspace.read(&cipher_path)?.ok_or_else(|| {
        GitveilError::configuration(format!(
            "ciphertext {cipher_path} is missing; run gitveil seal first"
        ))
    })?;
    if crate::seal::ciphertext_has_conflict_markers(&ciphertext) {
        return Err(GitveilError::new(
            ErrorCategory::Conflict,
            format!("{cipher_path} contains merge conflict markers; run gitveil resolve first"),
        ));
    }
    let format = CiphertextEnvelope::detect_format(&ciphertext)
        .map_err(|error| GitveilError::ciphertext(&cipher_path, &error.to_string()))?;
    if format != entry.format() {
        return Err(GitveilError::configuration(format!(
            "{cipher_path} carries format {format} but the manifest declares {}",
            entry.format()
        )));
    }
    let envelope = CiphertextEnvelope::parse(&ciphertext, entry.format())
        .map_err(|error| GitveilError::ciphertext(&cipher_path, &error.to_string()))?;
    let remote = decrypt_source(sops, &ciphertext, entry)?;
    let local = match workspace.read(path)? {
        None => None,
        Some(bytes) => Some(parse(entry.format(), &bytes).map_err(|error| match error {
            SourceError::ConflictMarkers { .. } => GitveilError::new(
                ErrorCategory::Conflict,
                format!(
                    "{path} contains conflict markers; edit it and run gitveil seal to finish \
                     the resolution"
                ),
            ),
            error => GitveilError::source(path, entry.format(), &error.to_string()),
        })?),
    };
    let baseline = store.and_then(|store| store.load(path));
    let outcome = plan_open(local.as_ref(), &remote, baseline.as_ref());
    let final_document = match &outcome.document {
        Some(document) => {
            let bytes = document
                .generate()
                .map_err(|error| GitveilError::source(path, entry.format(), &error.to_string()))?;
            // The baseline must describe what a later `status` will parse
            // from disk, and the rendered bytes must faithfully re-parse;
            // both are enforced by reading the result back through the
            // parser before it is recorded.
            let written = parse(entry.format(), &bytes).map_err(|error| {
                GitveilError::new(
                    ErrorCategory::Integrity,
                    format!("rendered plaintext does not re-parse at {path}: {error}"),
                )
            })?;
            if !written.semantic_eq(document) {
                return Err(GitveilError::new(
                    ErrorCategory::Integrity,
                    format!("rendered plaintext changed semantics at {path}"),
                ));
            }
            workspace.write_plaintext(path, &bytes)?;
            Some(written)
        }
        None => None,
    };
    if !outcome.conflicts.is_empty() {
        return Ok(OpenOutcome::Conflicts(outcome.conflicts));
    }
    // Successful, conflict-free open: record the synchronized state.
    if let Some(store) = store {
        let synced = match (&final_document, &local) {
            (Some(document), _) => Some(document),
            (None, Some(local)) => Some(local),
            (None, None) => None,
        };
        if let Some(synced) = synced {
            record_baseline(store, entry, synced, &envelope)?;
        }
    }
    Ok(match final_document {
        Some(_) => OpenOutcome::Opened,
        None => OpenOutcome::UpToDate,
    })
}

fn record_baseline(
    store: &BaselineStore,
    entry: &ResolvedManifestEntry<'_>,
    document: &SourceDocument,
    envelope: &CiphertextEnvelope,
) -> Result<()> {
    let record = BaselineRecord::capture(
        document,
        &CipherSummary::from_envelope(envelope),
        BaselineStore::fresh_salt(),
    );
    store.save(entry.path(), &record)
}

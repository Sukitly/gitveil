//! `gitveil status`: keyless, direction-aware data and recipient drift per managed pair.

use std::fmt;

use crate::baseline::{BaselineDiff, BaselineRecord, CipherSummary};
use crate::envelope::CiphertextEnvelope;
use crate::error::Result;
use crate::manifest::ResolvedManifestEntry;
use crate::path::ManagedPath;
use crate::recipient::RecipientSetDiff;
use crate::source::{SourceDocument, SourceError, parse};
use crate::workspace::Workspace;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PairDataStatus {
    Clean,
    /// Plaintext is ahead of the ciphertext: run `seal`.
    LocalEdits(BaselineDiff),
    /// Ciphertext is ahead of the plaintext: run `open`.
    Behind(BaselineDiff),
    /// Both sides changed since the last sync.
    Diverged {
        local: BaselineDiff,
        remote: BaselineDiff,
    },
    /// No baseline: only key-set differences are observable without a key.
    Differs {
        keys: Vec<String>,
    },
    /// No baseline and identical key sets: value drift is not observable
    /// without a key.
    Unknown,
    /// Merge conflict markers or an unmerged index entry.
    Conflicted,
    PlaintextMissing,
    CiphertextMissing,
    /// Neither side of the pair exists yet.
    Missing,
    /// A side exists but cannot be parsed.
    Corrupt(String),
}

impl fmt::Display for PairDataStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => formatter.write_str("clean"),
            Self::LocalEdits(diff) => {
                write!(
                    formatter,
                    "local edits ({}); run gitveil seal",
                    render(diff)
                )
            }
            Self::Behind(diff) => {
                write!(
                    formatter,
                    "ciphertext updated ({}); run gitveil open",
                    render(diff)
                )
            }
            Self::Diverged { local, remote } => write!(
                formatter,
                "diverged (local: {}; remote: {}); run gitveil open, review, then seal",
                render(local),
                render(remote)
            ),
            Self::Differs { keys } => write!(
                formatter,
                "differs without a baseline (keys: {}); run gitveil open to reconcile",
                keys.join(", ")
            ),
            Self::Unknown => formatter.write_str("no baseline; run gitveil open to establish one"),
            Self::Conflicted => formatter.write_str("merge conflict; run gitveil resolve"),
            Self::PlaintextMissing => formatter.write_str("plaintext missing; run gitveil open"),
            Self::CiphertextMissing => formatter.write_str("ciphertext missing; run gitveil seal"),
            Self::Missing => formatter.write_str("neither file exists yet"),
            Self::Corrupt(reason) => write!(formatter, "corrupt: {reason}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecipientStatus {
    Aligned,
    Drift {
        policy: String,
        diff: RecipientSetDiff,
    },
    /// Recipient metadata cannot exist when ciphertext is missing or cannot
    /// be inspected because a higher-priority pair state applies.
    NotApplicable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PairStatus {
    data: PairDataStatus,
    recipients: RecipientStatus,
}

impl PairStatus {
    pub(crate) const fn new(data: PairDataStatus, recipients: RecipientStatus) -> Self {
        Self { data, recipients }
    }

    pub(crate) const fn is_clean(&self) -> bool {
        matches!(self.data, PairDataStatus::Clean)
            && matches!(self.recipients, RecipientStatus::Aligned)
    }

    pub(crate) const fn is_bad(&self) -> bool {
        matches!(
            self.data,
            PairDataStatus::Conflicted | PairDataStatus::Corrupt(_)
        )
    }
}

impl fmt::Display for PairStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.data)?;
        if let RecipientStatus::Drift { policy, diff } = &self.recipients {
            // Data commands fail closed on drift; only the authorization
            // commands converge it, and a removal rotates the data key.
            let action = if diff.removed > 0 && diff.added > 0 {
                "run gitveil recipient add and gitveil recipient remove (removal rotates the file data key)"
            } else if diff.removed > 0 {
                "run gitveil recipient remove (rotates the file data key)"
            } else {
                "run gitveil recipient add"
            };
            write!(
                formatter,
                "; recipient drift (policy {policy}; add {}; remove {}); {action}",
                diff.added, diff.removed
            )?;
        }
        Ok(())
    }
}

fn render(diff: &BaselineDiff) -> String {
    let mut parts = Vec::new();
    if !diff.changed.is_empty() {
        parts.push(format!("changed {}", diff.changed.join(", ")));
    }
    if !diff.added.is_empty() {
        parts.push(format!("added {}", diff.added.join(", ")));
    }
    if !diff.removed.is_empty() {
        parts.push(format!("removed {}", diff.removed.join(", ")));
    }
    if diff.layout_changed {
        parts.push("layout".to_owned());
    }
    if parts.is_empty() {
        parts.push("no observable change".to_owned());
    }
    parts.join("; ")
}

pub(crate) struct StatusReport {
    pub path: ManagedPath,
    pub result: Result<PairStatus>,
}

pub(crate) fn status(
    workspace: &Workspace,
    paths: &[String],
    profile: Option<&str>,
) -> Result<Vec<StatusReport>> {
    let entries = workspace.entries(paths, profile)?;
    let cipher_paths = entries
        .iter()
        .map(ResolvedManifestEntry::ciphertext_path)
        .collect::<Vec<_>>();
    let unmerged = workspace
        .repository()
        .map(|repository| repository.unmerged_paths(&cipher_paths))
        .transpose()?
        .unwrap_or_default();
    let store = workspace.baseline_store();
    Ok(entries
        .into_iter()
        .map(|entry| StatusReport {
            path: entry.path().clone(),
            result: status_entry(workspace, store.as_ref(), &unmerged, &entry),
        })
        .collect())
}

fn status_entry(
    workspace: &Workspace,
    store: Option<&crate::baseline::BaselineStore>,
    unmerged: &std::collections::HashSet<ManagedPath>,
    entry: &ResolvedManifestEntry<'_>,
) -> Result<PairStatus> {
    let cipher_path = entry.ciphertext_path();
    let plaintext = workspace.read(entry.path())?;
    let ciphertext = workspace.read(&cipher_path)?;
    let (plaintext, ciphertext) = match (plaintext, ciphertext) {
        (None, None) => return Ok(not_applicable(PairDataStatus::Missing)),
        (Some(_), None) => return Ok(not_applicable(PairDataStatus::CiphertextMissing)),
        (plaintext, Some(ciphertext)) => (plaintext, ciphertext),
    };
    if crate::seal::ciphertext_has_conflict_markers(&ciphertext) || unmerged.contains(&cipher_path)
    {
        return Ok(not_applicable(PairDataStatus::Conflicted));
    }
    let envelope = match CiphertextEnvelope::parse(&ciphertext, entry.format()) {
        Ok(envelope) => envelope,
        Err(error) => {
            return Ok(not_applicable(PairDataStatus::Corrupt(format!(
                "{cipher_path}: {error}"
            ))));
        }
    };
    let recipients = {
        let diff = entry.recipient_policy().diff(envelope.age_recipients());
        if diff.is_empty() {
            RecipientStatus::Aligned
        } else {
            RecipientStatus::Drift {
                policy: entry.recipient_policy().name().as_str().to_owned(),
                diff,
            }
        }
    };
    let Some(plaintext) = plaintext else {
        return Ok(PairStatus::new(
            PairDataStatus::PlaintextMissing,
            recipients,
        ));
    };
    let local = match parse(entry.format(), &plaintext) {
        Ok(document) => document,
        Err(SourceError::ConflictMarkers { .. }) => {
            return Ok(PairStatus::new(PairDataStatus::Conflicted, recipients));
        }
        Err(error) => {
            return Ok(PairStatus::new(
                PairDataStatus::Corrupt(format!("{}: {error}", entry.path())),
                recipients,
            ));
        }
    };
    let summary = CipherSummary::from_envelope(&envelope);
    let data = if let Some(baseline) = store.and_then(|store| store.load(entry.path())) {
        baseline_status(&baseline, &local, &summary)
    } else {
        keyless_status(&local, &summary)
    };
    Ok(PairStatus::new(data, recipients))
}

const fn not_applicable(data: PairDataStatus) -> PairStatus {
    PairStatus::new(data, RecipientStatus::NotApplicable)
}

fn baseline_status(
    baseline: &BaselineRecord,
    local: &SourceDocument,
    summary: &CipherSummary,
) -> PairDataStatus {
    let local_diff = baseline.diff_plain(local);
    let remote_diff = baseline.diff_cipher(summary);
    match (local_diff.is_empty(), remote_diff.is_empty()) {
        (true, true) => PairDataStatus::Clean,
        (false, true) => PairDataStatus::LocalEdits(local_diff),
        (true, false) => PairDataStatus::Behind(remote_diff),
        (false, false) => PairDataStatus::Diverged {
            local: local_diff,
            remote: remote_diff,
        },
    }
}

/// Without a baseline and without a key, only the key sets are comparable.
fn keyless_status(local: &SourceDocument, summary: &CipherSummary) -> PairDataStatus {
    let local_keys: Vec<String> = local.root().mapping_keys().map_or_else(
        || vec![BaselineRecord::ROOT_UNIT.to_owned()],
        |keys| keys.into_iter().map(str::to_owned).collect(),
    );
    let remote_keys: Vec<String> = summary.unit_names().map(str::to_owned).collect();
    let mut differing: Vec<String> = local_keys
        .iter()
        .filter(|key| !remote_keys.contains(key))
        .chain(remote_keys.iter().filter(|key| !local_keys.contains(key)))
        .cloned()
        .collect();
    differing.dedup();
    if differing.is_empty() {
        PairDataStatus::Unknown
    } else {
        PairDataStatus::Differs { keys: differing }
    }
}

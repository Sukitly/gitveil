//! `gitveil verify`: read-only history scan.
//!
//! Detects the two irreversible accidents of the standalone architecture:
//! a manifest plaintext path that ever entered a commit tree, and a
//! ciphertext path whose historical blob is not a valid gitveil envelope.
//! Both checks are structural and need no private key.

use std::fmt;

use crate::envelope::CiphertextEnvelope;
use crate::error::{ErrorCategory, GitveilError, Result};
use crate::manifest::ManifestEntry;
use crate::path::ManagedPath;
use crate::workspace::Workspace;

mod policy;

use policy::validate_revision_range;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Violation {
    /// The plaintext path was added or modified by this commit.
    PlaintextInHistory { commit: String, path: ManagedPath },
    /// The ciphertext blob at this commit is not a valid envelope.
    InvalidCiphertext {
        commit: String,
        path: ManagedPath,
        reason: String,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlaintextInHistory { commit, path } => {
                write!(formatter, "{commit}: plaintext {path} entered this commit")
            }
            Self::InvalidCiphertext {
                commit,
                path,
                reason,
            } => write!(
                formatter,
                "{commit}: {path} is not a valid gitveil envelope ({reason})"
            ),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct VerifyReport {
    pub scanned_blobs: usize,
    pub violations: Vec<Violation>,
}

pub(crate) fn verify(workspace: &Workspace, range: Option<&str>) -> Result<VerifyReport> {
    let repository = workspace.require_repository()?;
    if let Some(range) = range {
        validate_revision_range(range)
            .map_err(|error| GitveilError::configuration(error.to_string()))?;
    }
    let mut report = VerifyReport::default();
    for entry in workspace.manifest().entries() {
        scan_plaintext_history(repository, entry, range, &mut report)?;
        scan_ciphertext_history(repository, entry, range, &mut report)?;
    }
    Ok(report)
}

fn scan_plaintext_history(
    repository: &crate::git::Repository,
    entry: &ManifestEntry,
    range: Option<&str>,
    report: &mut VerifyReport,
) -> Result<()> {
    for commit in touching_commits(repository, entry.path(), range)? {
        let Some(bytes) = repository.revision_blob(&commit, entry.path())? else {
            // The commit removed the path; nothing leaked by it.
            continue;
        };
        // Repositories migrated from the same-path filter architecture carry
        // valid envelope blobs at the plaintext path; those are ciphertext,
        // not leaks.
        if is_valid_envelope(&bytes) {
            continue;
        }
        report.violations.push(Violation::PlaintextInHistory {
            commit,
            path: entry.path().clone(),
        });
    }
    Ok(())
}

fn is_valid_envelope(bytes: &[u8]) -> bool {
    CiphertextEnvelope::detect_format(bytes)
        .and_then(|format| CiphertextEnvelope::parse(bytes, format))
        .is_ok()
}

fn scan_ciphertext_history(
    repository: &crate::git::Repository,
    entry: &ManifestEntry,
    range: Option<&str>,
    report: &mut VerifyReport,
) -> Result<()> {
    let cipher_path = entry.ciphertext_path();
    for commit in touching_commits(repository, &cipher_path, range)? {
        let Some(bytes) = repository.revision_blob(&commit, &cipher_path)? else {
            // The commit removed the path; nothing to validate.
            continue;
        };
        report.scanned_blobs += 1;
        let outcome = CiphertextEnvelope::detect_format(&bytes)
            .map_err(|error| error.to_string())
            .and_then(|format| {
                if format == entry.format() {
                    Ok(format)
                } else {
                    Err(format!(
                        "carries format {format} but the manifest declares {}",
                        entry.format()
                    ))
                }
            })
            .and_then(|format| {
                CiphertextEnvelope::parse(&bytes, format).map_err(|error| error.to_string())
            });
        if let Err(reason) = outcome {
            report.violations.push(Violation::InvalidCiphertext {
                commit,
                path: cipher_path.clone(),
                reason,
            });
        }
    }
    Ok(())
}

/// Lists the commits in the range (default: all refs) that added, modified,
/// or removed the path. A path that ever existed is always touched by at
/// least one commit.
fn touching_commits(
    repository: &crate::git::Repository,
    path: &ManagedPath,
    range: Option<&str>,
) -> Result<Vec<String>> {
    let mut args = vec!["rev-list".to_owned()];
    match range {
        Some(range) => args.push(range.to_owned()),
        None => args.push("--all".to_owned()),
    }
    let output = repository.run_git_literal_path(args, path)?;
    let text = std::str::from_utf8(&output).map_err(|_| {
        GitveilError::new(ErrorCategory::Protocol, "git rev-list output is not UTF-8")
    })?;
    Ok(text.lines().map(str::to_owned).collect())
}

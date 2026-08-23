//! Pure repository-onboarding plans.
//!

use std::collections::{HashMap, HashSet};

use thiserror::Error;

use crate::config::SourceFormat;
use crate::manifest::{
    CIPHERTEXT_SUFFIX, Manifest, ManifestEntry, ManifestEntryAddOutcome, ManifestMutationError,
};
use crate::path::ManagedPath;
use crate::profile::ProfileName;
use crate::recipient::PolicyName;

const BEGIN_MARKER: &[u8] = b"# BEGIN gitveil managed files";
const END_MARKER: &[u8] = b"# END gitveil managed files";
const MARKER_FRAGMENT: &[u8] = b"gitveil managed files";

#[derive(Clone)]
pub(crate) struct RegistrationRequest {
    pub(crate) path: ManagedPath,
    pub(crate) format: SourceFormat,
    pub(crate) recipient_policy: PolicyName,
    pub(crate) profile: ProfileName,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegistrationKind {
    Added,
    AlreadyManaged,
}

pub(crate) struct RegistrationPlan {
    manifest: Manifest,
    outcomes: Vec<(ManagedPath, RegistrationKind)>,
}

impl RegistrationPlan {
    pub(crate) fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub(crate) fn outcomes(&self) -> &[(ManagedPath, RegistrationKind)] {
        &self.outcomes
    }
}

pub(crate) fn plan_registration(
    mut manifest: Manifest,
    requests: Vec<RegistrationRequest>,
) -> Result<RegistrationPlan, RegistrationPlanError> {
    let mut requested = HashSet::with_capacity(requests.len());
    let mut outcomes = Vec::with_capacity(requests.len());
    for request in requests {
        if !requested.insert(request.path.case_collision_key()) {
            return Err(RegistrationPlanError::DuplicateRequest(request.path));
        }
        let path = request.path.clone();
        let outcome = manifest
            .add_entry(ManifestEntry::new(
                request.path,
                request.format,
                request.recipient_policy,
                request.profile,
            ))
            .map_err(RegistrationPlanError::Manifest)?;
        outcomes.push((
            path,
            match outcome {
                ManifestEntryAddOutcome::Added => RegistrationKind::Added,
                ManifestEntryAddOutcome::AlreadyManaged => RegistrationKind::AlreadyManaged,
            },
        ));
    }
    Ok(RegistrationPlan { manifest, outcomes })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IgnoreRuleSnapshot {
    source: String,
    line: usize,
    pattern: String,
    ignored: bool,
}

impl IgnoreRuleSnapshot {
    pub(crate) fn new(source: String, line: usize, pattern: String, ignored: bool) -> Self {
        Self {
            source,
            line,
            pattern,
            ignored,
        }
    }

    fn description(&self) -> String {
        format!(
            "{}:{}:{}",
            diagnostic_field(&self.source),
            self.line,
            diagnostic_field(&self.pattern)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IgnoreState {
    Unmatched,
    Matched(IgnoreRuleSnapshot),
}

impl IgnoreState {
    fn is_ignored(&self) -> bool {
        matches!(self, Self::Matched(rule) if rule.ignored)
    }

    fn evidence(&self) -> Option<&IgnoreRuleSnapshot> {
        match self {
            Self::Unmatched => None,
            Self::Matched(rule) => Some(rule),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VisibilityExpectation {
    PlaintextIgnored,
    CiphertextVisible,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VisibilityViolation {
    path: ManagedPath,
    expectation: VisibilityExpectation,
    evidence: Option<IgnoreRuleSnapshot>,
}

impl VisibilityViolation {
    pub(crate) fn describe(&self) -> String {
        let evidence = self.evidence.as_ref().map_or_else(
            || "no matching Git ignore rule".to_owned(),
            IgnoreRuleSnapshot::description,
        );
        match self.expectation {
            VisibilityExpectation::PlaintextIgnored => {
                format!("plaintext path {} is not ignored ({evidence})", self.path)
            }
            VisibilityExpectation::CiphertextVisible => format!(
                "ciphertext path {} remains ignored by {evidence}; adjust that rule or an ignored parent directory before retrying",
                self.path
            ),
        }
    }
}

pub(crate) fn visibility_violations(
    manifest: &Manifest,
    states: &HashMap<ManagedPath, IgnoreState>,
) -> Result<Vec<VisibilityViolation>, VisibilityPlanError> {
    let mut violations = Vec::new();
    for entry in manifest.entries() {
        let plaintext = states
            .get(entry.path())
            .ok_or_else(|| VisibilityPlanError::MissingEvaluation(entry.path().clone()))?;
        if !plaintext.is_ignored() {
            violations.push(VisibilityViolation {
                path: entry.path().clone(),
                expectation: VisibilityExpectation::PlaintextIgnored,
                evidence: plaintext.evidence().cloned(),
            });
        }
        let ciphertext_path = entry.ciphertext_path();
        let ciphertext = states
            .get(&ciphertext_path)
            .ok_or_else(|| VisibilityPlanError::MissingEvaluation(ciphertext_path.clone()))?;
        if ciphertext.is_ignored() {
            violations.push(VisibilityViolation {
                path: ciphertext_path,
                expectation: VisibilityExpectation::CiphertextVisible,
                evidence: ciphertext.evidence().cloned(),
            });
        }
    }
    Ok(violations)
}

pub(crate) fn merge_protection_paths(
    authoritative: &[ManagedPath],
    fail_safe: &[ManagedPath],
) -> Vec<ManagedPath> {
    let mut seen = HashSet::with_capacity(authoritative.len() + fail_safe.len());
    authoritative
        .iter()
        .chain(fail_safe)
        .filter(|path| seen.insert(path.case_collision_key()))
        .cloned()
        .collect()
}

pub(crate) fn render_managed_ignore(
    existing: &[u8],
    paths: &[ManagedPath],
) -> Result<Vec<u8>, ManagedIgnoreError> {
    let lines = lines(existing);
    let mut begin = Vec::new();
    let mut end = Vec::new();
    for line in &lines {
        let content = &existing[line.start..line.content_end];
        if content == BEGIN_MARKER {
            begin.push(*line);
        } else if content == END_MARKER {
            end.push(*line);
        } else if contains(content, MARKER_FRAGMENT) {
            return Err(ManagedIgnoreError::MalformedBlock);
        }
    }

    let mut base = match (begin.as_slice(), end.as_slice()) {
        ([], []) => existing.to_vec(),
        ([begin], [end]) if begin.start < end.start => {
            let mut base = Vec::with_capacity(existing.len());
            base.extend_from_slice(&existing[..begin.start]);
            base.extend_from_slice(&existing[end.end..]);
            base
        }
        _ => return Err(ManagedIgnoreError::MalformedBlock),
    };

    let newline = preferred_newline(existing);
    if !base.is_empty() && !base.ends_with(b"\n") {
        base.extend_from_slice(newline);
    }
    base.extend_from_slice(BEGIN_MARKER);
    base.extend_from_slice(newline);
    for path in paths {
        base.push(b'/');
        base.extend_from_slice(escape_trailing_spaces(path.as_str()).as_bytes());
        base.extend_from_slice(newline);
        base.extend_from_slice(b"!/");
        base.extend_from_slice(escape_trailing_spaces(path.as_str()).as_bytes());
        base.extend_from_slice(CIPHERTEXT_SUFFIX.as_bytes());
        base.extend_from_slice(newline);
    }
    base.extend_from_slice(END_MARKER);
    base.extend_from_slice(newline);
    Ok(base)
}

#[derive(Clone, Copy)]
struct Line {
    start: usize,
    content_end: usize,
    end: usize,
}

fn lines(input: &[u8]) -> Vec<Line> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, byte) in input.iter().enumerate() {
        if *byte == b'\n' {
            let content_end = if index > start && input[index - 1] == b'\r' {
                index - 1
            } else {
                index
            };
            lines.push(Line {
                start,
                content_end,
                end: index + 1,
            });
            start = index + 1;
        }
    }
    if start < input.len() {
        lines.push(Line {
            start,
            content_end: input.len(),
            end: input.len(),
        });
    }
    lines
}

fn preferred_newline(input: &[u8]) -> &'static [u8] {
    input
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(b"\n", |index| {
            if index > 0 && input[index - 1] == b'\r' {
                b"\r\n".as_slice()
            } else {
                b"\n".as_slice()
            }
        })
}

fn escape_trailing_spaces(value: &str) -> String {
    let trailing = value.bytes().rev().take_while(|byte| *byte == b' ').count();
    if trailing == 0 {
        return value.to_owned();
    }
    let split = value.len() - trailing;
    let mut escaped = String::with_capacity(value.len() + trailing);
    escaped.push_str(&value[..split]);
    for _ in 0..trailing {
        escaped.push_str("\\ ");
    }
    escaped
}

fn diagnostic_field(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[derive(Debug, Error)]
pub(crate) enum RegistrationPlanError {
    #[error("path {0} is requested more than once")]
    DuplicateRequest(ManagedPath),
    #[error(transparent)]
    Manifest(ManifestMutationError),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(crate) enum VisibilityPlanError {
    #[error("Git ignore evaluation is missing path {0}")]
    MissingEvaluation(ManagedPath),
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum ManagedIgnoreError {
    #[error(".gitignore contains a malformed Gitveil managed block")]
    MalformedBlock,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        IgnoreRuleSnapshot, IgnoreState, ManagedIgnoreError, RegistrationKind, RegistrationRequest,
        merge_protection_paths, plan_registration, render_managed_ignore, visibility_violations,
    };
    use crate::config::SourceFormat;
    use crate::manifest::Manifest;
    use crate::path::ManagedPath;
    use crate::profile::ProfileName;
    use crate::recipient::PolicyName;

    const RECIPIENT: &str = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq";

    fn paths(path: &str) -> Vec<ManagedPath> {
        vec![ManagedPath::new(path).expect("managed path")]
    }

    fn manifest(files: &str) -> Manifest {
        Manifest::parse(
            format!(
                r#"{{
                  "version": 1,
                  "recipientPolicies": {{ "default": {{ "age": ["{RECIPIENT}"] }} }},
                  "files": [{files}]
                }}"#
            )
            .as_bytes(),
        )
        .expect("manifest")
    }

    fn request(path: &str) -> RegistrationRequest {
        RegistrationRequest {
            path: ManagedPath::new(path).expect("managed path"),
            format: SourceFormat::Dotenv,
            recipient_policy: PolicyName::new("default").expect("policy"),
            profile: ProfileName::default(),
        }
    }

    #[test]
    fn registration_plan_preserves_order_and_reports_added_and_existing_entries() {
        let existing = r#"{
            "path": "existing.env",
            "format": "dotenv",
            "recipientPolicy": "default"
        }"#;
        let plan = plan_registration(
            manifest(existing),
            vec![request("existing.env"), request("new.env")],
        )
        .expect("registration plan");
        assert_eq!(
            plan.outcomes(),
            [
                (
                    ManagedPath::new("existing.env").expect("path"),
                    RegistrationKind::AlreadyManaged
                ),
                (
                    ManagedPath::new("new.env").expect("path"),
                    RegistrationKind::Added
                )
            ]
        );
    }

    #[test]
    fn registration_plan_rejects_case_colliding_requests_as_one_batch() {
        assert!(
            plan_registration(
                manifest(""),
                vec![request("secret.env"), request("SECRET.env")],
            )
            .is_err()
        );
    }

    #[test]
    fn visibility_plan_reports_every_path_with_rule_evidence() {
        let manifest = manifest(
            r#"{
                "path": "a/.env",
                "format": "dotenv",
                "recipientPolicy": "default"
            }, {
                "path": "b/.env",
                "format": "dotenv",
                "recipientPolicy": "default"
            }"#,
        );
        let mut states = HashMap::new();
        for entry in manifest.entries() {
            states.insert(
                entry.path().clone(),
                IgnoreState::Matched(IgnoreRuleSnapshot::new(
                    ".gitignore".to_owned(),
                    1,
                    "*/.env".to_owned(),
                    true,
                )),
            );
            states.insert(
                entry.ciphertext_path(),
                IgnoreState::Matched(IgnoreRuleSnapshot::new(
                    ".gitignore".to_owned(),
                    2,
                    "*.gitveil".to_owned(),
                    true,
                )),
            );
        }
        let violations = visibility_violations(&manifest, &states).expect("visibility plan");
        assert_eq!(violations.len(), 2);
        assert!(violations[0].describe().contains("a/.env.gitveil"));
        assert!(violations[1].describe().contains("b/.env.gitveil"));
        assert!(
            violations
                .iter()
                .all(|item| item.describe().contains(".gitignore:2:*.gitveil"))
        );
    }

    #[test]
    fn ignore_rule_evidence_escapes_terminal_control_characters() {
        let evidence = IgnoreRuleSnapshot::new(
            "\u{1b}[31m.gitignore".to_owned(),
            4,
            "secret\npattern".to_owned(),
            true,
        )
        .description();
        assert!(!evidence.contains('\u{1b}'));
        assert!(!evidence.contains('\n'));
        assert!(evidence.contains("\\u{1b}"));
        assert!(evidence.contains("secret\\npattern"));
    }

    #[test]
    fn fail_safe_protection_union_keeps_authoritative_order_then_candidate_extras() {
        let authoritative = [
            ManagedPath::new("concurrent.env").expect("path"),
            ManagedPath::new("shared.env").expect("path"),
        ];
        let candidate = [
            ManagedPath::new("SHARED.env").expect("path"),
            ManagedPath::new("requested.env").expect("path"),
        ];
        assert_eq!(
            merge_protection_paths(&authoritative, &candidate),
            [
                ManagedPath::new("concurrent.env").expect("path"),
                ManagedPath::new("shared.env").expect("path"),
                ManagedPath::new("requested.env").expect("path"),
            ]
        );
    }

    #[test]
    fn managed_block_is_moved_to_eof_without_rewriting_user_bytes() {
        let existing =
            b"before\n# BEGIN gitveil managed files\n/old\n# END gitveil managed files\nafter\n";
        let rendered = render_managed_ignore(existing, &paths(".env")).expect("render");
        assert_eq!(
            rendered,
            b"before\nafter\n# BEGIN gitveil managed files\n/.env\n!/.env.gitveil\n# END gitveil managed files\n"
        );
    }

    #[test]
    fn malformed_or_ambiguous_markers_are_rejected() {
        for input in [
            b"# BEGIN gitveil managed files\n".as_slice(),
            b"# END gitveil managed files\n".as_slice(),
            b"# BEGIN gitveil managed files extra\n".as_slice(),
        ] {
            assert_eq!(
                render_managed_ignore(input, &paths(".env")),
                Err(ManagedIgnoreError::MalformedBlock)
            );
        }
    }

    #[test]
    fn trailing_spaces_are_escaped_and_crlf_is_preserved_for_generated_lines() {
        let rendered =
            render_managed_ignore(b"user-rule\r\n", &paths("secret.env ")).expect("render");
        assert!(
            rendered
                .windows(b"/secret.env\\ \r\n".len())
                .any(|window| { window == b"/secret.env\\ \r\n" })
        );
        assert!(
            !rendered
                .windows(b"# BEGIN gitveil managed files\n".len())
                .any(|window| window == b"# BEGIN gitveil managed files\n")
        );
    }
}

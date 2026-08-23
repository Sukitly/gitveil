//!
//! Pure seal policy: turns the desired document and the decrypted state of
//! the existing ciphertext into a directly executable plan.

use crate::recipient::{RecipientAction, RecipientSetDiff};
use crate::source::SourceDocument;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SealAction {
    PreserveBaseline,
    EncryptNew,
    EditExisting,
}

/// The decrypted state of an existing ciphertext: its semantic document and
/// its recipient drift against the entry policy.
pub(super) struct SealBaseline<'a> {
    pub document: &'a SourceDocument,
    pub recipient_drift: RecipientSetDiff,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SealPlan {
    /// The executable action. Never contradicted by `recipient_action`: a
    /// rotation collapses to [`SealAction::EncryptNew`] here.
    pub action: SealAction,
    pub recipient_action: RecipientAction,
}

pub(super) fn plan_seal(desired: &SourceDocument, baseline: Option<SealBaseline<'_>>) -> SealPlan {
    let Some(baseline) = baseline else {
        // No envelope exists: there is no recipient set to align and
        // `EncryptNew` encrypts directly to the policy.
        return SealPlan {
            action: SealAction::EncryptNew,
            recipient_action: RecipientAction::Aligned,
        };
    };
    let recipient_action = baseline.recipient_drift.action();
    let action = match recipient_action {
        // Exclusion re-encrypts the desired plaintext under a fresh data key,
        // so the executable action is a new envelope regardless of
        // whether the content changed.
        RecipientAction::Rotate => SealAction::EncryptNew,
        RecipientAction::Aligned | RecipientAction::Rewrap => {
            if desired.semantic_eq(baseline.document) {
                SealAction::PreserveBaseline
            } else {
                SealAction::EditExisting
            }
        }
    };
    SealPlan {
        action,
        recipient_action,
    }
}

pub(super) fn result_matches(desired: &SourceDocument, actual: &SourceDocument) -> bool {
    desired.semantic_eq(actual)
}

/// Detects plaintext input that is actually a gitveil/SOPS envelope, e.g.
/// a ciphertext file copied over the plaintext path by mistake.
pub(super) fn resembles_envelope(input: &[u8]) -> bool {
    input.starts_with(b"gitveil_v")
        || input
            .windows(b"\nsops:".len())
            .any(|window| window == b"\nsops:")
}

/// Detects Git conflict markers in a ciphertext file left behind by a merge.
pub(crate) fn ciphertext_has_conflict_markers(input: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(input) else {
        return false;
    };
    text.lines().any(|line| {
        line.starts_with("<<<<<<<") || line.starts_with("=======") || line.starts_with(">>>>>>>")
    })
}

#[cfg(test)]
mod tests {
    use crate::config::SourceFormat;
    use crate::source::parse;

    use crate::recipient::{RecipientAction, RecipientSetDiff};
    use crate::source::SourceDocument;

    use super::{
        SealAction, SealBaseline, SealPlan, ciphertext_has_conflict_markers, plan_seal,
        resembles_envelope, result_matches,
    };

    fn document(value: &str) -> SourceDocument {
        parse(SourceFormat::Dotenv, format!("A={value}\n").as_bytes()).expect("document")
    }

    const fn baseline(document: &SourceDocument, added: usize, removed: usize) -> SealBaseline<'_> {
        SealBaseline {
            document,
            recipient_drift: RecipientSetDiff { added, removed },
        }
    }

    #[test]
    fn seal_plan_selects_new_preserve_and_edit_actions() {
        let desired = document("desired");
        let same = document("desired");
        let changed = document("baseline");
        assert_eq!(
            plan_seal(&desired, None),
            SealPlan {
                action: SealAction::EncryptNew,
                recipient_action: RecipientAction::Aligned,
            }
        );
        assert_eq!(
            plan_seal(&desired, Some(baseline(&same, 0, 0))),
            SealPlan {
                action: SealAction::PreserveBaseline,
                recipient_action: RecipientAction::Aligned,
            }
        );
        assert_eq!(
            plan_seal(&desired, Some(baseline(&changed, 0, 0))),
            SealPlan {
                action: SealAction::EditExisting,
                recipient_action: RecipientAction::Aligned,
            }
        );
    }

    #[test]
    fn recipient_drift_shapes_the_executable_action() {
        let desired = document("desired");
        let same = document("desired");
        let changed = document("old");
        // Additions keep the incremental action; only the alignment differs.
        assert_eq!(
            plan_seal(&desired, Some(baseline(&same, 1, 0))),
            SealPlan {
                action: SealAction::PreserveBaseline,
                recipient_action: RecipientAction::Rewrap,
            }
        );
        assert_eq!(
            plan_seal(&desired, Some(baseline(&changed, 1, 0))),
            SealPlan {
                action: SealAction::EditExisting,
                recipient_action: RecipientAction::Rewrap,
            }
        );
        // Any removal collapses to EncryptNew, even with unchanged content:
        // the executable action never contradicts the rotation.
        assert_eq!(
            plan_seal(&desired, Some(baseline(&same, 0, 1))),
            SealPlan {
                action: SealAction::EncryptNew,
                recipient_action: RecipientAction::Rotate,
            }
        );
        assert_eq!(
            plan_seal(&desired, Some(baseline(&changed, 1, 1))),
            SealPlan {
                action: SealAction::EncryptNew,
                recipient_action: RecipientAction::Rotate,
            }
        );
    }

    #[test]
    fn result_verification_is_semantic_equality() {
        assert!(result_matches(&document("x"), &document("x")));
        assert!(!result_matches(&document("x"), &document("y")));
    }

    #[test]
    fn envelope_lookalikes_are_detected() {
        assert!(resembles_envelope(b"gitveil_v1_dotenv:\n  data: {}\n"));
        assert!(resembles_envelope(b"anything\nsops:\n  mac: x\n"));
        assert!(!resembles_envelope(b"A=1\nB=2\n"));
    }

    #[test]
    fn ciphertext_conflict_markers_are_detected() {
        assert!(ciphertext_has_conflict_markers(
            b"<<<<<<< HEAD\ngitveil_v1_dotenv: {}\n=======\nother\n>>>>>>> branch\n"
        ));
        assert!(!ciphertext_has_conflict_markers(b"gitveil_v1_dotenv: {}\n"));
        assert!(!ciphertext_has_conflict_markers(&[0xff, 0xfe]));
    }
}

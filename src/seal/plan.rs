//! Pure seal policy: turns the desired document and the decrypted state of
//! the existing ciphertext into a directly executable action.
//!
//! Recipient drift never reaches this plan: `seal` is a data command and
//! fails closed on any manifest/envelope recipient difference before
//! decrypting; authorization changes only through `gitveil recipient`.

use crate::source::SourceDocument;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SealAction {
    PreserveBaseline,
    EncryptNew,
    EditExisting,
}

pub(super) fn plan_seal(desired: &SourceDocument, baseline: Option<&SourceDocument>) -> SealAction {
    match baseline {
        // No envelope exists: encrypt directly to the policy.
        None => SealAction::EncryptNew,
        Some(existing) if desired.semantic_eq(existing) => SealAction::PreserveBaseline,
        Some(_) => SealAction::EditExisting,
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
    use crate::source::SourceDocument;
    use crate::source::parse;

    use super::{
        SealAction, ciphertext_has_conflict_markers, plan_seal, resembles_envelope, result_matches,
    };

    fn document(value: &str) -> SourceDocument {
        parse(SourceFormat::Dotenv, format!("A={value}\n").as_bytes()).expect("document")
    }

    #[test]
    fn seal_plan_selects_new_preserve_and_edit_actions() {
        let desired = document("desired");
        let same = document("desired");
        let changed = document("baseline");
        assert_eq!(plan_seal(&desired, None), SealAction::EncryptNew);
        assert_eq!(
            plan_seal(&desired, Some(&same)),
            SealAction::PreserveBaseline
        );
        assert_eq!(
            plan_seal(&desired, Some(&changed)),
            SealAction::EditExisting
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

//! Pure authorization planning for `gitveil recipient add` and
//! `gitveil recipient remove`.
//!
//! Contract: a recipient gains or loses the ability to decrypt an existing
//! ciphertext only when the operator names it explicitly on the command
//! line. Every effective per-file recipient change must be explained by the
//! requested mutation; an unexplained difference rejects the whole command
//! and names the offending recipient (age recipients are public metadata).

use std::collections::HashSet;

use thiserror::Error;

use crate::path::ManagedPath;
use crate::recipient::{AgeRecipient, AgeRecipientPolicy};

/// The requested mutation, taken verbatim from argv.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RecipientMutation {
    Add(Vec<AgeRecipient>),
    Remove(Vec<AgeRecipient>),
}

/// Public envelope facts for one manifest entry referencing the policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FileRecipientFacts {
    pub path: ManagedPath,
    /// `None` when the ciphertext sibling does not exist yet.
    pub envelope_recipients: Option<Vec<AgeRecipient>>,
}

/// How one existing ciphertext is brought to the desired recipient set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConvergenceAction {
    AlreadyAligned,
    /// Additions only: the same data key is rewrapped and every encrypted
    /// leaf stays byte-for-byte stable.
    Rewrap,
    /// A removal: exclusion is only real under a fresh data key the removed
    /// party cannot unwrap, so the envelope is re-encrypted.
    Rotate,
}

/// Echo of one requested recipient's actual effect, rendered by the CLI so
/// the authorization action always names its subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GrantEcho {
    Added(AgeRecipient),
    AlreadyAuthorized(AgeRecipient),
    Removed(AgeRecipient),
    /// Absent from the policy but present on at least one ciphertext; the
    /// removal converges that drift.
    RemovedFromCiphertext(AgeRecipient),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AuthorizationPlan {
    /// Final ordered recipient list for the policy.
    pub desired_recipients: Vec<AgeRecipient>,
    /// Whether the manifest policy itself changes.
    pub manifest_changed: bool,
    /// Convergence action per entry with an existing ciphertext.
    pub files: Vec<(ManagedPath, ConvergenceAction)>,
    pub grants: Vec<GrantEcho>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(super) enum AuthorizationRejection {
    #[error("recipient {0} is requested more than once")]
    DuplicateRequest(AgeRecipient),
    #[error("recipient {0} is neither in the policy nor on any managed ciphertext")]
    RemoveNotMember(AgeRecipient),
    #[error("a policy must keep at least one recipient; this removal would empty it")]
    EmptyPolicy,
    #[error(
        "the policy grants {recipient} but {path}.gitveil does not include it and this command did not add it; remove it from .gitveilrc.json or name it explicitly with gitveil recipient add"
    )]
    UnexplainedAddition {
        path: ManagedPath,
        recipient: AgeRecipient,
    },
    #[error(
        "{path}.gitveil includes {recipient} but the policy does not, and this command did not remove it; restore it in .gitveilrc.json or name it explicitly with gitveil recipient remove"
    )]
    UnexplainedRemoval {
        path: ManagedPath,
        recipient: AgeRecipient,
    },
}

fn desired_and_grants(
    current: &[AgeRecipient],
    mutation: &RecipientMutation,
    files: &[FileRecipientFacts],
) -> Result<(Vec<AgeRecipient>, Vec<GrantEcho>), AuthorizationRejection> {
    match mutation {
        RecipientMutation::Add(additions) => {
            let mut desired = current.to_vec();
            let mut grants = Vec::with_capacity(additions.len());
            for addition in additions {
                if current.contains(addition) {
                    grants.push(GrantEcho::AlreadyAuthorized(addition.clone()));
                } else {
                    desired.push(addition.clone());
                    grants.push(GrantEcho::Added(addition.clone()));
                }
            }
            Ok((desired, grants))
        }
        RecipientMutation::Remove(removals) => {
            let mut grants = Vec::with_capacity(removals.len());
            for removal in removals {
                if current.contains(removal) {
                    grants.push(GrantEcho::Removed(removal.clone()));
                } else if files.iter().any(|facts| {
                    facts
                        .envelope_recipients
                        .as_deref()
                        .is_some_and(|envelope| envelope.contains(removal))
                }) {
                    grants.push(GrantEcho::RemovedFromCiphertext(removal.clone()));
                } else {
                    return Err(AuthorizationRejection::RemoveNotMember(removal.clone()));
                }
            }
            let desired = current
                .iter()
                .filter(|recipient| !removals.contains(recipient))
                .cloned()
                .collect::<Vec<_>>();
            if desired.is_empty() {
                return Err(AuthorizationRejection::EmptyPolicy);
            }
            Ok((desired, grants))
        }
    }
}

pub(super) fn plan_authorization(
    policy: &AgeRecipientPolicy,
    mutation: &RecipientMutation,
    files: &[FileRecipientFacts],
) -> Result<AuthorizationPlan, AuthorizationRejection> {
    let requested = match mutation {
        RecipientMutation::Add(recipients) | RecipientMutation::Remove(recipients) => recipients,
    };
    let mut seen = HashSet::with_capacity(requested.len());
    if let Some(duplicate) = requested
        .iter()
        .find(|recipient| !seen.insert(recipient.as_str()))
    {
        return Err(AuthorizationRejection::DuplicateRequest(duplicate.clone()));
    }

    let current = policy.recipients();
    let (desired, grants) = desired_and_grants(current, mutation, files)?;
    let manifest_changed = desired.as_slice() != current;

    let empty: &[AgeRecipient] = &[];
    let (named_additions, named_removals) = match mutation {
        RecipientMutation::Add(recipients) => (recipients.as_slice(), empty),
        RecipientMutation::Remove(recipients) => (empty, recipients.as_slice()),
    };

    let mut file_actions = Vec::with_capacity(files.len());
    for facts in files {
        let Some(envelope) = facts.envelope_recipients.as_deref() else {
            continue;
        };
        let additions_needed = desired
            .iter()
            .filter(|recipient| !envelope.contains(recipient))
            .collect::<Vec<_>>();
        let removals_needed = envelope
            .iter()
            .filter(|recipient| !desired.contains(recipient))
            .collect::<Vec<_>>();
        if let Some(recipient) = additions_needed
            .iter()
            .find(|recipient| !named_additions.contains(recipient))
        {
            return Err(AuthorizationRejection::UnexplainedAddition {
                path: facts.path.clone(),
                recipient: (*recipient).clone(),
            });
        }
        if let Some(recipient) = removals_needed
            .iter()
            .find(|recipient| !named_removals.contains(recipient))
        {
            return Err(AuthorizationRejection::UnexplainedRemoval {
                path: facts.path.clone(),
                recipient: (*recipient).clone(),
            });
        }
        let action = if removals_needed.is_empty() {
            if additions_needed.is_empty() {
                ConvergenceAction::AlreadyAligned
            } else {
                ConvergenceAction::Rewrap
            }
        } else {
            ConvergenceAction::Rotate
        };
        file_actions.push((facts.path.clone(), action));
    }
    Ok(AuthorizationPlan {
        desired_recipients: desired,
        manifest_changed,
        files: file_actions,
        grants,
    })
}

#[cfg(test)]
mod tests {
    use bech32::{Bech32, Hrp};

    use crate::path::ManagedPath;
    use crate::recipient::{AgeRecipient, AgeRecipientPolicy, PolicyName};

    use super::{
        AuthorizationRejection, ConvergenceAction, FileRecipientFacts, GrantEcho,
        RecipientMutation, plan_authorization,
    };

    fn recipient(seed: u8) -> AgeRecipient {
        let encoded = bech32::encode::<Bech32>(Hrp::parse_unchecked("age"), &[seed; 32])
            .expect("encode age recipient");
        AgeRecipient::new(encoded).expect("valid age recipient")
    }

    fn policy(recipients: &[&AgeRecipient]) -> AgeRecipientPolicy {
        AgeRecipientPolicy::new(
            PolicyName::new("team").expect("policy name"),
            recipients.iter().map(|value| (*value).clone()).collect(),
        )
        .expect("policy")
    }

    fn file(path: &str, envelope: Option<&[&AgeRecipient]>) -> FileRecipientFacts {
        FileRecipientFacts {
            path: ManagedPath::new(path).expect("managed path"),
            envelope_recipients: envelope
                .map(|recipients| recipients.iter().map(|value| (*value).clone()).collect()),
        }
    }

    #[test]
    fn adding_to_an_aligned_state_rewraps_every_existing_ciphertext() {
        let (a, b) = (recipient(1), recipient(2));
        let plan = plan_authorization(
            &policy(&[&a]),
            &RecipientMutation::Add(vec![b.clone()]),
            &[file(".env", Some(&[&a])), file("fresh.env", None)],
        )
        .expect("plan");
        assert_eq!(plan.desired_recipients, vec![a, b.clone()]);
        assert!(plan.manifest_changed);
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.files[0].1, ConvergenceAction::Rewrap);
        assert_eq!(plan.grants, vec![GrantEcho::Added(b)]);
    }

    #[test]
    fn an_idempotent_add_reports_already_authorized_and_already_aligned() {
        let (a, b) = (recipient(1), recipient(2));
        let plan = plan_authorization(
            &policy(&[&a, &b]),
            &RecipientMutation::Add(vec![b.clone()]),
            &[file(".env", Some(&[&a, &b]))],
        )
        .expect("plan");
        assert!(!plan.manifest_changed);
        assert_eq!(plan.files[0].1, ConvergenceAction::AlreadyAligned);
        assert_eq!(plan.grants, vec![GrantEcho::AlreadyAuthorized(b)]);
    }

    #[test]
    fn add_converges_a_hand_edited_manifest_when_the_difference_is_named() {
        let (a, b) = (recipient(1), recipient(2));
        let plan = plan_authorization(
            &policy(&[&a, &b]),
            &RecipientMutation::Add(vec![b.clone()]),
            &[file(".env", Some(&[&a]))],
        )
        .expect("plan");
        assert!(!plan.manifest_changed);
        assert_eq!(plan.files[0].1, ConvergenceAction::Rewrap);
    }

    #[test]
    fn an_injected_manifest_addition_is_rejected_and_named() {
        let (a, b, injected) = (recipient(1), recipient(2), recipient(9));
        assert_eq!(
            plan_authorization(
                &policy(&[&a, &injected]),
                &RecipientMutation::Add(vec![b]),
                &[file(".env", Some(&[&a]))],
            ),
            Err(AuthorizationRejection::UnexplainedAddition {
                path: ManagedPath::new(".env").expect("managed path"),
                recipient: injected,
            })
        );
    }

    #[test]
    fn an_injected_manifest_removal_is_rejected_by_add() {
        let (a, b, c) = (recipient(1), recipient(2), recipient(3));
        assert_eq!(
            plan_authorization(
                &policy(&[&a]),
                &RecipientMutation::Add(vec![c]),
                &[file(".env", Some(&[&a, &b]))],
            ),
            Err(AuthorizationRejection::UnexplainedRemoval {
                path: ManagedPath::new(".env").expect("managed path"),
                recipient: b,
            })
        );
    }

    #[test]
    fn removing_a_policy_member_rotates_every_existing_ciphertext() {
        let (a, b) = (recipient(1), recipient(2));
        let plan = plan_authorization(
            &policy(&[&a, &b]),
            &RecipientMutation::Remove(vec![b.clone()]),
            &[file(".env", Some(&[&a, &b]))],
        )
        .expect("plan");
        assert_eq!(plan.desired_recipients, vec![a]);
        assert!(plan.manifest_changed);
        assert_eq!(plan.files[0].1, ConvergenceAction::Rotate);
        assert_eq!(plan.grants, vec![GrantEcho::Removed(b)]);
    }

    #[test]
    fn removing_a_ciphertext_only_recipient_converges_removal_drift() {
        let (a, b) = (recipient(1), recipient(2));
        let plan = plan_authorization(
            &policy(&[&a]),
            &RecipientMutation::Remove(vec![b.clone()]),
            &[file(".env", Some(&[&a, &b]))],
        )
        .expect("plan");
        assert!(!plan.manifest_changed);
        assert_eq!(plan.files[0].1, ConvergenceAction::Rotate);
        assert_eq!(plan.grants, vec![GrantEcho::RemovedFromCiphertext(b)]);
    }

    #[test]
    fn remove_rejects_unknown_recipients_and_an_emptied_policy() {
        let (a, b, unknown) = (recipient(1), recipient(2), recipient(9));
        assert_eq!(
            plan_authorization(
                &policy(&[&a, &b]),
                &RecipientMutation::Remove(vec![unknown.clone()]),
                &[file(".env", Some(&[&a, &b]))],
            ),
            Err(AuthorizationRejection::RemoveNotMember(unknown.clone()))
        );
        assert_eq!(
            plan_authorization(
                &policy(&[&a]),
                &RecipientMutation::Remove(vec![a.clone()]),
                &[file(".env", Some(&[&a]))],
            ),
            Err(AuthorizationRejection::EmptyPolicy)
        );
    }

    #[test]
    fn remove_rejects_an_unexplained_manifest_addition() {
        // The attacker added `injected` to the manifest; a removal of `b`
        // must not silently wrap the data key to `injected`.
        let (a, b, injected) = (recipient(1), recipient(2), recipient(9));
        assert_eq!(
            plan_authorization(
                &policy(&[&a, &b, &injected]),
                &RecipientMutation::Remove(vec![b.clone()]),
                &[file(".env", Some(&[&a, &b]))],
            ),
            Err(AuthorizationRejection::UnexplainedAddition {
                path: ManagedPath::new(".env").expect("managed path"),
                recipient: injected,
            })
        );
    }

    #[test]
    fn duplicate_argv_recipients_are_rejected() {
        let a = recipient(1);
        let b = recipient(2);
        assert_eq!(
            plan_authorization(
                &policy(&[&a]),
                &RecipientMutation::Add(vec![b.clone(), b.clone()]),
                &[],
            ),
            Err(AuthorizationRejection::DuplicateRequest(b))
        );
    }

    #[test]
    fn entries_without_ciphertext_only_change_the_manifest() {
        let (a, b) = (recipient(1), recipient(2));
        let plan = plan_authorization(
            &policy(&[&a]),
            &RecipientMutation::Add(vec![b]),
            &[file(".env", None)],
        )
        .expect("plan");
        assert!(plan.manifest_changed);
        assert!(plan.files.is_empty());
    }
}

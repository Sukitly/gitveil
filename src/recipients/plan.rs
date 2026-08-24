//! Pure authorization planning for `gitveil recipient add` and
//! `gitveil recipient remove`.
//!
//! Contract: each command changes envelopes only in its own direction and
//! only for the recipients named on the command line. `add` computes each
//! file's target as `envelope ∪ named`, `remove` as `envelope ∖ named`; a
//! command never grants or revokes anything it did not name, so a tampered
//! manifest entry stays ineffective until someone names it explicitly.
//! Residual difference against the final policy is reported per file with
//! full recipient values (age recipients are public metadata) and keeps
//! `seal` fail-closed until it is converged.

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

/// How one existing ciphertext converges to its per-file target set.
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

/// The manifest-level effect of one requested recipient, rendered by the
/// CLI after publication so every claim is about a committed state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PolicyDelta {
    AddedToPolicy(AgeRecipient),
    AlreadyInPolicy(AgeRecipient),
    RemovedFromPolicy(AgeRecipient),
    /// Absent from the policy but present on at least one ciphertext; the
    /// removal converges that envelope-side drift.
    RemovedFromCiphertextOnly(AgeRecipient),
}

/// One file's convergence: the exact target set and the residual drift
/// against the final policy that remains after this command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FilePlan {
    pub path: ManagedPath,
    pub action: ConvergenceAction,
    /// `envelope ± named`: the set this file's envelope converges to.
    pub target_recipients: Vec<AgeRecipient>,
    /// Policy recipients not on the target: granting them needs `add`.
    pub pending_additions: Vec<AgeRecipient>,
    /// Target recipients not in the policy: revoking them needs `remove`.
    pub pending_removals: Vec<AgeRecipient>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AuthorizationPlan {
    /// Final ordered recipient list for the manifest policy.
    pub desired_recipients: Vec<AgeRecipient>,
    pub manifest_changed: bool,
    /// Plans for every entry with an existing, parseable ciphertext.
    pub files: Vec<FilePlan>,
    pub deltas: Vec<PolicyDelta>,
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
        "removing these recipients would leave {0}.gitveil with no recipient able to decrypt; run gitveil recipient add first"
    )]
    EmptiesEnvelope(ManagedPath),
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
    let (desired, deltas) = manifest_effect(current, mutation, files)?;
    let manifest_changed = desired.as_slice() != current;

    let mut file_plans = Vec::with_capacity(files.len());
    for facts in files {
        let Some(envelope) = facts.envelope_recipients.as_deref() else {
            continue;
        };
        let (target, action) = match mutation {
            RecipientMutation::Add(additions) => {
                let mut target = envelope.to_vec();
                target.extend(
                    additions
                        .iter()
                        .filter(|recipient| !envelope.contains(recipient))
                        .cloned(),
                );
                let action = if target.len() == envelope.len() {
                    ConvergenceAction::AlreadyAligned
                } else {
                    ConvergenceAction::Rewrap
                };
                (target, action)
            }
            RecipientMutation::Remove(removals) => {
                let target = envelope
                    .iter()
                    .filter(|recipient| !removals.contains(recipient))
                    .cloned()
                    .collect::<Vec<_>>();
                if target.is_empty() {
                    return Err(AuthorizationRejection::EmptiesEnvelope(facts.path.clone()));
                }
                let action = if target.len() == envelope.len() {
                    ConvergenceAction::AlreadyAligned
                } else {
                    ConvergenceAction::Rotate
                };
                (target, action)
            }
        };
        let pending_additions = desired
            .iter()
            .filter(|recipient| !target.contains(recipient))
            .cloned()
            .collect();
        let pending_removals = target
            .iter()
            .filter(|recipient| !desired.contains(recipient))
            .cloned()
            .collect();
        file_plans.push(FilePlan {
            path: facts.path.clone(),
            action,
            target_recipients: target,
            pending_additions,
            pending_removals,
        });
    }
    Ok(AuthorizationPlan {
        desired_recipients: desired,
        manifest_changed,
        files: file_plans,
        deltas,
    })
}

fn manifest_effect(
    current: &[AgeRecipient],
    mutation: &RecipientMutation,
    files: &[FileRecipientFacts],
) -> Result<(Vec<AgeRecipient>, Vec<PolicyDelta>), AuthorizationRejection> {
    match mutation {
        RecipientMutation::Add(additions) => {
            let mut desired = current.to_vec();
            let mut deltas = Vec::with_capacity(additions.len());
            for addition in additions {
                if current.contains(addition) {
                    deltas.push(PolicyDelta::AlreadyInPolicy(addition.clone()));
                } else {
                    desired.push(addition.clone());
                    deltas.push(PolicyDelta::AddedToPolicy(addition.clone()));
                }
            }
            Ok((desired, deltas))
        }
        RecipientMutation::Remove(removals) => {
            let mut deltas = Vec::with_capacity(removals.len());
            for removal in removals {
                if current.contains(removal) {
                    deltas.push(PolicyDelta::RemovedFromPolicy(removal.clone()));
                } else if files.iter().any(|facts| {
                    facts
                        .envelope_recipients
                        .as_deref()
                        .is_some_and(|envelope| envelope.contains(removal))
                }) {
                    deltas.push(PolicyDelta::RemovedFromCiphertextOnly(removal.clone()));
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
            Ok((desired, deltas))
        }
    }
}

#[cfg(test)]
mod tests {
    use bech32::{Bech32, Hrp};

    use crate::path::ManagedPath;
    use crate::recipient::{AgeRecipient, AgeRecipientPolicy, PolicyName};

    use super::{
        AuthorizationRejection, ConvergenceAction, FileRecipientFacts, PolicyDelta,
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
    fn add_targets_envelope_plus_named_and_rewraps() {
        let (a, b) = (recipient(1), recipient(2));
        let plan = plan_authorization(
            &policy(&[&a]),
            &RecipientMutation::Add(vec![b.clone()]),
            &[file(".env", Some(&[&a])), file("fresh.env", None)],
        )
        .expect("plan");
        assert_eq!(plan.desired_recipients, vec![a.clone(), b.clone()]);
        assert!(plan.manifest_changed);
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.files[0].action, ConvergenceAction::Rewrap);
        assert_eq!(plan.files[0].target_recipients, vec![a, b.clone()]);
        assert!(plan.files[0].pending_additions.is_empty());
        assert!(plan.files[0].pending_removals.is_empty());
        assert_eq!(plan.deltas, vec![PolicyDelta::AddedToPolicy(b)]);
    }

    // The confused-deputy case: an injected manifest recipient is never
    // wrapped by an add that does not name it; it surfaces as residual drift.
    #[test]
    fn add_grants_only_named_recipients_and_reports_injected_ones_as_pending() {
        let (a, b, injected) = (recipient(1), recipient(2), recipient(9));
        let plan = plan_authorization(
            &policy(&[&a, &injected]),
            &RecipientMutation::Add(vec![b.clone()]),
            &[file(".env", Some(&[&a]))],
        )
        .expect("plan");
        assert_eq!(plan.files[0].target_recipients, vec![a, b]);
        assert_eq!(plan.files[0].pending_additions, vec![injected]);
        assert_eq!(plan.files[0].action, ConvergenceAction::Rewrap);
    }

    // An add never executes a removal, even when the manifest lost a
    // recipient (attack or accident): the envelope keeps it, reported as
    // pending removal.
    #[test]
    fn add_never_removes_envelope_recipients() {
        let (a, b, c) = (recipient(1), recipient(2), recipient(3));
        let plan = plan_authorization(
            &policy(&[&a]),
            &RecipientMutation::Add(vec![c.clone()]),
            &[file(".env", Some(&[&a, &b]))],
        )
        .expect("plan");
        assert_eq!(plan.files[0].target_recipients, vec![a, b.clone(), c]);
        assert_eq!(plan.files[0].pending_removals, vec![b]);
        assert_eq!(plan.files[0].action, ConvergenceAction::Rewrap);
    }

    #[test]
    fn remove_targets_envelope_minus_named_and_rotates() {
        let (a, b) = (recipient(1), recipient(2));
        let plan = plan_authorization(
            &policy(&[&a, &b]),
            &RecipientMutation::Remove(vec![b.clone()]),
            &[file(".env", Some(&[&a, &b]))],
        )
        .expect("plan");
        assert_eq!(plan.desired_recipients, vec![a.clone()]);
        assert!(plan.manifest_changed);
        assert_eq!(plan.files[0].action, ConvergenceAction::Rotate);
        assert_eq!(plan.files[0].target_recipients, vec![a]);
        assert_eq!(plan.deltas, vec![PolicyDelta::RemovedFromPolicy(b)]);
    }

    // Mixed drift converges as two sequential one-sided commands: the user's
    // "remove Y, then add X" intuition, each step naming exactly its change.
    #[test]
    fn mixed_drift_converges_by_sequential_remove_then_add() {
        let (a, x, y) = (recipient(1), recipient(2), recipient(3));
        // State: policy [A, X] (X pulled in via manifest), envelope [A, Y].
        let first = plan_authorization(
            &policy(&[&a, &x]),
            &RecipientMutation::Remove(vec![y.clone()]),
            &[file(".env", Some(&[&a, &y]))],
        )
        .expect("remove plan");
        assert_eq!(first.files[0].action, ConvergenceAction::Rotate);
        assert_eq!(first.files[0].target_recipients, vec![a.clone()]);
        assert_eq!(first.files[0].pending_additions, vec![x.clone()]);
        assert!(!first.manifest_changed, "Y was never in the policy");
        assert_eq!(
            first.deltas,
            vec![PolicyDelta::RemovedFromCiphertextOnly(y)]
        );

        // After the rotation the envelope is [A]; the add converges fully.
        let second = plan_authorization(
            &policy(&[&a, &x]),
            &RecipientMutation::Add(vec![x.clone()]),
            &[file(".env", Some(&[&a]))],
        )
        .expect("add plan");
        assert_eq!(second.files[0].action, ConvergenceAction::Rewrap);
        assert_eq!(second.files[0].target_recipients, vec![a, x.clone()]);
        assert!(second.files[0].pending_additions.is_empty());
        assert!(second.files[0].pending_removals.is_empty());
        assert_eq!(second.deltas, vec![PolicyDelta::AlreadyInPolicy(x)]);
    }

    #[test]
    fn idempotent_add_is_already_aligned() {
        let (a, b) = (recipient(1), recipient(2));
        let plan = plan_authorization(
            &policy(&[&a, &b]),
            &RecipientMutation::Add(vec![b.clone()]),
            &[file(".env", Some(&[&a, &b]))],
        )
        .expect("plan");
        assert!(!plan.manifest_changed);
        assert_eq!(plan.files[0].action, ConvergenceAction::AlreadyAligned);
        assert_eq!(plan.deltas, vec![PolicyDelta::AlreadyInPolicy(b)]);
    }

    // Cleaning an injected manifest addition is itself in-product: removing
    // it touches only the manifest because no envelope carries it.
    #[test]
    fn removing_a_manifest_only_recipient_changes_no_envelope() {
        let (a, injected) = (recipient(1), recipient(9));
        let plan = plan_authorization(
            &policy(&[&a, &injected]),
            &RecipientMutation::Remove(vec![injected.clone()]),
            &[file(".env", Some(&[&a]))],
        )
        .expect("plan");
        assert!(plan.manifest_changed);
        assert_eq!(plan.files[0].action, ConvergenceAction::AlreadyAligned);
        assert!(plan.files[0].pending_additions.is_empty());
        assert_eq!(plan.deltas, vec![PolicyDelta::RemovedFromPolicy(injected)]);
    }

    #[test]
    fn remove_rejections_cover_membership_emptiness_and_envelope_emptying() {
        let (a, b, unknown) = (recipient(1), recipient(2), recipient(9));
        assert_eq!(
            plan_authorization(
                &policy(&[&a, &b]),
                &RecipientMutation::Remove(vec![unknown.clone()]),
                &[file(".env", Some(&[&a, &b]))],
            ),
            Err(AuthorizationRejection::RemoveNotMember(unknown))
        );
        assert_eq!(
            plan_authorization(
                &policy(&[&a]),
                &RecipientMutation::Remove(vec![a.clone()]),
                &[file(".env", Some(&[&a]))],
            ),
            Err(AuthorizationRejection::EmptyPolicy)
        );
        // The policy keeps a member, but this envelope would lose everyone.
        assert_eq!(
            plan_authorization(
                &policy(&[&a, &b]),
                &RecipientMutation::Remove(vec![b.clone()]),
                &[file("orphan.env", Some(&[&b]))],
            ),
            Err(AuthorizationRejection::EmptiesEnvelope(
                ManagedPath::new("orphan.env").expect("managed path")
            ))
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

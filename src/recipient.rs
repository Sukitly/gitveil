//! Pure age-recipient domain values shared by the manifest, envelope, and SOPS adapter.

use std::collections::HashSet;
use std::fmt;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Hrp};
use thiserror::Error;

const AGE_RECIPIENT_HRP: Hrp = Hrp::parse_unchecked("age");
const X25519_PUBLIC_KEY_BYTES: usize = 32;
const POLICY_NAME_MAX_BYTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgeRecipient(String);

impl AgeRecipient {
    pub fn new(value: impl AsRef<str>) -> Result<Self, RecipientError> {
        let value = value.as_ref();
        if value != value.to_ascii_lowercase() {
            return Err(RecipientError::NonCanonicalAgeRecipient);
        }
        // Age recipients are bech32, never bech32m. `bech32::decode` accepts either,
        // so pin the checksum algorithm explicitly instead.
        let parsed = CheckedHrpstring::new::<Bech32>(value)
            .map_err(|_| RecipientError::InvalidAgeRecipient)?;
        if parsed.hrp() != AGE_RECIPIENT_HRP {
            return Err(RecipientError::InvalidAgeRecipient);
        }
        let bytes = parsed.byte_iter().collect::<Vec<u8>>();
        if bytes.len() != X25519_PUBLIC_KEY_BYTES {
            return Err(RecipientError::InvalidAgeRecipient);
        }
        // Re-encoding is what rejects any residual non-canonical encoding, including
        // a data part whose trailing bits are not zero-padded.
        let canonical = bech32::encode::<Bech32>(AGE_RECIPIENT_HRP, &bytes)
            .map_err(|_| RecipientError::InvalidAgeRecipient)?;
        if canonical != value {
            return Err(RecipientError::NonCanonicalAgeRecipient);
        }
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgeRecipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicyName(String);

impl PolicyName {
    pub(crate) fn new(value: impl AsRef<str>) -> Result<Self, RecipientError> {
        let value = value.as_ref();
        let mut characters = value.chars();
        if value.len() > POLICY_NAME_MAX_BYTES
            || !characters
                .next()
                .is_some_and(|value| value.is_ascii_lowercase())
            || !characters
                .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == '-')
        {
            return Err(RecipientError::InvalidPolicyName);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgeRecipientPolicy {
    name: PolicyName,
    recipients: Vec<AgeRecipient>,
}

impl AgeRecipientPolicy {
    pub(crate) fn new(
        name: PolicyName,
        recipients: Vec<AgeRecipient>,
    ) -> Result<Self, RecipientError> {
        if recipients.is_empty() {
            return Err(RecipientError::EmptyPolicy);
        }
        let mut seen = HashSet::with_capacity(recipients.len());
        if recipients
            .iter()
            .any(|recipient| !seen.insert(recipient.as_str()))
        {
            return Err(RecipientError::DuplicateAgeRecipient);
        }
        Ok(Self { name, recipients })
    }

    pub(crate) fn name(&self) -> &PolicyName {
        &self.name
    }

    pub fn recipients(&self) -> &[AgeRecipient] {
        &self.recipients
    }

    pub(crate) fn matches(&self, actual: &[AgeRecipient]) -> bool {
        self.diff(actual).is_empty()
    }

    pub(crate) fn diff(&self, actual: &[AgeRecipient]) -> RecipientSetDiff {
        let desired = self
            .recipients
            .iter()
            .map(AgeRecipient::as_str)
            .collect::<HashSet<_>>();
        let actual = actual
            .iter()
            .map(AgeRecipient::as_str)
            .collect::<HashSet<_>>();
        RecipientSetDiff {
            added: desired.difference(&actual).count(),
            removed: actual.difference(&desired).count(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecipientSetDiff {
    pub(crate) added: usize,
    pub(crate) removed: usize,
}

/// How an envelope's recipient set is brought to a policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecipientAction {
    /// The sets already agree.
    Aligned,
    /// Only additions are needed: the same data key is rewrapped and every
    /// encrypted leaf stays byte-for-byte stable.
    Rewrap,
    /// The envelope carries a recipient outside the policy. Exclusion is only
    /// real under a data key the removed party cannot unwrap, so the envelope
    /// must be re-encrypted under a fresh one.
    Rotate,
}

impl RecipientSetDiff {
    pub(crate) const fn is_empty(self) -> bool {
        self.added == 0 && self.removed == 0
    }

    /// Any removal forces a fresh data key; additions alone rewrap.
    pub(crate) const fn action(self) -> RecipientAction {
        if self.removed > 0 {
            RecipientAction::Rotate
        } else if self.added > 0 {
            RecipientAction::Rewrap
        } else {
            RecipientAction::Aligned
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RecipientError {
    #[error("policy name must be lowercase kebab-case and at most 64 bytes")]
    InvalidPolicyName,
    #[error("age recipient is invalid")]
    InvalidAgeRecipient,
    #[error("age recipient must use its canonical lowercase encoding")]
    NonCanonicalAgeRecipient,
    #[error("age recipient policy must contain at least one recipient")]
    EmptyPolicy,
    #[error("age recipient policy contains a duplicate recipient")]
    DuplicateAgeRecipient,
}

#[cfg(test)]
mod tests {

    use super::{AgeRecipient, RecipientAction, RecipientError, RecipientSetDiff};

    #[test]
    fn set_diff_action_rotates_on_any_removal_and_rewraps_on_additions_only() {
        let drift = |added, removed| RecipientSetDiff { added, removed };
        assert_eq!(drift(0, 0).action(), RecipientAction::Aligned);
        assert_eq!(drift(1, 0).action(), RecipientAction::Rewrap);
        assert_eq!(drift(0, 1).action(), RecipientAction::Rotate);
        // Mixed additions and removals (including a policy switch) rotate.
        assert_eq!(drift(2, 1).action(), RecipientAction::Rotate);
    }

    /// HRP `age`, 32-byte payload, bech32 checksum: the only shape age accepts.
    const CANONICAL: &str = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq";
    /// Same HRP and payload as `CANONICAL` but carrying a bech32m checksum.
    const BECH32M_CHECKSUM: &str = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsyk4rdz";
    const PAYLOAD_31_BYTES: &str = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqpeaer";
    const PAYLOAD_33_BYTES: &str =
        "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz3hjx6d";
    const FOREIGN_HRP: &str = "notage1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsuc2584";

    #[test]
    fn accepts_a_canonical_age_recipient_and_preserves_its_encoding() {
        let recipient = AgeRecipient::new(CANONICAL).expect("canonical age recipient");
        assert_eq!(recipient.as_str(), CANONICAL);
    }

    #[test]
    fn rejects_a_bech32m_checksum() {
        assert_eq!(
            AgeRecipient::new(BECH32M_CHECKSUM),
            Err(RecipientError::InvalidAgeRecipient)
        );
    }

    #[test]
    fn rejects_a_payload_that_is_not_an_x25519_public_key() {
        for value in [PAYLOAD_31_BYTES, PAYLOAD_33_BYTES] {
            assert_eq!(
                AgeRecipient::new(value),
                Err(RecipientError::InvalidAgeRecipient),
                "must reject a {value} payload that is not 32 bytes"
            );
        }
    }

    #[test]
    fn rejects_a_human_readable_part_other_than_age() {
        assert_eq!(
            AgeRecipient::new(FOREIGN_HRP),
            Err(RecipientError::InvalidAgeRecipient)
        );
    }

    #[test]
    fn rejects_a_non_canonical_uppercase_encoding() {
        assert_eq!(
            AgeRecipient::new(CANONICAL.to_uppercase()),
            Err(RecipientError::NonCanonicalAgeRecipient)
        );
    }

    #[test]
    fn rejects_a_value_that_is_not_bech32_at_all() {
        assert_eq!(
            AgeRecipient::new("not-an-age-recipient"),
            Err(RecipientError::InvalidAgeRecipient)
        );
    }
}

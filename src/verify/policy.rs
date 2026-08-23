//!
//! Pure verify policy: revision-range validation.

use thiserror::Error;

#[derive(Debug, Error)]
pub(super) enum VerifyPolicyError {
    #[error("invalid revision range")]
    InvalidRevisionRange,
}

pub(super) fn validate_revision_range(range: &str) -> Result<(), VerifyPolicyError> {
    if range.is_empty()
        || range.starts_with('-')
        || range.contains(char::is_whitespace)
        || range.contains('\0')
    {
        return Err(VerifyPolicyError::InvalidRevisionRange);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_revision_range;

    #[test]
    fn revision_ranges_reject_flags_whitespace_and_empty_values() {
        assert!(validate_revision_range("origin/main..HEAD").is_ok());
        assert!(validate_revision_range("HEAD~5..HEAD").is_ok());
        for invalid in ["", "--all", "-n1", "a b", "a\0b"] {
            assert!(validate_revision_range(invalid).is_err(), "{invalid:?}");
        }
    }
}

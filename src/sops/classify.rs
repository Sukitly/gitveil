#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SopsFailure {
    IdentityUnavailable,
    Integrity,
    Configuration,
    Execution,
}

pub(super) fn classify(stderr: &[u8]) -> SopsFailure {
    let message = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    // Integrity is checked first and fails closed: a message that also claims
    // an integrity failure is never an unambiguous identity-unavailable signal.
    if message.contains("mac mismatch")
        || message.contains("integrity check failed")
        || message.contains("could not verify data integrity")
    {
        SopsFailure::Integrity
    } else if [
        "no identity matched",
        "failed to load age identities",
        "could not decrypt data key",
        "cannot get data key",
        "0 successful groups required",
        "no master key was able to decrypt",
    ]
    .iter()
    .any(|needle| message.contains(needle))
    {
        SopsFailure::IdentityUnavailable
    } else if message.contains("config")
        || message.contains("creation rule")
        || message.contains("no matching creation rules")
    {
        SopsFailure::Configuration
    } else {
        SopsFailure::Execution
    }
}

#[cfg(test)]
mod tests {
    use super::{SopsFailure, classify};

    #[test]
    fn classifies_every_identity_pattern() {
        for stderr in [
            "no identity matched any recipient",
            "failed to load age identities from keyfile",
            "could not decrypt data key with any key group",
            "cannot get data key",
            "0 successful groups required, got 0",
            "no master key was able to decrypt the data key",
        ] {
            assert_eq!(
                classify(stderr.as_bytes()),
                SopsFailure::IdentityUnavailable,
                "stderr: {stderr}"
            );
        }
    }

    #[test]
    fn classifies_every_integrity_pattern() {
        for stderr in [
            "MAC mismatch",
            "integrity check failed",
            "could not verify data integrity",
        ] {
            assert_eq!(
                classify(stderr.as_bytes()),
                SopsFailure::Integrity,
                "stderr: {stderr}"
            );
        }
    }

    #[test]
    fn classifies_every_configuration_pattern() {
        for stderr in [
            "error loading config: no creation rule",
            "no matching creation rules found",
            "config file not found",
        ] {
            assert_eq!(
                classify(stderr.as_bytes()),
                SopsFailure::Configuration,
                "stderr: {stderr}"
            );
        }
    }

    #[test]
    fn classification_is_case_insensitive() {
        assert_eq!(
            classify(b"COULD NOT DECRYPT DATA KEY"),
            SopsFailure::IdentityUnavailable
        );
        assert_eq!(classify(b"Mac Mismatch"), SopsFailure::Integrity);
    }

    #[test]
    fn unknown_and_non_utf8_stderr_fall_back_to_execution() {
        assert_eq!(
            classify(b"unexpected subprocess failure"),
            SopsFailure::Execution
        );
        assert_eq!(classify(b""), SopsFailure::Execution);
        assert_eq!(classify(&[0xff, 0xfe]), SopsFailure::Execution);
    }

    #[test]
    fn integrity_needles_win_over_identity_and_configuration_needles() {
        // Fail closed: a message that also claims an integrity failure is not
        // an unambiguous identity-unavailable signal; SOPS must explicitly
        // report that no usable identity exists.
        assert_eq!(
            classify(b"integrity check failed: could not decrypt data key"),
            SopsFailure::Integrity
        );
        assert_eq!(
            classify(b"mac mismatch in config file"),
            SopsFailure::Integrity
        );
    }

    #[test]
    fn identity_needles_win_over_the_broad_configuration_needle() {
        // Real identity failures routinely mention key file locations such as
        // ~/.config/sops/age; they must not degrade into Configuration.
        assert_eq!(
            classify(b"failed to load age identities from /home/dev/.config/sops/age/keys.txt"),
            SopsFailure::IdentityUnavailable
        );
    }
}

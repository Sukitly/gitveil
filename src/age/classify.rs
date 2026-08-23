use crate::error::{ErrorCategory, GitveilError, Result};
use crate::recipient::AgeRecipient;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GenerationFailure {
    NoSpace,
    PermissionDenied,
    ReadOnlyFilesystem,
    OutputIo,
    Execution,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecipientFailure {
    IdentityUnavailable,
    InvalidIdentity,
    Protocol,
    Execution,
}

pub(super) fn classify_generation(stderr: &[u8]) -> GenerationFailure {
    let message = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    if message.contains("no space left on device") {
        GenerationFailure::NoSpace
    } else if message.contains("permission denied") {
        GenerationFailure::PermissionDenied
    } else if message.contains("read-only file system") {
        GenerationFailure::ReadOnlyFilesystem
    } else if message.contains("failed to open output file")
        || message.contains("failed to close output file")
    {
        GenerationFailure::OutputIo
    } else {
        GenerationFailure::Execution
    }
}

pub(super) fn classify_recipient(stderr: &[u8]) -> RecipientFailure {
    let message = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    if message.contains("failed to open input file") {
        RecipientFailure::IdentityUnavailable
    } else if message.contains("failed to parse input")
        || message.contains("no identities found in the input")
    {
        RecipientFailure::InvalidIdentity
    } else if message.contains("internal error: unexpected identity type") {
        RecipientFailure::Protocol
    } else {
        RecipientFailure::Execution
    }
}

pub(super) fn parse_recipients(stdout: &[u8]) -> Result<Vec<AgeRecipient>> {
    let stdout = std::str::from_utf8(stdout).map_err(|_| {
        GitveilError::new(
            ErrorCategory::Protocol,
            "age-keygen recipient output is not UTF-8",
        )
    })?;
    let recipients = stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            AgeRecipient::new(line).map_err(|_| {
                GitveilError::new(
                    ErrorCategory::Protocol,
                    "age-keygen returned an invalid public recipient",
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if recipients.is_empty() {
        return Err(GitveilError::new(
            ErrorCategory::Protocol,
            "age-keygen returned no public recipients",
        ));
    }
    Ok(recipients)
}

#[cfg(test)]
mod tests {
    use crate::error::ErrorCategory;

    use super::{
        GenerationFailure, RecipientFailure, classify_generation, classify_recipient,
        parse_recipients,
    };

    #[test]
    fn classifies_generation_output_failures_without_exposing_stderr() {
        for (stderr, expected) in [
            (
                "failed to open output file: no space left on device",
                GenerationFailure::NoSpace,
            ),
            (
                "failed to open output file: permission denied",
                GenerationFailure::PermissionDenied,
            ),
            (
                "failed to open output file: read-only file system",
                GenerationFailure::ReadOnlyFilesystem,
            ),
            (
                "failed to close output file: input/output error",
                GenerationFailure::OutputIo,
            ),
            ("unexpected failure", GenerationFailure::Execution),
        ] {
            assert_eq!(classify_generation(stderr.as_bytes()), expected);
        }
        assert_eq!(
            classify_generation(&[0xff, 0xfe]),
            GenerationFailure::Execution
        );
    }

    #[test]
    fn classifies_recipient_failures_without_exposing_stderr() {
        for (stderr, expected) in [
            (
                "failed to open input file: no such file or directory",
                RecipientFailure::IdentityUnavailable,
            ),
            (
                "failed to parse input: malformed identity",
                RecipientFailure::InvalidIdentity,
            ),
            (
                "no identities found in the input",
                RecipientFailure::InvalidIdentity,
            ),
            (
                "internal error: unexpected identity type",
                RecipientFailure::Protocol,
            ),
            ("unexpected failure", RecipientFailure::Execution),
        ] {
            assert_eq!(classify_recipient(stderr.as_bytes()), expected);
        }
        assert_eq!(
            classify_recipient(&[0xff, 0xfe]),
            RecipientFailure::Execution
        );
    }

    #[test]
    fn parses_only_nonempty_native_age_recipients() {
        let recipient = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq";
        let parsed = parse_recipients(format!("{recipient}\n\n").as_bytes())
            .expect("valid recipient output");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].as_str(), recipient);
    }

    #[test]
    fn rejects_non_utf8_empty_and_invalid_recipient_output() {
        for output in [&[0xff][..], b"", b"not-an-age-recipient\n"] {
            let error = parse_recipients(output).expect_err("invalid recipient output");
            assert_eq!(error.category(), ErrorCategory::Protocol);
        }
    }
}

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::Duration;

use semver::Version;

use crate::error::{ErrorCategory, GitveilError, Result};
use crate::recipient::AgeRecipient;
use crate::runtime::{packaged_sidecar_path, run_capture};

mod classify;

use classify::{
    GenerationFailure, RecipientFailure, classify_generation, classify_recipient, parse_recipients,
};

pub(crate) const AGE_KEYGEN_VERSION: (u64, u64, u64) = (1, 3, 1);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub(crate) struct AgeKeygenBinary {
    path: PathBuf,
}

impl AgeKeygenBinary {
    pub(crate) fn discover(gitveil_binary: &Path) -> Result<Self> {
        let packaged = packaged_sidecar_path(gitveil_binary, "age-keygen")?;
        let path = if let Some(configured) = std::env::var_os("AGE_KEYGEN_BIN") {
            let configured = PathBuf::from(configured);
            if configured.as_os_str().is_empty() {
                return Err(GitveilError::dependency("AGE_KEYGEN_BIN cannot be empty"));
            }
            if !configured.is_file() {
                return Err(GitveilError::dependency(format!(
                    "AGE_KEYGEN_BIN does not point to a file: {}",
                    configured.display()
                )));
            }
            configured
        } else if packaged.is_file() {
            packaged
        } else {
            return Err(GitveilError::dependency(format!(
                "packaged age-keygen sidecar was not found at {}; reinstall Gitveil",
                packaged.display()
            )));
        };
        let binary = Self { path };
        binary.verify_version()?;
        Ok(binary)
    }

    pub(crate) fn generate(&self, output: &Path) -> Result<()> {
        let mut command = Command::new(&self.path);
        command.arg("-o").arg(output);
        let result = run_capture(command, None, PROCESS_TIMEOUT, "age-keygen")?;
        if !result.status.success() {
            let error = match classify_generation(result.stderr.as_slice()) {
                GenerationFailure::NoSpace => GitveilError::new(
                    ErrorCategory::Io,
                    "age-keygen could not write the identity: no space left on device",
                ),
                GenerationFailure::PermissionDenied => GitveilError::new(
                    ErrorCategory::Io,
                    "age-keygen could not write the identity: permission denied",
                ),
                GenerationFailure::ReadOnlyFilesystem => GitveilError::new(
                    ErrorCategory::Io,
                    "age-keygen could not write the identity: read-only file system",
                ),
                GenerationFailure::OutputIo => GitveilError::new(
                    ErrorCategory::Io,
                    "age-keygen could not write the identity: input/output failure",
                ),
                GenerationFailure::Execution => {
                    process_exit_error("age-keygen identity generation failed", result.status)
                }
            };
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn recipients(&self, identity: &Path) -> Result<Vec<AgeRecipient>> {
        let mut command = Command::new(&self.path);
        command.arg("-y").arg(identity);
        let output = run_capture(command, None, PROCESS_TIMEOUT, "age-keygen")?;
        if !output.status.success() {
            let error = match classify_recipient(output.stderr.as_slice()) {
                RecipientFailure::IdentityUnavailable => GitveilError::new(
                    ErrorCategory::IdentityUnavailable,
                    "age-keygen could not derive recipients from the selected identity file",
                ),
                RecipientFailure::InvalidIdentity => GitveilError::new(
                    ErrorCategory::IdentityUnavailable,
                    "selected identity file is not a valid native age identity",
                ),
                RecipientFailure::Protocol => GitveilError::new(
                    ErrorCategory::Protocol,
                    "age-keygen could not represent a native identity as a public recipient",
                ),
                RecipientFailure::Execution => {
                    process_exit_error("age-keygen recipient derivation failed", output.status)
                }
            };
            return Err(error);
        }
        parse_recipients(output.stdout.as_slice())
    }

    fn verify_version(&self) -> Result<()> {
        let mut command = Command::new(&self.path);
        command.arg("--version");
        let output = run_capture(command, None, Duration::from_secs(15), "age-keygen")
            .map_err(classify_dependency_process_error)?;
        if !output.status.success() {
            return Err(GitveilError::dependency(format!(
                "age-keygen version check failed {}",
                exit_status_description(output.status)
            )));
        }
        let stdout = std::str::from_utf8(output.stdout.as_slice())
            .map_err(|_| GitveilError::dependency("age-keygen version output is not UTF-8"))?;
        let token = stdout
            .split_whitespace()
            .find(|token| {
                token
                    .trim_start_matches('v')
                    .chars()
                    .next()
                    .is_some_and(|value| value.is_ascii_digit())
            })
            .ok_or_else(|| GitveilError::dependency("age-keygen version output is unrecognized"))?;
        let version = Version::parse(token.trim_start_matches('v'))
            .map_err(|_| GitveilError::dependency("age-keygen version output is unrecognized"))?;
        if version
            != Version::new(
                AGE_KEYGEN_VERSION.0,
                AGE_KEYGEN_VERSION.1,
                AGE_KEYGEN_VERSION.2,
            )
        {
            return Err(GitveilError::dependency(format!(
                "unsupported age-keygen version {version}; required {}.{}.{}",
                AGE_KEYGEN_VERSION.0, AGE_KEYGEN_VERSION.1, AGE_KEYGEN_VERSION.2
            )));
        }
        Ok(())
    }
}

fn process_exit_error(operation: &str, status: ExitStatus) -> GitveilError {
    GitveilError::new(
        ErrorCategory::Process,
        format!("{operation} {}", exit_status_description(status)),
    )
}

fn exit_status_description(status: ExitStatus) -> String {
    status.code().map_or_else(
        || "after termination by signal".to_owned(),
        |code| format!("with exit code {code}"),
    )
}

fn classify_dependency_process_error(_error: GitveilError) -> GitveilError {
    GitveilError::dependency("age-keygen dependency version check could not be completed")
}

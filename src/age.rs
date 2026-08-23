use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use semver::Version;

use crate::error::{ErrorCategory, GitveilError, Result};
use crate::recipient::AgeRecipient;
use crate::runtime::{packaged_sidecar_path, run_capture};

pub(crate) const AGE_KEYGEN_VERSION: (u64, u64, u64) = (1, 3, 1);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub(crate) struct AgeKeygenBinary {
    path: PathBuf,
}

impl AgeKeygenBinary {
    pub(crate) fn discover(gitveil_binary: &Path) -> Result<Self> {
        let packaged = packaged_sidecar_path(gitveil_binary, "age-keygen")?;
        let path = std::env::var_os("AGE_KEYGEN_BIN")
            .map(PathBuf::from)
            .or_else(|| packaged.is_file().then_some(packaged.clone()))
            .ok_or_else(|| {
                GitveilError::dependency(format!(
                    "packaged age-keygen sidecar was not found at {}; reinstall Gitveil",
                    packaged.display()
                ))
            })?;
        let binary = Self { path };
        binary.verify_version()?;
        Ok(binary)
    }

    pub(crate) fn generate(&self, output: &Path) -> Result<()> {
        let mut command = Command::new(&self.path);
        command.arg("-o").arg(output);
        let result = run_capture(command, None, PROCESS_TIMEOUT, "age-keygen")?;
        if !result.status.success() {
            return Err(GitveilError::new(
                ErrorCategory::Process,
                "age-keygen identity generation failed",
            ));
        }
        Ok(())
    }

    pub(crate) fn recipients(&self, identity: &Path) -> Result<Vec<AgeRecipient>> {
        let mut command = Command::new(&self.path);
        command.arg("-y").arg(identity);
        let output = run_capture(command, None, PROCESS_TIMEOUT, "age-keygen")?;
        if !output.status.success() {
            return Err(GitveilError::new(
                ErrorCategory::IdentityUnavailable,
                "age-keygen could not derive recipients from the identity file",
            ));
        }
        let stdout = std::str::from_utf8(output.stdout.as_slice()).map_err(|_| {
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

    fn verify_version(&self) -> Result<()> {
        let mut command = Command::new(&self.path);
        command.arg("--version");
        let output = run_capture(command, None, Duration::from_secs(15), "age-keygen")?;
        if !output.status.success() {
            return Err(GitveilError::dependency(
                "age-keygen version check failed with a non-zero exit code",
            ));
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

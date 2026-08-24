use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use semver::Version;

use crate::error::{GitveilError, Result};
use crate::runtime::{packaged_sidecar_path, run_capture};

use super::client::SOPS_VERSION;

#[derive(Clone, Debug)]
pub(crate) struct SopsBinary {
    path: PathBuf,
}

impl SopsBinary {
    pub(crate) fn discover(explicit: Option<PathBuf>, gitveil_binary: &Path) -> Result<Self> {
        let packaged = packaged_sidecar_path(gitveil_binary, "sops")?;
        let path = explicit
            .or_else(|| std::env::var_os("SOPS_BIN").map(PathBuf::from))
            .or_else(|| packaged.is_file().then_some(packaged.clone()))
            .ok_or_else(|| {
                GitveilError::dependency(format!(
                    "packaged SOPS sidecar was not found at {}; reinstall Gitveil",
                    packaged.display()
                ))
            })?;
        let binary = Self { path };
        binary.verify_version()?;
        Ok(binary)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn verify_version(&self) -> Result<()> {
        let mut command = Command::new(&self.path);
        command.arg("--disable-version-check").arg("--version");
        let output = run_capture(command, None, Duration::from_secs(15), "SOPS")?;
        if !output.status.success() {
            return Err(GitveilError::dependency(
                "SOPS version check failed with a non-zero exit code",
            ));
        }
        let stdout = std::str::from_utf8(output.stdout.as_slice())
            .map_err(|_| GitveilError::dependency("SOPS version output is not UTF-8"))?;
        let token = stdout
            .split_whitespace()
            .find(|token| {
                token
                    .chars()
                    .next()
                    .is_some_and(|value| value.is_ascii_digit())
            })
            .ok_or_else(|| GitveilError::dependency("SOPS version output is unrecognized"))?;
        let version = Version::parse(token.trim_start_matches('v'))
            .map_err(|_| GitveilError::dependency("SOPS version output is unrecognized"))?;
        if version != Version::new(SOPS_VERSION.0, SOPS_VERSION.1, SOPS_VERSION.2) {
            return Err(GitveilError::dependency(format!(
                "unsupported SOPS version {version}; required {}.{}.{}",
                SOPS_VERSION.0, SOPS_VERSION.1, SOPS_VERSION.2
            )));
        }
        Ok(())
    }
}

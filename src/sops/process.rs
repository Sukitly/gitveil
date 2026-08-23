use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

use semver::Version;
use wait_timeout::ChildExt;

use crate::error::{ErrorCategory, GitveilError, Result, SecretBytes};

use super::client::SOPS_VERSION;

#[derive(Clone, Debug)]
pub(crate) struct SopsBinary {
    path: PathBuf,
}

impl SopsBinary {
    pub(crate) fn discover(explicit: Option<PathBuf>, gitveil_binary: &Path) -> Result<Self> {
        let packaged = packaged_sops_path(gitveil_binary)?;
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
        let output = run_capture(command, None, Duration::from_secs(15))?;
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

pub(crate) struct ProcessOutput {
    pub status: ExitStatus,
    pub stdout: SecretBytes,
    pub stderr: SecretBytes,
}

pub(crate) fn run_capture(
    mut command: Command,
    input: Option<&SecretBytes>,
    timeout: Duration,
) -> Result<ProcessOutput> {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        GitveilError::new(
            ErrorCategory::Process,
            format!("could not start SOPS process: {}", error.kind()),
        )
    })?;
    let stdin_writer = if let Some(input) = input {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| GitveilError::new(ErrorCategory::Process, "SOPS stdin unavailable"))?;
        let input = SecretBytes::new(input.as_slice().to_vec());
        Some(thread::spawn(move || stdin.write_all(input.as_slice())))
    } else {
        None
    };
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| GitveilError::new(ErrorCategory::Process, "SOPS stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| GitveilError::new(ErrorCategory::Process, "SOPS stderr unavailable"))?;
    let stdout_reader = thread::spawn(move || read_all(stdout));
    let stderr_reader = thread::spawn(move || read_all(stderr));
    let (status, timed_out) = wait_for_child(&mut child, timeout)?;
    let stdin_result = join_stdin_writer(stdin_writer);
    let stdout = join_secret_reader(stdout_reader, "stdout")?;
    let stderr = join_secret_reader(stderr_reader, "stderr")?;
    if timed_out {
        return Err(GitveilError::new(
            ErrorCategory::Process,
            "SOPS process timed out",
        ));
    }
    if status.success() {
        stdin_result?;
    }
    Ok(ProcessOutput {
        status,
        stdout,
        stderr,
    })
}

fn wait_for_child(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<(ExitStatus, bool)> {
    let status = child.wait_timeout(timeout).map_err(|error| {
        GitveilError::new(
            ErrorCategory::Process,
            format!("could not wait for SOPS process: {}", error.kind()),
        )
    })?;
    if let Some(status) = status {
        return Ok((status, false));
    }
    let _ = child.kill();
    let status = child.wait().map_err(|error| {
        GitveilError::new(
            ErrorCategory::Process,
            format!("could not reap SOPS process: {}", error.kind()),
        )
    })?;
    Ok((status, true))
}

fn join_stdin_writer(
    writer: Option<thread::JoinHandle<std::io::Result<()>>>,
) -> Result<Option<()>> {
    writer
        .map(|writer| {
            writer
                .join()
                .map_err(|_| GitveilError::new(ErrorCategory::Process, "SOPS stdin writer failed"))?
                .map_err(|error| {
                    GitveilError::new(
                        ErrorCategory::Process,
                        format!("could not write SOPS input: {}", error.kind()),
                    )
                })
        })
        .transpose()
}

fn join_secret_reader(
    reader: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream: &str,
) -> Result<SecretBytes> {
    reader
        .join()
        .map_err(|_| {
            GitveilError::new(
                ErrorCategory::Process,
                format!("SOPS {stream} reader failed"),
            )
        })?
        .map(SecretBytes::new)
        .map_err(|error| {
            GitveilError::new(
                ErrorCategory::Process,
                format!("could not read SOPS {stream}: {}", error.kind()),
            )
        })
}

fn read_all(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn packaged_sops_path(gitveil_binary: &Path) -> Result<PathBuf> {
    let bin = gitveil_binary.parent().ok_or_else(|| {
        GitveilError::dependency("Gitveil executable has no installation directory")
    })?;
    let prefix = bin
        .parent()
        .ok_or_else(|| GitveilError::dependency("Gitveil executable has no installation prefix"))?;
    Ok(prefix.join("libexec").join("gitveil").join("sops"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::packaged_sops_path;

    #[test]
    fn sidecar_path_is_resolved_from_the_install_prefix() {
        assert_eq!(
            packaged_sops_path(Path::new("/opt/gitveil/bin/gitveil")).expect("path"),
            Path::new("/opt/gitveil/libexec/gitveil/sops")
        );
    }
}

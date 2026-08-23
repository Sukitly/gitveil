use std::io::{Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

use wait_timeout::ChildExt;

use crate::error::{ErrorCategory, GitveilError, Result, SecretBytes};

pub(crate) struct ProcessOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: SecretBytes,
    pub(crate) stderr: SecretBytes,
}

pub(crate) fn run_capture(
    mut command: Command,
    input: Option<&SecretBytes>,
    timeout: Duration,
    program: &'static str,
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
            format!("could not start {program} process: {}", error.kind()),
        )
    })?;
    let stdin_writer = if let Some(input) = input {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            GitveilError::new(
                ErrorCategory::Process,
                format!("{program} stdin unavailable"),
            )
        })?;
        let input = SecretBytes::new(input.as_slice().to_vec());
        Some(thread::spawn(move || stdin.write_all(input.as_slice())))
    } else {
        None
    };
    let stdout = child.stdout.take().ok_or_else(|| {
        GitveilError::new(
            ErrorCategory::Process,
            format!("{program} stdout unavailable"),
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        GitveilError::new(
            ErrorCategory::Process,
            format!("{program} stderr unavailable"),
        )
    })?;
    let stdout_reader = thread::spawn(move || read_all(stdout));
    let stderr_reader = thread::spawn(move || read_all(stderr));
    let (status, timed_out) = wait_for_child(&mut child, timeout, program)?;
    let stdin_result = join_stdin_writer(stdin_writer, program);
    let stdout = join_secret_reader(stdout_reader, "stdout", program)?;
    let stderr = join_secret_reader(stderr_reader, "stderr", program)?;
    if timed_out {
        return Err(GitveilError::new(
            ErrorCategory::Process,
            format!("{program} process timed out"),
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
    program: &'static str,
) -> Result<(ExitStatus, bool)> {
    let status = child.wait_timeout(timeout).map_err(|error| {
        GitveilError::new(
            ErrorCategory::Process,
            format!("could not wait for {program} process: {}", error.kind()),
        )
    })?;
    if let Some(status) = status {
        return Ok((status, false));
    }
    let _ = child.kill();
    let status = child.wait().map_err(|error| {
        GitveilError::new(
            ErrorCategory::Process,
            format!("could not reap {program} process: {}", error.kind()),
        )
    })?;
    Ok((status, true))
}

fn join_stdin_writer(
    writer: Option<thread::JoinHandle<std::io::Result<()>>>,
    program: &'static str,
) -> Result<Option<()>> {
    writer
        .map(|writer| {
            writer
                .join()
                .map_err(|_| {
                    GitveilError::new(
                        ErrorCategory::Process,
                        format!("{program} stdin writer failed"),
                    )
                })?
                .map_err(|error| {
                    GitveilError::new(
                        ErrorCategory::Process,
                        format!("could not write {program} input: {}", error.kind()),
                    )
                })
        })
        .transpose()
}

fn join_secret_reader(
    reader: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream: &str,
    program: &'static str,
) -> Result<SecretBytes> {
    reader
        .join()
        .map_err(|_| {
            GitveilError::new(
                ErrorCategory::Process,
                format!("{program} {stream} reader failed"),
            )
        })?
        .map(SecretBytes::new)
        .map_err(|error| {
            GitveilError::new(
                ErrorCategory::Process,
                format!("could not read {program} {stream}: {}", error.kind()),
            )
        })
}

fn read_all(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

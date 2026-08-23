use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroize;

use super::classify::{SopsFailure, classify};
use super::process::SopsBinary;
use crate::config::SourceFormat;
use crate::envelope::DecryptedEnvelope;
use crate::error::{ErrorCategory, GitveilError, Result, SecretBytes};
use crate::path::ManagedPath;
use crate::recipient::{AgeRecipient, AgeRecipientPolicy};
use crate::runtime::{
    ClosedRuntimeFile, EditorEndpoint, PrivateRuntime, receive_editor_payload, reject_editor_reuse,
};
use crate::runtime::{ProcessOutput, run_capture};

pub const SOPS_VERSION: (u64, u64, u64) = (3, 13, 3);
const PROCESS_TIMEOUT: Duration = Duration::from_mins(1);
const EDIT_TIMEOUT: Duration = Duration::from_mins(2);
#[derive(Clone, Debug)]
pub(crate) struct SopsPaths {
    pub(crate) repository: PathBuf,
    pub(crate) gitveil_binary: PathBuf,
}

pub(crate) struct SopsClient {
    binary: SopsBinary,
    paths: SopsPaths,
    runtime: PrivateRuntime,
    neutral_config: ClosedRuntimeFile,
}

impl SopsClient {
    pub(crate) fn new(
        binary: SopsBinary,
        paths: SopsPaths,
        runtime: PrivateRuntime,
    ) -> Result<Self> {
        let neutral_config = runtime.write_closed("sops-config-", b"{}\n")?;
        Ok(Self {
            binary,
            paths,
            runtime,
            neutral_config,
        })
    }

    pub(crate) fn decrypt(
        &self,
        ciphertext: &[u8],
        managed_path: &ManagedPath,
    ) -> std::result::Result<SecretBytes, SopsFailure> {
        let mut input = self
            .runtime
            .create("ciphertext-", false)
            .map_err(|_| SopsFailure::Execution)?;
        input
            .write_all(ciphertext)
            .map_err(|_| SopsFailure::Execution)?;
        let mut command = self.base_command();
        command
            .arg("--decrypt")
            .arg("--input-type")
            .arg("yaml")
            .arg("--output-type")
            .arg("yaml")
            .arg("--filename-override")
            .arg(managed_path.as_str())
            .arg(input.path());
        let output = run_capture(command, None, PROCESS_TIMEOUT, "SOPS")
            .map_err(|_| SopsFailure::Execution)?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(classify(output.stderr.as_slice()))
        }
    }

    pub(crate) fn encrypt_new(
        &self,
        desired: &SecretBytes,
        managed_path: &ManagedPath,
        policy: &AgeRecipientPolicy,
    ) -> Result<Vec<u8>> {
        let scaffold = empty_scaffold(managed_path, desired)?;
        let mut scaffold_file = self.runtime.create("scaffold-", false)?;
        scaffold_file.write_all(&scaffold)?;
        let mut command = self.base_command();
        command
            .arg("--encrypt")
            .arg("--input-type")
            .arg("yaml")
            .arg("--output-type")
            .arg("yaml")
            .arg("--encrypted-regex")
            .arg(".*")
            .arg("--age")
            .arg(render_recipients(policy))
            .arg("--filename-override")
            .arg(managed_path.as_str())
            .arg(scaffold_file.path());
        let output = run_capture(command, None, PROCESS_TIMEOUT, "SOPS")?;
        let baseline = require_success(&output, "encrypt")?;
        self.edit(&baseline, desired, managed_path)
    }

    pub(crate) fn edit(
        &self,
        baseline: &[u8],
        desired: &SecretBytes,
        managed_path: &ManagedPath,
    ) -> Result<Vec<u8>> {
        let mut ciphertext = self.runtime.create("ciphertext-edit-", false)?;
        ciphertext.write_all(baseline)?;
        let endpoint = EditorEndpoint::bind(&self.runtime)?;
        let wrapper = EditorWrapper::create(
            &self.runtime,
            &self.paths.gitveil_binary,
            endpoint.printable(),
            endpoint.token(),
        )?;
        let mut command = self.base_command();
        command
            .env("SOPS_EDITOR", wrapper.command_value())
            .env("TMPDIR", self.runtime.root())
            .env("TEMP", self.runtime.root())
            .env("TMP", self.runtime.root())
            .arg("--input-type")
            .arg("yaml")
            .arg("--output-type")
            .arg("yaml")
            .arg("--filename-override")
            .arg(managed_path.as_str())
            .arg(ciphertext.path());
        run_edit(command, &endpoint, desired)?;
        ciphertext.read_public()
    }

    pub(crate) fn rewrap(&self, baseline: &[u8], policy: &AgeRecipientPolicy) -> Result<Vec<u8>> {
        let mut ciphertext = self.runtime.create("ciphertext-updatekeys-", false)?;
        ciphertext.write_all(baseline)?;
        let config = self.runtime.write_closed(
            "updatekeys-config-",
            render_updatekeys_config(policy).as_bytes(),
        )?;
        let mut command = self.command_with_config(config.path());
        command
            .arg("updatekeys")
            .arg("--yes")
            .arg("--input-type")
            .arg("yaml")
            .arg(ciphertext.path());
        let output = run_capture(command, None, PROCESS_TIMEOUT, "SOPS")?;
        require_success(&output, "update keys")?;
        ciphertext.read_public()
    }

    fn base_command(&self) -> Command {
        self.command_with_config(self.neutral_config.path())
    }

    fn command_with_config(&self, config: &Path) -> Command {
        let mut command = Command::new(self.binary.path());
        command
            .current_dir(&self.paths.repository)
            .arg("--config")
            .arg(config)
            .env("SOPS_DISABLE_VERSION_CHECK", "1");
        command
    }
}

fn render_recipients(policy: &AgeRecipientPolicy) -> String {
    policy
        .recipients()
        .iter()
        .map(AgeRecipient::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

fn render_updatekeys_config(policy: &AgeRecipientPolicy) -> String {
    format!(
        "creation_rules:\n  - path_regex: .*\n    age: {}\n",
        render_recipients(policy)
    )
}

fn empty_scaffold(path: &ManagedPath, desired: &SecretBytes) -> Result<Vec<u8>> {
    let format = format_from_decrypted(desired.as_slice())?;
    let empty = crate::source::SourceDocument::new(
        format,
        crate::source::Node::Mapping(indexmap::IndexMap::new()),
        crate::source::Layout::new(crate::source::LineEnding::Lf, true),
    );
    let scaffold = DecryptedEnvelope::from_source(&empty)
        .and_then(|envelope| envelope.to_yaml())
        .map_err(|_| GitveilError::ciphertext(path, "could not build encrypted scaffold"))?;
    Ok(scaffold)
}

fn format_from_decrypted(input: &[u8]) -> Result<SourceFormat> {
    let text = std::str::from_utf8(input)
        .map_err(|_| GitveilError::configuration("decrypted envelope is not UTF-8"))?;
    for format in SourceFormat::ALL {
        if text
            .lines()
            .any(|line| line == format!("gitveil_v1_{}:", format.as_str()))
        {
            return Ok(format);
        }
    }
    Err(GitveilError::configuration(
        "decrypted envelope discriminator is missing",
    ))
}

fn require_success(output: &ProcessOutput, operation: &str) -> Result<Vec<u8>> {
    if output.status.success() {
        return Ok(output.stdout.copy_out());
    }
    let category = match classify(output.stderr.as_slice()) {
        SopsFailure::IdentityUnavailable => ErrorCategory::IdentityUnavailable,
        SopsFailure::Integrity => ErrorCategory::Integrity,
        SopsFailure::Configuration => ErrorCategory::Configuration,
        SopsFailure::Execution => ErrorCategory::Process,
    };
    Err(GitveilError::new(
        category,
        format!(
            "SOPS {operation} failed with exit code {}",
            output.status.code().unwrap_or(-1)
        ),
    ))
}

fn run_edit(mut command: Command, endpoint: &EditorEndpoint, desired: &SecretBytes) -> Result<()> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        GitveilError::new(
            ErrorCategory::Process,
            format!("could not start SOPS edit process: {}", error.kind()),
        )
    })?;
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
    let deadline = Instant::now() + EDIT_TIMEOUT;
    let mut delivered = false;
    let status = loop {
        if delivered {
            match reject_editor_reuse(endpoint) {
                Ok(false) => {}
                Ok(true) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = join_reader(stdout_reader, "stdout");
                    let _ = join_reader(stderr_reader, "stderr");
                    return Err(GitveilError::new(
                        ErrorCategory::Process,
                        "SOPS requested the one-time editor more than once",
                    ));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = join_reader(stdout_reader, "stdout");
                    let _ = join_reader(stderr_reader, "stderr");
                    return Err(error);
                }
            }
        } else {
            delivered = match receive_editor_payload(endpoint, desired) {
                Ok(delivered) => delivered,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = join_reader(stdout_reader, "stdout");
                    let _ = join_reader(stderr_reader, "stderr");
                    return Err(error);
                }
            };
        }
        if let Some(status) = child.try_wait().map_err(|error| {
            GitveilError::new(
                ErrorCategory::Process,
                format!("could not poll SOPS edit process: {}", error.kind()),
            )
        })? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = join_reader(stdout_reader, "stdout");
            let _ = join_reader(stderr_reader, "stderr");
            return Err(GitveilError::new(
                ErrorCategory::Process,
                "SOPS edit process timed out",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let _stdout = join_reader(stdout_reader, "stdout")?;
    let stderr = join_reader(stderr_reader, "stderr")?;
    if !status.success() || !delivered {
        let category = match classify(&stderr) {
            SopsFailure::IdentityUnavailable => ErrorCategory::IdentityUnavailable,
            SopsFailure::Integrity => ErrorCategory::Integrity,
            SopsFailure::Configuration => ErrorCategory::Configuration,
            SopsFailure::Execution => ErrorCategory::Process,
        };
        let detail = safe_editor_detail(&stderr)
            .map(|value| format!(": {value}"))
            .unwrap_or_default();
        return Err(GitveilError::new(
            category,
            format!(
                "SOPS edit failed with exit code {}{detail}",
                status.code().unwrap_or(-1)
            ),
        ));
    }
    Ok(())
}

fn safe_editor_detail(stderr: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(stderr).ok()?;
    text.lines().find_map(|line| {
        let index = line.find("gitveil: ")?;
        let detail = &line[index..];
        (detail.len() <= 512).then_some(detail)
    })
}

fn read_all(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn join_reader(
    reader: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream: &str,
) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| {
            GitveilError::new(
                ErrorCategory::Process,
                format!("SOPS {stream} reader failed"),
            )
        })?
        .map_err(|error| {
            GitveilError::new(
                ErrorCategory::Process,
                format!("could not read SOPS {stream}: {}", error.kind()),
            )
        })
}

struct EditorWrapper {
    command_value: OsString,
    _file: crate::runtime::ClosedRuntimeFile,
    _token_file: crate::runtime::ClosedRuntimeFile,
}

impl EditorWrapper {
    fn create(
        runtime: &PrivateRuntime,
        gitveil_binary: &Path,
        endpoint: &str,
        token: &str,
    ) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        let token_file = {
            let mut content = format!("{token}\n");
            let file = runtime.write_closed("editor-token-", content.as_bytes());
            content.zeroize();
            file?
        };
        let script = render_editor_script(
            &gitveil_binary.to_string_lossy(),
            endpoint,
            &token_file.path().to_string_lossy(),
            &runtime.root().to_string_lossy(),
        );
        let file = runtime.write_closed("editor-wrapper-", script.as_bytes());
        let file = file?;
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o700)).map_err(|error| {
            GitveilError::io(
                "secure editor wrapper",
                Some(file.path().to_path_buf()),
                &error,
            )
        })?;
        let command_value = file.path().as_os_str().to_os_string();
        Ok(Self {
            command_value,
            _file: file,
            _token_file: token_file,
        })
    }

    fn command_value(&self) -> &OsString {
        &self.command_value
    }
}

fn render_editor_script(
    gitveil_binary: &str,
    endpoint: &str,
    token_file: &str,
    runtime: &str,
) -> String {
    format!(
        "#!/bin/sh\nexec {} sops-editor --endpoint {} --token-file {} --runtime {} \"$@\"\n",
        shell_quote(gitveil_binary),
        shell_quote(endpoint),
        shell_quote(token_file),
        shell_quote(runtime)
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::render_editor_script;

    #[test]
    fn editor_script_references_a_token_file_and_never_a_token_value() {
        let script = render_editor_script(
            "/usr/local/bin/gitveil",
            "ns:gitveil-abc",
            "/repo/.git/gitveil/editor-token-xyz",
            "/repo/.git/gitveil",
        );
        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(script.contains("--token-file '/repo/.git/gitveil/editor-token-xyz'"));
        assert!(
            !script.contains("--token '"),
            "the editor wrapper must not pass a token value on argv"
        );
    }

    #[test]
    fn editor_script_quotes_shell_metacharacters_in_paths() {
        let script = render_editor_script(
            "/tmp/it's a binary",
            "fs:/tmp/sock",
            "/tmp/token",
            "/tmp/run",
        );
        assert!(script.contains("'/tmp/it'\\''s a binary'"));
    }
}

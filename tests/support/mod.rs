use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use bech32::{Bech32, Hrp};
use gitveil::sops::SOPS_VERSION;
use tempfile::TempDir;
use wait_timeout::ChildExt;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);

/// The SOPS build that wrote ciphertext already living in user repositories.
///
/// Mirrors `COMPATIBILITY_BASELINE_VERSION` in `scripts/sops_artifacts.py`; the two
/// are held in agreement by `baseline_binary_is_exactly_the_declared_baseline`, which
/// executes the fetched binary rather than trusting either declaration.
pub const SOPS_COMPATIBILITY_BASELINE: (u64, u64, u64) = (3, 13, 2);

/// The checksum-pinned age-keygen build used by the public quickstart contract.
pub const AGE_KEYGEN_VERSION: &str = "1.3.1";

fn test_tool_sops(version: (u64, u64, u64)) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-tools")
        .join(format!("sops-{}.{}.{}", version.0, version.1, version.2))
        .join("sops")
}

pub fn sops_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("SOPS_BIN") {
        return PathBuf::from(path);
    }
    test_tool_sops(SOPS_VERSION)
}

/// Resolves the checksum-pinned age-keygen executable used by quickstart tests.
pub fn age_keygen_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("AGE_KEYGEN_BIN") {
        return PathBuf::from(path);
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-tools")
        .join(format!("age-{AGE_KEYGEN_VERSION}"))
        .join("age-keygen")
}

/// Resolves the compatibility-baseline SOPS build used to author legacy ciphertext.
pub fn sops_baseline_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("SOPS_BASELINE_BIN") {
        return PathBuf::from(path);
    }
    test_tool_sops(SOPS_COMPATIBILITY_BASELINE)
}

/// Runs a test command.
///
/// # Panics
/// Panics when the declared test dependency cannot be started.
pub fn command_output(command: &mut Command) -> Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command.spawn().unwrap_or_else(|error| {
        panic!("could not execute test dependency: {error}");
    });
    child_output(child)
}

/// Waits for a test child with a fixed deadline and reaps it on timeout.
///
/// # Panics
/// Panics without rendering argv, environment, stdin, stdout, or stderr when the deadline expires.
pub fn child_output(child: Child) -> Output {
    child_output_with_timeout(child, PROCESS_TIMEOUT)
}

/// Waits for a test child with a caller-supplied deadline.
///
/// # Panics
/// Panics without rendering argv, environment, stdin, stdout, or stderr when the deadline expires.
pub fn child_output_with_timeout(mut child: Child, timeout: Duration) -> Output {
    if child
        .wait_timeout(timeout)
        .expect("wait for test dependency")
        .is_some()
    {
        return child.wait_with_output().expect("collect test dependency");
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("test dependency exceeded its deadline");
}

pub struct GitFixture {
    root: TempDir,
    credentials: TempDir,
    home: TempDir,
    identity: PathBuf,
    recipient: String,
    binary: PathBuf,
}

impl Default for GitFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl GitFixture {
    /// Creates an isolated repository and age identity.
    ///
    /// # Panics
    /// Panics when a required filesystem or Git test fixture operation fails.
    pub fn new() -> Self {
        let root = tempfile::tempdir().expect("temp repository");
        let home = tempfile::tempdir().expect("isolated home");
        // Git may detach automatic maintenance from fixture setup commands. Disable it so
        // repository snapshots observe only the command under test, not background fixture work.
        fs::write(
            home.path().join("gitconfig"),
            b"[gc]\n\tauto = 0\n[maintenance]\n\tauto = false\n",
        )
        .expect("isolated global Git config");
        run_ok(isolated_command("git", root.path(), home.path()).args(["init", "-q"]));
        run_ok(isolated_command("git", root.path(), home.path()).args([
            "symbolic-ref",
            "HEAD",
            "refs/heads/main",
        ]));
        run_ok(isolated_command("git", root.path(), home.path()).args([
            "config",
            "user.name",
            "Gitveil Test",
        ]));
        run_ok(isolated_command("git", root.path(), home.path()).args([
            "config",
            "user.email",
            "gitveil@example.invalid",
        ]));
        let credentials = tempfile::tempdir().expect("credential directory");
        let identity = credentials.path().join("age-key.txt");
        let recipient = generate_age_identity(&identity);
        let binary = assert_cmd::cargo::cargo_bin!("gitveil").to_path_buf();
        Self {
            root,
            credentials,
            home,
            identity,
            recipient,
            binary,
        }
    }

    pub fn root(&self) -> &Path {
        self.root.path()
    }

    pub fn binary(&self) -> &Path {
        &self.binary
    }

    pub fn identity(&self) -> &Path {
        &self.identity
    }

    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    /// Adds another private identity to the fixture key file and returns its recipient.
    ///
    /// # Panics
    /// Panics when the fixture credential directory or identity cannot be read or written.
    pub fn add_identity(&self) -> String {
        self.add_identity_with_path().0
    }

    /// Adds another private identity and returns its recipient and standalone key-file path.
    ///
    /// The fixture command identity is extended with the new key, while the returned path
    /// contains only the new identity so multi-recipient tests can prove independent access.
    ///
    /// # Panics
    /// Panics when the fixture credential directory or identity cannot be read or written.
    pub fn add_identity_with_path(&self) -> (String, PathBuf) {
        let path = self.credentials.path().join(format!(
            "age-key-{}.txt",
            fs::read_dir(self.credentials.path())
                .expect("read credentials")
                .count()
        ));
        let recipient = generate_age_identity(&path);
        let mut identity = fs::read(&path).expect("read additional identity");
        let mut combined = fs::read(&self.identity).expect("read primary identity");
        combined.push(b'\n');
        combined.append(&mut identity);
        fs::write(&self.identity, &combined).expect("append additional identity");
        combined.zeroize();
        (recipient, path)
    }

    pub fn gitveil(&self) -> Command {
        let mut command = self.command_with_identity(&self.binary);
        command.env("SOPS_BIN", sops_binary());
        command
    }

    pub fn command_with_identity(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = isolated_command(program, self.root(), self.home.path());
        command.env("SOPS_AGE_KEY_FILE", &self.identity);
        command
    }

    pub fn git(&self) -> Command {
        let mut command = isolated_command("git", self.root(), self.home.path());
        command
            .env("SOPS_BIN", sops_binary())
            .env("SOPS_AGE_KEY_FILE", &self.identity);
        command
    }

    pub fn command_without_identity(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = isolated_command(program, self.root(), self.home.path());
        command.env("SOPS_BIN", sops_binary());
        command
    }

    pub fn run_gitveil(&self, args: &[&str]) -> Output {
        let mut command = self.gitveil();
        command.args(args);
        command_output(&mut command)
    }

    pub fn run_git(&self, args: &[&str]) -> Output {
        let mut command = self.git();
        command.args(args);
        command_output(&mut command)
    }

    /// Writes `.gitveilrc.json` with the given `(path, format)` entries.
    ///
    /// # Panics
    /// Panics when the manifest cannot be written.
    pub fn write_manifest(&self, entries: &[(&str, &str)]) {
        self.write_manifest_with_recipients(entries, &[self.recipient.as_str()]);
    }

    /// Writes the manifest with an explicit recipient set for the default `team` policy.
    ///
    /// # Panics
    /// Panics when the manifest cannot be serialized or written.
    pub fn write_manifest_with_recipients(&self, entries: &[(&str, &str)], recipients: &[&str]) {
        let entries = entries
            .iter()
            .map(|(path, format)| (*path, *format, None))
            .collect::<Vec<_>>();
        self.write_manifest_with_profiles_and_recipients(&entries, recipients);
    }

    /// Writes entries with optional explicit profiles and the fixture recipient.
    ///
    /// `None` deliberately omits the field so compatibility tests exercise
    /// the manifest-level `default` profile.
    ///
    /// # Panics
    /// Panics when the manifest cannot be serialized or written.
    pub fn write_manifest_with_profiles(&self, entries: &[(&str, &str, Option<&str>)]) {
        self.write_manifest_with_profiles_and_recipients(entries, &[self.recipient.as_str()]);
    }

    fn write_manifest_with_profiles_and_recipients(
        &self,
        entries: &[(&str, &str, Option<&str>)],
        recipients: &[&str],
    ) {
        let files = entries
            .iter()
            .map(|(path, format, profile)| {
                let mut entry = serde_json::json!({
                    "path": path,
                    "format": format,
                    "recipientPolicy": "team"
                });
                if let Some(profile) = profile {
                    entry["profile"] = serde_json::Value::String((*profile).to_owned());
                }
                entry
            })
            .collect::<Vec<_>>();
        let manifest = serde_json::json!({
            "version": 1,
            "recipientPolicies": {
                "team": { "age": recipients }
            },
            "files": files
        });
        fs::write(
            self.root().join(".gitveilrc.json"),
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write manifest");
    }

    /// Writes the default manifest and commits the workspace configuration.
    pub fn initialize(&self) {
        self.write_manifest(&[("secret.env", "dotenv")]);
        assert_success(self.run_git(&["add", ".gitveilrc.json"]), "git add config");
        assert_success(
            self.run_git(&["commit", "-qm", "initialize gitveil"]),
            "git commit config",
        );
    }

    /// Private baseline state directory under `.git/gitveil/`.
    pub fn state_dir(&self) -> PathBuf {
        self.root().join(".git").join("gitveil").join("state")
    }

    /// Copies the baseline state directory to a snapshot location.
    ///
    /// # Panics
    /// Panics when the snapshot cannot be created.
    pub fn snapshot_state(&self, snapshot: &Path) {
        let _ = fs::remove_dir_all(snapshot);
        fs::create_dir_all(snapshot).expect("create state snapshot");
        if let Ok(entries) = fs::read_dir(self.state_dir()) {
            for entry in entries {
                let entry = entry.expect("state entry");
                fs::copy(entry.path(), snapshot.join(entry.file_name())).expect("copy state entry");
            }
        }
    }

    /// Restores the baseline state directory from a snapshot location.
    ///
    /// # Panics
    /// Panics when the snapshot cannot be restored.
    pub fn restore_state(&self, snapshot: &Path) {
        let _ = fs::remove_dir_all(self.state_dir());
        fs::create_dir_all(self.state_dir()).expect("create state directory");
        if let Ok(entries) = fs::read_dir(snapshot) {
            for entry in entries {
                let entry = entry.expect("snapshot entry");
                fs::copy(entry.path(), self.state_dir().join(entry.file_name()))
                    .expect("restore state entry");
            }
        }
    }
}

/// Reports whether a byte haystack contains a byte needle.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Extracts the `ENC[...]` payload of one encrypted leaf from a SOPS YAML document.
///
/// # Panics
/// Panics when the document is not UTF-8 or the key has no encrypted leaf.
pub fn encrypted_leaf(document: &[u8], key: &str) -> String {
    let text = std::str::from_utf8(document).expect("ciphertext UTF-8");
    let pattern = regex::Regex::new(&format!(
        r"(?m)^\s+{}: (ENC\[[^\n]+\])$",
        regex::escape(key)
    ))
    .expect("regex");
    pattern
        .captures(text)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_owned())
        .expect("encrypted leaf")
}

/// Asserts that a test process succeeded.
///
/// # Panics
/// Panics with redacted process diagnostics when the command fails.
pub fn assert_success(output: Output, operation: &str) -> Output {
    assert!(
        output.status.success(),
        "{operation} failed with status {:?}",
        output.status.code()
    );
    output
}

/// Writes a generated age identity and returns its recipient.
///
/// # Panics
/// Panics when the test identity cannot be generated or written.
pub fn generate_age_identity(path: &Path) -> String {
    let identity = StaticSecret::random();
    let public = PublicKey::from(&identity);
    let mut secret_bytes = identity.to_bytes();
    let secret_hrp = Hrp::parse("age-secret-key-").expect("valid age secret HRP");
    let mut encoded = bech32::encode::<Bech32>(secret_hrp, &secret_bytes)
        .expect("valid age secret key")
        .to_uppercase();
    secret_bytes.zeroize();
    fs::write(path, encoded.as_bytes()).expect("write age identity");
    encoded.zeroize();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("secure age identity");
    }
    let recipient_hrp = Hrp::parse("age").expect("valid age recipient HRP");
    bech32::encode::<Bech32>(recipient_hrp, public.as_bytes()).expect("valid age recipient")
}

fn isolated_command(
    program: impl AsRef<std::ffi::OsStr>,
    current_dir: &Path,
    home: &Path,
) -> Command {
    let mut command = Command::new(program);
    command
        .current_dir(current_dir)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", home.join("gitconfig"));
    for variable in ["SOPS_AGE_KEY", "SOPS_AGE_KEY_FILE", "SOPS_AGE_KEY_CMD"] {
        command.env_remove(variable);
    }
    command
}

fn run_ok(command: &mut Command) {
    let output = command_output(command);
    assert!(output.status.success(), "test setup command failed");
}

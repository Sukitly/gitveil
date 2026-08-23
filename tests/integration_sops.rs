pub mod support;

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use gitveil::sops::SOPS_VERSION;
use tempfile::TempDir;

use support::{
    SOPS_COMPATIBILITY_BASELINE, child_output, command_output, encrypted_leaf,
    generate_age_identity, sops_baseline_binary, sops_binary,
};

fn reported_version(binary: &Path) -> String {
    let output = command_output(Command::new(binary).arg("--version"));
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("version output is UTF-8");
    stdout
        .lines()
        .next()
        .expect("version output has a first line")
        .to_owned()
}

#[test]
fn pinned_sops_version_is_exactly_supported_version() {
    let expected = format!("{}.{}.{}", SOPS_VERSION.0, SOPS_VERSION.1, SOPS_VERSION.2);
    assert!(reported_version(&sops_binary()).contains(&expected));
}

#[test]
fn baseline_binary_is_exactly_the_declared_baseline() {
    let expected = format!(
        "{}.{}.{}",
        SOPS_COMPATIBILITY_BASELINE.0, SOPS_COMPATIBILITY_BASELINE.1, SOPS_COMPATIBILITY_BASELINE.2
    );
    assert!(reported_version(&sops_baseline_binary()).contains(&expected));
    assert_ne!(
        SOPS_COMPATIBILITY_BASELINE, SOPS_VERSION,
        "the baseline must differ from the pinned sidecar or the suite proves nothing"
    );
}

#[test]
fn edit_reencrypts_only_changed_leaf_and_updates_mac() {
    assert_edit_preserves_unchanged_leaves(&sops_binary());
}

/// The upgrade path users actually take: every ciphertext in their repository was
/// written by the previous sidecar, and the first `seal` after upgrading edits it
/// with the new one. Authoring the fixture with the pinned binary would never
/// exercise that transition, so the leaf stability contract would go unverified
/// exactly where a sidecar bump can break it.
#[test]
fn edit_preserves_leaves_written_by_the_compatibility_baseline() {
    assert_edit_preserves_unchanged_leaves(&sops_baseline_binary());
}

fn assert_edit_preserves_unchanged_leaves(authoring_binary: &Path) {
    let fixture = SopsFixture::new();
    let plaintext = b"gitveil_v1_dotenv:\n  data:\n    A: one\n    B: two\n  layout: layout\n";
    let before = fixture.encrypt_with(authoring_binary, plaintext, "secret.env");
    let encrypted_path = fixture.root.path().join("secret.sops.yaml");
    fs::write(&encrypted_path, &before).expect("write encrypted fixture");
    let editor = fixture.editor("one", "changed");

    let output = command_output(
        Command::new(sops_binary())
            .current_dir(fixture.root.path())
            .env("SOPS_AGE_KEY_FILE", &fixture.identity)
            .env("SOPS_EDITOR", &editor)
            .arg("--input-type")
            .arg("yaml")
            .arg("--output-type")
            .arg("yaml")
            .arg("--filename-override")
            .arg("secret.env")
            .arg(&encrypted_path),
    );
    assert!(output.status.success(), "SOPS edit failed");
    let after = fs::read(&encrypted_path).expect("read edited ciphertext");

    assert_ne!(encrypted_leaf(&before, "A"), encrypted_leaf(&after, "A"));
    assert_eq!(
        encrypted_leaf(&before, "B"),
        encrypted_leaf(&after, "B"),
        "an untouched leaf must stay byte-for-byte identical"
    );
    assert_eq!(
        encrypted_leaf(&before, "layout"),
        encrypted_leaf(&after, "layout"),
        "an untouched layout leaf must stay byte-for-byte identical"
    );
    assert_ne!(field(&before, "mac"), field(&after, "mac"));
    let decrypted: yaml_serde::Value =
        yaml_serde::from_slice(&fixture.decrypt(&after)).expect("decrypted YAML");
    let expected: yaml_serde::Value =
        yaml_serde::from_slice(&plaintext.replace(b"one", b"changed")).expect("expected YAML");
    assert!(decrypted == expected, "decrypted semantics mismatch");
}

struct SopsFixture {
    root: TempDir,
    identity: std::path::PathBuf,
    recipient: String,
}

impl SopsFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let identity = root.path().join("age-key.txt");
        let recipient = generate_age_identity(&identity);
        Self {
            root,
            identity,
            recipient,
        }
    }

    fn encrypt_with(&self, binary: &Path, plaintext: &[u8], filename: &str) -> Vec<u8> {
        let mut child = Command::new(binary)
            .current_dir(self.root.path())
            .arg("--encrypt")
            .arg("--input-type")
            .arg("yaml")
            .arg("--output-type")
            .arg("yaml")
            .arg("--encrypted-regex")
            .arg(".*")
            .arg("--age")
            .arg(&self.recipient)
            .arg("--filename-override")
            .arg(filename)
            .arg(stdin_path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn SOPS");
        child
            .stdin
            .take()
            .expect("SOPS stdin")
            .write_all(plaintext)
            .expect("write plaintext");
        let output = child_output(child);
        assert!(output.status.success(), "SOPS encrypt failed");
        output.stdout
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let path = self.root.path().join("decrypt.sops.yaml");
        fs::write(&path, ciphertext).expect("write decrypt input");
        let output = command_output(
            Command::new(sops_binary())
                .env("SOPS_AGE_KEY_FILE", &self.identity)
                .arg("--decrypt")
                .arg("--input-type")
                .arg("yaml")
                .arg("--output-type")
                .arg("yaml")
                .arg(&path),
        );
        assert!(output.status.success(), "SOPS decrypt failed");
        output.stdout
    }

    fn editor(&self, from: &str, to: &str) -> std::path::PathBuf {
        let path = self.root.path().join("editor");
        let script = format!(
            "#!/usr/bin/env python3\nimport pathlib, sys\np = pathlib.Path(sys.argv[1])\ns = p.read_text()\np.write_text(s.replace({from:?}, {to:?}))\n"
        );
        fs::write(&path, script).expect("write editor");
        make_executable(&path);
        path
    }
}

fn stdin_path() -> &'static str {
    "/dev/stdin"
}

fn field(document: &[u8], key: &str) -> String {
    encrypted_leaf(document, key)
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("permissions");
}

trait ReplaceBytes {
    fn replace(&self, from: &[u8], to: &[u8]) -> Vec<u8>;
}

impl ReplaceBytes for [u8] {
    fn replace(&self, from: &[u8], to: &[u8]) -> Vec<u8> {
        assert!(!from.is_empty());
        let mut result = Vec::new();
        let mut remaining = self;
        while let Some(index) = remaining
            .windows(from.len())
            .position(|window| window == from)
        {
            result.extend_from_slice(&remaining[..index]);
            result.extend_from_slice(to);
            remaining = &remaining[index + from.len()..];
        }
        result.extend_from_slice(remaining);
        result
    }
}

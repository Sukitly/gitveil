pub mod support;

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use support::{
    age_keygen_binary, assert_success, child_output, command_output, generate_age_identity,
};

fn binary() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("gitveil").to_path_buf()
}

struct IdentityFixture {
    root: tempfile::TempDir,
    home: PathBuf,
    xdg: PathBuf,
}

impl IdentityFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("identity fixture");
        let home = root.path().join("home");
        let xdg = home.join("xdg");
        fs::create_dir_all(&xdg).expect("create isolated config root");
        Self { root, home, xdg }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(binary());
        command
            .current_dir(self.root.path())
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env("AGE_KEYGEN_BIN", age_keygen_binary())
            .env_remove("SOPS_AGE_KEY")
            .env_remove("SOPS_AGE_KEY_FILE")
            .env_remove("SOPS_AGE_KEY_CMD");
        command
    }

    fn default_identity(&self) -> PathBuf {
        self.xdg.join("sops/age/keys.txt")
    }
}

fn recipient_from_age_keygen(identity: &Path) -> String {
    let output = assert_success(
        command_output(Command::new(age_keygen_binary()).arg("-y").arg(identity)),
        "derive recipient independently",
    );
    String::from_utf8(output.stdout)
        .expect("recipient UTF-8")
        .trim()
        .to_owned()
}

#[test]
fn generate_creates_the_default_identity_without_revealing_private_material() {
    let fixture = IdentityFixture::new();
    let output = assert_success(
        command_output(fixture.command().args(["identity", "generate"])),
        "generate identity",
    );

    let identity_path = fixture.default_identity();
    let identity = fs::read(&identity_path).expect("generated identity");
    assert!(identity.starts_with(b"# created:"));
    assert!(
        identity
            .windows(b"AGE-SECRET-KEY-".len())
            .any(|value| value == b"AGE-SECRET-KEY-")
    );
    assert_eq!(
        fs::metadata(&identity_path)
            .expect("identity metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(identity_path.parent().expect("identity parent"))
            .expect("identity parent metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(
        !output
            .stdout
            .windows(identity.len())
            .any(|value| value == identity)
    );
    assert!(
        !output
            .stderr
            .windows(identity.len())
            .any(|value| value == identity)
    );

    let recipient = recipient_from_age_keygen(&identity_path);
    let stdout = String::from_utf8(output.stdout).expect("generate output UTF-8");
    assert!(stdout.contains(&format!(
        "created age identity at {}",
        identity_path.display()
    )));
    assert!(stdout.contains(&format!("recipient: {recipient}")));
}

#[test]
fn generation_uses_the_platform_sops_path_when_xdg_is_unset() {
    let fixture = IdentityFixture::new();
    let mut command = fixture.command();
    command.env_remove("XDG_CONFIG_HOME");
    assert_success(
        command_output(command.args(["identity", "generate"])),
        "generate platform-default identity",
    );

    #[cfg(target_os = "macos")]
    let identity = fixture
        .home
        .join("Library/Application Support/sops/age/keys.txt");
    #[cfg(target_os = "linux")]
    let identity = fixture.home.join(".config/sops/age/keys.txt");
    assert!(identity.is_file());
    assert!(recipient_from_age_keygen(&identity).starts_with("age1"));
}

#[test]
fn recipients_uses_the_default_or_explicit_identity_and_prints_only_public_values() {
    let fixture = IdentityFixture::new();
    let default_identity = fixture.default_identity();
    fs::create_dir_all(default_identity.parent().expect("default identity parent"))
        .expect("create default identity parent");
    let default_recipient = generate_age_identity(&default_identity);

    let default_output = assert_success(
        command_output(fixture.command().args(["identity", "recipients"])),
        "derive default recipient",
    );
    assert_eq!(
        default_output.stdout,
        format!("{default_recipient}\n").as_bytes()
    );
    assert!(default_output.stderr.is_empty());

    let explicit_identity = fixture.root.path().join("explicit-identity.txt");
    let explicit_recipient = generate_age_identity(&explicit_identity);
    let explicit_output = assert_success(
        command_output(fixture.command().args([
            "identity",
            "recipients",
            "--identity",
            explicit_identity.to_str().expect("identity path UTF-8"),
        ])),
        "derive explicit recipient",
    );
    assert_eq!(
        explicit_output.stdout,
        format!("{explicit_recipient}\n").as_bytes()
    );
    let private = fs::read(explicit_identity).expect("explicit private identity");
    assert!(
        !explicit_output
            .stdout
            .windows(private.len())
            .any(|value| value == private)
    );
    assert!(
        !explicit_output
            .stderr
            .windows(private.len())
            .any(|value| value == private)
    );
}

#[test]
fn generate_honors_the_sops_identity_path_and_never_replaces_an_existing_leaf() {
    let fixture = IdentityFixture::new();
    let identity_path = fixture.root.path().join("credentials/team.txt");
    let mut command = fixture.command();
    command.env("SOPS_AGE_KEY_FILE", &identity_path);
    assert_success(
        command_output(command.args(["identity", "generate"])),
        "generate configured identity",
    );
    assert!(identity_path.is_file());

    let original = fs::read(&identity_path).expect("configured identity");
    let mut command = fixture.command();
    command.env("SOPS_AGE_KEY_FILE", &identity_path);
    let output = command_output(command.args(["identity", "generate"]));
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
    assert_eq!(
        fs::read(&identity_path).expect("preserved identity"),
        original
    );

    let symlink_path = fixture.root.path().join("identity-link.txt");
    symlink(&identity_path, &symlink_path).expect("identity symlink");
    let output = command_output(fixture.command().args([
        "identity",
        "generate",
        "--output",
        symlink_path.to_str().expect("symlink path UTF-8"),
    ]));
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        fs::read(&identity_path).expect("preserved symlink target"),
        original
    );
}

#[test]
fn concurrent_generation_publishes_exactly_one_complete_identity() {
    let fixture = IdentityFixture::new();
    let identity_path = fixture.root.path().join("concurrent/identity.txt");
    let mut first = fixture.command();
    first
        .args(["identity", "generate", "--output"])
        .arg(&identity_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut second = fixture.command();
    second
        .args(["identity", "generate", "--output"])
        .arg(&identity_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let first = first.spawn().expect("start first identity generation");
    let second = second.spawn().expect("start second identity generation");
    let outputs = [child_output(first), child_output(second)];
    assert_eq!(
        outputs
            .iter()
            .filter(|output| output.status.success())
            .count(),
        1
    );
    assert_eq!(
        outputs
            .iter()
            .filter(|output| output.status.code() == Some(1))
            .count(),
        1
    );
    assert!(identity_path.is_file());
    let recipient = recipient_from_age_keygen(&identity_path);
    assert!(recipient.starts_with("age1"));
    assert_eq!(
        fs::metadata(&identity_path)
            .expect("concurrent identity metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn generation_failure_leaves_no_identity_and_redacts_child_output() {
    let fixture = IdentityFixture::new();
    let fake = fixture.root.path().join("failing-age-keygen");
    fs::write(
        &fake,
        "#!/bin/sh\nif [ \"${1:-}\" = \"--version\" ]; then\n  printf 'v1.3.1\\n'\n  exit 0\nfi\noutput=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-o\" ]; then\n    shift\n    output=$1\n  fi\n  shift\ndone\nprintf 'AGE-SECRET-KEY-FAILURE-CANARY\\n' >\"$output\"\nprintf 'AGE-SECRET-KEY-FAILURE-CANARY\\n' >&2\nexit 9\n",
    )
    .expect("fake age-keygen");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("fake executable mode");

    let identity_path = fixture.root.path().join("failed.txt");
    let mut command = fixture.command();
    command.env("AGE_KEYGEN_BIN", &fake);
    let output = command_output(command.args([
        "identity",
        "generate",
        "--output",
        identity_path.to_str().expect("identity path UTF-8"),
    ]));
    assert_eq!(output.status.code(), Some(1));
    assert!(!identity_path.exists());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("FAILURE-CANARY"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("FAILURE-CANARY"));
    assert!(
        fs::read_dir(fixture.root.path())
            .expect("scan identity fixture")
            .all(|entry| !entry
                .expect("identity fixture entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".gitveil-identity-"))
    );
}

#[test]
fn generated_staging_symlinks_are_rejected_without_touching_their_targets() {
    let fixture = IdentityFixture::new();
    let protected = fixture.root.path().join("protected-private-material");
    fs::write(&protected, b"PROTECTED-PRIVATE-CANARY").expect("protected target");
    let fake = fixture.root.path().join("symlink-age-keygen");
    fs::write(
        &fake,
        "#!/bin/sh\nif [ \"${1:-}\" = \"--version\" ]; then\n  printf 'v1.3.1\\n'\n  exit 0\nfi\nshift\nln -s \"$PROTECTED_TARGET\" \"$1\"\n",
    )
    .expect("symlink age-keygen");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("symlink age-keygen mode");
    let identity = fixture.root.path().join("generated.txt");
    let mut command = fixture.command();
    command
        .env("AGE_KEYGEN_BIN", &fake)
        .env("PROTECTED_TARGET", &protected);
    let output = command_output(command.args([
        "identity",
        "generate",
        "--output",
        identity.to_str().expect("identity path UTF-8"),
    ]));

    assert_eq!(output.status.code(), Some(1));
    assert!(!identity.exists());
    assert_eq!(
        fs::read(&protected).expect("preserved protected target"),
        b"PROTECTED-PRIVATE-CANARY"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE-CANARY"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE-CANARY"));
}

#[test]
fn generated_staging_hard_links_are_rejected_without_touching_their_targets() {
    let fixture = IdentityFixture::new();
    let protected = fixture.root.path().join("hard-linked-private-material");
    fs::write(&protected, b"HARD-LINKED-PRIVATE-CANARY").expect("protected target");
    fs::set_permissions(&protected, fs::Permissions::from_mode(0o640))
        .expect("protected target mode");
    let fake = fixture.root.path().join("hard-link-age-keygen");
    fs::write(
        &fake,
        "#!/bin/sh\nif [ \"${1:-}\" = \"--version\" ]; then\n  printf 'v1.3.1\\n'\n  exit 0\nfi\nshift\nln \"$PROTECTED_TARGET\" \"$1\"\n",
    )
    .expect("hard-link age-keygen");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700))
        .expect("hard-link age-keygen mode");
    let identity = fixture.root.path().join("hard-link-generated.txt");
    let mut command = fixture.command();
    command
        .env("AGE_KEYGEN_BIN", &fake)
        .env("PROTECTED_TARGET", &protected);
    let output = command_output(command.args([
        "identity",
        "generate",
        "--output",
        identity.to_str().expect("identity path UTF-8"),
    ]));

    assert_eq!(output.status.code(), Some(1));
    assert!(!identity.exists());
    assert_eq!(
        fs::read(&protected).expect("preserved hard-link target"),
        b"HARD-LINKED-PRIVATE-CANARY"
    );
    assert_eq!(
        fs::metadata(&protected)
            .expect("hard-link target metadata")
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE-CANARY"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE-CANARY"));
}

#[test]
fn identity_commands_never_fall_back_to_age_keygen_on_path() {
    let fixture = IdentityFixture::new();
    let tools = fixture.root.path().join("path-tools");
    fs::create_dir(&tools).expect("create PATH tool directory");
    let marker = fixture.root.path().join("path-age-keygen-ran");
    let fake = tools.join("age-keygen");
    fs::write(
        &fake,
        format!(
            "#!/bin/sh\ntouch '{}'\nprintf 'v1.3.1\\n'\n",
            marker.display()
        ),
    )
    .expect("PATH age-keygen");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("PATH age-keygen mode");

    let mut command = fixture.command();
    command.env_remove("AGE_KEYGEN_BIN").env("PATH", &tools);
    let output = command_output(command.args(["identity", "recipients"]));
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("packaged age-keygen sidecar"));
    assert!(!marker.exists());
}

#[test]
fn identity_commands_reject_a_missing_or_wrong_version_sidecar() {
    let fixture = IdentityFixture::new();
    let missing = fixture.root.path().join("missing-age-keygen");
    let unavailable_identity = fixture.root.path().join("unavailable/identity.txt");
    let mut command = fixture.command();
    command.env("AGE_KEYGEN_BIN", &missing);
    let output = command_output(command.args([
        "identity",
        "generate",
        "--output",
        unavailable_identity.to_str().expect("identity path UTF-8"),
    ]));
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("age-keygen"));
    assert!(!unavailable_identity.exists());
    assert!(
        !unavailable_identity
            .parent()
            .expect("identity parent")
            .exists()
    );

    let wrong = fixture.root.path().join("wrong-age-keygen");
    fs::write(&wrong, "#!/bin/sh\nprintf 'v1.2.0\\n'\n").expect("wrong age-keygen");
    fs::set_permissions(&wrong, fs::Permissions::from_mode(0o700)).expect("wrong executable mode");
    let mut command = fixture.command();
    command.env("AGE_KEYGEN_BIN", &wrong);
    let output = command_output(command.args(["identity", "recipients"]));
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsupported age-keygen version 1.2.0")
    );
}

pub mod support;

use std::fs;
use std::path::{Path, PathBuf};

use gitveil::config::SourceFormat;
use gitveil::envelope::CiphertextEnvelope;
use gitveil::recipient::AgeRecipient;

use support::{GitFixture, assert_success, command_output, contains, encrypted_leaf, sops_binary};

const CANARY: &str = "gitveil-resolve-recipient-canary";

fn write(fixture: &GitFixture, path: &str, body: &str) {
    fs::write(fixture.root().join(path), body).expect("write fixture file");
}

fn read(fixture: &GitFixture, path: &str) -> Vec<u8> {
    fs::read(fixture.root().join(path)).expect("read fixture file")
}

fn state_snapshot(fixture: &GitFixture) -> Vec<(std::ffi::OsString, Vec<u8>)> {
    let mut files = fs::read_dir(fixture.state_dir())
        .expect("read state")
        .map(|entry| {
            let entry = entry.expect("state entry");
            (
                entry.file_name(),
                fs::read(entry.path()).expect("read state entry"),
            )
        })
        .collect::<Vec<_>>();
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn no_op_updatekeys_wrapper(directory: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = directory.join("sops");
    let real_sops = sops_binary().to_string_lossy().replace('\'', "'\\''");
    let script = format!(
        "#!/bin/sh\nfor argument in \"$@\"; do\n  if [ \"$argument\" = updatekeys ]; then\n    exit 0\n  fi\ndone\nexec '{real_sops}' \"$@\"\n"
    );
    fs::write(&path, script).expect("write SOPS fault wrapper");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .expect("secure SOPS fault wrapper");
    path
}

fn seal_and_commit(fixture: &GitFixture, body: &str, message: &str) {
    write(fixture, "secret.env", body);
    assert_success(fixture.run_gitveil(&["seal"]), "gitveil seal");
    assert_success(
        fixture.run_git(&["add", "secret.env.gitveil"]),
        "git add ciphertext",
    );
    assert_success(fixture.run_git(&["commit", "-qm", message]), "git commit");
}

/// Creates a merge conflict on the ciphertext file: `main` and `feature`
/// both reseal from a common base.
fn conflicted_fixture(main_body: &str, feature_body: &str) -> GitFixture {
    let fixture = GitFixture::new();
    fixture.initialize();
    seal_and_commit(&fixture, "A=base\nB=base\n", "base");
    assert_success(
        fixture.run_git(&["checkout", "-q", "-b", "feature"]),
        "create feature branch",
    );
    seal_and_commit(&fixture, feature_body, "feature change");
    assert_success(
        fixture.run_git(&["checkout", "-q", "main"]),
        "checkout main",
    );
    seal_and_commit(&fixture, main_body, "main change");
    let merge = fixture.run_git(&["merge", "--no-edit", "feature"]);
    assert!(
        !merge.status.success(),
        "resealed envelopes must conflict textually"
    );
    fixture
}

#[test]
fn different_key_conflict_resolves_into_one_merged_pair() {
    let fixture = conflicted_fixture("A=ours\nB=base\n", "A=base\nB=theirs\n");
    let ours_cipher = assert_success(
        fixture.run_git(&["show", ":2:secret.env.gitveil"]),
        "read ours stage",
    )
    .stdout;

    let resolved = assert_success(fixture.run_gitveil(&["resolve"]), "gitveil resolve");
    assert!(
        String::from_utf8_lossy(&resolved.stdout).contains("secret.env: resolved"),
        "resolve must report success"
    );
    assert_eq!(read(&fixture, "secret.env"), b"A=ours\nB=theirs\n");

    let merged_cipher = read(&fixture, "secret.env.gitveil");
    assert!(!contains(&merged_cipher, b"ours"));
    assert!(!contains(&merged_cipher, b"theirs"));
    // Keys taking the ours value keep the ours leaf ciphertext byte for byte.
    assert_eq!(
        encrypted_leaf(&merged_cipher, "A"),
        encrypted_leaf(&ours_cipher, "A")
    );
    let envelope =
        CiphertextEnvelope::parse(&merged_cipher, SourceFormat::Dotenv).expect("resolved envelope");
    assert_eq!(
        envelope.age_recipients(),
        &[AgeRecipient::new(fixture.recipient()).expect("recipient")]
    );

    // The user finishes the merge with plain git.
    assert_success(
        fixture.run_git(&["add", "secret.env.gitveil"]),
        "git add merged ciphertext",
    );
    assert_success(
        fixture.run_git(&["commit", "-qm", "merge feature"]),
        "commit merge",
    );
}

#[test]
fn resolve_rejects_successful_updatekeys_output_with_the_wrong_recipients() {
    let fixture = conflicted_fixture(
        &format!("A={CANARY}-ours\nB=base\n"),
        &format!("A=base\nB={CANARY}-theirs\n"),
    );
    let ciphertext_before = read(&fixture, "secret.env.gitveil");
    let plaintext_before = read(&fixture, "secret.env");
    let state_before = state_snapshot(&fixture);
    let index_before = assert_success(
        fixture.run_git(&["ls-files", "-u", "--", "secret.env.gitveil"]),
        "read conflicted index",
    )
    .stdout;

    // Addition-only drift keeps resolve on the updatekeys path whose output
    // this test corrupts; removals take the rotation path instead.
    let second_recipient = fixture.add_identity();
    let first_recipient = fixture.recipient().to_owned();
    fixture.write_manifest_with_recipients(
        &[("secret.env", "dotenv")],
        &[first_recipient.as_str(), second_recipient.as_str()],
    );
    let wrapper_directory = tempfile::tempdir().expect("SOPS fault wrapper directory");
    let wrapper = no_op_updatekeys_wrapper(wrapper_directory.path());
    let mut command = fixture.gitveil();
    command.env("SOPS_BIN", wrapper).arg("resolve");
    let output = command_output(&mut command);

    assert!(
        !output.status.success(),
        "wrong recipients must be rejected"
    );
    assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext_before);
    assert_eq!(read(&fixture, "secret.env"), plaintext_before);
    assert_eq!(state_snapshot(&fixture), state_before);
    let index_after = assert_success(
        fixture.run_git(&["ls-files", "-u", "--", "secret.env.gitveil"]),
        "read conflicted index after failure",
    )
    .stdout;
    assert_eq!(index_after, index_before);
    assert!(!contains(&output.stdout, CANARY.as_bytes()));
    assert!(!contains(&output.stderr, CANARY.as_bytes()));
}

// An addition-only recipient drift rewraps the merged result in place; keys
// taking the ours value keep the ours leaf bytes.
#[test]
fn resolve_rewraps_recipient_additions_with_stable_leaves() {
    let fixture = conflicted_fixture("A=ours\nB=base\n", "A=base\nB=theirs\n");
    let ours_cipher = assert_success(
        fixture.run_git(&["show", ":2:secret.env.gitveil"]),
        "read ours stage",
    )
    .stdout;

    let second = fixture.add_identity();
    let first = fixture.recipient().to_owned();
    fixture.write_manifest_with_recipients(
        &[("secret.env", "dotenv")],
        &[first.as_str(), second.as_str()],
    );

    let resolved = assert_success(fixture.run_gitveil(&["resolve"]), "gitveil resolve");
    let stdout = String::from_utf8_lossy(&resolved.stdout);
    assert!(stdout.contains("resolved"), "stdout: {stdout}");
    assert!(
        !stdout.contains("data key rotated"),
        "additions must not rotate the data key: {stdout}"
    );
    assert_eq!(read(&fixture, "secret.env"), b"A=ours\nB=theirs\n");

    let merged_cipher = read(&fixture, "secret.env.gitveil");
    let envelope = CiphertextEnvelope::parse(&merged_cipher, SourceFormat::Dotenv)
        .expect("rewrapped envelope");
    assert_eq!(envelope.age_recipients().len(), 2);
    // The same data key is kept: the ours-side leaf stays byte-for-byte.
    assert_eq!(
        encrypted_leaf(&merged_cipher, "A"),
        encrypted_leaf(&ours_cipher, "A")
    );
}

// When the policy removed a recipient, the merged result is written under a
// fresh data key and the removed identity cannot decrypt it.
#[test]
fn resolve_rotates_the_data_key_when_the_policy_removed_a_recipient() {
    let fixture = conflicted_fixture("A=ours\nB=base\n", "A=base\nB=theirs\n");
    let ours_cipher = assert_success(
        fixture.run_git(&["show", ":2:secret.env.gitveil"]),
        "read ours stage",
    )
    .stdout;

    // Snapshot the original identity alone before the fixture key file gains
    // the replacement identity.
    let removed_only = tempfile::tempdir().expect("removed identity directory");
    let removed_identity = removed_only.path().join("removed.txt");
    fs::copy(fixture.identity(), &removed_identity).expect("snapshot first identity");

    let (replacement, replacement_identity) = fixture.add_identity_with_path();
    fixture.write_manifest_with_recipients(&[("secret.env", "dotenv")], &[replacement.as_str()]);

    let resolved = assert_success(fixture.run_gitveil(&["resolve"]), "gitveil resolve");
    let stdout = String::from_utf8_lossy(&resolved.stdout);
    assert!(stdout.contains("resolved"), "stdout: {stdout}");
    assert!(
        stdout.contains("data key rotated"),
        "rotation must be reported: {stdout}"
    );
    assert_eq!(read(&fixture, "secret.env"), b"A=ours\nB=theirs\n");

    let merged_cipher = read(&fixture, "secret.env.gitveil");
    let envelope =
        CiphertextEnvelope::parse(&merged_cipher, SourceFormat::Dotenv).expect("rotated envelope");
    assert_eq!(
        envelope.age_recipients(),
        &[AgeRecipient::new(&replacement).expect("recipient")]
    );
    // A fresh data key re-encrypts every leaf, including the ours-side value.
    assert_ne!(
        encrypted_leaf(&merged_cipher, "A"),
        encrypted_leaf(&ours_cipher, "A")
    );

    // The kept identity decrypts the merged result; the removed one does not.
    let mut kept = fixture.command_without_identity(fixture.binary());
    kept.env("SOPS_AGE_KEY_FILE", &replacement_identity)
        .arg("open");
    assert_success(command_output(&mut kept), "open with the kept identity");
    let mut excluded = fixture.command_without_identity(fixture.binary());
    excluded
        .env("SOPS_AGE_KEY_FILE", &removed_identity)
        .arg("open");
    let output = command_output(&mut excluded);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the removed identity must not decrypt the merged result"
    );
}

#[test]
fn same_key_conflict_writes_markers_to_plaintext_and_normalizes_ciphertext() {
    let fixture = conflicted_fixture("A=ours-value\nB=base\n", "A=theirs-value\nB=base\n");
    let ours_cipher = assert_success(
        fixture.run_git(&["show", ":2:secret.env.gitveil"]),
        "read ours stage",
    )
    .stdout;

    let resolved = fixture.run_gitveil(&["resolve"]);
    assert_eq!(resolved.status.code(), Some(1), "conflict exits non-zero");
    let stdout = String::from_utf8_lossy(&resolved.stdout);
    assert!(stdout.contains("conflict at A"), "stdout: {stdout}");

    let plaintext = String::from_utf8(read(&fixture, "secret.env")).expect("utf-8");
    assert!(plaintext.contains("<<<<<<< ours"), "plaintext: {plaintext}");
    assert!(plaintext.contains("A=ours-value"));
    assert!(plaintext.contains("A=theirs-value"));
    assert!(plaintext.contains(">>>>>>> theirs"));

    // Working ciphertext is normalized to the valid ours side so a later
    // seal has an incremental baseline.
    assert_eq!(read(&fixture, "secret.env.gitveil"), ours_cipher);

    // The user picks a value and seals to finish.
    write(&fixture, "secret.env", "A=picked\nB=base\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal resolution");
    let sealed = read(&fixture, "secret.env.gitveil");
    assert!(!contains(&sealed, b"picked"));
    assert_success(
        fixture.run_git(&["add", "secret.env.gitveil"]),
        "git add resolution",
    );
    assert_success(
        fixture.run_git(&["commit", "-qm", "resolve conflict"]),
        "commit resolution",
    );
}

#[test]
fn resolve_without_conflicts_reports_nothing_to_do() {
    let fixture = GitFixture::new();
    fixture.initialize();
    seal_and_commit(&fixture, "A=one\n", "seal");
    let resolved = fixture.run_gitveil(&["resolve"]);
    assert_eq!(resolved.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&resolved.stderr).contains("nothing to resolve"),
        "resolve must explain there is no conflict"
    );
}

#[test]
fn open_and_seal_refuse_conflicted_ciphertext_and_point_to_resolve() {
    let fixture = conflicted_fixture("A=ours\nB=base\n", "A=base\nB=theirs\n");
    for command in [["open"], ["seal"]] {
        let output = fixture.run_gitveil(&command);
        assert_eq!(output.status.code(), Some(1), "{command:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("gitveil resolve"),
            "{command:?} must point to resolve"
        );
    }
}

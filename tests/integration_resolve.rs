pub mod support;

use std::fs;

use gitveil::config::SourceFormat;
use gitveil::envelope::CiphertextEnvelope;
use gitveil::recipient::AgeRecipient;

use support::{GitFixture, assert_success, contains, encrypted_leaf};

fn write(fixture: &GitFixture, path: &str, body: &str) {
    fs::write(fixture.root().join(path), body).expect("write fixture file");
}

fn read(fixture: &GitFixture, path: &str) -> Vec<u8> {
    fs::read(fixture.root().join(path)).expect("read fixture file")
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

// Resolve is a data command: the merged envelope keeps the ours-side
// recipient set even when the manifest policy drifted, and the remaining
// drift is reported for the authorization command to converge.
#[test]
fn resolve_preserves_ours_recipients_and_reports_policy_drift() {
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

    let resolved = fixture.run_gitveil(&["resolve"]);
    assert_eq!(
        resolved.status.code(),
        Some(1),
        "remaining drift is an attention outcome"
    );
    let stdout = String::from_utf8_lossy(&resolved.stdout);
    assert!(stdout.contains("resolved"), "stdout: {stdout}");
    assert!(
        stdout.contains("recipient drift remains"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("gitveil recipient"), "stdout: {stdout}");
    assert_eq!(read(&fixture, "secret.env"), b"A=ours\nB=theirs\n");

    // The merge changed data only: the ours-side recipient set is kept and
    // keys taking the ours value keep the ours leaf bytes.
    let merged_cipher = read(&fixture, "secret.env.gitveil");
    let envelope =
        CiphertextEnvelope::parse(&merged_cipher, SourceFormat::Dotenv).expect("merged envelope");
    assert_eq!(
        envelope.age_recipients(),
        &[AgeRecipient::new(&first).expect("recipient")]
    );
    assert_eq!(
        encrypted_leaf(&merged_cipher, "A"),
        encrypted_leaf(&ours_cipher, "A")
    );

    // The authorization command converges the reported drift.
    assert_success(
        fixture.run_gitveil(&["recipient", "add", "--recipient", second.as_str()]),
        "converge drift after resolve",
    );
    let converged = read(&fixture, "secret.env.gitveil");
    let envelope =
        CiphertextEnvelope::parse(&converged, SourceFormat::Dotenv).expect("converged envelope");
    assert_eq!(envelope.age_recipients().len(), 2);
    assert_eq!(
        encrypted_leaf(&converged, "A"),
        encrypted_leaf(&ours_cipher, "A"),
        "an addition-only convergence keeps the merged leaves"
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

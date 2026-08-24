pub mod support;

use std::fs;

use gitveil::config::SourceFormat;
use gitveil::envelope::CiphertextEnvelope;
use gitveil::recipient::AgeRecipient;

use support::{GitFixture, assert_success, command_output, contains, encrypted_leaf};

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
        fixture.run_gitveil(&["recipient", "add", second.as_str()]),
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

/// Builds a ciphertext merge conflict whose stage envelopes carry two
/// recipients, so a policy removal can be exercised against the merge.
/// Returns the fixture, the second recipient, the second-only identity
/// file, and a first-only identity file snapshot for exclusion assertions.
fn conflicted_two_recipient_fixture() -> (GitFixture, String, std::path::PathBuf, std::path::PathBuf)
{
    let fixture = GitFixture::new();
    fixture.initialize();
    seal_and_commit(&fixture, "A=base\nB=base\n", "base");
    // Snapshot the first identity alone before the fixture key file gains
    // the second identity.
    let first_only = fixture.root().join("..").join("first-only-identity.txt");
    fs::copy(fixture.identity(), &first_only).expect("snapshot first identity");
    let (second, second_identity) = fixture.add_identity_with_path();
    assert_success(
        fixture.run_gitveil(&["recipient", "add", second.as_str()]),
        "authorize the second identity",
    );
    assert_success(
        fixture.run_git(&["add", ".gitveilrc.json", "secret.env.gitveil"]),
        "git add converged configuration",
    );
    assert_success(
        fixture.run_git(&["commit", "-qm", "add second recipient"]),
        "commit second recipient",
    );
    assert_success(
        fixture.run_git(&["checkout", "-q", "-b", "feature"]),
        "create feature branch",
    );
    seal_and_commit(&fixture, "A=base\nB=theirs\n", "feature change");
    assert_success(
        fixture.run_git(&["checkout", "-q", "main"]),
        "checkout main",
    );
    seal_and_commit(&fixture, "A=ours\nB=base\n", "main change");
    let merge = fixture.run_git(&["merge", "--no-edit", "feature"]);
    assert!(
        !merge.status.success(),
        "resealed envelopes must conflict textually"
    );
    (fixture, second, second_identity, first_only)
}

// A policy that removed a recipient before the merge: resolve encrypts the
// merged content to the intersection of the ours envelope and the policy,
// so the removed identity never gains the merged (theirs-side) values.
#[test]
fn resolve_narrows_to_the_policy_intersection_and_excludes_removed_recipients() {
    let (fixture, second, second_identity, removed_identity) = conflicted_two_recipient_fixture();

    // The manifest drops the first recipient (pulled policy change).
    fixture.write_manifest_with_recipients(&[("secret.env", "dotenv")], &[second.as_str()]);

    let resolved = assert_success(fixture.run_gitveil(&["resolve"]), "gitveil resolve");
    let stdout = String::from_utf8_lossy(&resolved.stdout);
    assert!(
        stdout.contains("data key rotated"),
        "the narrowing must be reported: {stdout}"
    );
    assert!(
        !stdout.contains("recipient drift remains"),
        "a pure removal narrows to the full policy: {stdout}"
    );
    assert_eq!(read(&fixture, "secret.env"), b"A=ours\nB=theirs\n");

    let merged_cipher = read(&fixture, "secret.env.gitveil");
    let envelope =
        CiphertextEnvelope::parse(&merged_cipher, SourceFormat::Dotenv).expect("merged envelope");
    assert_eq!(
        envelope.age_recipients(),
        &[AgeRecipient::new(&second).expect("recipient")],
        "the removed recipient must not be on the merged envelope"
    );

    // The kept identity decrypts the merged result through the product
    // binary; the removed identity cannot: the merged theirs-side value was
    // never encrypted under a key the removed party holds.
    let mut kept = fixture.command_without_identity(fixture.binary());
    kept.env("SOPS_AGE_KEY_FILE", &second_identity).arg("open");
    assert_success(command_output(&mut kept), "open with the kept identity");
    let mut excluded = fixture.command_without_identity(fixture.binary());
    excluded
        .env("SOPS_AGE_KEY_FILE", &removed_identity)
        .arg("open");
    assert_eq!(
        command_output(&mut excluded).status.code(),
        Some(1),
        "the removed identity must not decrypt the merged result"
    );
}

// A policy with no recipient in common with the ours envelope cannot accept
// merged content anywhere safely: resolve refuses with zero side effects.
#[test]
fn resolve_refuses_a_disjoint_policy_with_zero_side_effects() {
    let fixture = conflicted_fixture("A=ours\nB=base\n", "A=base\nB=theirs\n");
    let replacement = fixture.add_identity();
    fixture.write_manifest_with_recipients(&[("secret.env", "dotenv")], &[replacement.as_str()]);
    let ciphertext_before = read(&fixture, "secret.env.gitveil");
    let plaintext_before = read(&fixture, "secret.env");
    let index_before = assert_success(
        fixture.run_git(&["ls-files", "-u", "--", "secret.env.gitveil"]),
        "read conflicted index",
    )
    .stdout;

    let output = fixture.run_gitveil(&["resolve"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("gitveil recipient"),
        "the refusal must route to the authorization command"
    );
    assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext_before);
    assert_eq!(read(&fixture, "secret.env"), plaintext_before);
    let index_after = assert_success(
        fixture.run_git(&["ls-files", "-u", "--", "secret.env.gitveil"]),
        "read conflicted index after refusal",
    )
    .stdout;
    assert_eq!(index_after, index_before);
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

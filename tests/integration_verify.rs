pub mod support;

use std::fs;

use support::{GitFixture, assert_success};

fn write(fixture: &GitFixture, path: &str, body: &str) {
    fs::write(fixture.root().join(path), body).expect("write fixture file");
}

fn committed_fixture() -> GitFixture {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal");
    assert_success(
        fixture.run_git(&["add", "secret.env.gitveil"]),
        "git add ciphertext",
    );
    assert_success(
        fixture.run_git(&["commit", "-qm", "seal secret"]),
        "git commit ciphertext",
    );
    fixture
}

#[test]
fn clean_history_verifies_with_zero_output_and_exit_zero() {
    let fixture = committed_fixture();
    let output = assert_success(fixture.run_gitveil(&["verify"]), "gitveil verify");
    assert!(
        output.stdout.is_empty(),
        "clean history must produce zero report lines"
    );
}

#[test]
fn plaintext_committed_to_history_is_reported() {
    let fixture = committed_fixture();
    assert_success(
        fixture.run_git(&["add", "-f", "secret.env"]),
        "force add plaintext",
    );
    assert_success(
        fixture.run_git(&["commit", "-qm", "accidental plaintext"]),
        "commit plaintext",
    );
    let output = fixture.run_gitveil(&["verify"]);
    assert_eq!(output.status.code(), Some(3), "history violation exits 3");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("plaintext secret.env entered this commit"),
        "stdout: {stdout}"
    );
}

#[test]
fn envelope_blobs_at_the_plaintext_path_are_not_leaks() {
    // A repository migrated from the same-path filter architecture has
    // valid envelope blobs at the plaintext path throughout its history;
    // those are ciphertext, not leaks.
    let fixture = committed_fixture();
    let envelope = fs::read(fixture.root().join("secret.env.gitveil")).expect("ciphertext");
    fs::write(fixture.root().join("secret.env"), &envelope).expect("legacy same-path blob");
    assert_success(
        fixture.run_git(&["add", "-f", "secret.env"]),
        "add legacy ciphertext",
    );
    assert_success(
        fixture.run_git(&["commit", "-qm", "legacy same-path ciphertext"]),
        "commit legacy ciphertext",
    );
    // Restore the plaintext working file.
    fs::write(fixture.root().join("secret.env"), "A=one\n").expect("restore plaintext");
    let output = assert_success(fixture.run_gitveil(&["verify"]), "gitveil verify");
    assert!(
        output.stdout.is_empty(),
        "envelope blobs at the plaintext path must not be reported: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn fake_ciphertext_blob_is_reported() {
    let fixture = committed_fixture();
    // A plaintext accidentally saved under the ciphertext name.
    write(&fixture, "secret.env.gitveil", "A=oops-plaintext\n");
    assert_success(
        fixture.run_git(&["add", "secret.env.gitveil"]),
        "add fake ciphertext",
    );
    assert_success(
        fixture.run_git(&["commit", "-qm", "fake ciphertext"]),
        "commit fake ciphertext",
    );
    let output = fixture.run_gitveil(&["verify"]);
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("secret.env.gitveil is not a valid gitveil envelope"),
        "stdout: {stdout}"
    );
}

#[test]
fn range_restricts_the_scan_and_rejects_flag_injection() {
    let fixture = committed_fixture();
    // Leak plaintext in one commit, then remove it in the next.
    assert_success(
        fixture.run_git(&["add", "-f", "secret.env"]),
        "force add plaintext",
    );
    assert_success(
        fixture.run_git(&["commit", "-qm", "accidental plaintext"]),
        "commit plaintext",
    );
    assert_success(
        fixture.run_git(&["rm", "-q", "--cached", "secret.env"]),
        "unstage plaintext",
    );
    assert_success(
        fixture.run_git(&["commit", "-qm", "remove plaintext"]),
        "commit removal",
    );

    // The removal commit also "touches" the plaintext path, so a range that
    // covers it still reports; a range before the leak is clean.
    let clean = fixture.run_gitveil(&["verify", "--range", "HEAD~2..HEAD~2"]);
    assert_eq!(clean.status.code(), Some(0));

    let invalid = fixture.run_gitveil(&["verify", "--range=--all"]);
    assert_eq!(invalid.status.code(), Some(1), "flags are not ranges");
}

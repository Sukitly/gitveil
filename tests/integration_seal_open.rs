pub mod support;

use std::fs;
use std::path::Path;
use std::process::Command;

use gitveil::config::SourceFormat;
use gitveil::envelope::CiphertextEnvelope;
use gitveil::recipient::AgeRecipient;
use sha2::{Digest, Sha256};

use support::{GitFixture, assert_success, command_output, contains, encrypted_leaf, sops_binary};

const CANARY: &str = "gitveil-secret-standalone-canary";

fn read(fixture: &GitFixture, path: &str) -> Vec<u8> {
    fs::read(fixture.root().join(path)).expect("read fixture file")
}

fn write(fixture: &GitFixture, path: &str, body: &str) {
    fs::write(fixture.root().join(path), body).expect("write fixture file");
}

fn decrypt_with_identity(identity: &Path, ciphertext: &Path) -> Vec<u8> {
    let mut command = Command::new(sops_binary());
    command
        .env("SOPS_AGE_KEY_FILE", identity)
        .arg("--disable-version-check")
        .arg("--decrypt")
        .arg("--input-type")
        .arg("yaml")
        .arg("--output-type")
        .arg("yaml")
        .arg(ciphertext);
    assert_success(command_output(&mut command), "decrypt with one identity").stdout
}

fn baseline(fixture: &GitFixture, path: &str) -> Option<Vec<u8>> {
    let digest = Sha256::digest(path.as_bytes());
    fs::read(
        fixture
            .state_dir()
            .join(format!("{}.json", hex::encode(digest))),
    )
    .ok()
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

#[test]
fn profile_selection_scopes_seal_and_open_without_touching_other_groups() {
    let fixture = GitFixture::new();
    fixture.write_manifest_with_profiles(&[
        ("dev.env", "dotenv", Some("dev")),
        ("prod.env", "dotenv", Some("prod")),
        ("shared.env", "dotenv", None),
    ]);
    write(&fixture, "dev.env", "VALUE=dev\n");
    write(&fixture, "prod.env", "VALUE=prod\n");
    write(&fixture, "shared.env", "VALUE=shared\n");

    let dev_seal = assert_success(
        fixture.run_gitveil(&["seal", "--profile", "dev"]),
        "seal dev profile",
    );
    let stdout = String::from_utf8_lossy(&dev_seal.stdout);
    assert!(stdout.contains("dev.env: sealed"), "stdout: {stdout}");
    assert!(!stdout.contains("prod.env"), "stdout: {stdout}");
    assert!(!stdout.contains("shared.env"), "stdout: {stdout}");
    assert!(fixture.root().join("dev.env.gitveil").is_file());
    assert!(!fixture.root().join("prod.env.gitveil").exists());
    assert!(!fixture.root().join("shared.env.gitveil").exists());
    assert!(baseline(&fixture, "dev.env").is_some());
    assert!(baseline(&fixture, "prod.env").is_none());
    assert!(baseline(&fixture, "shared.env").is_none());

    assert_success(
        fixture.run_gitveil(&["seal", "--profile", "prod"]),
        "seal prod profile",
    );
    let prod_ciphertext = read(&fixture, "prod.env.gitveil");
    let prod_baseline = baseline(&fixture, "prod.env").expect("prod baseline");
    write(&fixture, "prod.env", "VALUE=local-prod\n");
    fs::remove_file(fixture.root().join("dev.env")).expect("remove dev plaintext");

    let dev_open = assert_success(
        fixture.run_gitveil(&["open", "--profile", "dev"]),
        "open dev profile",
    );
    let stdout = String::from_utf8_lossy(&dev_open.stdout);
    assert!(stdout.contains("dev.env: opened"), "stdout: {stdout}");
    assert!(!stdout.contains("prod.env"), "stdout: {stdout}");
    assert_eq!(read(&fixture, "dev.env"), b"VALUE=dev\n");
    assert_eq!(read(&fixture, "prod.env"), b"VALUE=local-prod\n");
    assert_eq!(read(&fixture, "prod.env.gitveil"), prod_ciphertext);
    assert_eq!(
        baseline(&fixture, "prod.env").expect("prod baseline after dev open"),
        prod_baseline
    );

    assert_success(
        fixture.run_gitveil(&["seal", "--profile", "default"]),
        "seal default profile",
    );
    assert!(fixture.root().join("shared.env.gitveil").is_file());
}

#[test]
fn changing_profile_only_changes_selection_membership() {
    let fixture = GitFixture::new();
    fixture.write_manifest_with_profiles(&[("secret.env", "dotenv", Some("dev"))]);
    write(&fixture, "secret.env", "VALUE=one\n");
    assert_success(
        fixture.run_gitveil(&["seal", "--profile", "dev"]),
        "seal dev profile",
    );
    let ciphertext = read(&fixture, "secret.env.gitveil");
    let original_baseline = baseline(&fixture, "secret.env").expect("baseline");

    fixture.write_manifest_with_profiles(&[("secret.env", "dotenv", Some("prod"))]);
    let status = assert_success(
        fixture.run_gitveil(&["status", "--profile", "prod"]),
        "status reassigned profile",
    );
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("secret.env: clean"),
        "status must find the pair through its new profile"
    );
    assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext);
    assert_eq!(
        baseline(&fixture, "secret.env").expect("baseline after profile change"),
        original_baseline
    );
}

#[test]
fn profile_and_paths_form_an_atomic_constrained_intersection() {
    let fixture = GitFixture::new();
    fixture.write_manifest_with_profiles(&[
        ("dev-a.env", "dotenv", Some("dev")),
        ("dev-b.env", "dotenv", Some("dev")),
        ("prod.env", "dotenv", Some("prod")),
    ]);
    write(&fixture, "dev-a.env", "A=one\n");
    write(&fixture, "dev-b.env", "B=two\n");
    write(&fixture, "prod.env", "P=three\n");

    let mismatch = fixture.run_gitveil(&["seal", "--profile", "dev", "dev-a.env", "prod.env"]);
    assert_eq!(mismatch.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&mismatch.stderr);
    assert!(stderr.contains("prod.env"), "stderr: {stderr}");
    assert!(stderr.contains("dev"), "stderr: {stderr}");
    assert!(!fixture.root().join("dev-a.env.gitveil").exists());
    assert!(!fixture.root().join("prod.env.gitveil").exists());

    let subset = assert_success(
        fixture.run_gitveil(&["seal", "--profile", "dev", "dev-b.env"]),
        "seal dev subset",
    );
    let stdout = String::from_utf8_lossy(&subset.stdout);
    assert!(stdout.contains("dev-b.env: sealed"), "stdout: {stdout}");
    assert!(!stdout.contains("dev-a.env"), "stdout: {stdout}");
    assert!(fixture.root().join("dev-b.env.gitveil").is_file());
    assert!(!fixture.root().join("dev-a.env.gitveil").exists());

    let unknown = fixture.run_gitveil(&["seal", "--profile", "staging"]);
    assert_eq!(unknown.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("staging"),
        "unknown profile must be named"
    );
}

#[test]
fn seal_creates_a_valid_envelope_without_plaintext_and_is_idempotent() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(
        &fixture,
        "secret.env",
        &format!("# first comment\nA={CANARY}\nB=stable\n"),
    );
    let sealed = assert_success(fixture.run_gitveil(&["seal"]), "gitveil seal");
    assert!(String::from_utf8_lossy(&sealed.stdout).contains("secret.env: sealed"));

    let ciphertext = read(&fixture, "secret.env.gitveil");
    CiphertextEnvelope::parse(&ciphertext, SourceFormat::Dotenv).expect("valid envelope");
    assert!(!contains(&ciphertext, CANARY.as_bytes()));
    assert!(!contains(&ciphertext, b"first comment"));

    // Idempotence: sealing an unchanged plaintext is byte-stable (B8).
    let again = assert_success(fixture.run_gitveil(&["seal"]), "gitveil seal again");
    assert!(String::from_utf8_lossy(&again.stdout).contains("secret.env: unchanged"));
    assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext);
}

#[test]
fn seal_uses_manifest_recipients_without_a_repository_sops_config() {
    let fixture = GitFixture::new();
    fixture.initialize();
    let standalone_identities = tempfile::tempdir().expect("standalone identities");
    let first_identity = standalone_identities.path().join("first-age-key.txt");
    fs::copy(fixture.identity(), &first_identity).expect("copy first identity");
    let (second, second_identity) = fixture.add_identity_with_path();
    let first = fixture.recipient().to_owned();
    fixture.write_manifest_with_recipients(
        &[("secret.env", "dotenv")],
        &[first.as_str(), second.as_str()],
    );
    write(&fixture, "secret.env", "A=one\n");

    assert_success(fixture.run_gitveil(&["seal"]), "seal with two recipients");
    assert!(!fixture.root().join(".sops.yaml").exists());
    let ciphertext = read(&fixture, "secret.env.gitveil");
    let envelope =
        CiphertextEnvelope::parse(&ciphertext, SourceFormat::Dotenv).expect("valid envelope");
    let mut actual = envelope
        .age_recipients()
        .iter()
        .map(AgeRecipient::as_str)
        .collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = vec![first.as_str(), second.as_str()];
    expected.sort_unstable();
    assert_eq!(actual, expected);

    let ciphertext_path = fixture.root().join("secret.env.gitveil");
    let first_decrypted = decrypt_with_identity(&first_identity, &ciphertext_path);
    let second_decrypted = decrypt_with_identity(&second_identity, &ciphertext_path);
    assert_eq!(first_decrypted, second_decrypted);

    fixture.write_manifest_with_recipients(
        &[("secret.env", "dotenv")],
        &[second.as_str(), first.as_str()],
    );
    let unchanged = assert_success(fixture.run_gitveil(&["seal"]), "recipient order only");
    assert!(String::from_utf8_lossy(&unchanged.stdout).contains("unchanged"));
    assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext);
}

#[test]
fn repository_sops_config_is_ignored_even_when_it_is_invalid() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, ".sops.yaml", "this: [is not valid YAML\n");
    write(&fixture, "secret.env", "A=one\n");

    assert_success(
        fixture.run_gitveil(&["seal"]),
        "seal ignores repository config",
    );
    fs::remove_file(fixture.root().join("secret.env")).expect("remove plaintext");
    assert_success(
        fixture.run_gitveil(&["open"]),
        "open ignores repository config",
    );
    assert_eq!(read(&fixture, "secret.env"), b"A=one\n");
}

#[test]
fn seal_fails_closed_on_recipient_drift_in_both_directions() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\nB=stable\n");
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let ciphertext = read(&fixture, "secret.env.gitveil");
    let plaintext = read(&fixture, "secret.env");
    let state = state_snapshot(&fixture);

    let second = fixture.add_identity();
    let first = fixture.recipient().to_owned();
    for recipients in [
        vec![first.as_str(), second.as_str()], // addition direction
        vec![second.as_str()],                 // removal direction
    ] {
        fixture.write_manifest_with_recipients(&[("secret.env", "dotenv")], &recipients);
        let output = fixture.run_gitveil(&["seal"]);
        assert_eq!(output.status.code(), Some(1), "seal must fail closed");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("recipient set differs from policy team"),
            "stderr: {stderr}"
        );
        assert!(
            stderr.contains("gitveil recipient"),
            "the error must point to the authorization command: {stderr}"
        );
        assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext);
        assert_eq!(read(&fixture, "secret.env"), plaintext);
        assert_eq!(state_snapshot(&fixture), state);
    }

    // The refusal is keyless: it fires identically without any identity.
    let mut keyless: Command = fixture.command_without_identity(fixture.binary());
    keyless.arg("seal");
    let output = command_output(&mut keyless);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("recipient set differs"),
        "the drift refusal must not require an identity"
    );
}

// A pending content edit must not ride around the drift refusal; after the
// explicit authorization converges the drift, the same seal succeeds.
#[test]
fn content_edits_do_not_bypass_the_recipient_drift_refusal() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\nB=stable\n");
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let before = read(&fixture, "secret.env.gitveil");

    let second = fixture.add_identity();
    let first = fixture.recipient().to_owned();
    fixture.write_manifest_with_recipients(
        &[("secret.env", "dotenv")],
        &[first.as_str(), second.as_str()],
    );
    write(&fixture, "secret.env", "A=changed\nB=stable\n");
    let refused = fixture.run_gitveil(&["seal"]);
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(read(&fixture, "secret.env.gitveil"), before);
    assert_eq!(read(&fixture, "secret.env"), b"A=changed\nB=stable\n");

    assert_success(
        fixture.run_gitveil(&["recipient", "add", "--recipient", second.as_str()]),
        "authorize the addition explicitly",
    );
    assert_success(fixture.run_gitveil(&["seal"]), "seal after convergence");
    let after = read(&fixture, "secret.env.gitveil");
    assert_ne!(encrypted_leaf(&after, "A"), encrypted_leaf(&before, "A"));
    assert_eq!(encrypted_leaf(&after, "B"), encrypted_leaf(&before, "B"));
    let envelope = CiphertextEnvelope::parse(&after, SourceFormat::Dotenv).expect("valid envelope");
    assert_eq!(envelope.age_recipients().len(), 2);
}

// A first seal has no envelope to anchor authorization, so the policy's
// other existing ciphertexts are the anchor: drift there blocks encrypting
// new files until the authorization command converges it.
#[test]
fn first_seal_requires_aligned_policy_siblings() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal the existing file");

    let second = fixture.add_identity();
    let first = fixture.recipient().to_owned();
    fixture.write_manifest_with_recipients(
        &[("secret.env", "dotenv"), ("fresh.env", "dotenv")],
        &[first.as_str(), second.as_str()],
    );
    write(&fixture, "fresh.env", "B=two\n");

    let refused = fixture.run_gitveil(&["seal", "fresh.env"]);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "first seal must fail closed"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("drifted ciphertext at secret.env.gitveil"),
        "stderr: {stderr}"
    );
    assert!(
        !fixture.root().join("fresh.env.gitveil").exists(),
        "no ciphertext may be created under a drifted policy"
    );

    assert_success(
        fixture.run_gitveil(&["recipient", "add", "--recipient", second.as_str()]),
        "converge the policy",
    );
    assert_success(
        fixture.run_gitveil(&["seal", "fresh.env"]),
        "first seal after convergence",
    );
    let envelope =
        CiphertextEnvelope::parse(&read(&fixture, "fresh.env.gitveil"), SourceFormat::Dotenv)
            .expect("valid envelope");
    assert_eq!(envelope.age_recipients().len(), 2);
}

#[test]
fn seal_without_any_envelope_identity_leaves_all_three_files_unchanged() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let ciphertext = read(&fixture, "secret.env.gitveil");
    let state = state_snapshot(&fixture);

    let second = fixture.add_identity();
    let first = fixture.recipient().to_owned();
    // Recipient drift now fails closed before any decryption, and a seal
    // without drift still needs an identity to decrypt its baseline; both
    // directions leave every file untouched without an identity.
    for recipients in [
        vec![first.as_str(), second.as_str()], // addition: drift refusal
        vec![second.as_str()],                 // removal: drift refusal
    ] {
        fixture.write_manifest_with_recipients(&[("secret.env", "dotenv")], &recipients);
        let mut command: Command = fixture.command_without_identity(fixture.binary());
        command.arg("seal");
        let output = support::command_output(&mut command);
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext);
        assert_eq!(state_snapshot(&fixture), state);
    }
}

#[test]
fn seal_changes_only_the_edited_leaf() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", &format!("A={CANARY}\nB=stable\n"));
    assert_success(fixture.run_gitveil(&["seal"]), "gitveil seal");
    let first = read(&fixture, "secret.env.gitveil");
    let stable_leaf = encrypted_leaf(&first, "B");
    let layout_leaf = encrypted_leaf(&first, "layout");

    write(
        &fixture,
        "secret.env",
        &format!("A={CANARY}-changed\nB=stable\n"),
    );
    assert_success(fixture.run_gitveil(&["seal"]), "gitveil seal edit");
    let second = read(&fixture, "secret.env.gitveil");
    assert_ne!(encrypted_leaf(&second, "A"), encrypted_leaf(&first, "A"));
    assert_eq!(encrypted_leaf(&second, "B"), stable_leaf);
    assert_eq!(encrypted_leaf(&second, "layout"), layout_leaf);
}

#[test]
fn open_materializes_plaintext_losslessly_with_owner_only_permissions() {
    let fixture = GitFixture::new();
    fixture.initialize();
    let body = format!("# leading comment\n\nexport A='{CANARY}' # inline\nB=stable\n");
    write(&fixture, "secret.env", &body);
    assert_success(fixture.run_gitveil(&["seal"]), "gitveil seal");
    fs::remove_file(fixture.root().join("secret.env")).expect("remove plaintext");

    let opened = assert_success(fixture.run_gitveil(&["open"]), "gitveil open");
    assert!(String::from_utf8_lossy(&opened.stdout).contains("secret.env: opened"));
    assert_eq!(
        String::from_utf8(read(&fixture, "secret.env")).expect("utf-8"),
        body
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(fixture.root().join("secret.env"))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "plaintext must be owner-only");
    }
}

#[test]
fn open_pulls_a_remote_update_when_local_is_unchanged() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\nB=two\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal v1");
    let snapshot = fixture.root().join("state-v1");
    fixture.snapshot_state(&snapshot);

    // Another machine seals an update.
    write(&fixture, "secret.env", "A=remote\nB=two\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal v2");

    // This machine is still at v1 (plaintext and baseline).
    write(&fixture, "secret.env", "A=one\nB=two\n");
    fixture.restore_state(&snapshot);

    assert_success(fixture.run_gitveil(&["open"]), "gitveil open");
    assert_eq!(read(&fixture, "secret.env"), b"A=remote\nB=two\n");
}

#[test]
fn open_preserves_local_unsealed_edits_and_additions() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\nB=two\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal v1");

    // Local edit and addition without seal; ciphertext unchanged.
    write(&fixture, "secret.env", "A=local\nB=two\nLOCAL=extra\n");
    let opened = assert_success(fixture.run_gitveil(&["open"]), "gitveil open");
    assert!(String::from_utf8_lossy(&opened.stdout).contains("up to date"));
    assert_eq!(
        read(&fixture, "secret.env"),
        b"A=local\nB=two\nLOCAL=extra\n"
    );
}

#[test]
fn open_reports_same_key_conflicts_and_keeps_the_local_value() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\nB=two\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal v1");
    let snapshot = fixture.root().join("state-v1");
    fixture.snapshot_state(&snapshot);

    write(&fixture, "secret.env", "A=remote\nB=two\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal v2");

    write(&fixture, "secret.env", "A=local\nB=two\n");
    fixture.restore_state(&snapshot);

    let opened = fixture.run_gitveil(&["open"]);
    assert_eq!(opened.status.code(), Some(1), "conflicts exit non-zero");
    let stdout = String::from_utf8_lossy(&opened.stdout);
    assert!(stdout.contains("conflicts"), "stdout: {stdout}");
    assert!(stdout.contains("key A"), "stdout: {stdout}");
    assert_eq!(read(&fixture, "secret.env"), b"A=local\nB=two\n");
}

#[test]
fn open_applies_arbitrable_changes_even_when_one_key_conflicts() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\nB=two\nC=three\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal v1");
    let snapshot = fixture.root().join("state-v1");
    fixture.snapshot_state(&snapshot);

    write(
        &fixture,
        "secret.env",
        "A=remote\nB=remote\nC=three\nD=four\n",
    );
    assert_success(fixture.run_gitveil(&["seal"]), "seal v2");

    write(&fixture, "secret.env", "A=local\nB=two\nC=three\n");
    fixture.restore_state(&snapshot);

    let opened = fixture.run_gitveil(&["open"]);
    assert_eq!(opened.status.code(), Some(1));
    assert_eq!(
        read(&fixture, "secret.env"),
        b"A=local\nB=remote\nC=three\nD=four\n"
    );
}

#[test]
fn open_propagates_remote_deletions_only_for_unchanged_local_keys() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\nB=two\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal v1");
    let snapshot = fixture.root().join("state-v1");
    fixture.snapshot_state(&snapshot);

    write(&fixture, "secret.env", "B=two\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal deletion");

    write(&fixture, "secret.env", "A=one\nB=two\n");
    fixture.restore_state(&snapshot);

    assert_success(fixture.run_gitveil(&["open"]), "gitveil open");
    assert_eq!(read(&fixture, "secret.env"), b"B=two\n");
}

#[test]
fn open_syncs_remote_layout_changes_when_local_layout_is_unchanged() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal v1");
    let snapshot = fixture.root().join("state-v1");
    fixture.snapshot_state(&snapshot);

    write(
        &fixture,
        "secret.env",
        "# production, do not touch\nA=one\n",
    );
    assert_success(fixture.run_gitveil(&["seal"]), "seal comment");

    write(&fixture, "secret.env", "A=one\n");
    fixture.restore_state(&snapshot);

    assert_success(fixture.run_gitveil(&["open"]), "gitveil open");
    assert_eq!(
        read(&fixture, "secret.env"),
        b"# production, do not touch\nA=one\n"
    );
}

#[test]
fn missing_files_report_per_pair_without_aborting_other_pairs() {
    let fixture = GitFixture::new();
    fixture.write_manifest(&[("secret.env", "dotenv"), ("secret.json", "json")]);
    write(&fixture, "secret.env", "A=one\n");
    // secret.json plaintext is missing: seal must fail for it and still seal
    // secret.env (B10, B18).
    let sealed = fixture.run_gitveil(&["seal"]);
    assert_eq!(sealed.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&sealed.stdout);
    let stderr = String::from_utf8_lossy(&sealed.stderr);
    assert!(stdout.contains("secret.env: sealed"), "stdout: {stdout}");
    assert!(stderr.contains("secret.json"), "stderr: {stderr}");
    assert!(fixture.root().join("secret.env.gitveil").is_file());
}

#[test]
fn seal_rejects_envelope_lookalike_plaintext() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal v1");
    let ciphertext = read(&fixture, "secret.env.gitveil");
    fs::write(fixture.root().join("secret.env"), &ciphertext).expect("clobber plaintext");
    let sealed = fixture.run_gitveil(&["seal"]);
    assert_eq!(sealed.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&sealed.stderr).contains("looks like a gitveil envelope"),
        "seal must refuse to double-encrypt an envelope"
    );
    assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext);
}

#[test]
fn corrupt_ciphertext_fails_open_without_touching_the_plaintext() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal v1");
    write(&fixture, "secret.env.gitveil", "not: an envelope\n");
    let opened = fixture.run_gitveil(&["open"]);
    assert_eq!(opened.status.code(), Some(1));
    assert_eq!(read(&fixture, "secret.env"), b"A=one\n");
}

#[test]
fn fresh_clone_open_yields_clean_status_for_values_with_inner_quotes() {
    // Regression: an unquoted value containing quote characters must
    // materialize byte-identically on a fresh clone (no baseline, no
    // plaintext) and report clean immediately afterwards.
    let fixture = GitFixture::new();
    fixture.initialize();
    let body = "ADMIN_API_TOKENS=alice:\"tok=1\",bob:\"tok=2\"\nB=plain\n";
    write(&fixture, "secret.env", body);
    assert_success(fixture.run_gitveil(&["seal"]), "seal");

    // Simulate a fresh clone: no plaintext, no baseline state.
    fs::remove_file(fixture.root().join("secret.env")).expect("remove plaintext");
    let _ = fs::remove_dir_all(fixture.state_dir());

    assert_success(fixture.run_gitveil(&["open"]), "open on fresh clone");
    assert_eq!(
        String::from_utf8(read(&fixture, "secret.env")).expect("utf-8"),
        body,
        "materialized plaintext must be byte-identical to the sealed original"
    );
    let status = fixture.run_gitveil(&["status"]);
    assert_eq!(
        status.status.code(),
        Some(0),
        "status must be clean right after open: {}",
        String::from_utf8_lossy(&status.stdout)
    );
}

#[test]
fn workspace_works_without_a_git_repository_in_conservative_mode() {
    let fixture = GitFixture::new();
    // Strip the repository: keep the directory, manifest, and SOPS config.
    fs::remove_dir_all(fixture.root().join(".git")).expect("remove .git");
    fixture.write_manifest(&[("secret.env", "dotenv")]);
    write(&fixture, "secret.env", &format!("A={CANARY}\n"));

    assert_success(fixture.run_gitveil(&["seal"]), "seal without git");
    let ciphertext = read(&fixture, "secret.env.gitveil");
    assert!(!contains(&ciphertext, CANARY.as_bytes()));

    fs::remove_file(fixture.root().join("secret.env")).expect("remove plaintext");
    assert_success(fixture.run_gitveil(&["open"]), "open without git");
    assert_eq!(
        read(&fixture, "secret.env"),
        format!("A={CANARY}\n").as_bytes()
    );
}

//! `gitveil recipient add` / `gitveil recipient remove`: the explicit
//! authorization commands, and the fail-closed drift contract they anchor.

pub mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gitveil::config::SourceFormat;
use gitveil::envelope::CiphertextEnvelope;
use gitveil::recipient::AgeRecipient;

use support::{
    GitFixture, assert_success, command_output, contains, encrypted_leaf, generate_age_identity,
    sops_binary,
};

const CANARY: &str = "gitveil-recipient-authorization-canary";

fn write(fixture: &GitFixture, path: &str, body: &str) {
    fs::write(fixture.root().join(path), body).expect("write fixture file");
}

fn read(fixture: &GitFixture, path: &str) -> Vec<u8> {
    fs::read(fixture.root().join(path)).expect("read fixture file")
}

fn recipients_of(fixture: &GitFixture, cipher: &str) -> Vec<String> {
    let envelope = CiphertextEnvelope::parse(&read(fixture, cipher), SourceFormat::Dotenv)
        .expect("valid envelope");
    let mut recipients = envelope
        .age_recipients()
        .iter()
        .map(|recipient| recipient.as_str().to_owned())
        .collect::<Vec<_>>();
    recipients.sort_unstable();
    recipients
}

fn manifest_json(fixture: &GitFixture) -> serde_json::Value {
    serde_json::from_slice(&read(fixture, ".gitveilrc.json")).expect("manifest JSON")
}

/// A recipient whose private identity the fixture never holds: the attacker.
fn foreign_recipient() -> String {
    let directory = tempfile::tempdir().expect("foreign identity directory");
    generate_age_identity(&directory.path().join("foreign.txt"))
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

#[test]
fn recipient_add_rewraps_every_policy_file_and_echoes_the_grant() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", &format!("A={CANARY}\nB=stable\n"));
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let before = read(&fixture, "secret.env.gitveil");
    let plaintext_before = read(&fixture, "secret.env");

    let (second, second_identity) = fixture.add_identity_with_path();
    let added = assert_success(
        fixture.run_gitveil(&["recipient", "add", "--recipient", second.as_str()]),
        "recipient add",
    );
    let stdout = String::from_utf8_lossy(&added.stdout);
    // Authorization names its subject: the full public recipient.
    assert!(
        stdout.contains(&format!("policy team: added {second}")),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("secret.env: rewrapped"), "stdout: {stdout}");

    // Manifest and envelope both converged in one command.
    assert_eq!(
        manifest_json(&fixture)["recipientPolicies"]["team"]["age"]
            .as_array()
            .expect("age array")
            .len(),
        2
    );
    let after = read(&fixture, "secret.env.gitveil");
    let mut expected = vec![fixture.recipient().to_owned(), second.clone()];
    expected.sort_unstable();
    assert_eq!(recipients_of(&fixture, "secret.env.gitveil"), expected);

    // Additions rewrap the same data key: every leaf stays byte-stable.
    for leaf in ["A", "B", "layout"] {
        assert_eq!(encrypted_leaf(&after, leaf), encrypted_leaf(&before, leaf));
    }
    // The authorization command never touches workspace plaintext.
    assert_eq!(read(&fixture, "secret.env"), plaintext_before);

    // The newly authorized identity decrypts through the product binary.
    let mut opened: Command = fixture.command_without_identity(fixture.binary());
    opened
        .env("SOPS_AGE_KEY_FILE", &second_identity)
        .args(["open"]);
    assert_success(command_output(&mut opened), "open with the added identity");

    // An idempotent rerun changes nothing.
    let rerun = assert_success(
        fixture.run_gitveil(&["recipient", "add", "--recipient", second.as_str()]),
        "idempotent rerun",
    );
    let stdout = String::from_utf8_lossy(&rerun.stdout);
    assert!(stdout.contains("already authorized"), "stdout: {stdout}");
    assert!(stdout.contains("already aligned"), "stdout: {stdout}");
    assert_eq!(read(&fixture, "secret.env.gitveil"), after);

    // Sealing still works after the convergence: no drift remains.
    assert_success(fixture.run_gitveil(&["seal"]), "seal after add");
}

#[test]
fn recipient_remove_rotates_the_data_key_and_excludes_the_removed_identity() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", &format!("A={CANARY}\nB=two\n"));
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");

    // Snapshot the first identity alone before the fixture key file gains
    // the second identity.
    let removed_only = tempfile::tempdir().expect("removed identity directory");
    let removed_identity = removed_only.path().join("removed.txt");
    fs::copy(fixture.identity(), &removed_identity).expect("snapshot first identity");

    let (second, second_identity) = fixture.add_identity_with_path();
    assert_success(
        fixture.run_gitveil(&["recipient", "add", "--recipient", second.as_str()]),
        "authorize the second identity",
    );
    let before_removal = read(&fixture, "secret.env.gitveil");

    // A pending local edit must not be consumed by the authorization command.
    write(
        &fixture,
        "secret.env",
        &format!("A={CANARY}-edited\nB=two\n"),
    );

    let first = fixture.recipient().to_owned();
    let removed = assert_success(
        fixture.run_gitveil(&["recipient", "remove", "--recipient", first.as_str()]),
        "recipient remove",
    );
    let stdout = String::from_utf8_lossy(&removed.stdout);
    assert!(
        stdout.contains(&format!("policy team: removed {first}")),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("secret.env: data key rotated"),
        "stdout: {stdout}"
    );

    // A fresh data key re-encrypts every leaf.
    let rotated = read(&fixture, "secret.env.gitveil");
    assert_eq!(recipients_of(&fixture, "secret.env.gitveil"), vec![second]);
    for leaf in ["A", "B", "layout"] {
        assert_ne!(
            encrypted_leaf(&rotated, leaf),
            encrypted_leaf(&before_removal, leaf),
            "leaf {leaf} must be re-encrypted under the fresh data key"
        );
    }
    // The local edit stayed local: the rotated ciphertext still carries the
    // old value, and the plaintext still carries the edit for a later seal.
    assert_eq!(
        read(&fixture, "secret.env"),
        format!("A={CANARY}-edited\nB=two\n").into_bytes()
    );

    // The kept identity decrypts; the local edit survives the open because
    // the refreshed baseline still adjudicates it as a local-only change.
    let mut kept: Command = fixture.command_without_identity(fixture.binary());
    kept.env("SOPS_AGE_KEY_FILE", &second_identity)
        .args(["open"]);
    assert_success(command_output(&mut kept), "open with the kept identity");
    assert_eq!(
        read(&fixture, "secret.env"),
        format!("A={CANARY}-edited\nB=two\n").into_bytes()
    );
    let mut excluded: Command = fixture.command_without_identity(fixture.binary());
    excluded
        .env("SOPS_AGE_KEY_FILE", &removed_identity)
        .args(["open"]);
    let output = command_output(&mut excluded);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the removed identity must not decrypt the rotated envelope"
    );
    assert!(!contains(&output.stdout, CANARY.as_bytes()));
    assert!(!contains(&output.stderr, CANARY.as_bytes()));

    // The pending edit seals normally afterwards (drift is fully converged).
    let sealed = assert_success(fixture.run_gitveil(&["seal"]), "seal the pending edit");
    assert!(String::from_utf8_lossy(&sealed.stdout).contains("sealed"));
}

// The confused-deputy case D8 exists for: a manifest edit alone must never
// become effective authorization, even when an identity holder runs the
// authorization command for an unrelated recipient.
#[test]
fn an_injected_manifest_recipient_is_rejected_and_named() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", &format!("A={CANARY}\n"));
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let ciphertext = read(&fixture, "secret.env.gitveil");

    // The attacker writes their recipient into the tracked manifest.
    let attacker = foreign_recipient();
    let first = fixture.recipient().to_owned();
    fixture.write_manifest_with_recipients(
        &[("secret.env", "dotenv")],
        &[first.as_str(), attacker.as_str()],
    );
    let tampered_manifest = read(&fixture, ".gitveilrc.json");

    // The user grants a legitimate new machine; the injected recipient is
    // not named, so the whole command is rejected and names the attacker.
    let (second, _) = fixture.add_identity_with_path();
    let refused = fixture.run_gitveil(&["recipient", "add", "--recipient", second.as_str()]);
    assert_eq!(refused.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains(attacker.as_str()),
        "the unexplained recipient must be named in full: {stderr}"
    );
    assert!(
        stderr.contains("did not add it"),
        "the error explains the rejection: {stderr}"
    );
    assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext);
    assert_eq!(read(&fixture, ".gitveilrc.json"), tampered_manifest);

    // The attacker cannot decrypt, and daily seal stays blocked, so the
    // injected recipient never becomes effective.
    let refused_seal = fixture.run_gitveil(&["seal"]);
    assert_eq!(refused_seal.status.code(), Some(1));
    assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext);
}

#[test]
fn an_injected_manifest_removal_requires_an_explicit_remove() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let (second, _) = fixture.add_identity_with_path();
    assert_success(
        fixture.run_gitveil(&["recipient", "add", "--recipient", second.as_str()]),
        "authorize the second identity",
    );

    // The manifest is hand-edited to drop the second recipient (attacker or
    // accident); an unrelated add must not silently revoke it.
    let first = fixture.recipient().to_owned();
    fixture.write_manifest_with_recipients(&[("secret.env", "dotenv")], &[first.as_str()]);
    let (third, _) = fixture.add_identity_with_path();
    let refused = fixture.run_gitveil(&["recipient", "add", "--recipient", third.as_str()]);
    assert_eq!(refused.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains(second.as_str()), "stderr: {stderr}");
    assert!(
        stderr.contains("gitveil recipient remove"),
        "stderr: {stderr}"
    );

    // Naming the removal explicitly converges it and rotates the data key.
    let removed = assert_success(
        fixture.run_gitveil(&["recipient", "remove", "--recipient", second.as_str()]),
        "explicit removal",
    );
    let stdout = String::from_utf8_lossy(&removed.stdout);
    assert!(
        stdout.contains(&format!(
            "policy team: removed {second} (was present only on ciphertext)"
        )),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("secret.env: data key rotated"),
        "stdout: {stdout}"
    );
    assert_eq!(
        recipients_of(&fixture, "secret.env.gitveil"),
        vec![first.clone()]
    );
    assert_success(fixture.run_gitveil(&["seal"]), "seal after convergence");
}

// Mid-run failure semantics: the manifest publishes first, a failed file
// convergence leaves drift that seal refuses, and a rerun converges it.
#[test]
fn a_failed_convergence_leaves_refusable_drift_and_a_rerun_converges() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", &format!("A={CANARY}\n"));
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let ciphertext = read(&fixture, "secret.env.gitveil");

    let (second, _) = fixture.add_identity_with_path();
    let wrapper_directory = tempfile::tempdir().expect("SOPS fault wrapper directory");
    let wrapper = no_op_updatekeys_wrapper(wrapper_directory.path());
    let mut faulted = fixture.gitveil();
    faulted
        .env("SOPS_BIN", wrapper)
        .args(["recipient", "add", "--recipient", second.as_str()]);
    let output = command_output(&mut faulted);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a rewrap that did not produce the authorized set must fail"
    );
    assert!(!contains(&output.stdout, CANARY.as_bytes()));
    assert!(!contains(&output.stderr, CANARY.as_bytes()));
    // The ciphertext is untouched; the manifest was already published, so
    // the observable state is exactly recipient drift.
    assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext);
    assert_eq!(
        manifest_json(&fixture)["recipientPolicies"]["team"]["age"]
            .as_array()
            .expect("age array")
            .len(),
        2
    );
    let refused_seal = fixture.run_gitveil(&["seal"]);
    assert_eq!(
        refused_seal.status.code(),
        Some(1),
        "drift left by the failure keeps seal fail-closed"
    );

    // The idempotent rerun (without the fault) converges the drift.
    let rerun = assert_success(
        fixture.run_gitveil(&["recipient", "add", "--recipient", second.as_str()]),
        "converging rerun",
    );
    assert!(String::from_utf8_lossy(&rerun.stdout).contains("secret.env: rewrapped"));
    assert_success(fixture.run_gitveil(&["seal"]), "seal after recovery");
}

// Preflight fails closed: without any usable identity nothing is published,
// including the manifest.
#[test]
fn no_identity_means_no_manifest_publication_and_no_file_changes() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let ciphertext = read(&fixture, "secret.env.gitveil");
    let manifest = read(&fixture, ".gitveilrc.json");

    let (second, _) = fixture.add_identity_with_path();
    let mut command: Command = fixture.command_without_identity(fixture.binary());
    command.args(["recipient", "add", "--recipient", second.as_str()]);
    let output = command_output(&mut command);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext);
    assert_eq!(read(&fixture, ".gitveilrc.json"), manifest);
}

#[test]
fn recipient_argument_validation_fails_before_any_effect() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let manifest = read(&fixture, ".gitveilrc.json");
    let first = fixture.recipient().to_owned();

    // Invalid and private-identity values are rejected.
    for invalid in ["not-a-recipient", "AGE-SECRET-KEY-PRIVATE"] {
        let output = fixture.run_gitveil(&["recipient", "add", "--recipient", invalid]);
        assert_eq!(output.status.code(), Some(1), "{invalid}");
    }
    // Removing the last recipient would leave the policy unable to encrypt.
    let output = fixture.run_gitveil(&["recipient", "remove", "--recipient", first.as_str()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("at least one recipient"),
        "the emptied-policy rejection must be explained"
    );
    // Removing an unknown recipient is rejected.
    let unknown = foreign_recipient();
    let output = fixture.run_gitveil(&["recipient", "remove", "--recipient", unknown.as_str()]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(read(&fixture, ".gitveilrc.json"), manifest);

    // A usage error without any --recipient exits 2 through clap.
    let output = fixture.run_gitveil(&["recipient", "add"]);
    assert_eq!(output.status.code(), Some(2));
}

// Multi-file policies converge together; entries without ciphertext only
// change the manifest and are sealed to the converged policy afterwards.
#[test]
fn recipient_add_converges_multiple_files_and_predeclared_entries() {
    let fixture = GitFixture::new();
    fixture.initialize();
    fixture.write_manifest_with_recipients(
        &[
            ("secret.env", "dotenv"),
            ("other.env", "dotenv"),
            ("pending.env", "dotenv"),
        ],
        &[fixture.recipient()],
    );
    write(&fixture, "secret.env", "A=one\n");
    write(&fixture, "other.env", "B=two\n");
    assert_success(
        fixture.run_gitveil(&["seal", "secret.env", "other.env"]),
        "seal existing files",
    );

    let (second, _) = fixture.add_identity_with_path();
    let added = assert_success(
        fixture.run_gitveil(&["recipient", "add", "--recipient", second.as_str()]),
        "recipient add across the policy",
    );
    let stdout = String::from_utf8_lossy(&added.stdout);
    assert!(stdout.contains("secret.env: rewrapped"), "stdout: {stdout}");
    assert!(stdout.contains("other.env: rewrapped"), "stdout: {stdout}");
    assert!(
        !stdout.contains("pending.env:"),
        "entries without ciphertext have nothing to converge: {stdout}"
    );
    assert_eq!(recipients_of(&fixture, "secret.env.gitveil").len(), 2);
    assert_eq!(recipients_of(&fixture, "other.env.gitveil").len(), 2);

    // The predeclared entry seals directly to the converged policy.
    write(&fixture, "pending.env", "C=three\n");
    assert_success(
        fixture.run_gitveil(&["seal", "pending.env"]),
        "first seal after convergence",
    );
    assert_eq!(recipients_of(&fixture, "pending.env.gitveil").len(), 2);

    let _ = AgeRecipient::new(second).expect("recipient remains canonical");
}

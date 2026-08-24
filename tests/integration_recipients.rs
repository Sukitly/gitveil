//! `gitveil recipient add` / `gitveil recipient remove`: the explicit
//! authorization commands, and the fail-closed drift contract they anchor.
//!
//! Semantics under test: each command converges envelopes only in its own
//! direction and only for the recipients named on the command line; residual
//! drift against the policy is reported with full values and keeps `seal`
//! fail-closed until it is explicitly converged.

pub mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gitveil::config::SourceFormat;
use gitveil::envelope::CiphertextEnvelope;

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

fn manifest_recipients(fixture: &GitFixture) -> Vec<String> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&read(fixture, ".gitveilrc.json")).expect("manifest JSON");
    let mut recipients = manifest["recipientPolicies"]["team"]["age"]
        .as_array()
        .expect("age array")
        .iter()
        .map(|value| value.as_str().expect("recipient string").to_owned())
        .collect::<Vec<_>>();
    recipients.sort_unstable();
    recipients
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

/// A SOPS wrapper that fails every encryption, so a removal's data-key
/// rotation fails after the manifest already published.
fn failing_encrypt_wrapper(directory: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = directory.join("sops");
    let real_sops = sops_binary().to_string_lossy().replace('\'', "'\\''");
    let script = format!(
        "#!/bin/sh\nfor argument in \"$@\"; do\n  if [ \"$argument\" = --encrypt ]; then\n    exit 1\n  fi\ndone\nexec '{real_sops}' \"$@\"\n"
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
        fixture.run_gitveil(&["recipient", "add", second.as_str()]),
        "recipient add",
    );
    let stdout = String::from_utf8_lossy(&added.stdout);
    // Authorization names its subject, and the per-file effect renders
    // before the policy-level claim.
    assert!(
        stdout.contains(&format!("policy team: added {second}")),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("secret.env: rewrapped"), "stdout: {stdout}");
    let file_line = stdout.find("secret.env: rewrapped").expect("file line");
    let policy_line = stdout.find("policy team: added").expect("policy line");
    assert!(
        file_line < policy_line,
        "file effects must render before policy claims: {stdout}"
    );

    // Manifest and envelope both converged in one command.
    let mut expected = vec![fixture.recipient().to_owned(), second.clone()];
    expected.sort_unstable();
    assert_eq!(manifest_recipients(&fixture), expected);
    assert_eq!(recipients_of(&fixture, "secret.env.gitveil"), expected);

    // Additions rewrap the same data key: every leaf stays byte-stable.
    let after = read(&fixture, "secret.env.gitveil");
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
        fixture.run_gitveil(&["recipient", "add", second.as_str()]),
        "idempotent rerun",
    );
    let stdout = String::from_utf8_lossy(&rerun.stdout);
    assert!(stdout.contains("already in policy"), "stdout: {stdout}");
    assert!(stdout.contains("no change needed"), "stdout: {stdout}");
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
        fixture.run_gitveil(&["recipient", "add", second.as_str()]),
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
        fixture.run_gitveil(&["recipient", "remove", first.as_str()]),
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
// become effective authorization. An add that does not name the injected
// recipient proceeds for what it names, never wraps the injected one, and
// surfaces it with its full value until it is explicitly added or removed.
#[test]
fn an_injected_manifest_recipient_is_never_wrapped_and_is_surfaced() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", &format!("A={CANARY}\n"));
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");

    // The attacker writes their recipient into the tracked manifest.
    let attacker = foreign_recipient();
    let first = fixture.recipient().to_owned();
    fixture.write_manifest_with_recipients(
        &[("secret.env", "dotenv")],
        &[first.as_str(), attacker.as_str()],
    );

    // The user grants a legitimate new machine. The command converges only
    // what it names; the injected recipient stays off the envelope and is
    // reported in full for review.
    let (second, _) = fixture.add_identity_with_path();
    let output = fixture.run_gitveil(&["recipient", "add", second.as_str()]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "residual drift is an attention outcome"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("drift remains (add {attacker})")),
        "the unexplained recipient must be named in full: {stdout}"
    );
    assert!(
        stdout.contains(&format!("next: gitveil recipient add {attacker}")),
        "stdout: {stdout}"
    );
    let mut expected = vec![first.clone(), second.clone()];
    expected.sort_unstable();
    assert_eq!(
        recipients_of(&fixture, "secret.env.gitveil"),
        expected,
        "the injected recipient must never be wrapped"
    );

    // Daily seal stays blocked while the injected recipient is unresolved.
    let refused_seal = fixture.run_gitveil(&["seal"]);
    assert_eq!(refused_seal.status.code(), Some(1));

    // Cleaning up the injection is itself in-product: removing it touches
    // only the manifest because no envelope carries it.
    let cleaned = assert_success(
        fixture.run_gitveil(&["recipient", "remove", attacker.as_str()]),
        "remove the injected recipient",
    );
    let stdout = String::from_utf8_lossy(&cleaned.stdout);
    assert!(
        stdout.contains(&format!("policy team: removed {attacker}")),
        "stdout: {stdout}"
    );
    assert_eq!(manifest_recipients(&fixture), {
        let mut expected = vec![first, second];
        expected.sort_unstable();
        expected
    });
    assert_success(fixture.run_gitveil(&["seal"]), "seal after cleanup");
}

// The removal direction of an injected manifest edit: an unrelated add never
// executes the removal; revoking requires naming the recipient explicitly.
#[test]
fn an_injected_manifest_removal_requires_an_explicit_remove() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let (second, _) = fixture.add_identity_with_path();
    assert_success(
        fixture.run_gitveil(&["recipient", "add", second.as_str()]),
        "authorize the second identity",
    );

    // The manifest is hand-edited to drop the second recipient (attacker or
    // accident); an unrelated add proceeds but never executes the removal.
    let first = fixture.recipient().to_owned();
    fixture.write_manifest_with_recipients(&[("secret.env", "dotenv")], &[first.as_str()]);
    let (third, _) = fixture.add_identity_with_path();
    let output = fixture.run_gitveil(&["recipient", "add", third.as_str()]);
    assert_eq!(output.status.code(), Some(1), "residual drift remains");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("drift remains (remove {second})")),
        "the pending removal must be named in full: {stdout}"
    );
    assert!(
        stdout.contains(&format!("next: gitveil recipient remove {second}")),
        "stdout: {stdout}"
    );
    // The second identity keeps its access until the removal is explicit.
    let mut on_envelope = vec![first.clone(), second.clone(), third.clone()];
    on_envelope.sort_unstable();
    assert_eq!(recipients_of(&fixture, "secret.env.gitveil"), on_envelope);

    // Naming the removal explicitly converges it and rotates the data key.
    let removed = assert_success(
        fixture.run_gitveil(&["recipient", "remove", second.as_str()]),
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
    let mut expected = vec![first, third];
    expected.sort_unstable();
    assert_eq!(recipients_of(&fixture, "secret.env.gitveil"), expected);
    assert_success(fixture.run_gitveil(&["seal"]), "seal after convergence");
}

// Mixed drift (both directions at once, e.g. after a pulled policy change
// plus a resolved merge) converges as two sequential one-sided commands.
#[test]
fn mixed_drift_converges_by_sequential_remove_then_add() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", &format!("A={CANARY}\n"));
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");

    // Y is a real envelope recipient; snapshot its standalone identity.
    let (y, y_identity) = fixture.add_identity_with_path();
    assert_success(
        fixture.run_gitveil(&["recipient", "add", y.as_str()]),
        "authorize Y",
    );

    // The manifest arrives with X in and Y out (teammate's policy change).
    let (x, x_identity) = fixture.add_identity_with_path();
    let first = fixture.recipient().to_owned();
    fixture
        .write_manifest_with_recipients(&[("secret.env", "dotenv")], &[first.as_str(), x.as_str()]);

    // Both data commands refuse; the state is converged by two explicit
    // one-sided authorization commands, in the user's natural order.
    assert_eq!(fixture.run_gitveil(&["seal"]).status.code(), Some(1));

    let removed = fixture.run_gitveil(&["recipient", "remove", y.as_str()]);
    assert_eq!(
        removed.status.code(),
        Some(1),
        "the pending addition still needs attention"
    );
    let stdout = String::from_utf8_lossy(&removed.stdout);
    assert!(
        stdout.contains("secret.env: data key rotated"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains(&format!("drift remains (add {x})")),
        "stdout: {stdout}"
    );
    assert_eq!(
        recipients_of(&fixture, "secret.env.gitveil"),
        vec![first.clone()]
    );

    let added = assert_success(
        fixture.run_gitveil(&["recipient", "add", x.as_str()]),
        "grant X explicitly",
    );
    assert!(String::from_utf8_lossy(&added.stdout).contains("secret.env: rewrapped"));
    let mut expected = vec![first, x];
    expected.sort_unstable();
    assert_eq!(recipients_of(&fixture, "secret.env.gitveil"), expected);
    assert_success(fixture.run_gitveil(&["seal"]), "seal after convergence");

    // X decrypts; Y does not.
    let mut granted: Command = fixture.command_without_identity(fixture.binary());
    granted.env("SOPS_AGE_KEY_FILE", &x_identity).args(["open"]);
    assert_success(
        command_output(&mut granted),
        "open with the granted identity",
    );
    let mut revoked: Command = fixture.command_without_identity(fixture.binary());
    revoked.env("SOPS_AGE_KEY_FILE", &y_identity).args(["open"]);
    let output = command_output(&mut revoked);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the revoked identity must not decrypt"
    );
    assert!(!contains(&output.stdout, CANARY.as_bytes()));
    assert!(!contains(&output.stderr, CANARY.as_bytes()));
}

// Mid-run add failure: the manifest publishes first, a failed rewrap leaves
// drift that seal refuses, and a rerun converges it.
#[test]
fn a_failed_rewrap_leaves_refusable_drift_and_a_rerun_converges() {
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
        .args(["recipient", "add", second.as_str()]);
    let output = command_output(&mut faulted);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a rewrap that did not produce the authorized set must fail"
    );
    assert!(!contains(&output.stdout, CANARY.as_bytes()));
    assert!(!contains(&output.stderr, CANARY.as_bytes()));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not fully effective"),
        "a partial failure must be called out"
    );
    // The ciphertext is untouched; the manifest was already published, so
    // the observable state is exactly recipient drift.
    assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext);
    let mut expected = vec![fixture.recipient().to_owned(), second.clone()];
    expected.sort_unstable();
    assert_eq!(manifest_recipients(&fixture), expected);
    assert_eq!(
        fixture.run_gitveil(&["seal"]).status.code(),
        Some(1),
        "drift left by the failure keeps seal fail-closed"
    );

    // The idempotent rerun (without the fault) converges the drift.
    let rerun = assert_success(
        fixture.run_gitveil(&["recipient", "add", second.as_str()]),
        "converging rerun",
    );
    assert!(String::from_utf8_lossy(&rerun.stdout).contains("secret.env: rewrapped"));
    assert_success(fixture.run_gitveil(&["seal"]), "seal after recovery");
}

// Mid-run remove failure: the output must not claim an effective revocation
// while the removed identity still decrypts the file.
#[test]
fn a_failed_rotation_does_not_claim_effective_revocation() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", &format!("A={CANARY}\n"));
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let removed_only = tempfile::tempdir().expect("removed identity directory");
    let removed_identity = removed_only.path().join("removed.txt");
    fs::copy(fixture.identity(), &removed_identity).expect("snapshot first identity");
    let (second, _) = fixture.add_identity_with_path();
    assert_success(
        fixture.run_gitveil(&["recipient", "add", second.as_str()]),
        "authorize the second identity",
    );
    let ciphertext = read(&fixture, "secret.env.gitveil");

    let first = fixture.recipient().to_owned();
    let wrapper_directory = tempfile::tempdir().expect("SOPS fault wrapper directory");
    let wrapper = failing_encrypt_wrapper(wrapper_directory.path());
    let mut faulted = fixture.gitveil();
    faulted
        .env("SOPS_BIN", wrapper)
        .args(["recipient", "remove", first.as_str()]);
    let output = command_output(&mut faulted);
    assert_eq!(output.status.code(), Some(1), "the rotation must fail");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains("data key rotated"),
        "no rotation may be claimed: {stdout}"
    );
    assert!(
        stderr.contains("not fully effective"),
        "the ineffective revocation must be called out: {stderr}"
    );
    // The removed identity still decrypts the untouched file: assert the
    // real state the output must not contradict.
    assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext);
    let mut still_able: Command = fixture.command_without_identity(fixture.binary());
    still_able
        .env("SOPS_AGE_KEY_FILE", &removed_identity)
        .args(["open"]);
    assert_success(
        command_output(&mut still_able),
        "the identity still decrypts until the rotation really happens",
    );

    // The rerun converges and only then excludes the identity.
    let rerun = assert_success(
        fixture.run_gitveil(&["recipient", "remove", first.as_str()]),
        "converging rerun",
    );
    assert!(String::from_utf8_lossy(&rerun.stdout).contains("secret.env: data key rotated"));
    let mut excluded: Command = fixture.command_without_identity(fixture.binary());
    excluded
        .env("SOPS_AGE_KEY_FILE", &removed_identity)
        .args(["open"]);
    assert_eq!(command_output(&mut excluded).status.code(), Some(1));
}

// Preflight fails closed with per-file reporting: without any usable
// identity nothing is published and every affected file is reported.
#[test]
fn no_identity_reports_every_file_and_publishes_nothing() {
    let fixture = GitFixture::new();
    fixture.initialize();
    fixture.write_manifest_with_recipients(
        &[("secret.env", "dotenv"), ("other.env", "dotenv")],
        &[fixture.recipient()],
    );
    write(&fixture, "secret.env", "A=one\n");
    write(&fixture, "other.env", "B=two\n");
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let manifest = read(&fixture, ".gitveilrc.json");
    let first_cipher = read(&fixture, "secret.env.gitveil");
    let second_cipher = read(&fixture, "other.env.gitveil");

    let (second, _) = fixture.add_identity_with_path();
    let mut command: Command = fixture.command_without_identity(fixture.binary());
    command.args(["recipient", "add", second.as_str()]);
    let output = command_output(&mut command);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("secret.env") && stderr.contains("other.env"),
        "every affected file must be reported: {stderr}"
    );
    assert!(
        stderr.contains("nothing was published"),
        "the withheld publication must be explicit: {stderr}"
    );
    assert_eq!(read(&fixture, ".gitveilrc.json"), manifest);
    assert_eq!(read(&fixture, "secret.env.gitveil"), first_cipher);
    assert_eq!(read(&fixture, "other.env.gitveil"), second_cipher);
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
        let output = fixture.run_gitveil(&["recipient", "add", invalid]);
        assert_eq!(output.status.code(), Some(1), "{invalid}");
    }
    // Removing the last recipient would leave the policy unable to encrypt.
    let output = fixture.run_gitveil(&["recipient", "remove", first.as_str()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("at least one recipient"),
        "the emptied-policy rejection must be explained"
    );
    // Removing an unknown recipient is rejected.
    let unknown = foreign_recipient();
    let output = fixture.run_gitveil(&["recipient", "remove", unknown.as_str()]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(read(&fixture, ".gitveilrc.json"), manifest);

    // A usage error without any recipient exits 2 through clap.
    for subcommand in ["add", "remove"] {
        let output = fixture.run_gitveil(&["recipient", subcommand]);
        assert_eq!(output.status.code(), Some(2), "{subcommand}");
    }
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
        fixture.run_gitveil(&["recipient", "add", second.as_str()]),
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
}

/// Writes a two-policy manifest: `team` guards `secret.env`, `ops` guards
/// `ops.env`.
fn write_two_policy_manifest(fixture: &GitFixture, team: &[&str], ops: &[&str]) {
    let manifest = serde_json::json!({
        "version": 1,
        "recipientPolicies": {
            "team": { "age": team },
            "ops": { "age": ops }
        },
        "files": [
            { "path": "secret.env", "format": "dotenv", "recipientPolicy": "team" },
            { "path": "ops.env", "format": "dotenv", "recipientPolicy": "ops" }
        ]
    });
    fs::write(
        fixture.root().join(".gitveilrc.json"),
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");
}

// An authorization command touches exactly the selected policy: files under
// other policies keep their bytes, and with several policies the selector
// is mandatory.
#[test]
fn recipient_commands_are_scoped_to_the_selected_policy() {
    let fixture = GitFixture::new();
    fixture.initialize();
    let first = fixture.recipient().to_owned();
    let (ops_member, _) = fixture.add_identity_with_path();
    write_two_policy_manifest(&fixture, &[first.as_str()], &[ops_member.as_str()]);
    write(&fixture, "secret.env", "A=one\n");
    write(&fixture, "ops.env", "B=two\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal both policies");
    let ops_cipher = read(&fixture, "ops.env.gitveil");

    // Several policies: the selector is required.
    let (third, _) = fixture.add_identity_with_path();
    let output = fixture.run_gitveil(&["recipient", "add", third.as_str()]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("pass --policy"),
        "the selector requirement must be explained: {stderr}"
    );
    assert_eq!(read(&fixture, "ops.env.gitveil"), ops_cipher);

    // The explicit selector converges only the selected policy's files.
    let added = assert_success(
        fixture.run_gitveil(&["recipient", "add", "--policy", "team", third.as_str()]),
        "recipient add scoped to team",
    );
    let stdout = String::from_utf8_lossy(&added.stdout);
    assert!(stdout.contains("secret.env: rewrapped"), "stdout: {stdout}");
    assert!(
        !stdout.contains("ops.env"),
        "the other policy's file must not appear: {stdout}"
    );
    assert_eq!(
        read(&fixture, "ops.env.gitveil"),
        ops_cipher,
        "the other policy's ciphertext must keep its bytes"
    );
    assert_eq!(recipients_of(&fixture, "secret.env.gitveil").len(), 2);
    assert_eq!(
        recipients_of(&fixture, "ops.env.gitveil"),
        vec![ops_member.clone()]
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&read(&fixture, ".gitveilrc.json")).expect("manifest JSON");
    assert_eq!(
        manifest["recipientPolicies"]["ops"]["age"],
        serde_json::json!([ops_member]),
        "the other policy must be untouched"
    );
    assert_success(fixture.run_gitveil(&["seal"]), "seal after scoped add");
}

// A ciphertext that cannot be parsed is reported per file while the rest of
// the policy converges; repairing it and rerunning converges the leftover.
#[test]
fn a_broken_ciphertext_is_reported_per_file_while_others_converge() {
    let fixture = GitFixture::new();
    fixture.initialize();
    fixture.write_manifest_with_recipients(
        &[("secret.env", "dotenv"), ("other.env", "dotenv")],
        &[fixture.recipient()],
    );
    write(&fixture, "secret.env", "A=one\n");
    write(&fixture, "other.env", "B=two\n");
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let intact = read(&fixture, "other.env.gitveil");
    write(&fixture, "other.env.gitveil", "not an envelope\n");

    let (second, _) = fixture.add_identity_with_path();
    let output = fixture.run_gitveil(&["recipient", "add", second.as_str()]);
    assert_eq!(output.status.code(), Some(1), "the broken file must fail");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("secret.env: rewrapped"), "stdout: {stdout}");
    assert!(
        stderr.contains("other.env"),
        "the broken file must be reported: {stderr}"
    );
    assert!(
        stderr.contains("not fully effective"),
        "the partial convergence must be called out: {stderr}"
    );
    assert_eq!(recipients_of(&fixture, "secret.env.gitveil").len(), 2);
    let mut expected = vec![fixture.recipient().to_owned(), second.clone()];
    expected.sort_unstable();
    assert_eq!(manifest_recipients(&fixture), expected);

    // Repairing the ciphertext and rerunning converges the leftover drift.
    fs::write(fixture.root().join("other.env.gitveil"), &intact).expect("repair ciphertext");
    let rerun = assert_success(
        fixture.run_gitveil(&["recipient", "add", second.as_str()]),
        "converging rerun",
    );
    let stdout = String::from_utf8_lossy(&rerun.stdout);
    assert!(stdout.contains("other.env: rewrapped"), "stdout: {stdout}");
    assert!(
        stdout.contains("secret.env: no change needed"),
        "stdout: {stdout}"
    );
    assert_eq!(recipients_of(&fixture, "other.env.gitveil").len(), 2);
    assert_success(fixture.run_gitveil(&["seal"]), "seal after repair");
}

// Removing the only recipient an envelope carries is refused even when the
// policy itself keeps other members: someone must be granted first.
#[test]
fn removing_an_envelopes_last_recipient_is_refused_with_zero_side_effects() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "initial seal");
    let ciphertext = read(&fixture, "secret.env.gitveil");

    // The manifest gained another member without envelope convergence
    // (hand edit); the envelope still carries only the first recipient.
    let injected = foreign_recipient();
    let first = fixture.recipient().to_owned();
    fixture.write_manifest_with_recipients(
        &[("secret.env", "dotenv")],
        &[injected.as_str(), first.as_str()],
    );
    let manifest = read(&fixture, ".gitveilrc.json");

    let output = fixture.run_gitveil(&["recipient", "remove", first.as_str()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no recipient able to decrypt"),
        "the emptied-envelope refusal must be explained"
    );
    assert_eq!(read(&fixture, "secret.env.gitveil"), ciphertext);
    assert_eq!(read(&fixture, ".gitveilrc.json"), manifest);
}

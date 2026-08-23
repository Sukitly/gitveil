pub mod support;

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use support::{GitFixture, assert_success, command_output};

fn write(fixture: &GitFixture, path: &str, body: &str) {
    fs::write(fixture.root().join(path), body).expect("write fixture file");
}

fn status_line(fixture: &GitFixture) -> (Option<i32>, String) {
    let output = fixture.run_gitveil(&["status"]);
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

fn profile_status(fixture: &GitFixture, profile: &str) -> (Option<i32>, String) {
    let output = fixture.run_gitveil(&["status", "--profile", profile]);
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

fn git_on_path() -> PathBuf {
    let path = std::env::var_os("PATH").expect("test PATH");
    std::env::split_paths(&path)
        .map(|directory| directory.join("git"))
        .find(|candidate| {
            candidate
                .metadata()
                .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
        })
        .expect("Git executable on PATH")
}

fn logging_git_path() -> (tempfile::TempDir, PathBuf, OsString, PathBuf) {
    let directory = tempfile::tempdir().expect("Git logging wrapper directory");
    let log = directory.path().join("calls.log");
    let wrapper = directory.path().join("git");
    let real_git = git_on_path();
    fs::write(
        &wrapper,
        "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$GITVEIL_TEST_GIT_LOG\"\n\
         exec \"$GITVEIL_TEST_REAL_GIT\" \"$@\"\n",
    )
    .expect("write Git logging wrapper");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))
        .expect("make Git logging wrapper executable");
    let path = std::env::join_paths(std::iter::once(directory.path().to_path_buf()).chain(
        std::env::split_paths(&std::env::var_os("PATH").expect("test PATH")),
    ))
    .expect("compose logging PATH");
    (directory, log, path, real_git)
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

#[test]
fn status_uses_a_constant_number_of_git_processes_for_multiple_pairs() {
    let fixture = GitFixture::new();
    fixture.write_manifest_with_profiles(&[
        ("first.env", "dotenv", Some("dev")),
        ("second.env", "dotenv", Some("dev")),
        ("nested/third.env", "dotenv", Some("prod")),
    ]);
    fs::create_dir_all(fixture.root().join("nested")).expect("create nested fixture directory");
    write(&fixture, "first.env", "A=one\n");
    write(&fixture, "second.env", "B=two\n");
    write(&fixture, "nested/third.env", "C=three\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal managed pairs");

    let (_wrapper, log, path, real_git) = logging_git_path();
    let mut command = fixture.gitveil();
    command
        .current_dir(fixture.root().join("nested"))
        .env("PATH", path)
        .env("GITVEIL_TEST_GIT_LOG", &log)
        .env("GITVEIL_TEST_REAL_GIT", real_git)
        .args(["status", "--profile", "dev"]);
    let output = assert_success(command_output(&mut command), "status managed pairs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("first.env"), "stdout: {stdout}");
    assert!(stdout.contains("second.env"), "stdout: {stdout}");
    assert!(!stdout.contains("nested/third.env"), "stdout: {stdout}");

    let calls = fs::read_to_string(log).expect("read Git process log");
    assert_eq!(
        calls.lines().collect::<Vec<_>>(),
        ["rev-parse", "ls-files"],
        "status must discover the repository once and inspect the index once"
    );
}

#[test]
fn status_profile_scopes_output_drift_and_exit_outcome() {
    let fixture = GitFixture::new();
    fixture.write_manifest_with_profiles(&[
        ("dev.env", "dotenv", Some("dev")),
        ("prod.env", "dotenv", Some("prod")),
    ]);
    write(&fixture, "dev.env", "VALUE=dev\n");
    write(&fixture, "prod.env", "VALUE=prod\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal all profiles");
    write(&fixture, "prod.env", "VALUE=changed\n");

    let (code, stdout) = profile_status(&fixture, "dev");
    assert_eq!(code, Some(0));
    assert!(stdout.contains("dev.env: clean"), "stdout: {stdout}");
    assert!(!stdout.contains("prod.env"), "stdout: {stdout}");

    let (code, stdout) = profile_status(&fixture, "prod");
    assert_eq!(code, Some(1));
    assert!(stdout.contains("prod.env: local edits"), "stdout: {stdout}");
    assert!(!stdout.contains("dev.env"), "stdout: {stdout}");
}

#[test]
fn status_profile_excludes_corrupt_files_in_other_groups() {
    let fixture = GitFixture::new();
    fixture.write_manifest_with_profiles(&[
        ("dev.env", "dotenv", Some("dev")),
        ("prod.env", "dotenv", Some("prod")),
    ]);
    write(&fixture, "dev.env", "VALUE=dev\n");
    write(&fixture, "prod.env", "VALUE=prod\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal all profiles");
    write(&fixture, "prod.env.gitveil", "not: an envelope\n");

    let (code, stdout) = profile_status(&fixture, "dev");
    assert_eq!(code, Some(0));
    assert!(stdout.contains("dev.env: clean"), "stdout: {stdout}");
    assert!(!stdout.contains("prod.env"), "stdout: {stdout}");
}

#[test]
fn status_reports_an_index_conflict_without_worktree_markers() {
    let fixture = GitFixture::new();
    fixture.initialize();
    seal_and_commit(&fixture, "A=base\n", "base");
    assert_success(
        fixture.run_git(&["checkout", "-q", "-b", "feature"]),
        "create feature branch",
    );
    seal_and_commit(&fixture, "A=feature\n", "feature change");
    assert_success(
        fixture.run_git(&["checkout", "-q", "main"]),
        "checkout main",
    );
    seal_and_commit(&fixture, "A=main\n", "main change");
    let merge = fixture.run_git(&["merge", "--no-edit", "feature"]);
    assert!(!merge.status.success(), "ciphertext merge must conflict");

    let ours = assert_success(
        fixture.run_git(&["show", ":2:secret.env.gitveil"]),
        "read ours stage",
    )
    .stdout;
    fs::write(fixture.root().join("secret.env.gitveil"), ours)
        .expect("replace worktree conflict with a valid envelope");

    let (code, stdout) = status_line(&fixture);
    assert_eq!(code, Some(1));
    assert!(stdout.contains("merge conflict"), "stdout: {stdout}");
}

#[test]
fn status_reports_clean_after_a_successful_seal() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal");
    let (code, stdout) = status_line(&fixture);
    assert_eq!(code, Some(0));
    assert!(stdout.contains("secret.env: clean"), "stdout: {stdout}");
}

#[test]
fn status_reports_recipient_drift_alongside_data_state() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal");

    let second = fixture.add_identity();
    let first = fixture.recipient().to_owned();
    fixture.write_manifest_with_recipients(
        &[("secret.env", "dotenv")],
        &[first.as_str(), second.as_str()],
    );
    let (code, stdout) = status_line(&fixture);
    assert_eq!(code, Some(1));
    assert!(stdout.contains("clean"), "stdout: {stdout}");
    assert!(stdout.contains("recipient drift"), "stdout: {stdout}");
    assert!(stdout.contains("policy team"), "stdout: {stdout}");
    assert!(stdout.contains("add 1"), "stdout: {stdout}");
    assert!(stdout.contains("remove 0"), "stdout: {stdout}");
    // Additions rewrap in place; only removals rotate the data key.
    assert!(
        !stdout.contains("rotates the file data key"),
        "stdout: {stdout}"
    );
    assert!(!stdout.contains(&first), "recipient must not be rendered");
    assert!(!stdout.contains(&second), "recipient must not be rendered");

    fs::remove_file(fixture.root().join("secret.env")).expect("remove plaintext");
    let (_, stdout) = status_line(&fixture);
    assert!(stdout.contains("plaintext missing"), "stdout: {stdout}");
    assert!(stdout.contains("recipient drift"), "stdout: {stdout}");

    write(&fixture, "secret.env", "A=local\n");
    let (_, stdout) = status_line(&fixture);
    assert!(stdout.contains("local edits"), "stdout: {stdout}");
    assert!(stdout.contains("recipient drift"), "stdout: {stdout}");

    // A drift that removes a recipient announces the coming rotation.
    fixture.write_manifest_with_recipients(&[("secret.env", "dotenv")], &[second.as_str()]);
    let (_, stdout) = status_line(&fixture);
    assert!(stdout.contains("remove 1"), "stdout: {stdout}");
    assert!(
        stdout.contains("rotates the file data key"),
        "stdout: {stdout}"
    );
}

#[test]
fn status_reports_direction_of_drift_with_a_baseline() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\nB=two\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal v1");

    // Local edit: plaintext is ahead.
    write(&fixture, "secret.env", "A=local\nB=two\n");
    let (code, stdout) = status_line(&fixture);
    assert_eq!(code, Some(1));
    assert!(stdout.contains("local edits"), "stdout: {stdout}");
    assert!(stdout.contains("changed A"), "stdout: {stdout}");
    assert!(stdout.contains("run gitveil seal"), "stdout: {stdout}");

    // Remote update: ciphertext is ahead.
    let snapshot = fixture.root().join("state-v1");
    fixture.snapshot_state(&snapshot);
    write(&fixture, "secret.env", "A=remote\nB=two\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal v2");
    write(&fixture, "secret.env", "A=one\nB=two\n");
    fixture.restore_state(&snapshot);
    let (code, stdout) = status_line(&fixture);
    assert_eq!(code, Some(1));
    assert!(stdout.contains("ciphertext updated"), "stdout: {stdout}");
    assert!(stdout.contains("run gitveil open"), "stdout: {stdout}");

    // Both sides changed: diverged.
    write(&fixture, "secret.env", "A=one\nB=local\n");
    let (code, stdout) = status_line(&fixture);
    assert_eq!(code, Some(1));
    assert!(stdout.contains("diverged"), "stdout: {stdout}");
}

#[test]
fn status_without_baseline_reports_key_set_differences_only() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal");
    fs::remove_dir_all(fixture.state_dir()).expect("drop baseline");

    // Same key set: value drift is unobservable without a key.
    let (code, stdout) = status_line(&fixture);
    assert_eq!(code, Some(1));
    assert!(stdout.contains("no baseline"), "stdout: {stdout}");

    // Key-set difference is observable.
    write(&fixture, "secret.env", "A=one\nNEW=extra\n");
    let (code, stdout) = status_line(&fixture);
    assert_eq!(code, Some(1));
    assert!(stdout.contains("NEW"), "stdout: {stdout}");
}

#[test]
fn status_reports_missing_sides_and_corrupt_ciphertext() {
    let fixture = GitFixture::new();
    fixture.initialize();
    let (code, stdout) = status_line(&fixture);
    assert_eq!(code, Some(1));
    assert!(stdout.contains("neither file exists"), "stdout: {stdout}");

    write(&fixture, "secret.env", "A=one\n");
    let (_, stdout) = status_line(&fixture);
    assert!(stdout.contains("ciphertext missing"), "stdout: {stdout}");

    assert_success(fixture.run_gitveil(&["seal"]), "seal");
    fs::remove_file(fixture.root().join("secret.env")).expect("remove plaintext");
    let (_, stdout) = status_line(&fixture);
    assert!(stdout.contains("plaintext missing"), "stdout: {stdout}");

    write(&fixture, "secret.env", "A=one\n");
    write(&fixture, "secret.env.gitveil", "not: an envelope\n");
    let (code, stdout) = status_line(&fixture);
    assert_eq!(code, Some(1));
    assert!(stdout.contains("corrupt"), "stdout: {stdout}");
}

#[test]
fn status_reports_conflict_markers_in_the_ciphertext() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", "A=one\n");
    assert_success(fixture.run_gitveil(&["seal"]), "seal");
    write(
        &fixture,
        "secret.env.gitveil",
        "<<<<<<< HEAD\ngitveil_v1_dotenv: {}\n=======\nother\n>>>>>>> branch\n",
    );
    let (code, stdout) = status_line(&fixture);
    assert_eq!(code, Some(1));
    assert!(stdout.contains("merge conflict"), "stdout: {stdout}");
    assert!(stdout.contains("gitveil resolve"), "stdout: {stdout}");
}

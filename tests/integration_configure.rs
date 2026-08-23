pub mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use support::{GitFixture, assert_success, child_output, command_output, contains};

fn init(fixture: &GitFixture) -> std::process::Output {
    fixture.run_gitveil(&["init", "--recipient", fixture.recipient()])
}

fn add(fixture: &GitFixture, path: &str, format: &str) -> std::process::Output {
    fixture.run_gitveil(&["add", path, "--format", format])
}

fn manifest(root: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(root.join(".gitveilrc.json")).expect("read manifest"))
        .expect("parse manifest JSON")
}

fn index_snapshot(fixture: &GitFixture) -> Vec<u8> {
    assert_success(
        fixture.run_git(&["ls-files", "--stage", "-z"]),
        "snapshot index",
    )
    .stdout
}

#[test]
fn init_preserves_recipient_order_without_echoing_or_writing_unrelated_state() {
    let fixture = GitFixture::new();
    let second = fixture.add_identity();
    let before_index = index_snapshot(&fixture);
    let mut command = fixture.command_without_identity(fixture.binary());
    command.env_remove("SOPS_BIN").args([
        "init",
        "--policy",
        "team",
        "--recipient",
        fixture.recipient(),
        "--recipient",
        &second,
    ]);
    let output = assert_success(command_output(&mut command), "init");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("initialized"), "stdout: {stdout}");
    assert!(stdout.contains("team"), "stdout: {stdout}");
    assert!(
        !stdout.contains(fixture.recipient()),
        "must not echo recipients"
    );

    let value = manifest(fixture.root());
    assert_eq!(value["version"], 1);
    assert_eq!(
        value["recipientPolicies"]["team"]["age"],
        serde_json::json!([fixture.recipient(), second])
    );
    assert_eq!(value["files"], serde_json::json!([]));
    let manifest_path = fixture.root().join(".gitveilrc.json");
    let bytes = fs::read(&manifest_path).expect("manifest bytes");
    assert!(bytes.ends_with(b"\n"), "canonical manifest needs final LF");
    assert_eq!(
        fs::metadata(&manifest_path)
            .expect("manifest metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert!(!fixture.root().join(".gitignore").exists());
    assert_eq!(index_snapshot(&fixture), before_index);
}

#[test]
fn init_rejects_repository_subdirectories_without_product_file_writes() {
    let fixture = GitFixture::new();
    let nested = fixture.root().join("packages/api");
    fs::create_dir_all(&nested).expect("nested directory");
    let mut command = fixture.gitveil();
    command
        .current_dir(&nested)
        .args(["init", "--recipient", fixture.recipient()]);
    let output = command_output(&mut command);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("repository root"));
    assert!(!fixture.root().join(".gitveilrc.json").exists());
}

#[test]
fn init_never_replaces_an_existing_manifest() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "root init");
    let before = fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest before");
    let repeated = init(&fixture);
    assert_eq!(repeated.status.code(), Some(1));
    assert_eq!(
        fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest after"),
        before
    );
}

#[test]
fn init_rejects_invalid_private_and_duplicate_recipients() {
    for invalid in ["not-an-age-recipient", "AGE-SECRET-KEY-PRIVATE"] {
        let fixture = GitFixture::new();
        let output = fixture.run_gitveil(&["init", "--recipient", invalid]);
        assert_eq!(output.status.code(), Some(1));
        assert!(!fixture.root().join(".gitveilrc.json").exists());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE"));
    }

    let fixture = GitFixture::new();
    let output = fixture.run_gitveil(&[
        "init",
        "--recipient",
        fixture.recipient(),
        "--recipient",
        fixture.recipient(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!fixture.root().join(".gitveilrc.json").exists());
}

#[test]
fn init_rejects_non_git_directories() {
    let fixture = GitFixture::new();
    let directory = tempfile::tempdir().expect("non-Git directory");
    let output = command_output(
        Command::new(fixture.binary())
            .current_dir(directory.path())
            .args(["init", "--recipient", fixture.recipient()]),
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Git repository"));
    assert!(!directory.path().join(".gitveilrc.json").exists());
}

#[test]
fn init_rejects_bare_repositories() {
    let fixture = GitFixture::new();
    let bare = tempfile::tempdir().expect("bare repository");
    assert_success(
        command_output(Command::new("git").args([
            "init",
            "--bare",
            "-q",
            bare.path().to_str().expect("UTF-8 bare path"),
        ])),
        "initialize bare repository",
    );
    let output = command_output(
        Command::new(fixture.binary())
            .current_dir(bare.path())
            .args(["init", "--recipient", fixture.recipient()]),
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(!bare.path().join(".gitveilrc.json").exists());
}

#[test]
fn init_preserves_git_process_failures_instead_of_reporting_a_root_error() {
    let fixture = GitFixture::new();
    let empty_path = tempfile::tempdir().expect("empty PATH");
    let mut command = fixture.gitveil();
    command
        .env("PATH", empty_path.path())
        .args(["init", "--recipient", fixture.recipient()]);
    let output = command_output(&mut command);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("could not execute Git"), "stderr: {stderr}");
    assert!(!stderr.contains("run this command from a Git repository root"));
    assert!(!fixture.root().join(".gitveilrc.json").exists());
}

#[test]
fn init_preserves_protocol_and_path_failures_from_repository_discovery() {
    let real_git = String::from_utf8(
        assert_success(
            command_output(Command::new("sh").args(["-c", "command -v git"])),
            "locate git",
        )
        .stdout,
    )
    .expect("git path UTF-8")
    .trim()
    .to_owned();
    for (discovery_output, expected) in [
        ("only-one-line\n", "invalid Git repository discovery output"),
        ("relative-root\n.git/gitveil\n", "root is not absolute"),
    ] {
        let fixture = GitFixture::new();
        let wrappers = tempfile::tempdir().expect("wrapper directory");
        let wrapper = wrappers.path().join("git");
        fs::write(
            &wrapper,
            r#"#!/bin/sh
if [ "$1" = "rev-parse" ]; then
    printf '%s' "$DISCOVERY_OUTPUT"
    exit 0
fi
exec "$REAL_GIT" "$@"
"#,
        )
        .expect("git wrapper");
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).expect("wrapper mode");
        let path = format!(
            "{}:{}",
            wrappers.path().display(),
            std::env::var("PATH").expect("PATH")
        );
        let mut command = fixture.gitveil();
        command
            .env("PATH", path)
            .env("REAL_GIT", &real_git)
            .env("DISCOVERY_OUTPUT", discovery_output)
            .args(["init", "--recipient", fixture.recipient()]);
        let output = command_output(&mut command);
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "stderr: {stderr}");
        assert!(!stderr.contains("run this command from a Git repository root"));
    }
}

#[test]
fn init_reports_unreadable_existing_git_metadata_as_a_process_failure() {
    let fixture = GitFixture::new();
    fs::remove_dir_all(fixture.root().join(".git")).expect("remove repository metadata");
    fs::write(fixture.root().join(".git"), "not valid gitdir metadata\n")
        .expect("corrupt Git metadata marker");

    let output = init(&fixture);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("metadata exists but could not be read"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("run this command from a Git repository root"));
}

#[test]
fn concurrent_init_publishes_exactly_one_manifest() {
    let fixture = GitFixture::new();
    let mut first = fixture.gitveil();
    first
        .args(["init", "--recipient", fixture.recipient()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut second = fixture.gitveil();
    second
        .args(["init", "--recipient", fixture.recipient()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let first = first.spawn().expect("spawn first init");
    let second = second.spawn().expect("spawn second init");
    let mut codes = [
        child_output(first).status.code(),
        child_output(second).status.code(),
    ];
    codes.sort();
    assert_eq!(codes, [Some(0), Some(1)]);
    assert_eq!(manifest(fixture.root())["version"], 1);
}

#[test]
fn init_accepts_a_linked_worktree_root() {
    let fixture = GitFixture::new();
    assert_success(
        fixture.run_git(&["commit", "--allow-empty", "-qm", "initial"]),
        "initial commit",
    );
    let parent = tempfile::tempdir().expect("worktree parent");
    let linked = parent.path().join("linked");
    assert_success(
        fixture.run_git(&[
            "worktree",
            "add",
            "--detach",
            "-q",
            linked.to_str().expect("UTF-8 linked path"),
        ]),
        "create linked worktree",
    );
    assert!(linked.join(".git").is_file(), "linked worktree marker");
    let mut command = fixture.command_without_identity(fixture.binary());
    command.current_dir(&linked).env_remove("SOPS_BIN").args([
        "init",
        "--recipient",
        fixture.recipient(),
    ]);
    assert_success(command_output(&mut command), "linked worktree init");
    assert!(linked.join(".gitveilrc.json").is_file());
    assert!(!fixture.root().join(".gitveilrc.json").exists());
}

#[test]
fn add_rejects_repository_subdirectories_without_configuration_writes() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    let nested = fixture.root().join("packages/api");
    fs::create_dir_all(&nested).expect("nested directory");
    let mut command = fixture.gitveil();
    command
        .current_dir(&nested)
        .args(["add", ".env", "--format", "dotenv"]);
    let output = command_output(&mut command);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("repository root"));
    assert!(!fixture.root().join(".gitignore").exists());
}

#[test]
fn add_rejects_symlinked_plaintext() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::write(fixture.root().join("outside.env"), "A=1\n").expect("outside source");
    std::os::unix::fs::symlink(
        fixture.root().join("outside.env"),
        fixture.root().join("secret.env"),
    )
    .expect("source symlink");
    let output = add(&fixture, "secret.env", "dotenv");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("secret.env"));
    assert_eq!(manifest(fixture.root())["files"], serde_json::json!([]));
}

#[test]
fn add_rejects_non_regular_plaintext_without_blocking() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    assert_success(
        command_output(Command::new("mkfifo").arg(fixture.root().join("pipe.env"))),
        "create FIFO",
    );
    let output = add(&fixture, "pipe.env", "dotenv");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("pipe.env"));
    assert_eq!(manifest(fixture.root())["files"], serde_json::json!([]));
}

#[test]
fn add_rejects_leading_colon_before_git_pathspec_evaluation() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    let output = add(&fixture, ":secret.env", "dotenv");
    assert_eq!(output.status.code(), Some(1));
    assert!(!fixture.root().join(".gitignore").exists());
    assert_eq!(manifest(fixture.root())["files"], serde_json::json!([]));
}

#[test]
fn add_predeclares_missing_plaintext_and_installs_an_effective_managed_block() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    let before_index = index_snapshot(&fixture);
    let output = assert_success(add(&fixture, ".env", "dotenv"), "add missing source");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("create the plaintext"), "stdout: {stdout}");
    assert!(stdout.contains("gitveil verify"), "stdout: {stdout}");
    assert!(
        !stdout.contains("gitveil seal --"),
        "missing plaintext must not be suggested for sealing: {stdout}"
    );

    let value = manifest(fixture.root());
    assert_eq!(
        value["files"],
        serde_json::json!([{
            "path": ".env",
            "format": "dotenv",
            "recipientPolicy": "default",
            "profile": "default"
        }])
    );
    let ignore_path = fixture.root().join(".gitignore");
    let ignore = fs::read_to_string(&ignore_path).expect("gitignore");
    assert_eq!(
        fs::metadata(&ignore_path)
            .expect("gitignore metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert_eq!(ignore.matches("# BEGIN gitveil managed files").count(), 1);
    assert_eq!(ignore.matches("# END gitveil managed files").count(), 1);
    assert!(
        ignore.contains("/.env\n!/.env.gitveil\n"),
        "ignore: {ignore}"
    );
    assert_eq!(
        fixture
            .run_git(&["check-ignore", "--no-index", "-q", "--", ".env"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        fixture
            .run_git(&["check-ignore", "--no-index", "-q", "--", ".env.gitveil",])
            .status
            .code(),
        Some(1)
    );
    assert!(!fixture.root().join(".env").exists());
    assert!(!fixture.root().join(".env.gitveil").exists());
    assert_eq!(index_snapshot(&fixture), before_index);
}

#[test]
fn add_works_without_sops_and_overrides_a_broad_file_ignore_safely() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::write(fixture.root().join(".gitignore"), "*.env*\n").expect("broad ignore");
    fs::write(fixture.root().join(".env"), "A=1\n").expect("source");
    let mut command = fixture.command_without_identity(fixture.binary());
    command
        .env_remove("SOPS_BIN")
        .args(["add", ".env", "--format", "dotenv"]);
    assert_success(command_output(&mut command), "keyless add");
    assert_eq!(
        fixture
            .run_git(&["check-ignore", "--no-index", "-q", "--", ".env"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        fixture
            .run_git(&["check-ignore", "--no-index", "-q", "--", ".env.gitveil",])
            .status
            .code(),
        Some(1)
    );
}

#[test]
fn add_adopts_existing_plaintext_without_changing_bytes_or_disclosing_values() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    let body = b"# local secret\nTOKEN=gitveil-secret-configure-canary\n";
    fs::write(fixture.root().join(".env"), body).expect("write source");
    fs::set_permissions(
        fixture.root().join(".env"),
        fs::Permissions::from_mode(0o644),
    )
    .expect("source mode");

    let output = assert_success(add(&fixture, ".env", "dotenv"), "adopt source");
    assert!(String::from_utf8_lossy(&output.stdout).contains("existing plaintext protected"));
    assert_eq!(fs::read(fixture.root().join(".env")).expect("source"), body);
    assert_eq!(
        fs::metadata(fixture.root().join(".env"))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!contains(
        &output.stdout,
        b"gitveil-secret-configure-canary"
    ));
    assert!(!contains(
        &output.stderr,
        b"gitveil-secret-configure-canary"
    ));
}

#[test]
fn idempotent_add_repairs_a_missing_managed_ignore_block() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::write(fixture.root().join(".env"), "A=1\n").expect("source");
    assert_success(add(&fixture, ".env", "dotenv"), "initial add");
    let manifest_before = fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest");
    fs::remove_file(fixture.root().join(".gitignore")).expect("remove managed ignore");

    let repeated = assert_success(add(&fixture, ".env", "dotenv"), "repeat add");
    assert!(String::from_utf8_lossy(&repeated.stdout).contains("already managed"));
    assert_eq!(
        fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest"),
        manifest_before
    );
    let ignore = fs::read_to_string(fixture.root().join(".gitignore")).expect("gitignore");
    assert_eq!(ignore.matches("# BEGIN gitveil managed files").count(), 1);
}

#[test]
fn conflicting_add_never_updates_an_existing_entry() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    assert_success(add(&fixture, ".env", "dotenv"), "initial add");
    let manifest_before = fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest");

    let conflict = fixture.run_gitveil(&["add", ".env", "--format", "dotenv", "--profile", "dev"]);
    assert_eq!(conflict.status.code(), Some(1));
    assert_eq!(
        fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest"),
        manifest_before
    );
}

#[test]
fn tracked_plaintext_rejects_the_entire_mixed_batch_without_index_writes() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::write(fixture.root().join("tracked.env"), "A=1\n").expect("tracked source");
    fs::write(fixture.root().join("valid.env"), "B=2\n").expect("valid source");
    assert_success(
        fixture.run_git(&["add", "tracked.env"]),
        "track plaintext in index",
    );
    let manifest_before = fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest");
    let index_before = index_snapshot(&fixture);

    let output = fixture.run_gitveil(&["add", "valid.env", "tracked.env", "--format", "dotenv"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("tracked.env"), "stderr: {stderr}");
    assert!(stderr.contains("git rm --cached"), "stderr: {stderr}");
    assert_eq!(
        fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest"),
        manifest_before
    );
    assert!(!fixture.root().join(".gitignore").exists());
    assert_eq!(index_snapshot(&fixture), index_before);
}

#[test]
fn malformed_existing_source_is_rejected_without_value_disclosure() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::write(
        fixture.root().join("invalid.env"),
        "A=gitveil-secret-configure-canary\nA=duplicate\n",
    )
    .expect("invalid source");
    let manifest_before = fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest");

    let output = add(&fixture, "invalid.env", "dotenv");
    assert_eq!(output.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("gitveil-secret-configure-canary"));
    assert_eq!(
        fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest"),
        manifest_before
    );
    assert!(!fixture.root().join(".gitignore").exists());
}

#[test]
fn add_canonicalizes_legacy_missing_profile_to_explicit_default() {
    let fixture = GitFixture::new();
    fixture.write_manifest(&[("existing.env", "dotenv")]);
    assert_success(
        add(&fixture, "new.env", "dotenv"),
        "add to existing manifest",
    );
    let value = manifest(fixture.root());
    let files = value["files"].as_array().expect("files");
    assert_eq!(files[0]["profile"], "default");
    assert_eq!(files[1]["profile"], "default");
}

#[test]
fn add_registers_a_same_configuration_batch_in_argument_order() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::create_dir_all(fixture.root().join("service-a")).expect("service-a directory");
    fs::write(fixture.root().join("service-a/.env"), "A=1\n").expect("existing plaintext");
    let output = assert_success(
        fixture.run_gitveil(&[
            "add",
            "service-a/.env",
            "service-b/.env",
            "--format",
            "dotenv",
            "--profile",
            "dev",
        ]),
        "batch add",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gitveil seal -- service-a/.env"));
    assert!(
        !stdout.contains("gitveil seal -- service-a/.env service-b/.env"),
        "missing service-b plaintext must be excluded: {stdout}"
    );
    let files = manifest(fixture.root())["files"]
        .as_array()
        .expect("files")
        .clone();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0]["path"], "service-a/.env");
    assert_eq!(files[1]["path"], "service-b/.env");
    assert!(files.iter().all(|entry| entry["profile"] == "dev"));
}

#[test]
fn idempotent_next_action_seals_only_already_managed_existing_plaintext() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::write(fixture.root().join("existing.env"), "A=1\n").expect("existing plaintext");
    assert_success(
        fixture.run_gitveil(&["add", "existing.env", "missing.env", "--format", "dotenv"]),
        "initial batch",
    );

    let output = assert_success(
        fixture.run_gitveil(&["add", "existing.env", "missing.env", "--format", "dotenv"]),
        "idempotent batch",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("existing.env: already managed"));
    assert!(stdout.contains("missing.env: already managed"));
    assert!(stdout.contains("gitveil seal -- existing.env"));
    assert!(!stdout.contains("gitveil seal -- existing.env missing.env"));
}

#[test]
fn multiple_policies_require_an_explicit_valid_selection() {
    let fixture = GitFixture::new();
    let second = fixture.add_identity();
    fs::write(
        fixture.root().join(".gitveilrc.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "recipientPolicies": {
                "team": { "age": [fixture.recipient()] },
                "prod": { "age": [second] }
            },
            "files": []
        }))
        .expect("serialize manifest"),
    )
    .expect("write manifest");

    let ambiguous = add(&fixture, ".env", "dotenv");
    assert_eq!(ambiguous.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(stderr.contains("recipient polic"), "stderr: {stderr}");
    assert!(
        stderr.contains("prod") && stderr.contains("team"),
        "stderr: {stderr}"
    );
    assert_success(
        fixture.run_gitveil(&[
            "add",
            ".env",
            "--format",
            "dotenv",
            "--recipient-policy",
            "team",
        ]),
        "explicit policy add",
    );
    assert_eq!(
        manifest(fixture.root())["files"][0]["recipientPolicy"],
        "team"
    );
}

#[test]
fn manifest_without_recipient_policies_is_rejected_before_ignore_writes() {
    let fixture = GitFixture::new();
    fs::write(
        fixture.root().join(".gitveilrc.json"),
        br#"{ "version": 1, "recipientPolicies": {}, "files": [] }"#,
    )
    .expect("empty-policy manifest");
    let output = add(&fixture, ".env", "dotenv");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no recipient policy"));
    assert!(!fixture.root().join(".gitignore").exists());
}

#[test]
fn malformed_managed_ignore_block_is_rejected_without_rewriting_user_bytes() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::write(
        fixture.root().join(".gitignore"),
        "# BEGIN gitveil managed files\n/old.env\n",
    )
    .expect("malformed block");
    let before = fs::read(fixture.root().join(".gitignore")).expect("ignore before");
    let output = add(&fixture, ".env", "dotenv");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("managed"));
    assert_eq!(
        fs::read(fixture.root().join(".gitignore")).expect("ignore after"),
        before
    );
}

#[test]
fn failed_parent_ignore_proof_reports_every_rule_and_restores_safe_original_bytes() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    let ignore_path = fixture.root().join(".gitignore");
    let original = b"packages/\nprivate/\n";
    fs::write(&ignore_path, original).expect("parent ignores");
    fs::set_permissions(&ignore_path, fs::Permissions::from_mode(0o640)).expect("ignore mode");
    let manifest_before = fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest");
    let output = fixture.run_gitveil(&[
        "add",
        "packages/api/.env",
        "private/token.env",
        "--format",
        "dotenv",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    for expected in [
        "packages/api/.env.gitveil",
        "private/token.env.gitveil",
        ".gitignore:1:packages/",
        ".gitignore:2:private/",
    ] {
        assert!(stderr.contains(expected), "missing {expected:?}: {stderr}");
    }
    assert_eq!(
        fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest"),
        manifest_before
    );
    assert_eq!(fs::read(&ignore_path).expect("restored ignore"), original);
    assert_eq!(
        fs::metadata(&ignore_path)
            .expect("ignore metadata")
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
}

#[test]
fn failed_batch_proof_retains_protection_for_previously_visible_plaintext() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::write(fixture.root().join(".gitignore"), "packages/\n").expect("parent ignore");
    fs::write(fixture.root().join(".env"), "A=1\n").expect("existing plaintext");

    let output = fixture.run_gitveil(&["add", ".env", "packages/api/.env", "--format", "dotenv"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(manifest(fixture.root())["files"], serde_json::json!([]));
    let ignore = fs::read_to_string(fixture.root().join(".gitignore")).expect("retained ignore");
    assert!(
        ignore.contains("/.env\n!/.env.gitveil\n"),
        "ignore: {ignore}"
    );
    assert_eq!(
        fixture
            .run_git(&["check-ignore", "--no-index", "-q", "--", ".env"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        fs::metadata(fixture.root().join(".env"))
            .expect("plaintext metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644,
        "proof failure happens before permission tightening"
    );
}

#[test]
fn add_preserves_existing_valid_ciphertext_bytes() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::write(fixture.root().join(".env"), "A=1\n").expect("source");
    assert_success(add(&fixture, ".env", "dotenv"), "initial add");
    assert_success(fixture.run_gitveil(&["seal", ".env"]), "seal");
    let ciphertext = fs::read(fixture.root().join(".env.gitveil")).expect("ciphertext");
    let mut value = manifest(fixture.root());
    value["files"] = serde_json::json!([]);
    fs::write(
        fixture.root().join(".gitveilrc.json"),
        serde_json::to_vec_pretty(&value).expect("serialize reset manifest"),
    )
    .expect("reset manifest");

    assert_success(add(&fixture, ".env", "dotenv"), "readopt ciphertext");
    assert_eq!(
        fs::read(fixture.root().join(".env.gitveil")).expect("ciphertext after"),
        ciphertext
    );
}

#[test]
fn add_rejects_corrupt_ciphertext_without_overwriting_it() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::write(fixture.root().join(".env.gitveil"), "not ciphertext\n").expect("corrupt ciphertext");
    let manifest_before = fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest");

    let output = add(&fixture, ".env", "dotenv");
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        fs::read(fixture.root().join(".gitveilrc.json")).expect("manifest"),
        manifest_before
    );
    assert_eq!(
        fs::read(fixture.root().join(".env.gitveil")).expect("corrupt after"),
        b"not ciphertext\n"
    );
}

#[test]
fn concurrent_gitignore_edit_before_publication_is_not_overwritten() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::write(fixture.root().join(".env"), "A=1\n").expect("source");
    fs::write(fixture.root().join(".gitignore"), "original-rule\n").expect("original ignore");

    let real_git = String::from_utf8(
        assert_success(
            command_output(Command::new("sh").args(["-c", "command -v git"])),
            "locate git",
        )
        .stdout,
    )
    .expect("git path UTF-8")
    .trim()
    .to_owned();
    let wrappers = tempfile::tempdir().expect("wrapper directory");
    let external_ignore = wrappers.path().join("external-ignore");
    fs::write(&external_ignore, "external-rule\n").expect("external ignore");
    let wrapper = wrappers.path().join("git");
    fs::write(
        &wrapper,
        r#"#!/bin/sh
if [ "$1" = "check-ignore" ]; then
    "$REAL_GIT" "$@"
    status=$?
    cp "$EXTERNAL_IGNORE" "$GITIGNORE_FILE"
    exit "$status"
fi
exec "$REAL_GIT" "$@"
"#,
    )
    .expect("git wrapper");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).expect("wrapper mode");
    let path = format!(
        "{}:{}",
        wrappers.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let mut command = fixture.gitveil();
    command
        .env("PATH", path)
        .env("REAL_GIT", real_git)
        .env("EXTERNAL_IGNORE", &external_ignore)
        .env("GITIGNORE_FILE", fixture.root().join(".gitignore"))
        .args(["add", ".env", "--format", "dotenv"]);
    let output = command_output(&mut command);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains(".gitignore changed"));
    assert_eq!(
        fs::read(fixture.root().join(".gitignore")).expect("preserved external edit"),
        b"external-rule\n"
    );
    assert_eq!(manifest(fixture.root())["files"], serde_json::json!([]));
}

#[test]
fn concurrent_gitignore_edit_before_failed_proof_rollback_is_not_overwritten() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::write(fixture.root().join(".gitignore"), "packages/\n").expect("original ignore");

    let real_git = String::from_utf8(
        assert_success(
            command_output(Command::new("sh").args(["-c", "command -v git"])),
            "locate git",
        )
        .stdout,
    )
    .expect("git path UTF-8")
    .trim()
    .to_owned();
    let wrappers = tempfile::tempdir().expect("wrapper directory");
    let external_ignore = wrappers.path().join("external-ignore");
    fs::write(&external_ignore, "external-rule\n").expect("external ignore");
    let wrapper = wrappers.path().join("git");
    fs::write(
        &wrapper,
        r#"#!/bin/sh
if [ "$1" = "check-ignore" ]; then
    "$REAL_GIT" "$@"
    status=$?
    cp "$EXTERNAL_IGNORE" "$GITIGNORE_FILE"
    exit "$status"
fi
exec "$REAL_GIT" "$@"
"#,
    )
    .expect("git wrapper");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).expect("wrapper mode");
    let path = format!(
        "{}:{}",
        wrappers.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let mut command = fixture.gitveil();
    command
        .env("PATH", path)
        .env("REAL_GIT", real_git)
        .env("EXTERNAL_IGNORE", &external_ignore)
        .env("GITIGNORE_FILE", fixture.root().join(".gitignore"))
        .args(["add", "packages/api/.env", "--format", "dotenv"]);
    let output = command_output(&mut command);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains(".gitignore changed"));
    assert_eq!(
        fs::read(fixture.root().join(".gitignore")).expect("preserved external edit"),
        b"external-rule\n"
    );
    assert_eq!(manifest(fixture.root())["files"], serde_json::json!([]));
}

#[test]
fn concurrent_manifest_entry_after_ignore_publication_is_preserved_and_protected() {
    let fixture = GitFixture::new();
    assert_success(init(&fixture), "init");
    fs::write(fixture.root().join(".env"), "A=1\n").expect("source");
    fs::set_permissions(
        fixture.root().join(".env"),
        fs::Permissions::from_mode(0o644),
    )
    .expect("source mode");

    let real_git = String::from_utf8(
        assert_success(
            command_output(Command::new("sh").args(["-c", "command -v git"])),
            "locate git",
        )
        .stdout,
    )
    .expect("git path UTF-8")
    .trim()
    .to_owned();
    let wrappers = tempfile::tempdir().expect("wrapper directory");
    let concurrent_manifest = wrappers.path().join("concurrent-manifest.json");
    let mut concurrent = manifest(fixture.root());
    concurrent["files"] = serde_json::json!([{
        "path": "concurrent.env",
        "format": "dotenv",
        "recipientPolicy": "default",
        "profile": "default"
    }]);
    fs::write(
        &concurrent_manifest,
        serde_json::to_vec_pretty(&concurrent).expect("serialize concurrent manifest"),
    )
    .expect("write concurrent manifest");

    let wrapper = wrappers.path().join("git");
    let count = wrappers.path().join("check-ignore-count");
    fs::write(
        &wrapper,
        r#"#!/bin/sh
if [ "$1" = "check-ignore" ]; then
    value=0
    if [ -f "$COUNT_FILE" ]; then value=$(cat "$COUNT_FILE"); fi
    value=$((value + 1))
    printf '%s\n' "$value" > "$COUNT_FILE"
    "$REAL_GIT" "$@"
    status=$?
    if [ "$value" -eq 2 ]; then cp "$CONCURRENT_MANIFEST" "$MANIFEST_FILE"; fi
    exit "$status"
fi
exec "$REAL_GIT" "$@"
"#,
    )
    .expect("git wrapper");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).expect("wrapper mode");
    let path = format!(
        "{}:{}",
        wrappers.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let mut command = fixture.gitveil();
    command
        .env("PATH", path)
        .env("REAL_GIT", real_git)
        .env("COUNT_FILE", &count)
        .env("CONCURRENT_MANIFEST", &concurrent_manifest)
        .env("MANIFEST_FILE", fixture.root().join(".gitveilrc.json"))
        .args(["add", ".env", "--format", "dotenv"]);
    let output = command_output(&mut command);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("changed"));
    assert_eq!(manifest(fixture.root()), concurrent);
    assert_eq!(
        fs::metadata(fixture.root().join(".env"))
            .expect("source metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644,
        "manifest freshness must be checked before chmod"
    );
    for path in [".env", "concurrent.env"] {
        assert_eq!(
            fixture
                .run_git(&["check-ignore", "--no-index", "-q", "--", path])
                .status
                .code(),
            Some(0),
            "{path} must remain protected"
        );
        let ciphertext = format!("{path}.gitveil");
        assert_eq!(
            fixture
                .run_git(&["check-ignore", "--no-index", "-q", "--", &ciphertext])
                .status
                .code(),
            Some(1),
            "{ciphertext} must remain visible"
        );
    }
}

#[test]
fn add_does_not_hide_historical_plaintext_and_verify_reports_it_after_registration() {
    let fixture = GitFixture::new();
    fs::write(fixture.root().join(".env"), "A=old-secret\n").expect("historical source");
    assert_success(fixture.run_git(&["add", ".env"]), "stage historical source");
    assert_success(
        fixture.run_git(&["commit", "-qm", "plaintext history"]),
        "commit historical source",
    );
    assert_success(
        fixture.run_git(&["rm", "--cached", "-q", "--", ".env"]),
        "remove source from index",
    );
    assert_success(
        fixture.run_git(&["commit", "-qm", "stop tracking plaintext"]),
        "commit source removal",
    );

    assert_success(init(&fixture), "init");
    assert_success(add(&fixture, ".env", "dotenv"), "add historical path");
    let verify = fixture.run_gitveil(&["verify"]);
    assert_eq!(verify.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&verify.stdout).contains(".env"));
}

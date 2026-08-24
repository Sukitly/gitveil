pub mod support;

use std::fs;
use std::process::Command;

use support::{GitFixture, age_keygen_binary, assert_success, command_output, sops_binary};

fn binary() -> std::path::PathBuf {
    assert_cmd::cargo::cargo_bin!("gitveil").to_path_buf()
}

#[test]
fn help_lists_exactly_the_nine_public_commands() {
    let output = command_output(Command::new(binary()).arg("--help"));
    assert_eq!(output.status.code(), Some(0));
    let help = String::from_utf8(output.stdout).expect("help UTF-8");
    for command in [
        "identity",
        "init",
        "add",
        "recipient",
        "open",
        "seal",
        "status",
        "verify",
        "resolve",
    ] {
        assert!(help.contains(command), "help must list {command}: {help}");
    }
    for removed in [
        "install",
        "uninstall",
        "track",
        "untrack",
        "rekey",
        "filter-process",
        "diff-driver",
        "merge-driver",
        "sops-editor",
        "doctor",
    ] {
        assert!(
            !help
                .lines()
                .any(|line| line.trim_start().starts_with(removed)),
            "help must not list {removed}: {help}"
        );
    }
}

#[test]
fn identity_help_lists_generation_and_recipient_derivation() {
    let output = command_output(Command::new(binary()).args(["identity", "--help"]));
    assert_eq!(output.status.code(), Some(0));
    let help = String::from_utf8(output.stdout).expect("identity help UTF-8");
    assert!(
        help.lines()
            .any(|line| line.trim_start().starts_with("generate"))
    );
    assert!(
        help.lines()
            .any(|line| line.trim_start().starts_with("recipients"))
    );

    let output = command_output(Command::new(binary()).args(["identity", "recipients", "--help"]));
    assert_eq!(output.status.code(), Some(0));
    let help = String::from_utf8(output.stdout).expect("recipient help UTF-8");
    let normalized = help.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains("SOPS_AGE_KEY_FILE"));
    assert!(normalized.contains("platform default key file"));
    assert!(!normalized.contains("SOPS_AGE_KEY_CMD"));
}

#[test]
fn recipient_help_names_the_explicit_authorization_surface() {
    let output = command_output(Command::new(binary()).args(["recipient", "--help"]));
    assert_eq!(output.status.code(), Some(0));
    let help = String::from_utf8(output.stdout).expect("recipient help UTF-8");
    assert!(
        help.lines()
            .any(|line| line.trim_start().starts_with("add"))
    );
    assert!(
        help.lines()
            .any(|line| line.trim_start().starts_with("remove"))
    );

    for subcommand in ["add", "remove"] {
        let output =
            command_output(Command::new(binary()).args(["recipient", subcommand, "--help"]));
        assert_eq!(output.status.code(), Some(0));
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(help.contains("--policy"), "{subcommand} help: {help}");
        // Recipients are the positional direct object, not a flag.
        assert!(help.contains("AGE_RECIPIENT"), "{subcommand} help: {help}");
        assert!(!help.contains("--recipient"), "{subcommand} help: {help}");
    }

    // The recipient is the required, explicit authorization statement.
    for subcommand in ["add", "remove"] {
        let output = command_output(Command::new(binary()).args(["recipient", subcommand]));
        assert_eq!(output.status.code(), Some(2), "{subcommand} without value");
    }
}

#[test]
fn profile_is_exposed_only_on_the_scoped_pair_commands() {
    for command in ["open", "seal", "status"] {
        let output = command_output(Command::new(binary()).args([command, "--help"]));
        assert_eq!(output.status.code(), Some(0));
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(help.contains("--profile"), "{command} help: {help}");
    }
    for command in ["resolve", "verify"] {
        let output = command_output(Command::new(binary()).args([command, "--help"]));
        assert_eq!(output.status.code(), Some(0));
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(!help.contains("--profile"), "{command} help: {help}");
    }
}

#[test]
fn invalid_cli_profile_is_a_configuration_error() {
    let fixture = GitFixture::new();
    fixture.initialize();
    let output = fixture.run_gitveil(&["status", "--profile", "Dev"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("profile"), "stderr: {stderr}");
    assert!(stderr.contains("Dev"), "stderr: {stderr}");
}

#[test]
fn usage_errors_exit_two() {
    let unknown = command_output(Command::new(binary()).arg("no-such-command"));
    assert_eq!(unknown.status.code(), Some(2));
    let missing = command_output(&mut Command::new(binary()));
    assert_eq!(missing.status.code(), Some(2));
    let identity_without_operation = command_output(Command::new(binary()).arg("identity"));
    assert_eq!(identity_without_operation.status.code(), Some(2));
    let init_without_recipient = command_output(Command::new(binary()).arg("init"));
    assert_eq!(init_without_recipient.status.code(), Some(2));
    let add_without_format = command_output(Command::new(binary()).args(["add", ".env"]));
    assert_eq!(add_without_format.status.code(), Some(2));
    let add_without_path =
        command_output(Command::new(binary()).args(["add", "--format", "dotenv"]));
    assert_eq!(add_without_path.status.code(), Some(2));
}

#[test]
fn missing_manifest_is_a_configuration_error() {
    let directory = tempfile::tempdir().expect("temp dir");
    let output = command_output(Command::new(binary()).arg("status").current_dir(&directory));
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(".gitveilrc.json"),
        "error must name the manifest file"
    );
}

#[test]
fn invalid_manifest_entries_are_rejected_with_the_offending_field() {
    let fixture = GitFixture::new();
    fs::write(
        fixture.root().join(".gitveilrc.json"),
        format!(
            r#"{{
                "version": 1,
                "recipientPolicies": {{ "team": {{ "age": ["{}"] }} }},
                "files": [ {{ "path": "secret.env", "recipientPolicy": "team" }} ]
            }}"#,
            fixture.recipient()
        ),
    )
    .expect("write manifest");
    let output = fixture.run_gitveil(&["status"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("format"),
        "error must mention the missing format field"
    );
}

#[test]
fn legacy_manifest_reports_a_breaking_migration_error() {
    let fixture = GitFixture::new();
    fs::write(
        fixture.root().join(".gitveilrc.json"),
        r#"{ "files": [ { "path": "secret.env", "format": "dotenv" } ] }"#,
    )
    .expect("write legacy manifest");
    let output = fixture.run_gitveil(&["status"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("legacy"), "stderr: {stderr}");
    assert!(stderr.contains("recipientPolicies"), "stderr: {stderr}");
}

#[test]
fn seal_does_not_fall_back_to_a_system_sops_on_path() {
    let fixture = GitFixture::new();
    fixture.initialize();
    fs::write(fixture.root().join("secret.env"), "A=1\n").expect("write plaintext");
    let mut command = fixture.gitveil();
    command
        .env_remove("SOPS_BIN")
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .arg("seal");
    let output = command_output(&mut command);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("SOPS sidecar"), "stderr: {stderr}");
}

#[test]
fn explicit_sops_override_still_rejects_the_wrong_version() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = GitFixture::new();
    fixture.initialize();
    fs::write(fixture.root().join("secret.env"), "A=1\n").expect("write plaintext");
    let fake_directory = tempfile::tempdir().expect("fake SOPS directory");
    let fake = fake_directory.path().join("sops");
    fs::write(&fake, "#!/bin/sh\nprintf 'sops 3.13.1\\n'\n").expect("fake SOPS body");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("fake SOPS mode");

    let mut command = fixture.gitveil();
    command.env("SOPS_BIN", &fake).arg("seal");
    let output = command_output(&mut command);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported SOPS version 3.13.1"));
    assert!(!fixture.root().join("secret.env.gitveil").exists());
}

#[test]
fn keyless_commands_do_not_require_a_sidecar() {
    let fixture = GitFixture::new();
    fixture.initialize();
    fs::write(fixture.root().join("secret.env"), "A=1\n").expect("write plaintext");
    assert_success(fixture.run_gitveil(&["seal"]), "establish clean pair");

    for arguments in [["status"].as_slice(), ["verify"].as_slice()] {
        let mut command = fixture.gitveil();
        command
            .env_remove("SOPS_BIN")
            .env("PATH", "/usr/bin:/bin")
            .args(arguments);
        let output = command_output(&mut command);
        assert_eq!(output.status.code(), Some(0), "{arguments:?}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SOPS sidecar"));
    }
}

#[test]
fn installed_layout_uses_the_private_sidecar_without_system_sops_or_age() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = GitFixture::new();
    fixture.initialize();
    fs::write(fixture.root().join("secret.env"), "A=1\n").expect("write plaintext");
    let prefix = tempfile::tempdir().expect("install prefix");
    let installed_binary = prefix.path().join("bin/gitveil");
    let installed_sops = prefix.path().join("libexec/gitveil/sops");
    let installed_age_keygen = prefix.path().join("libexec/gitveil/age-keygen");
    fs::create_dir_all(installed_binary.parent().expect("bin parent")).expect("create bin");
    fs::create_dir_all(installed_sops.parent().expect("sidecar parent")).expect("create libexec");
    fs::copy(binary(), &installed_binary).expect("install gitveil");
    fs::copy(sops_binary(), &installed_sops).expect("install sops");
    fs::copy(age_keygen_binary(), &installed_age_keygen).expect("install age-keygen");
    fs::set_permissions(&installed_binary, fs::Permissions::from_mode(0o755))
        .expect("gitveil mode");
    fs::set_permissions(&installed_sops, fs::Permissions::from_mode(0o755)).expect("sops mode");
    fs::set_permissions(&installed_age_keygen, fs::Permissions::from_mode(0o755))
        .expect("age-keygen mode");

    let mut identity_command = fixture.command_with_identity(&installed_binary);
    identity_command
        .env_remove("AGE_KEYGEN_BIN")
        .env("PATH", "/usr/bin:/bin")
        .args(["identity", "recipients", "--identity"])
        .arg(fixture.identity());
    let identity_output = assert_success(
        command_output(&mut identity_command),
        "installed recipient derivation",
    );
    assert_eq!(
        String::from_utf8(identity_output.stdout)
            .expect("installed recipient UTF-8")
            .trim(),
        fixture.recipient()
    );

    let mut command = fixture.command_with_identity(&installed_binary);
    command
        .env_remove("SOPS_BIN")
        .env("PATH", "/usr/bin:/bin")
        .arg("seal");
    assert_success(command_output(&mut command), "installed seal");
    assert!(fixture.root().join("secret.env.gitveil").is_file());

    fs::remove_file(fixture.root().join("secret.env")).expect("remove plaintext");
    let mut command = fixture.command_with_identity(&installed_binary);
    command
        .env_remove("SOPS_BIN")
        .env("PATH", "/usr/bin:/bin")
        .arg("open");
    assert_success(command_output(&mut command), "installed open");
    assert_eq!(
        fs::read(fixture.root().join("secret.env")).expect("read opened plaintext"),
        b"A=1\n"
    );
}

#[test]
fn piped_output_contains_no_ansi_escapes() {
    // Colors are a TTY affordance; captured pipes must stay plain so
    // scripts and tests never see escape bytes.
    let fixture = GitFixture::new();
    fixture.initialize();
    fs::write(fixture.root().join("secret.env"), "A=1\n").expect("write plaintext");
    for command in [["status"], ["seal"], ["open"]] {
        let output = fixture.run_gitveil(&command);
        assert!(
            !output.stdout.contains(&0x1b) && !output.stderr.contains(&0x1b),
            "{command:?} must not emit ANSI escapes to a pipe"
        );
    }
}

#[test]
fn undeclared_paths_are_rejected() {
    let fixture = GitFixture::new();
    fixture.initialize();
    let output = fixture.run_gitveil(&["seal", "other.env"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not declared"),
        "undeclared path must be refused"
    );
    let escape = fixture.run_gitveil(&["seal", "../escape.env"]);
    assert_eq!(escape.status.code(), Some(1));
}

#[test]
fn resolve_requires_a_git_repository() {
    let fixture = GitFixture::new();
    fs::remove_dir_all(fixture.root().join(".git")).expect("remove .git");
    fixture.write_manifest(&[("secret.env", "dotenv")]);
    let output = fixture.run_gitveil(&["resolve"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires a Git repository"),
        "resolve outside a repository must explain the requirement"
    );
}

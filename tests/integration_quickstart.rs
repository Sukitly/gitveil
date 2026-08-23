pub mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use support::{
    AGE_KEYGEN_VERSION, age_keygen_binary, assert_success, child_output_with_timeout,
    command_output, contains, sops_binary,
};

const PLAINTEXT_CANARY: &[u8] = b"gitveil-quickstart-secret-canary";
const QUICKSTART_TIMEOUT: Duration = Duration::from_secs(90);

struct QuickstartFixture {
    root: tempfile::TempDir,
    tools: PathBuf,
    workspaces: PathBuf,
    gitveil: PathBuf,
}

impl QuickstartFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("quickstart fixture");
        let tools = root.path().join("bin");
        let workspaces = root.path().join("workspaces");
        fs::create_dir(&tools).expect("create tool directory");
        fs::create_dir(&workspaces).expect("create workspace parent");
        Self {
            root,
            tools,
            workspaces,
            gitveil: assert_cmd::cargo::cargo_bin!("gitveil").to_path_buf(),
        }
    }

    fn command(&self) -> Command {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let path = std::env::join_paths([
            self.tools.clone(),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ])
        .expect("join isolated PATH");
        let mut command = Command::new("sh");
        command
            .current_dir(root)
            .arg(root.join("examples/quickstart.sh"))
            .env("PATH", path)
            .env("GITVEIL_BIN", &self.gitveil)
            .env("SOPS_BIN", sops_binary())
            .env("AGE_KEYGEN_BIN", age_keygen_binary())
            .env("TMPDIR", &self.workspaces)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for variable in ["SOPS_AGE_KEY", "SOPS_AGE_KEY_FILE", "SOPS_AGE_KEY_CMD"] {
            command.env_remove(variable);
        }
        command
    }

    fn run(&self, arguments: &[&str]) -> Output {
        let mut command = self.command();
        command.args(arguments);
        child_output_with_timeout(
            command.spawn().expect("start executable quickstart"),
            QUICKSTART_TIMEOUT,
        )
    }

    fn single_workspace(&self) -> PathBuf {
        let mut entries = fs::read_dir(&self.workspaces)
            .expect("read workspace parent")
            .map(|entry| entry.expect("read workspace entry").path())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1, "quickstart must retain one workspace");
        entries.pop().expect("one retained workspace")
    }

    fn assert_no_workspaces(&self) {
        assert!(
            fs::read_dir(&self.workspaces)
                .expect("read workspace parent")
                .next()
                .is_none(),
            "quickstart must remove its temporary workspace"
        );
    }

    fn replace_tool(&self, name: &str, body: &[u8]) {
        let path = self.tools.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            fs::remove_file(&path).expect("remove existing test tool");
        }
        fs::write(&path, body).expect("write replacement test tool");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("make replacement test tool executable");
    }

    fn isolated_command(&self, workspace: &Path, repository: &Path, program: &Path) -> Command {
        let path = std::env::join_paths([
            self.tools.clone(),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ])
        .expect("join isolated PATH");
        let mut command = Command::new(program);
        command
            .current_dir(repository)
            .env("PATH", path)
            .env("HOME", workspace.join("home"))
            .env("XDG_CONFIG_HOME", workspace.join("home/xdg"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", workspace.join("home/gitconfig"));
        command
    }
}

fn assert_no_secret_output(output: &Output, forbidden: &[&[u8]]) {
    for value in forbidden {
        assert!(
            !contains(&output.stdout, value),
            "stdout leaked protected material"
        );
        assert!(
            !contains(&output.stderr, value),
            "stderr leaked protected material"
        );
    }
}

fn assert_mode(path: &Path, expected: u32) {
    assert_eq!(
        fs::metadata(path)
            .expect("read file metadata")
            .permissions()
            .mode()
            & 0o777,
        expected
    );
}

#[test]
fn pinned_age_keygen_is_the_declared_real_version() {
    let output = assert_success(
        command_output(Command::new(age_keygen_binary()).arg("--version")),
        "age-keygen version",
    );
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("age-keygen version is UTF-8")
            .trim(),
        format!("v{AGE_KEYGEN_VERSION}")
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn executable_example_leaves_an_independently_verifiable_repository_when_requested() {
    let fixture = QuickstartFixture::new();
    let output = fixture.run(&["--keep-workspace"]);
    assert!(
        output.status.success(),
        "quickstart failed with status {:?}",
        output.status.code()
    );
    assert!(contains(
        &output.stdout,
        b"Gitveil quickstart completed successfully."
    ));

    let workspace = fixture.single_workspace();
    let source = workspace.join("source");
    let clone = workspace.join("clone");
    let identity = fs::read(workspace.join("identity.txt")).expect("read quickstart identity");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(source.join(".gitveilrc.json")).expect("read quickstart manifest"),
    )
    .expect("parse quickstart manifest");
    let recipient = manifest["recipientPolicies"]["team"]["age"][0]
        .as_str()
        .expect("quickstart recipient");
    assert_no_secret_output(
        &output,
        &[&identity, recipient.as_bytes(), PLAINTEXT_CANARY],
    );

    assert_eq!(
        fs::read(source.join(".gitignore")).expect("read managed ignore block"),
        b"# BEGIN gitveil managed files\n/.env\n!/.env.gitveil\n# END gitveil managed files\n"
    );

    let tree = assert_success(
        command_output(
            fixture
                .isolated_command(&workspace, &source, Path::new("git"))
                .args(["ls-tree", "-r", "--name-only", "HEAD"]),
        ),
        "read quickstart commit tree",
    );
    let tracked = String::from_utf8(tree.stdout).expect("tree paths are UTF-8");
    assert!(tracked.lines().any(|path| path == ".env.gitveil"));
    assert!(!tracked.lines().any(|path| path == ".env"));

    let plaintext_index = command_output(
        fixture
            .isolated_command(&workspace, &source, Path::new("git"))
            .args(["ls-files", "--error-unmatch", ".env"]),
    );
    assert_eq!(plaintext_index.status.code(), Some(1));
    assert_success(
        command_output(
            fixture
                .isolated_command(&workspace, &source, Path::new("git"))
                .args(["ls-files", "--error-unmatch", ".env.gitveil"]),
        ),
        "confirm tracked ciphertext",
    );
    assert_success(
        command_output(
            fixture
                .isolated_command(&workspace, &source, Path::new("git"))
                .args(["check-ignore", "-q", ".env"]),
        ),
        "confirm ignored plaintext",
    );
    let ciphertext_ignore = command_output(
        fixture
            .isolated_command(&workspace, &source, Path::new("git"))
            .args(["check-ignore", "-q", ".env.gitveil"]),
    );
    assert_eq!(ciphertext_ignore.status.code(), Some(1));

    assert_eq!(
        fs::read(source.join(".env")).expect("read source plaintext"),
        fs::read(clone.join(".env")).expect("read cloned plaintext")
    );
    assert_mode(&workspace.join("identity.txt"), 0o600);
    assert_mode(&clone.join(".env"), 0o600);

    let status = assert_success(
        command_output(
            fixture
                .isolated_command(&workspace, &clone, &fixture.gitveil)
                .env("SOPS_BIN", sops_binary())
                .args(["status", ".env"]),
        ),
        "independent quickstart status",
    );
    assert!(contains(&status.stdout, b".env: clean"));
    let verify = assert_success(
        command_output(
            fixture
                .isolated_command(&workspace, &clone, &fixture.gitveil)
                .env("SOPS_BIN", sops_binary())
                .arg("verify"),
        ),
        "independent quickstart verify",
    );
    assert!(verify.stdout.is_empty());
}

#[test]
fn executable_example_cleans_up_after_success_by_default() {
    let fixture = QuickstartFixture::new();
    let output = fixture.run(&[]);
    assert!(output.status.success());
    assert!(contains(
        &output.stdout,
        b"Gitveil quickstart completed successfully."
    ));
    assert_no_secret_output(&output, &[b"AGE-SECRET-KEY-", b"age1", PLAINTEXT_CANARY]);
    fixture.assert_no_workspaces();
}

#[test]
fn executable_example_preserves_diagnostics_redacts_secrets_and_cleans_up_on_failure() {
    let fixture = QuickstartFixture::new();
    let failing_sops = fixture.root.path().join("not-sops");
    fs::write(
        &failing_sops,
        b"#!/bin/sh\nprintf '%s\\n' 'forced SOPS process failure' >&2\nexit 9\n",
    )
    .expect("write failing SOPS");
    fs::set_permissions(&failing_sops, fs::Permissions::from_mode(0o755))
        .expect("make failing SOPS executable");
    let mut command = fixture.command();
    command.env("SOPS_BIN", failing_sops);
    let output = child_output_with_timeout(
        command.spawn().expect("start failing quickstart"),
        QUICKSTART_TIMEOUT,
    );

    assert!(!output.status.success());
    assert!(contains(&output.stderr, b"gitveil seal failed"));
    assert_no_secret_output(&output, &[b"AGE-SECRET-KEY-", b"age1", PLAINTEXT_CANARY]);
    fixture.assert_no_workspaces();
}

#[test]
fn executable_example_redacts_age_keygen_failure_and_cleans_up() {
    let fixture = QuickstartFixture::new();
    let failing_age_keygen = fixture.root.path().join("failing-age-keygen");
    fs::write(
        &failing_age_keygen,
        b"#!/bin/sh\nif [ \"${1:-}\" = \"--version\" ]; then\n  printf 'v1.3.1\\n'\n  exit 0\nfi\nprintf '%s\\n' 'AGE-SECRET-KEY-FAILURE-CANARY' >&2\nexit 9\n",
    )
    .expect("write failing age-keygen");
    fs::set_permissions(&failing_age_keygen, fs::Permissions::from_mode(0o755))
        .expect("make failing age-keygen executable");
    let mut command = fixture.command();
    command.env("AGE_KEYGEN_BIN", failing_age_keygen);
    let output = child_output_with_timeout(
        command.spawn().expect("start failing quickstart"),
        QUICKSTART_TIMEOUT,
    );

    assert!(!output.status.success());
    assert!(contains(
        &output.stderr,
        b"age-keygen identity generation failed with exit code 9"
    ));
    assert_no_secret_output(
        &output,
        &[
            b"AGE-SECRET-KEY-",
            b"FAILURE-CANARY",
            b"age1",
            PLAINTEXT_CANARY,
        ],
    );
    fixture.assert_no_workspaces();
}

#[test]
fn executable_example_does_not_treat_a_git_probe_failure_as_a_safe_negative() {
    let fixture = QuickstartFixture::new();
    fixture.replace_tool(
        "git",
        b"#!/bin/sh\nfor argument in \"$@\"; do\n  if [ \"$argument\" = \"--error-unmatch\" ]; then\n    printf '%s\\n' 'forced git ls-files failure' >&2\n    exit 128\n  fi\ndone\nexec /usr/bin/git \"$@\"\n",
    );
    let output = fixture.run(&[]);

    assert!(!output.status.success());
    assert!(contains(&output.stderr, b"forced git ls-files failure"));
    assert!(contains(&output.stderr, b"git ls-files failed"));
    assert_no_secret_output(&output, &[b"AGE-SECRET-KEY-", b"age1", PLAINTEXT_CANARY]);
    fixture.assert_no_workspaces();
}

#[test]
fn executable_example_does_not_treat_a_git_ignore_failure_as_not_ignored() {
    let fixture = QuickstartFixture::new();
    fixture.replace_tool(
        "git",
        b"#!/bin/sh\nif [ \"${1:-}\" = \"check-ignore\" ]; then\n  for argument in \"$@\"; do\n    if [ \"$argument\" = \"-q\" ]; then\n      printf '%s\\n' 'forced git check-ignore failure' >&2\n      exit 128\n    fi\n  done\nfi\nexec /usr/bin/git \"$@\"\n",
    );
    let output = fixture.run(&[]);

    assert!(!output.status.success());
    assert!(contains(&output.stderr, b"forced git check-ignore failure"));
    assert!(contains(&output.stderr, b"git check-ignore failed"));
    assert_no_secret_output(&output, &[b"AGE-SECRET-KEY-", b"age1", PLAINTEXT_CANARY]);
    fixture.assert_no_workspaces();
}

#[test]
fn executable_example_cleans_up_its_workspace_when_age_keygen_cannot_start() {
    let fixture = QuickstartFixture::new();
    let mut command = fixture.command();
    command.env(
        "AGE_KEYGEN_BIN",
        fixture.root.path().join("missing-age-keygen"),
    );
    let output = child_output_with_timeout(
        command.spawn().expect("start dependency failure"),
        QUICKSTART_TIMEOUT,
    );

    assert!(!output.status.success());
    assert!(contains(
        &output.stderr,
        b"AGE_KEYGEN_BIN does not point to a file"
    ));
    assert!(contains(
        &output.stderr,
        b"Gitveil quickstart failed: gitveil identity generation failed"
    ));
    assert_no_secret_output(&output, &[b"AGE-SECRET-KEY-", b"age1", PLAINTEXT_CANARY]);
    fixture.assert_no_workspaces();
}

#[test]
fn executable_example_reports_a_missing_gitveil_before_creating_a_workspace() {
    let fixture = QuickstartFixture::new();
    let mut command = fixture.command();
    command.env("GITVEIL_BIN", fixture.root.path().join("missing-gitveil"));
    let output = child_output_with_timeout(
        command.spawn().expect("start dependency failure"),
        QUICKSTART_TIMEOUT,
    );

    assert!(!output.status.success());
    assert!(contains(&output.stderr, b"gitveil is required"));
    assert_no_secret_output(&output, &[b"AGE-SECRET-KEY-", b"age1", PLAINTEXT_CANARY]);
    fixture.assert_no_workspaces();
}

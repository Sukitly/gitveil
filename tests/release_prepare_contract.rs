//! Failure-path contract for `scripts/prepare-release.py`: every content and
//! tool check runs before the first write, a write-phase failure rolls the
//! three release files back, and a push that loses its pull request leaves a
//! recoverable, documented state. The happy path past `gh pr create`
//! requires an authenticated GitHub CLI and is exercised by real releases,
//! not here; `gh` is stubbed only at that external boundary.

pub mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use support::command_output;

const MANIFEST: &str = "[package]\n\
name = \"gitveil\"\n\
version = \"0.1.0\"\n\
edition = \"2021\"\n";

const README: &str = "# Fixture\n\
Pinned: https://github.com/Sukitly/gitveil/releases/download/v0.1.0/gitveil-installer.sh\n\
Latest: https://github.com/Sukitly/gitveil/releases/latest/download/gitveil-installer.sh\n";

struct ReleaseFixture {
    root: tempfile::TempDir,
    home: tempfile::TempDir,
    origin: tempfile::TempDir,
    stub_path: Option<PathBuf>,
}

impl ReleaseFixture {
    fn new(readme: &str, manifest: &str) -> Self {
        let root = tempfile::tempdir().expect("fixture root");
        let home = tempfile::tempdir().expect("fixture home");
        let origin = tempfile::tempdir().expect("fixture origin");
        fs::write(
            home.path().join(".gitconfig"),
            "[user]\n\tname = Release Fixture\n\temail = release@example.invalid\n",
        )
        .expect("fixture gitconfig");

        fs::write(root.path().join("Cargo.toml"), manifest).expect("fixture manifest");
        fs::write(root.path().join("README.md"), readme).expect("fixture readme");
        fs::create_dir(root.path().join("src")).expect("fixture src");
        fs::write(root.path().join("src/main.rs"), "fn main() {}\n").expect("fixture main");
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("repository root");
        let scripts = root.path().join("scripts");
        fs::create_dir_all(scripts.join("_lib")).expect("fixture scripts");
        for relative in [
            "scripts/prepare-release.py",
            "scripts/_lib/__init__.py",
            "scripts/_lib/release_version.py",
        ] {
            fs::copy(repository_root.join(relative), root.path().join(relative))
                .expect("copy release script");
        }

        let fixture = Self {
            root,
            home,
            origin,
            stub_path: None,
        };
        fixture.git(&["init", "-q"]);
        fixture.git(&["symbolic-ref", "HEAD", "refs/heads/main"]);
        assert!(
            fixture
                .cargo(&["generate-lockfile", "--offline"])
                .status
                .success(),
            "fixture lockfile"
        );
        fixture.git(&["add", "-A"]);
        fixture.git(&["commit", "-qm", "fixture"]);
        let origin_path = fixture.origin.path().join("origin.git");
        assert!(
            fixture
                .command("git")
                .args(["init", "-q", "--bare"])
                .arg(&origin_path)
                .output()
                .expect("bare origin")
                .status
                .success()
        );
        fixture.git(&[
            "remote",
            "add",
            "origin",
            origin_path.to_str().expect("utf-8"),
        ]);
        fixture.git(&["push", "-qu", "origin", "main"]);
        fixture
    }

    /// Installs a `gh` stub: `auth status` succeeds, everything else follows
    /// `pr_create_succeeds`. This is the external boundary the tests cannot
    /// exercise for real.
    fn stub_gh(&mut self, pr_create_succeeds: bool) {
        use std::os::unix::fs::PermissionsExt;

        // The stub lives outside the repository so it never dirties the
        // worktree the script is about to inspect.
        let directory = self.home.path().join("stub-bin");
        fs::create_dir_all(&directory).expect("stub directory");
        let exit = i32::from(!pr_create_succeeds);
        let body = format!(
            "#!/bin/sh\nif [ \"$1\" = auth ]; then exit 0; fi\n\
             if [ \"$1\" = pr ]; then echo https://example.invalid/pr/1; exit {exit}; fi\nexit 1\n"
        );
        let stub = directory.join("gh");
        fs::write(&stub, body).expect("stub gh");
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o700)).expect("stub mode");
        self.stub_path = Some(directory);
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(self.root.path())
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE");
        if let Some(stub) = &self.stub_path {
            let path = std::env::var_os("PATH").expect("PATH");
            let mut entries = vec![stub.clone()];
            entries.extend(std::env::split_paths(&path));
            command.env("PATH", std::env::join_paths(entries).expect("join PATH"));
        }
        command
    }

    fn git(&self, args: &[&str]) -> Output {
        let output = command_output(self.command("git").args(args));
        assert!(output.status.success(), "git {args:?} must succeed");
        output
    }

    fn cargo(&self, args: &[&str]) -> Output {
        command_output(self.command("cargo").args(args))
    }

    fn prepare_release(&self, level: &str) -> Output {
        command_output(
            self.command("python3")
                .arg("scripts/prepare-release.py")
                .arg(level)
                .arg("--yes"),
        )
    }

    fn read(&self, path: &str) -> Vec<u8> {
        fs::read(self.root.path().join(path)).expect("read fixture file")
    }

    fn assert_untouched(&self, manifest: &str, readme: &str) {
        let status = command_output(self.command("git").args(["status", "--porcelain"]));
        assert!(
            status.stdout.is_empty(),
            "the working tree must stay clean: {}",
            String::from_utf8_lossy(&status.stdout)
        );
        let branch = command_output(self.command("git").args(["branch", "--show-current"]));
        assert_eq!(String::from_utf8_lossy(&branch.stdout).trim(), "main");
        assert_eq!(self.read("Cargo.toml"), manifest.as_bytes());
        assert_eq!(self.read("README.md"), readme.as_bytes());
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn refusals_happen_before_any_write() {
    // Off main.
    let fixture = ReleaseFixture::new(README, MANIFEST);
    fixture.git(&["switch", "-qc", "feature"]);
    let output = fixture.prepare_release("patch");
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("main"),
        "{}",
        stderr_of(&output)
    );
    fixture.git(&["switch", "-q", "main"]);
    fixture.assert_untouched(MANIFEST, README);

    // Dirty worktree.
    fs::write(fixture.root.path().join("README.md"), "dirty\n").expect("dirty readme");
    let output = fixture.prepare_release("patch");
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("uncommitted"),
        "{}",
        stderr_of(&output)
    );
    fixture.git(&["checkout", "--", "README.md"]);

    // Behind origin/main.
    fs::write(fixture.root.path().join("extra.txt"), "extra\n").expect("extra file");
    fixture.git(&["add", "extra.txt"]);
    fixture.git(&["commit", "-qm", "extra"]);
    fixture.git(&["push", "-q", "origin", "main"]);
    fixture.git(&["reset", "-q", "--hard", "HEAD~1"]);
    let output = fixture.prepare_release("patch");
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("not up to date"),
        "{}",
        stderr_of(&output)
    );
}

#[test]
fn a_readme_without_pinned_links_is_refused_before_the_first_write() {
    let readme = "# Fixture\nLatest only: releases/latest/download/gitveil-installer.sh\n";
    let fixture = ReleaseFixture::new(readme, MANIFEST);
    let output = fixture.prepare_release("patch");
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("pinned release download links"),
        "{}",
        stderr_of(&output)
    );
    fixture.assert_untouched(MANIFEST, readme);
}

#[test]
fn an_existing_branch_or_tag_is_refused_before_the_first_write() {
    let fixture = ReleaseFixture::new(README, MANIFEST);
    fixture.git(&["tag", "v0.1.1"]);
    let output = fixture.prepare_release("patch");
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("tag v0.1.1 already exists"),
        "{}",
        stderr_of(&output)
    );
    fixture.git(&["tag", "-d", "v0.1.1"]);

    fixture.git(&["push", "-q", "origin", "main:refs/heads/release/v0.1.1"]);
    let output = fixture.prepare_release("patch");
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("branch release/v0.1.1 already exists"),
        "{}",
        stderr_of(&output)
    );
    fixture.assert_untouched(MANIFEST, README);
}

// A write-phase failure (here: `cargo update` on a manifest whose dependency
// cannot resolve) must restore all three release files and leave main clean.
#[test]
fn a_write_phase_failure_rolls_back_every_release_file() {
    // The lockfile is generated while the manifest is healthy; the broken
    // dependency lands afterwards so only the script's `cargo update` fails.
    let mut fixture = ReleaseFixture::new(README, MANIFEST);
    let broken = format!("{MANIFEST}\n[dependencies]\nmissing = {{ path = \"does-not-exist\" }}\n");
    fs::write(fixture.root.path().join("Cargo.toml"), &broken).expect("break the manifest");
    fixture.git(&["add", "Cargo.toml"]);
    fixture.git(&["commit", "-qm", "break dependency"]);
    fixture.git(&["push", "-q", "origin", "main"]);
    fixture.stub_gh(true);
    let output = fixture.prepare_release("patch");
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("rolled back"),
        "the rollback must be reported: {}",
        stderr_of(&output)
    );
    fixture.assert_untouched(&broken, README);
    let remote = command_output(fixture.command("git").args([
        "ls-remote",
        "--heads",
        "origin",
        "release/v0.1.1",
    ]));
    assert!(remote.stdout.is_empty(), "nothing may be pushed");
}

// When the push succeeded but the pull request was not created, the state is
// recoverable and the error says exactly how.
#[test]
fn a_failed_pull_request_reports_the_recovery_commands() {
    let mut fixture = ReleaseFixture::new(README, MANIFEST);
    fixture.stub_gh(false);
    let output = fixture.prepare_release("patch");
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("gh pr create --head release/v0.1.1"),
        "retry command must be named: {stderr}"
    );
    assert!(
        stderr.contains("git push origin --delete release/v0.1.1"),
        "abandon command must be named: {stderr}"
    );
    // The branch is pushed (that is the recoverable state), and the local
    // checkout is back on a clean main.
    let remote = command_output(fixture.command("git").args([
        "ls-remote",
        "--heads",
        "origin",
        "release/v0.1.1",
    ]));
    assert!(!remote.stdout.is_empty(), "the pushed branch must survive");
    let branch = command_output(fixture.command("git").args(["branch", "--show-current"]));
    assert_eq!(String::from_utf8_lossy(&branch.stdout).trim(), "main");
    assert_eq!(fixture.read("Cargo.toml"), MANIFEST.as_bytes());
    assert_eq!(fixture.read("README.md"), README.as_bytes());
}

// The pure version logic agrees with the release contract: bumps, the
// [package]-anchored read/write, and the pinned-link rewrite that must not
// touch releases/latest.
#[test]
fn pure_version_logic_matches_the_release_contract() {
    let script = r#"
import importlib.util
import sys

spec = importlib.util.spec_from_file_location(
    "release_version", "scripts/_lib/release_version.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

assert module.bumped_version("0.2.9", "patch") == "0.2.10"
assert module.bumped_version("0.2.9", "minor") == "0.3.0"
assert module.bumped_version("0.2.9", "major") == "1.0.0"

manifest = (
    "[dependencies.other]\nversion = \"9.9.9\"\n\n"
    "[package]\nname = \"gitveil\"\nversion = \"0.2.0\"\n\n"
    "[dev-dependencies.more]\nversion = \"8.8.8\"\n"
)
assert module.package_version(manifest) == "0.2.0"
rewritten = module.set_package_version(manifest, "0.3.0")
assert 'version = "0.3.0"' in rewritten
assert 'version = "9.9.9"' in rewritten
assert 'version = "8.8.8"' in rewritten
assert 'version = "0.2.0"' not in rewritten

document = (
    "releases/download/v0.2.0/gitveil-installer.sh\n"
    "releases/latest/download/gitveil-installer.sh\n"
)
updated = module.rewrite_pinned_downloads(document, "0.3.0")
assert "releases/download/v0.3.0/" in updated
assert "releases/latest/download/" in updated

for malformed in ("version = \"1.2.3\"\n", "[package]\nname = \"gitveil\"\n"):
    try:
        module.package_version(malformed)
    except module.ReleaseVersionError:
        pass
    else:
        raise AssertionError(f"malformed manifest accepted: {malformed!r}")

print("OK")
"#;
    let output = command_output(
        Command::new("python3")
            .arg("-c")
            .arg(script)
            .current_dir(env!("CARGO_MANIFEST_DIR")),
    );
    assert!(
        output.status.success(),
        "pure logic assertions failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("OK"));
}

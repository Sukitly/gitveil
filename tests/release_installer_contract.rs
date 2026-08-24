pub mod support;

use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use support::{assert_success, command_output};

const VERSION: &str = "9.8.7";
const TARGETS: [(&str, &str); 4] = [
    ("darwin", "aarch64"),
    ("darwin", "x86_64"),
    ("linux", "aarch64"),
    ("linux", "x86_64"),
];
const INSTALL_FILES: [(&str, u32); 8] = [
    ("share/licenses/gitveil/LICENSE", 0o644),
    ("share/licenses/gitveil/SOPS-MPL-2.0.txt", 0o644),
    ("share/licenses/gitveil/SOPS-NOTICE.txt", 0o644),
    ("share/licenses/gitveil/AGE-BSD-3-Clause.txt", 0o644),
    ("share/licenses/gitveil/AGE-NOTICE.txt", 0o644),
    ("libexec/gitveil/sops", 0o755),
    ("libexec/gitveil/age-keygen", 0o755),
    ("bin/gitveil", 0o755),
];

#[derive(Clone, Copy, Eq, PartialEq)]
enum CurrentArchiveMutation {
    None,
    UnexpectedMember,
    SymlinkedSidecar,
}

struct ReleaseFixture {
    temporary: tempfile::TempDir,
    archives: PathBuf,
    output: PathBuf,
    home: PathBuf,
}

impl ReleaseFixture {
    fn new(mutation: CurrentArchiveMutation) -> Self {
        let temporary = tempfile::tempdir().expect("release fixture");
        let archives = temporary.path().join("archives");
        let output = temporary.path().join("output");
        let home = temporary.path().join("home");
        fs::create_dir_all(&archives).expect("archive directory");
        fs::create_dir_all(&home).expect("isolated home");
        for (system, machine) in TARGETS {
            let selected_mutation = if (system, machine) == current_target() {
                mutation
            } else {
                CurrentArchiveMutation::None
            };
            create_archive(
                temporary.path(),
                &archives,
                system,
                machine,
                selected_mutation,
            );
        }
        Self {
            temporary,
            archives,
            output,
            home,
        }
    }

    fn assemble(&self) -> Output {
        self.assemble_version(VERSION)
    }

    fn assemble_version(&self, version: &str) -> Output {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        command_output(
            Command::new(root.join("scripts/assemble-release-assets.py"))
                .current_dir(root)
                .arg("--version")
                .arg(version)
                .arg("--archive-dir")
                .arg(&self.archives)
                .arg("--output-dir")
                .arg(&self.output),
        )
    }

    fn installer(&self) -> PathBuf {
        self.output.join("gitveil-installer.sh")
    }

    fn current_archive(&self) -> PathBuf {
        let (system, machine) = current_target();
        self.archives.join(archive_name(system, machine))
    }

    fn fake_bin(&self, fail_during_commit: bool) -> PathBuf {
        let fake_bin = self.temporary.path().join(if fail_during_commit {
            "fake-bin-failing-mv"
        } else {
            "fake-bin"
        });
        fs::create_dir_all(&fake_bin).expect("fake executable directory");
        write_executable(
            &fake_bin.join("curl"),
            r#"#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output)
            output=$2
            shift 2
            ;;
        https://*)
            url=$1
            shift
            ;;
        *)
            shift
            ;;
    esac
done
[ -n "$output" ]
[ -n "$url" ]
printf '%s\n' "$url" > "$FAKE_CURL_LOG"
cp "$FAKE_RELEASE_ASSETS/${url##*/}" "$output"
"#,
        );
        write_executable(
            &fake_bin.join("sudo"),
            r#"#!/bin/sh
printf 'sudo was invoked\n' > "$FAKE_SUDO_MARKER"
exit 99
"#,
        );
        if fail_during_commit {
            write_executable(
                &fake_bin.join("mv"),
                r#"#!/bin/sh
set -eu
case "$1" in
    */payload/libexec/gitveil/sops)
        exit 73
        ;;
esac
exec /bin/mv "$@"
"#,
            );
        }
        fake_bin
    }

    fn run_installer(&self, prefix: Option<&Path>, fail_during_commit: bool) -> Output {
        let fake_bin = self.fake_bin(fail_during_commit);
        let inherited_path = std::env::var_os("PATH").expect("test PATH");
        let path = std::env::join_paths(
            std::iter::once(fake_bin.as_path()).chain(
                std::env::split_paths(&inherited_path)
                    .collect::<Vec<_>>()
                    .iter()
                    .map(PathBuf::as_path),
            ),
        )
        .expect("isolated PATH");
        let profile = self.home.join(".profile");
        if !profile.exists() {
            fs::write(&profile, b"profile-canary\n").expect("profile canary");
        }
        let curl_log = self.temporary.path().join("curl.log");
        let sudo_marker = self.temporary.path().join("sudo-invoked");
        let mut command = Command::new("sh");
        command
            .arg(self.installer())
            .env("HOME", &self.home)
            .env("PATH", path)
            .env("FAKE_RELEASE_ASSETS", &self.archives)
            .env("FAKE_CURL_LOG", curl_log)
            .env("FAKE_SUDO_MARKER", sudo_marker);
        if let Some(prefix) = prefix {
            command.arg("--prefix").arg(prefix);
        }
        command_output(&mut command)
    }
}

fn current_target() -> (&'static str, &'static str) {
    let system = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        other => panic!("unsupported test system: {other}"),
    };
    let machine = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        other => panic!("unsupported test architecture: {other}"),
    };
    (system, machine)
}

fn archive_name(system: &str, machine: &str) -> String {
    format!("gitveil-v{VERSION}-{system}-{machine}.tar.gz")
}

fn archive_root(system: &str, machine: &str) -> String {
    format!("gitveil-v{VERSION}-{system}-{machine}")
}

fn write_executable(path: &Path, content: &str) {
    fs::write(path, content).expect("write executable fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("executable fixture mode");
}

fn create_archive(
    temporary: &Path,
    archive_directory: &Path,
    system: &str,
    machine: &str,
    mutation: CurrentArchiveMutation,
) {
    let root_name = archive_root(system, machine);
    let staging = temporary
        .join("staging")
        .join(format!("{system}-{machine}"));
    let root = staging.join(&root_name);
    for (relative, mode) in INSTALL_FILES {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("release member parent"))
            .expect("release member directory");
        if mutation == CurrentArchiveMutation::SymlinkedSidecar
            && relative == "libexec/gitveil/age-keygen"
        {
            symlink("sops", &path).expect("symlinked sidecar fixture");
        } else if relative.starts_with("share/licenses/") {
            fs::write(&path, format!("fixture {relative}\n")).expect("license fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .expect("license fixture mode");
        } else {
            write_executable(
                &path,
                &format!("#!/bin/sh\nprintf '%s\\n' 'fixture {relative} {VERSION}'\n"),
            );
        }
    }
    let archive = archive_directory.join(archive_name(system, machine));
    if mutation == CurrentArchiveMutation::UnexpectedMember {
        let python = r#"import io
import pathlib
import sys
import tarfile
root = pathlib.Path(sys.argv[1])
archive = pathlib.Path(sys.argv[2])
with tarfile.open(archive, "w:gz") as output:
    output.add(root, arcname=root.name)
    payload = b"must-not-extract"
    member = tarfile.TarInfo(f"{root.name}/../escape")
    member.size = len(payload)
    output.addfile(member, io.BytesIO(payload))
"#;
        assert_success(
            command_output(
                Command::new("python3")
                    .arg("-c")
                    .arg(python)
                    .arg(&root)
                    .arg(&archive),
            ),
            "malicious archive fixture",
        );
    } else {
        assert_success(
            command_output(
                Command::new("tar")
                    .arg("-czf")
                    .arg(&archive)
                    .arg("-C")
                    .arg(&staging)
                    .arg(&root_name),
            ),
            "release archive fixture",
        );
    }
}

fn digest(path: &Path) -> String {
    let bytes = fs::read(path).expect("digest input");
    hex::encode(Sha256::digest(bytes))
}

fn assert_complete_install(prefix: &Path) {
    for (relative, mode) in INSTALL_FILES {
        let path = prefix.join(relative);
        let metadata = fs::symlink_metadata(&path).expect("installed release member");
        assert!(metadata.is_file(), "{} must be a file", path.display());
        assert_eq!(metadata.permissions().mode() & 0o777, mode, "{relative}");
    }
}

#[test]
fn release_asset_assembler_emits_a_version_pinned_installer_and_manifest() {
    let fixture = ReleaseFixture::new(CurrentArchiveMutation::None);
    assert_success(fixture.assemble(), "release asset assembly");

    let installer = fixture.installer();
    assert_eq!(
        fs::metadata(&installer)
            .expect("installer metadata")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    let script = fs::read_to_string(&installer).expect("generated installer");
    assert!(script.contains("releases/download/v9.8.7"));
    assert!(!script.contains("releases/latest"));
    assert!(!script.contains("/main/"));
    for (system, machine) in TARGETS {
        let archive = fixture.archives.join(archive_name(system, machine));
        let assembled = fixture.output.join(archive_name(system, machine));
        assert_eq!(
            fs::read(&assembled).expect("assembled native archive"),
            fs::read(&archive).expect("input native archive")
        );
        assert!(script.contains(&archive_name(system, machine)));
        assert!(script.contains(&digest(&archive)));
    }

    let mut assets = TARGETS
        .iter()
        .map(|(system, machine)| fixture.archives.join(archive_name(system, machine)))
        .collect::<Vec<_>>();
    assets.push(installer);
    assets.sort_by_key(|path| path.file_name().map(ToOwned::to_owned));
    let mut expected = String::new();
    for path in &assets {
        writeln!(
            expected,
            "{}  {}",
            digest(path),
            path.file_name()
                .expect("release asset name")
                .to_string_lossy()
        )
        .expect("checksum manifest expectation");
    }
    assert_eq!(
        fs::read_to_string(fixture.output.join("SHA256SUMS")).expect("checksum manifest"),
        expected
    );
}

#[test]
fn release_asset_assembler_rejects_a_non_exact_version_without_output() {
    let fixture = ReleaseFixture::new(CurrentArchiveMutation::None);

    let output = fixture.assemble_version("v9.8.7");
    assert!(!output.status.success());
    assert!(!fixture.output.exists());
}

#[test]
fn release_asset_assembler_requires_all_four_native_archives() {
    let fixture = ReleaseFixture::new(CurrentArchiveMutation::None);
    fs::remove_file(fixture.archives.join(archive_name("linux", "aarch64")))
        .expect("remove release target fixture");

    let output = fixture.assemble();
    assert!(!output.status.success());
    assert!(!fixture.output.exists());
}

#[test]
fn release_installer_selects_the_current_platform_and_installs_the_complete_layout() {
    let fixture = ReleaseFixture::new(CurrentArchiveMutation::None);
    assert_success(fixture.assemble(), "release asset assembly");

    let output = assert_success(fixture.run_installer(None, false), "release installation");
    let prefix = fixture.home.join(".local");
    assert_complete_install(&prefix);
    assert!(String::from_utf8_lossy(&output.stdout).contains(prefix.to_string_lossy().as_ref()));
    let requested = fs::read_to_string(fixture.temporary.path().join("curl.log"))
        .expect("requested release URL");
    let current_archive = fixture.current_archive();
    let expected_suffix = format!(
        "/{}\n",
        current_archive
            .file_name()
            .expect("current archive name")
            .to_string_lossy()
    );
    assert!(requested.ends_with(&expected_suffix));
    assert_eq!(
        fs::read(fixture.home.join(".profile")).expect("preserved shell profile"),
        b"profile-canary\n"
    );
    assert!(!fixture.temporary.path().join("sudo-invoked").exists());
    assert!(!fixture.home.join(".config/sops/age/keys.txt").exists());
}

#[test]
fn release_installer_help_does_not_require_home_or_download() {
    let fixture = ReleaseFixture::new(CurrentArchiveMutation::None);
    assert_success(fixture.assemble(), "release asset assembly");

    let output = assert_success(
        command_output(
            Command::new("sh")
                .arg(fixture.installer())
                .arg("--help")
                .env_remove("HOME"),
        ),
        "release installer help",
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("--prefix PATH"));
}

#[test]
fn release_installer_rejects_a_relative_prefix_without_downloading() {
    let fixture = ReleaseFixture::new(CurrentArchiveMutation::None);
    assert_success(fixture.assemble(), "release asset assembly");

    let output = fixture.run_installer(Some(Path::new("relative-prefix")), false);
    assert!(!output.status.success());
    assert!(!fixture.temporary.path().join("curl.log").exists());
}

#[test]
fn release_installer_rejects_a_checksum_mismatch_without_changing_an_existing_install() {
    let fixture = ReleaseFixture::new(CurrentArchiveMutation::None);
    assert_success(fixture.assemble(), "release asset assembly");
    let prefix = fixture.temporary.path().join("prefix");
    write_existing_install(&prefix);
    fs::OpenOptions::new()
        .append(true)
        .open(fixture.current_archive())
        .expect("mutated archive")
        .write_all(b"mutated")
        .expect("archive mutation");

    let output = fixture.run_installer(Some(&prefix), false);
    assert!(!output.status.success());
    assert_existing_install(&prefix);
}

#[test]
fn release_installer_rejects_unexpected_archive_members_before_extraction() {
    let fixture = ReleaseFixture::new(CurrentArchiveMutation::UnexpectedMember);
    assert_success(fixture.assemble(), "release asset assembly");
    let prefix = fixture.temporary.path().join("prefix");

    let output = fixture.run_installer(Some(&prefix), false);
    assert!(!output.status.success());
    assert!(!prefix.join("bin/gitveil").exists());
    assert!(!fixture.temporary.path().join("escape").exists());
}

#[test]
fn release_installer_rejects_symlinked_archive_members() {
    let fixture = ReleaseFixture::new(CurrentArchiveMutation::SymlinkedSidecar);
    assert_success(fixture.assemble(), "release asset assembly");
    let prefix = fixture.temporary.path().join("prefix");

    let output = fixture.run_installer(Some(&prefix), false);
    assert!(!output.status.success());
    assert!(!prefix.join("libexec/gitveil/age-keygen").exists());
}

#[test]
fn release_installer_rolls_back_every_file_when_commit_fails() {
    let fixture = ReleaseFixture::new(CurrentArchiveMutation::None);
    assert_success(fixture.assemble(), "release asset assembly");
    let prefix = fixture.temporary.path().join("prefix");
    write_existing_install(&prefix);

    let output = fixture.run_installer(Some(&prefix), true);
    assert!(!output.status.success());
    assert_existing_install(&prefix);
}

fn write_existing_install(prefix: &Path) {
    for (relative, mode) in INSTALL_FILES {
        let path = prefix.join(relative);
        fs::create_dir_all(path.parent().expect("existing member parent"))
            .expect("existing install directory");
        fs::write(&path, format!("existing:{relative}\n")).expect("existing install member");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("existing member mode");
    }
}

fn assert_existing_install(prefix: &Path) {
    for (relative, mode) in INSTALL_FILES {
        let path = prefix.join(relative);
        assert_eq!(
            fs::read(&path).expect("preserved install member"),
            format!("existing:{relative}\n").as_bytes(),
            "{relative} must be restored"
        );
        assert_eq!(
            fs::metadata(path)
                .expect("preserved member metadata")
                .permissions()
                .mode()
                & 0o777,
            mode,
            "{relative} mode must be restored"
        );
    }
}

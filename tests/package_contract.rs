pub mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gitveil::sops::SOPS_VERSION;
use support::{assert_success, command_output, sops_binary};

fn installer_command() -> Command {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new("python3");
    command
        .current_dir(root)
        .arg("scripts/install-local.py")
        .arg("--skip-build")
        .arg("--binary")
        .arg(assert_cmd::cargo::cargo_bin!("gitveil"))
        .arg("--sops-bin")
        .arg(sops_binary());
    command
}

fn assert_installed_layout(prefix: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let files = [
        (PathBuf::from("bin/gitveil"), 0o755),
        (PathBuf::from("libexec/gitveil/sops"), 0o755),
        (PathBuf::from("share/licenses/gitveil/LICENSE"), 0o644),
        (
            PathBuf::from("share/licenses/gitveil/SOPS-MPL-2.0.txt"),
            0o644,
        ),
        (
            PathBuf::from("share/licenses/gitveil/SOPS-NOTICE.txt"),
            0o644,
        ),
    ];
    for (relative, expected_mode) in files {
        let installed = prefix.join(relative);
        let metadata = fs::metadata(&installed).expect("installed release member");
        assert!(metadata.is_file(), "{} must be a file", installed.display());
        assert_eq!(metadata.permissions().mode() & 0o777, expected_mode);
    }

    let installed_license =
        fs::read(prefix.join("share/licenses/gitveil/LICENSE")).expect("installed Gitveil license");
    let tracked_license = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("LICENSE"))
        .expect("tracked Gitveil license");
    assert_eq!(installed_license, tracked_license);

    // The redistribution notice names the bundled SOPS build. It is a tracked file
    // rather than generated output, so without this assertion a SOPS version bump
    // would ship a notice pointing at the wrong upstream source tree.
    let notice = fs::read_to_string(prefix.join("share/licenses/gitveil/SOPS-NOTICE.txt"))
        .expect("installed SOPS notice");
    let version = format!("{}.{}.{}", SOPS_VERSION.0, SOPS_VERSION.1, SOPS_VERSION.2);
    assert!(
        notice.contains(&version),
        "SOPS notice must name the bundled {version} build"
    );
    assert!(
        notice.contains(&format!("getsops/sops/tree/v{version}")),
        "SOPS notice must link the {version} source tree"
    );

    let output = command_output(Command::new(prefix.join("bin/gitveil")).arg("--version"));
    assert_success(output, "installed Gitveil version check");
}

#[test]
fn local_installer_defaults_to_cargo_home_and_installs_the_complete_layout() {
    let temporary = tempfile::tempdir().expect("installer fixture");
    let cargo_home = temporary.path().join("cargo-home");
    let output = command_output(
        installer_command()
            .env("HOME", temporary.path())
            .env("CARGO_HOME", &cargo_home),
    );
    assert_success(output, "default local install");
    assert_installed_layout(&cargo_home);
}

#[test]
fn local_installer_honors_a_custom_prefix_and_can_replace_an_existing_install() {
    let temporary = tempfile::tempdir().expect("installer fixture");
    let cargo_home = temporary.path().join("unused-cargo-home");
    let prefix = temporary.path().join("custom-prefix");

    for _ in 0..2 {
        let output = command_output(
            installer_command()
                .env("HOME", temporary.path())
                .env("CARGO_HOME", &cargo_home)
                .arg("--prefix")
                .arg(&prefix),
        );
        assert_success(output, "custom local install");
    }

    assert_installed_layout(&prefix);
    assert!(
        !cargo_home.exists(),
        "explicit prefix must override CARGO_HOME"
    );
}

#[test]
fn local_installer_rejects_a_directory_destination_without_partial_replacement() {
    let temporary = tempfile::tempdir().expect("installer fixture");
    let prefix = temporary.path().join("prefix");
    let existing_sidecar = prefix.join("libexec/gitveil/sops");
    fs::create_dir_all(existing_sidecar.parent().expect("sidecar parent"))
        .expect("create existing libexec");
    fs::write(&existing_sidecar, b"existing-sidecar").expect("write existing sidecar");
    fs::create_dir_all(prefix.join("bin/gitveil")).expect("create conflicting directory");

    let output = command_output(
        installer_command()
            .env("HOME", temporary.path())
            .arg("--prefix")
            .arg(&prefix),
    );
    assert!(!output.status.success());
    // The failure must be the destination conflict itself, not an unrelated
    // script error that happens to exit non-zero.
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("bin/gitveil"),
        "installer must fail on the conflicting destination"
    );
    assert_eq!(
        fs::read(&existing_sidecar).expect("read preserved sidecar"),
        b"existing-sidecar"
    );
    assert!(prefix.join("bin/gitveil").is_dir());
}

#[test]
fn release_packaging_rejects_a_sidecar_with_the_wrong_checksum_without_an_archive() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let temporary = tempfile::tempdir().expect("package fixture");
    let fake_sops = temporary.path().join("sops");
    fs::write(&fake_sops, b"not the official SOPS artifact").expect("fake sidecar");
    let output_dir = temporary.path().join("output");

    let output = command_output(
        Command::new("python3")
            .current_dir(root)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .arg("scripts/package-release.py")
            .arg("--skip-build")
            .arg("--binary")
            .arg(assert_cmd::cargo::cargo_bin!("gitveil"))
            .arg("--sops-bin")
            .arg(&fake_sops)
            .arg("--output-dir")
            .arg(&output_dir),
    );
    assert!(!output.status.success());
    // The failure must be the checksum verification itself, not an unrelated
    // script error that happens to exit non-zero.
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("SOPS checksum mismatch"),
        "packaging must fail on the sidecar checksum"
    );
    assert!(
        !output_dir.exists(),
        "failed packaging must emit no archive"
    );
}

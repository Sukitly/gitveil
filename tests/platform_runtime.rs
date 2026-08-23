pub mod support;

use std::fs;
use std::thread;
use std::time::{Duration, Instant};

use gitveil::error::SecretBytes;
use gitveil::runtime::{
    EditorEndpoint, PrivateRuntime, acquire_lock, receive_editor_payload, reject_editor_reuse,
    run_internal_editor,
};
use serial_test::serial;

#[test]
fn operation_lock_times_out_without_side_effects_and_releases_on_drop() {
    let root = tempfile::tempdir().expect("runtime parent");
    let runtime = PrivateRuntime::open(root.path().join("gitveil")).expect("runtime");
    let first = acquire_lock(&runtime, Duration::from_millis(100)).expect("first lock");
    let started = Instant::now();
    assert!(acquire_lock(&runtime, Duration::from_millis(75)).is_err());
    assert!(started.elapsed() >= Duration::from_millis(75));
    drop(first);
    acquire_lock(&runtime, Duration::from_millis(100)).expect("lock after release");
}

#[test]
#[serial]
fn authenticated_editor_ipc_transfers_payload_without_argv_or_filename_content() {
    let root = tempfile::tempdir().expect("runtime parent");
    let runtime = PrivateRuntime::open(root.path().join("gitveil")).expect("runtime");
    let target = runtime.root().join("sops-edit.yaml");
    fs::write(&target, b"old").expect("target");
    let endpoint = EditorEndpoint::bind(&runtime).expect("endpoint");
    let printable = endpoint.printable().to_owned();
    let token = endpoint.token().to_owned();
    let runtime_for_editor = runtime.root().to_path_buf();
    let target_for_editor = target.clone();
    let editor = thread::spawn(move || {
        run_internal_editor(&printable, &token, &runtime_for_editor, &target_for_editor)
    });
    let payload = SecretBytes::new(b"runtime-secret-canary".to_vec());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if receive_editor_payload(&endpoint, &payload).expect("IPC") {
            break;
        }
        assert!(Instant::now() < deadline, "editor did not connect");
        thread::sleep(Duration::from_millis(10));
    }
    editor
        .join()
        .expect("editor thread")
        .expect("editor result");
    assert_eq!(
        fs::read(&target).expect("edited target"),
        payload.as_slice()
    );
    assert!(!target.to_string_lossy().contains("runtime-secret-canary"));
    assert!(!endpoint.printable().contains("runtime-secret-canary"));
}

#[test]
#[serial]
fn sops_editor_cli_authenticates_via_token_file_and_replaces_target() {
    use std::process::{Command, Stdio};

    let root = tempfile::tempdir().expect("runtime parent");
    let runtime = PrivateRuntime::open(root.path().join("gitveil")).expect("runtime");
    let target = runtime.root().join("sops-edit.yaml");
    fs::write(&target, b"old").expect("target");
    let endpoint = EditorEndpoint::bind(&runtime).expect("endpoint");
    let token_file = runtime.root().join("editor-token");
    fs::write(&token_file, format!("{}\n", endpoint.token())).expect("token file");
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("gitveil"));
    command
        .arg("sops-editor")
        .arg("--endpoint")
        .arg(endpoint.printable())
        .arg("--token-file")
        .arg(&token_file)
        .arg("--runtime")
        .arg(runtime.root())
        .arg(&target)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().expect("spawn sops-editor");
    let payload = SecretBytes::new(b"token-file-payload".to_vec());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if receive_editor_payload(&endpoint, &payload).expect("IPC") {
            break;
        }
        assert!(Instant::now() < deadline, "editor did not connect");
        thread::sleep(Duration::from_millis(10));
    }
    let output = support::child_output(child);
    assert!(
        output.status.success(),
        "sops-editor must succeed with a token file"
    );
    assert_eq!(
        fs::read(&target).expect("edited target"),
        payload.as_slice()
    );
}

// The endpoint may be reachable beyond the runtime directory (Linux uses an
// abstract-namespace socket), so authentication failure must abort the
// operation instead of leaving the payload available for further attempts.
#[test]
#[serial]
fn editor_endpoint_fails_closed_on_a_wrong_token() {
    let root = tempfile::tempdir().expect("runtime parent");
    let runtime = PrivateRuntime::open(root.path().join("gitveil")).expect("runtime");
    let target = runtime.root().join("sops-edit.yaml");
    fs::write(&target, b"old").expect("target");
    let endpoint = EditorEndpoint::bind(&runtime).expect("endpoint");
    let printable = endpoint.printable().to_owned();
    let runtime_path = runtime.root().to_path_buf();
    let target_for_editor = target.clone();
    let editor = thread::spawn(move || {
        run_internal_editor(&printable, "wrong-token", &runtime_path, &target_for_editor)
    });
    let payload = SecretBytes::new(b"runtime-secret-canary".to_vec());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match receive_editor_payload(&endpoint, &payload) {
            Ok(true) => panic!("payload must not be delivered to a wrong token"),
            Ok(false) => {
                assert!(
                    Instant::now() < deadline,
                    "wrong-token connection must abort the operation"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
    assert!(editor.join().expect("editor thread").is_err());
    assert_eq!(
        fs::read(&target).expect("unchanged target"),
        b"old",
        "a rejected editor must not modify the target"
    );
}

#[test]
#[serial]
fn editor_endpoint_rejects_a_second_connection() {
    let root = tempfile::tempdir().expect("runtime parent");
    let runtime = PrivateRuntime::open(root.path().join("gitveil")).expect("runtime");
    let target = runtime.root().join("sops-edit.yaml");
    fs::write(&target, b"old").expect("target");
    let endpoint = EditorEndpoint::bind(&runtime).expect("endpoint");
    let printable = endpoint.printable().to_owned();
    let token = endpoint.token().to_owned();
    let runtime_path = runtime.root().to_path_buf();
    let editor =
        thread::spawn(move || run_internal_editor(&printable, &token, &runtime_path, &target));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if reject_editor_reuse(&endpoint).expect("reject reuse") {
            break;
        }
        assert!(Instant::now() < deadline, "second editor did not connect");
        thread::sleep(Duration::from_millis(10));
    }
    assert!(editor.join().expect("editor thread").is_err());
}

#[test]
fn test_process_timeout_kills_and_reaps_without_rendering_environment() {
    use std::process::{Command, Stdio};

    use support::child_output_with_timeout;

    let root = tempfile::tempdir().expect("timeout fixture");
    let marker = root.path().join("orphan-marker");
    let mut child = Command::new(std::env::current_exe().expect("test executable"));
    child
        .args(["--exact", "timeout_process_helper", "--nocapture"])
        .env("GITVEIL_TIMEOUT_HELPER", "timeout-secret-canary")
        .env("GITVEIL_TIMEOUT_MARKER", &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = child.spawn().expect("spawn timeout helper");
    let panic = std::panic::catch_unwind(|| {
        child_output_with_timeout(child, Duration::from_millis(50));
    })
    .expect_err("timeout should panic");
    let message = panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .expect("panic message");
    assert!(!message.contains("timeout-secret-canary"));
    thread::sleep(Duration::from_millis(100));
    assert!(
        !marker.exists(),
        "timed out child survived to publish output"
    );
}

#[test]
fn timeout_process_helper() {
    if std::env::var_os("GITVEIL_TIMEOUT_HELPER").is_none() {
        return;
    }
    thread::sleep(Duration::from_secs(10));
    fs::write(
        std::env::var_os("GITVEIL_TIMEOUT_MARKER").expect("marker path"),
        b"survived",
    )
    .expect("write orphan marker");
}

#[cfg(unix)]
#[test]
fn closed_runtime_executable_runs_while_cleanup_guard_is_alive() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let root = tempfile::tempdir().expect("runtime parent");
    let runtime = PrivateRuntime::open(root.path().join("gitveil")).expect("runtime");
    let executable = runtime
        .write_closed("executable-", b"#!/bin/sh\nexit 0\n")
        .expect("closed executable");
    fs::set_permissions(executable.path(), fs::Permissions::from_mode(0o700))
        .expect("executable permissions");
    assert!(
        Command::new(executable.path())
            .status()
            .expect("run")
            .success()
    );
    let path = executable.path().to_path_buf();
    drop(executable);
    assert!(!path.exists(), "closed runtime file was not removed");
}

#[cfg(unix)]
#[test]
fn runtime_permissions_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().expect("runtime parent");
    let runtime = PrivateRuntime::open(root.path().join("gitveil")).expect("runtime");
    assert_eq!(
        fs::metadata(runtime.root())
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let file = runtime.create("secret-", true).expect("runtime file");
    assert_eq!(
        fs::metadata(file.path())
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}
